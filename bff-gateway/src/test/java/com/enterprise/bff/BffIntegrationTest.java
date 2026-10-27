package com.enterprise.bff;

import com.enterprise.bff.session.SessionData;
import com.enterprise.bff.session.SessionStore;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.context.annotation.Bean;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.InMemoryReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.UUID;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * BFF con contesto completo su Redis reale: relay del gateway verso un servizio a valle simulato,
 * endpoint /bff/**, contratto JSON della sessione e WebSession di login su Redis (Spring Session).
 * Lo IAM non e' coinvolto: la client registration usa URI fittizi, quindi niente discovery all'avvio.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "IAM_CLIENT_SECRET=test",
        "bff.login-rate-limit.max-requests=3"
})
@Testcontainers
class BffIntegrationTest {

    @Container
    @ServiceConnection(name = "redis")
    static final GenericContainer<?> REDIS = new GenericContainer<>("redis:7.4").withExposedPorts(6379);

    /** Servizio di dominio simulato: risponde con gli header ricevuti, uno per riga. */
    static final HttpServer DOWNSTREAM = startEchoServer();

    @DynamicPropertySource
    static void routes(DynamicPropertyRegistry registry) {
        String prefix = "spring.cloud.gateway.server.webflux.routes";
        registry.add(prefix + "[0].id", () -> "clinical-service");
        registry.add(prefix + "[0].uri", () -> "http://localhost:" + DOWNSTREAM.getAddress().getPort());
        registry.add(prefix + "[0].predicates[0]", () -> "Path=/api/v1/clinical/**");
        registry.add(prefix + "[1].id", () -> "down-service");
        registry.add(prefix + "[1].uri", () -> "http://localhost:" + freePort());
        registry.add(prefix + "[1].predicates[0]", () -> "Path=/api/v1/down/**");
    }

    @TestConfiguration
    static class FakeIam {
        @Bean
        ReactiveClientRegistrationRepository clientRegistrations() {
            return new InMemoryReactiveClientRegistrationRepository(ClientRegistration.withRegistrationId("iam")
                    .clientId("bff-gateway")
                    .clientSecret("test")
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
                    .scope("openid", "profile", "email")
                    .authorizationUri("http://iam.test/auth")
                    .tokenUri("http://iam.test/token")
                    .jwkSetUri("http://iam.test/certs")
                    .providerConfigurationMetadata(Map.of("end_session_endpoint", "http://iam.test/logout"))
                    .userNameAttributeName("preferred_username")
                    .build());
        }
    }

    @LocalServerPort
    int port;

    @Autowired
    SessionStore sessionStore;

    @Autowired
    ReactiveStringRedisTemplate redis;

    WebTestClient client;

    @BeforeEach
    void setUp() {
        client = WebTestClient.bindToServer().baseUrl("http://localhost:" + port).build();
        redis.getConnectionFactory().getReactiveConnection().serverCommands().flushAll().block();
    }

    @AfterAll
    static void stopDownstream() {
        DOWNSTREAM.stop(0);
    }

    @Test
    void sessionIsStoredWithSharedJsonContractAndTtl() {
        String id = newSession("TENANT_A");

        String json = redis.opsForValue().get("session:" + id).block();
        assertThat(json).contains("\"session_id\":\"" + id + "\"", "\"tenant_id\":\"TENANT_A\"",
                "\"created_at\"", "\"expires_at\"");
        assertThat(redis.getExpire("session:" + id).block()).isPositive();
    }

    @Test
    void validSessionIsRelayedWithOnlyTheSessionHeader() {
        String id = newSession("TENANT_A");

        String echoed = client.get().uri("/api/v1/clinical/patients")
                .cookie("SESSION_ID", id)
                .header(HttpHeaders.AUTHORIZATION, "Bearer forged")
                .header("X-Session-ID", "forged")
                .exchange()
                .expectStatus().isOk()
                .expectBody(String.class).returnResult().getResponseBody();

        assertThat(echoed).contains("x-session-id: " + id)
                .doesNotContain("authorization")
                .doesNotContain("cookie");
    }

    @Test
    void unknownSessionIsUnauthorized() {
        client.get().uri("/api/v1/clinical/patients")
                .cookie("SESSION_ID", UUID.randomUUID().toString())
                .exchange()
                .expectStatus().isUnauthorized()
                .expectHeader().contentType(MediaType.APPLICATION_PROBLEM_JSON);
    }

    @Test
    void unreachableDownstreamIsServiceUnavailable() {
        client.get().uri("/api/v1/down/anything")
                .cookie("SESSION_ID", newSession("TENANT_A"))
                .exchange()
                .expectStatus().isEqualTo(503)
                .expectBody().jsonPath("$.status").isEqualTo(503);
    }

    @Test
    void sessionEndpointReturnsUserContext() {
        client.get().uri("/bff/session")
                .cookie("SESSION_ID", newSession("TENANT_B"))
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.username").isEqualTo("utente.test")
                .jsonPath("$.tenant_id").isEqualTo("TENANT_B")
                .jsonPath("$.session_id").doesNotExist();
    }

    @Test
    void logoutRequiresAllowedOriginAndRevokesSession() {
        String id = newSession("TENANT_A");
        sessionStore.saveIdToken(id, "eyJ.id.token", Duration.ofMinutes(30)).block();

        client.post().uri("/bff/logout").cookie("SESSION_ID", id).header(HttpHeaders.ORIGIN, "https://evil.example")
                .exchange().expectStatus().isForbidden();
        assertThat(redis.hasKey("session:" + id).block()).isTrue();

        client.post().uri("/bff/logout").cookie("SESSION_ID", id).header(HttpHeaders.ORIGIN, TestProperties.FRONTEND)
                .exchange()
                .expectStatus().isOk()
                .expectHeader().cacheControl(org.springframework.http.CacheControl.noStore())
                .expectBody()
                .jsonPath("$.logout_url").value(url -> assertThat((String) url)
                        .startsWith("http://iam.test/logout?")
                        .contains("client_id=bff-gateway", "id_token_hint=eyJ.id.token", "post_logout_redirect_uri="));

        assertThat(redis.hasKey("session:" + id).block()).isFalse();
        assertThat(redis.hasKey("bff:id_token:" + id).block()).isFalse();
    }

    @Test
    void loginStateIsKeptInRedisSoAnyInstanceCanCompleteIt() {
        String setCookie = client.get().uri("/bff/login?tenant=TENANT_B")
                .exchange()
                .expectStatus().isFound()
                .expectHeader().location("/oauth2/authorization/iam")
                .returnResult(Void.class).getResponseHeaders().getFirst(HttpHeaders.SET_COOKIE);

        assertThat(setCookie).startsWith("BFF_LOGIN=").containsIgnoringCase("HttpOnly")
                .contains("Secure", "SameSite=Lax");
        String loginSessionId = setCookie.substring("BFF_LOGIN=".length(), setCookie.indexOf(';'));
        Map<Object, Object> stored = redis.opsForHash()
                .entries("bff:login:sessions:" + loginSessionId)
                .collectMap(Map.Entry::getKey, Map.Entry::getValue).block();
        assertThat(stored).containsKey("sessionAttr:BFF_TENANT_HINT");
    }

    @Test
    void invalidTenantHintIsRejectedWithoutCreatingState() {
        client.get().uri("/bff/login?tenant=../../x").exchange().expectStatus().isBadRequest();

        assertThat(redis.keys("bff:login:*").collectList().block()).isEmpty();
    }

    @Test
    void loginEntryPointsAreRateLimitedPerClient() {
        for (int i = 0; i < 3; i++) {
            client.get().uri("/bff/login?tenant=TENANT_A").exchange().expectStatus().isFound();
        }

        client.get().uri("/oauth2/authorization/iam")
                .exchange()
                .expectStatus().isEqualTo(429)
                .expectHeader().exists(HttpHeaders.RETRY_AFTER)
                .expectHeader().contentType(MediaType.APPLICATION_PROBLEM_JSON);

        // Le chiamate applicative non sono soggette al limite del login
        client.get().uri("/bff/session").exchange().expectStatus().isUnauthorized();
        assertThat(redis.keys("bff:login:*").collectList().block()).hasSize(3);
    }

    @Test
    void sessionsAreIndexedPerUser() {
        String first = newSession("mario.rossi", "TENANT_A");
        String second = newSession("mario.rossi", "TENANT_A");

        assertThat(redis.opsForSet().members("user_sessions:mario.rossi").collectList().block())
                .containsExactlyInAnyOrder(first, second);
        assertThat(redis.getExpire("user_sessions:mario.rossi").block()).isPositive();
    }

    @Test
    void tenantAdminRevokesOnlySessionsOfOwnTenant() {
        String onTenantA = newSession("mario.rossi", "TENANT_A");
        String onTenantB = newSession("mario.rossi", "TENANT_B");
        String admin = newSession("admin.a", "TENANT_A", "session:revoke");

        revoke("mario.rossi", admin)
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.revoked_sessions").isEqualTo(1)
                .jsonPath("$.tenant_id").isEqualTo("TENANT_A");

        assertThat(redis.hasKey("session:" + onTenantA).block()).isFalse();
        assertThat(redis.hasKey("session:" + onTenantB).block()).isTrue();
    }

    @Test
    void globalAdminRevokesAllSessionsAndCleansIndex() {
        String onTenantA = newSession("mario.rossi", "TENANT_A");
        String onTenantB = newSession("mario.rossi", "TENANT_B");
        String admin = newSession("admin.global", "TENANT_A", "session:revoke-global");

        revoke("mario.rossi", admin).expectStatus().isOk().expectBody().jsonPath("$.revoked_sessions").isEqualTo(2);

        assertThat(redis.hasKey("session:" + onTenantA).block()).isFalse();
        assertThat(redis.hasKey("session:" + onTenantB).block()).isFalse();
        assertThat(redis.hasKey("bff:id_token:" + onTenantA).block()).as("ID token revocato con la sessione").isFalse();
        assertThat(redis.opsForSet().size("user_sessions:mario.rossi").block()).isZero();
    }

    @Test
    void revocationRequiresPermissionSessionAndAllowedOrigin() {
        String target = newSession("mario.rossi", "TENANT_A");
        String plainUser = newSession("utente.test", "TENANT_A", "patient:read");

        revoke("mario.rossi", plainUser).expectStatus().isForbidden();
        client.delete().uri("/bff/admin/users/mario.rossi/sessions").header(HttpHeaders.ORIGIN, TestProperties.FRONTEND)
                .exchange().expectStatus().isUnauthorized();
        client.delete().uri("/bff/admin/users/mario.rossi/sessions")
                .cookie("SESSION_ID", newSession("admin.global", "TENANT_A", "session:revoke-global"))
                .header(HttpHeaders.ORIGIN, "https://evil.example")
                .exchange().expectStatus().isForbidden();

        assertThat(redis.hasKey("session:" + target).block()).isTrue();
    }

    private WebTestClient.ResponseSpec revoke(String username, String callerSessionId) {
        return client.delete().uri("/bff/admin/users/{username}/sessions", username)
                .cookie("SESSION_ID", callerSessionId)
                .header(HttpHeaders.ORIGIN, TestProperties.FRONTEND)
                .exchange();
    }

    private String newSession(String tenant) {
        return newSession("utente.test", tenant, "patient:read");
    }

    private String newSession(String username, String tenant, String... permissions) {
        String id = UUID.randomUUID().toString();
        Instant now = Instant.now();
        sessionStore.save(new SessionData(id, username, username + "@example.org", tenant,
                List.of("DOCTOR"), List.of(permissions), now.toString(), now.plusSeconds(1800).toString()),
                Duration.ofMinutes(30)).block();
        sessionStore.saveIdToken(id, "eyJ.id.token." + id, Duration.ofMinutes(30)).block();
        return id;
    }

    private static HttpServer startEchoServer() {
        try {
            HttpServer server = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
            server.createContext("/", exchange -> {
                Map<String, List<String>> sorted = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
                sorted.putAll(exchange.getRequestHeaders());
                byte[] body = sorted.entrySet().stream()
                        .map(e -> e.getKey().toLowerCase() + ": " + String.join(",", e.getValue()))
                        .collect(Collectors.joining("\n"))
                        .getBytes(StandardCharsets.UTF_8);
                exchange.sendResponseHeaders(200, body.length);
                exchange.getResponseBody().write(body);
                exchange.close();
            });
            server.start();
            return server;
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    private static int freePort() {
        try (ServerSocket socket = new ServerSocket(0)) {
            return socket.getLocalPort();
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }
}
