package com.enterprise.auth;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.RequestPostProcessor;
import org.springframework.test.web.servlet.ResultActions;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.List;

import static org.hamcrest.Matchers.contains;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * POST /api/v1/auth/enrich su PostgreSQL reale: schema Flyway + dati demo (db/seed).
 * - jwt(): JWT simulato, per le regole di autorizzazione e le query;
 * - bearer(): JWT firmato con una chiave di test e verificato dal decoder reale (JWKS servito localmente),
 *   per firma, issuer, scadenza e audience.
 */
@SpringBootTest(properties = {
        "AUTH_DB_PASSWORD=unused", // sostituita dalla ServiceConnection del container
        "spring.flyway.locations=classpath:db/migration,classpath:db/seed"
})
@AutoConfigureMockMvc
@Testcontainers
class EnrichIntegrationTest {

    @Container
    @ServiceConnection
    static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:17");

    static final String ISSUER = "http://iam.test/realms/enterprise";
    static final RSAKey SIGNING_KEY = rsaKey();
    static final HttpServer JWKS = jwksServer();

    @DynamicPropertySource
    static void iam(DynamicPropertyRegistry registry) {
        registry.add("spring.security.oauth2.resourceserver.jwt.issuer-uri", () -> ISSUER);
        registry.add("spring.security.oauth2.resourceserver.jwt.jwk-set-uri",
                () -> "http://localhost:" + JWKS.getAddress().getPort() + "/certs");
    }

    @AfterAll
    static void stopJwks() {
        JWKS.stop(0);
    }

    @Autowired
    MockMvc mvc;

    @Test
    void openApiDefinitionIsNotPublishedByDefault() throws Exception {
        mvc.perform(get("/v3/api-docs")).andExpect(status().isNotFound());
    }

    @Test
    void signedAccessTokenForThisServiceIsAccepted() throws Exception {
        enrichWithBearer(signedToken(ISSUER, List.of("auth-service", "account"), 300))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("mario.rossi"));
    }

    @Test
    void tokenIssuedForAnotherAudienceIsRejected() throws Exception {
        // E' il caso di un ID token del BFF (aud = bff-gateway) presentato come Bearer
        enrichWithBearer(signedToken(ISSUER, List.of("bff-gateway"), 300))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void tokenFromAnotherIssuerIsRejected() throws Exception {
        enrichWithBearer(signedToken("http://altro-iam.test/realms/x", List.of("auth-service"), 300))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void expiredTokenIsRejected() throws Exception {
        enrichWithBearer(signedToken(ISSUER, List.of("auth-service"), -120))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void userWithSingleTenantIsEnriched() throws Exception {
        enrich("""
                {"username":"mario.rossi"}""", asUser("mario.rossi"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.tenant_id").value("TENANT_A"))
                .andExpect(jsonPath("$.roles").value(contains("CUP_OPERATOR", "DOCTOR")))
                .andExpect(jsonPath("$.permissions")
                        .value(contains("booking:manage", "patient:read", "patient:write", "prescription:create")));
    }

    @Test
    void userWithManyTenantsMustChooseOne() throws Exception {
        enrich("""
                {"username":"anna.bianchi"}""", asUser("anna.bianchi"))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.available_tenants").value(contains("TENANT_A", "TENANT_B")));

        enrich("""
                {"username":"anna.bianchi","tenant_id":"TENANT_B"}""", asUser("anna.bianchi"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.tenant_id").value("TENANT_B"));
    }

    @Test
    void tenantWithoutRolesIsForbidden() throws Exception {
        enrich("""
                {"username":"mario.rossi","tenant_id":"TENANT_B"}""", asUser("mario.rossi"))
                .andExpect(status().isForbidden());
    }

    @Test
    void unknownUserGetsSameAnswerAsUnauthorizedUser() throws Exception {
        enrich("""
                {"username":"nessuno"}""", asUser("nessuno"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.type").value("urn:problem:auth-service:user-not-authorized"));
    }

    @Test
    void userCannotEnrichSomeoneElse() throws Exception {
        enrich("""
                {"username":"anna.bianchi","tenant_id":"TENANT_A"}""", asUser("mario.rossi"))
                .andExpect(status().isForbidden());
    }

    @Test
    void serviceClientWithScopeCanEnrichAnyUser() throws Exception {
        enrich("""
                {"username":"anna.bianchi","tenant_id":"TENANT_A"}""",
                jwt().jwt(j -> j.subject("service-account"))
                        .authorities(new SimpleGrantedAuthority("SCOPE_auth:enrich")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("anna.bianchi"));
    }

    @Test
    void missingTokenIsUnauthorized() throws Exception {
        mvc.perform(post("/api/v1/auth/enrich").contentType(MediaType.APPLICATION_JSON).content("""
                        {"username":"mario.rossi"}"""))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void invalidTenantFormatIsRejected() throws Exception {
        enrich("""
                {"username":"mario.rossi","tenant_id":"A' OR '1'='1"}""", asUser("mario.rossi"))
                .andExpect(status().isBadRequest());
    }

    private ResultActions enrichWithBearer(String token) throws Exception {
        return mvc.perform(post("/api/v1/auth/enrich")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                        {"username":"mario.rossi"}"""));
    }

    private static String signedToken(String issuer, List<String> audience, long validForSeconds) throws Exception {
        Instant now = Instant.now();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(issuer)
                .subject("sub-mario.rossi")
                .audience(audience)
                .claim("preferred_username", "mario.rossi")
                .issueTime(Date.from(now.minusSeconds(Math.max(0, -validForSeconds) + 10)))
                .expirationTime(Date.from(now.plusSeconds(validForSeconds)))
                .build();
        SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(SIGNING_KEY.getKeyID()).build(),
                claims);
        jwt.sign(new RSASSASigner(SIGNING_KEY));
        return jwt.serialize();
    }

    private static RSAKey rsaKey() {
        try {
            return new RSAKeyGenerator(2048).keyID("test-key").generate();
        } catch (JOSEException e) {
            throw new IllegalStateException(e);
        }
    }

    private static HttpServer jwksServer() {
        try {
            HttpServer server = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
            byte[] jwks = new JWKSet(SIGNING_KEY.toPublicJWK()).toString().getBytes(StandardCharsets.UTF_8);
            server.createContext("/certs", exchange -> {
                exchange.getResponseHeaders().add("Content-Type", "application/json");
                exchange.sendResponseHeaders(200, jwks.length);
                exchange.getResponseBody().write(jwks);
                exchange.close();
            });
            server.start();
            return server;
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    private ResultActions enrich(String body, RequestPostProcessor auth) throws Exception {
        return mvc.perform(post("/api/v1/auth/enrich")
                .with(auth)
                .contentType(MediaType.APPLICATION_JSON)
                .content(body));
    }

    private static RequestPostProcessor asUser(String username) {
        return jwt().jwt(j -> j.subject("sub-" + username).claim("preferred_username", username));
    }
}
