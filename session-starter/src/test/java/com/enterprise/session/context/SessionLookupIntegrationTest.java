package com.enterprise.session.context;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import tools.jackson.databind.json.JsonMapper;

import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@Testcontainers
class SessionLookupIntegrationTest {

    @Container
    static final GenericContainer<?> REDIS = new GenericContainer<>("redis:7.4").withExposedPorts(6379);

    private static final Duration L1_TTL = Duration.ofMillis(300);
    private static LettuceConnectionFactory connectionFactory;
    private static StringRedisTemplate redis;
    private SessionLookup lookup;

    @BeforeAll
    static void connect() {
        connectionFactory = connectionFactory(REDIS.getHost(), REDIS.getMappedPort(6379));
        redis = new StringRedisTemplate(connectionFactory);
    }

    @AfterAll
    static void disconnect() {
        connectionFactory.destroy();
    }

    @BeforeEach
    void setUp() {
        lookup = newLookup(redis);
    }

    @Test
    void sessionWrittenByTheBffIsResolved() {
        String id = store(Instant.now().plusSeconds(1800));

        SessionContext session = lookup.find(id).orElseThrow();

        assertThat(session.username()).isEqualTo("mario.rossi");
        assertThat(session.tenantId()).isEqualTo("TENANT_A");
        assertThat(session.permissions()).containsExactly("patient:read", "patient:write");
    }

    @Test
    void revocationIsVisibleWithinTheL1Ttl() throws InterruptedException {
        String id = store(Instant.now().plusSeconds(1800));
        assertThat(lookup.find(id)).isPresent();

        redis.delete("session:" + id);
        assertThat(lookup.find(id)).as("ancora in cache L1").isPresent();

        Thread.sleep(L1_TTL.toMillis() + 200);
        assertThat(lookup.find(id)).isEmpty();
    }

    @Test
    void missingSessionIsNotCachedSoNewSessionsAreVisibleImmediately() {
        String id = UUID.randomUUID().toString();
        assertThat(lookup.find(id)).isEmpty();

        redis.opsForValue().set("session:" + id, json(id, Instant.now().plusSeconds(1800)));
        assertThat(lookup.find(id)).isPresent();
    }

    @Test
    void expiredSessionIsRejectedEvenIfStillInRedis() {
        assertThat(lookup.find(store(Instant.now().minusSeconds(1)))).isEmpty();
    }

    @Test
    void malformedIdIsRejectedWithoutQueryingRedis() {
        assertThat(lookup.find("*")).isEmpty();
        assertThat(lookup.find(null)).isEmpty();
    }

    @Test
    void unreachableRedisIsReportedAsUnavailable() {
        LettuceConnectionFactory down = connectionFactory("localhost", 1);
        try {
            SessionLookup offline = newLookup(new StringRedisTemplate(down));
            assertThatThrownBy(() -> offline.find(UUID.randomUUID().toString()))
                    .isInstanceOf(SessionStoreUnavailableException.class);
        } finally {
            down.destroy();
        }
    }

    private static SessionLookup newLookup(StringRedisTemplate template) {
        return new SessionLookup(template, JsonMapper.builder().build(),
                new SessionContextProperties("X-Session-ID", "session:",
                        new SessionContextProperties.Cache(L1_TTL, 100)));
    }

    private static String store(Instant expiresAt) {
        String id = UUID.randomUUID().toString();
        redis.opsForValue().set("session:" + id, json(id, expiresAt));
        return id;
    }

    /** Payload come lo scrive il BFF, con un campo in piu' per verificare la compatibilita' in avanti. */
    private static String json(String id, Instant expiresAt) {
        return """
                {"session_id":"%s","username":"mario.rossi","email":"mario.rossi@example.org",
                 "tenant_id":"TENANT_A","roles":["DOCTOR"],"permissions":["patient:read","patient:write"],
                 "created_at":"%s","expires_at":"%s","campo_futuro":"ignorato"}"""
                .formatted(id, Instant.now(), expiresAt);
    }

    private static LettuceConnectionFactory connectionFactory(String host, int port) {
        LettuceConnectionFactory factory = new LettuceConnectionFactory(new RedisStandaloneConfiguration(host, port));
        factory.afterPropertiesSet();
        factory.start();
        return factory;
    }
}
