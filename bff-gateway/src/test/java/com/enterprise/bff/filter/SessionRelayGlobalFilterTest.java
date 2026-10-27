package com.enterprise.bff.filter;

import com.enterprise.bff.TestProperties;
import com.enterprise.bff.config.BffProperties;
import com.enterprise.bff.security.OriginPolicy;
import com.enterprise.bff.session.SessionCookies;
import com.enterprise.bff.session.SessionIdGenerator;
import com.enterprise.bff.session.SessionStore;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.http.HttpCookie;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class SessionRelayGlobalFilterTest {

    private static final String SESSION_ID = "c83b860d-4581-4246-86d7-e07584bd3bc1";

    private SessionStore sessionStore;
    private SessionRelayGlobalFilter filter;
    private final AtomicReference<ServerWebExchange> forwarded = new AtomicReference<>();
    private final GatewayFilterChain chain = exchange -> {
        forwarded.set(exchange);
        return Mono.empty();
    };

    @BeforeEach
    void setUp() {
        BffProperties properties = TestProperties.bff();
        sessionStore = mock(SessionStore.class);
        filter = new SessionRelayGlobalFilter(sessionStore, new SessionCookies(properties),
                new SessionIdGenerator(), new OriginPolicy(properties));
    }

    @Test
    void validSessionIsRelayedWithHeaderAndSpoofedHeadersAreStripped() {
        when(sessionStore.exists(SESSION_ID)).thenReturn(Mono.just(true));
        MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/api/v1/clinical/x")
                .cookie(new HttpCookie("SESSION_ID", SESSION_ID))
                .header("X-Session-ID", "attacker-value")
                .header("X-User-Roles", "ADMIN")
                .header("Authorization", "Bearer attacker-token"));

        StepVerifier.create(filter.filter(exchange, chain)).verifyComplete();

        var headers = forwarded.get().getRequest().getHeaders();
        assertThat(headers.get("X-Session-ID")).containsExactly(SESSION_ID);
        assertThat(headers.containsHeader("X-User-Roles")).isFalse();
        assertThat(headers.containsHeader("Cookie")).isFalse();
        assertThat(headers.containsHeader("Authorization")).isFalse();
    }

    @Test
    void missingCookieIsRejectedWith401() {
        MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/api/v1/clinical/x"));

        StepVerifier.create(filter.filter(exchange, chain)).verifyComplete();

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(forwarded.get()).isNull();
    }

    @Test
    void expiredSessionIsRejectedWith401() {
        when(sessionStore.exists(SESSION_ID)).thenReturn(Mono.just(false));
        MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/api/v1/clinical/x")
                .cookie(new HttpCookie("SESSION_ID", SESSION_ID)));

        StepVerifier.create(filter.filter(exchange, chain)).verifyComplete();

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void redisFailureIsReportedAs503() {
        when(sessionStore.exists(SESSION_ID)).thenReturn(Mono.error(new IllegalStateException("redis down")));
        MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/api/v1/clinical/x")
                .cookie(new HttpCookie("SESSION_ID", SESSION_ID)));

        StepVerifier.create(filter.filter(exchange, chain)).verifyComplete();

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.SERVICE_UNAVAILABLE);
    }

    @Test
    void unsafeRequestFromForeignOriginIsRejected() {
        MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.post("/api/v1/clinical/x")
                .header("Origin", "https://evil.example")
                .cookie(new HttpCookie("SESSION_ID", SESSION_ID)));

        StepVerifier.create(filter.filter(exchange, chain)).verifyComplete();

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(forwarded.get()).isNull();
    }

    @Test
    void unsafeRequestFromAllowedOriginIsRelayed() {
        when(sessionStore.exists(SESSION_ID)).thenReturn(Mono.just(true));
        MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.post("/api/v1/clinical/x")
                .header("Origin", TestProperties.FRONTEND)
                .cookie(new HttpCookie("SESSION_ID", SESSION_ID)));

        StepVerifier.create(filter.filter(exchange, chain)).verifyComplete();

        assertThat(forwarded.get()).isNotNull();
    }

    @Test
    void unsafeRequestWithoutOriginIsRejected() {
        MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.post("/api/v1/clinical/x")
                .cookie(new HttpCookie("SESSION_ID", SESSION_ID)));

        StepVerifier.create(filter.filter(exchange, chain)).verifyComplete();

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(forwarded.get()).isNull();
    }
}
