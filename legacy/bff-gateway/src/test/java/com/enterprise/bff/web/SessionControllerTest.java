package com.enterprise.bff.web;

import com.enterprise.bff.TestProperties;
import com.enterprise.bff.config.BffProperties;
import com.enterprise.bff.security.IamLogout;
import com.enterprise.bff.security.OriginPolicy;
import com.enterprise.bff.session.SessionCookies;
import com.enterprise.bff.session.SessionIdGenerator;
import com.enterprise.bff.session.SessionStore;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpCookie;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class SessionControllerTest {

    private static final String SESSION_ID = "c83b860d-4581-4246-86d7-e07584bd3bc1";

    private SessionStore sessionStore;
    private SessionController controller;
    private IamLogout iamLogout;

    @BeforeEach
    void setUp() {
        BffProperties properties = TestProperties.bff();
        sessionStore = mock(SessionStore.class);
        iamLogout = mock(IamLogout.class);
        when(iamLogout.logoutUrl(any())).thenAnswer(inv -> Mono.just("http://iam.test/logout?hint=" + inv.getArgument(0)));
        controller = new SessionController(sessionStore, new SessionCookies(properties), new SessionIdGenerator(),
                new OriginPolicy(properties), iamLogout);
    }

    @Test
    void logoutFromAllowedOriginRevokesSessionAndReturnsIamLogoutUrl() {
        when(sessionStore.takeIdToken(SESSION_ID)).thenReturn(Mono.just("id-token"));
        when(sessionStore.delete(SESSION_ID)).thenReturn(Mono.just(true));
        MockServerWebExchange exchange = logoutRequest(TestProperties.FRONTEND);

        StepVerifier.create(controller.logout(exchange))
                .assertNext(response -> {
                    assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
                    assertThat(response.getBody().logoutUrl()).isEqualTo("http://iam.test/logout?hint=id-token");
                })
                .verifyComplete();

        verify(sessionStore).delete(SESSION_ID);
        assertThat(exchange.getResponse().getCookies().getFirst("SESSION_ID").getMaxAge()).isZero();
    }

    @Test
    void logoutWithoutSessionStillReturnsIamLogoutUrl() {
        MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.post("/bff/logout")
                .header("Origin", TestProperties.FRONTEND));

        StepVerifier.create(controller.logout(exchange))
                .assertNext(response -> assertThat(response.getBody().logoutUrl()).endsWith("hint=null"))
                .verifyComplete();
        verify(sessionStore, never()).delete(any());
    }

    @Test
    void logoutFromForeignOriginIsRejectedAndSessionIsKept() {
        MockServerWebExchange exchange = logoutRequest("https://evil.example");

        StepVerifier.create(controller.logout(exchange))
                .assertNext(response -> assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN))
                .verifyComplete();

        verify(sessionStore, never()).delete(any());
        assertThat(exchange.getResponse().getCookies().containsKey("SESSION_ID")).isFalse();
    }

    @Test
    void logoutWithoutOriginIsRejected() {
        MockServerWebExchange exchange = logoutRequest(null);

        StepVerifier.create(controller.logout(exchange))
                .assertNext(response -> assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN))
                .verifyComplete();

        verify(sessionStore, never()).delete(any());
    }

    private static MockServerWebExchange logoutRequest(String origin) {
        MockServerHttpRequest.BaseBuilder<?> request = MockServerHttpRequest.post("/bff/logout")
                .cookie(new HttpCookie("SESSION_ID", SESSION_ID));
        if (origin != null) {
            request.header("Origin", origin);
        }
        return MockServerWebExchange.from(request);
    }
}
