package com.enterprise.bff.filter;

import io.netty.channel.ConnectTimeoutException;
import org.junit.jupiter.api.Test;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.io.IOException;
import java.net.ConnectException;
import java.net.UnknownHostException;

import static org.assertj.core.api.Assertions.assertThat;

class DownstreamErrorGlobalFilterTest {

    private final DownstreamErrorGlobalFilter filter = new DownstreamErrorGlobalFilter();

    @Test
    void connectionRefusedIsReportedAs503() {
        MockServerWebExchange exchange = exchange();

        StepVerifier.create(filter.filter(exchange, failingWith(new ConnectException("Connection refused"))))
                .verifyComplete();

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.SERVICE_UNAVAILABLE);
        assertThat(exchange.getResponse().getHeaders().getContentType()).isEqualTo(MediaType.APPLICATION_PROBLEM_JSON);
        StepVerifier.create(exchange.getResponse().getBodyAsString())
                .assertNext(body -> assertThat(body).contains("\"status\":503"))
                .verifyComplete();
    }

    @Test
    void connectTimeoutAndUnknownHostAreReportedAs503() {
        assertThat(DownstreamErrorGlobalFilter.statusFor(new ConnectTimeoutException("connection timed out")))
                .isEqualTo(HttpStatus.SERVICE_UNAVAILABLE);
        assertThat(DownstreamErrorGlobalFilter.statusFor(new IllegalStateException(new UnknownHostException("svc"))))
                .isEqualTo(HttpStatus.SERVICE_UNAVAILABLE);
    }

    @Test
    void connectionDroppedDuringExchangeIsReportedAs502() {
        MockServerWebExchange exchange = exchange();

        StepVerifier.create(filter.filter(exchange, failingWith(new IOException("Connection reset by peer"))))
                .verifyComplete();

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.BAD_GATEWAY);
    }

    @Test
    void otherErrorsArePropagated() {
        IllegalStateException error = new IllegalStateException("bug");

        StepVerifier.create(filter.filter(exchange(), failingWith(error))).verifyErrorMatches(e -> e == error);
    }

    @Test
    void errorsAfterResponseCommitAreNotRewritten() {
        MockServerWebExchange exchange = exchange();
        GatewayFilterChain chain = ex -> ex.getResponse().setComplete()
                .then(Mono.error(new IOException("Connection reset by peer")));

        StepVerifier.create(filter.filter(exchange, chain)).verifyError(IOException.class);
    }

    private static MockServerWebExchange exchange() {
        return MockServerWebExchange.from(MockServerHttpRequest.get("/api/v1/clinical/x"));
    }

    private static GatewayFilterChain failingWith(Throwable error) {
        return exchange -> Mono.error(error);
    }
}
