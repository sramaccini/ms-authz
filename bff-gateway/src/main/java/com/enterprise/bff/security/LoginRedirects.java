package com.enterprise.bff.security;

import com.enterprise.bff.config.BffProperties;
import org.springframework.security.web.server.DefaultServerRedirectStrategy;
import org.springframework.security.web.server.ServerRedirectStrategy;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.util.UriComponentsBuilder;
import reactor.core.publisher.Mono;

/** Redirect verso URL del frontend fissi da configurazione (nessun open redirect). */
@Component
public class LoginRedirects {

    private final ServerRedirectStrategy redirectStrategy = new DefaultServerRedirectStrategy();
    private final BffProperties.Frontend frontend;

    public LoginRedirects(BffProperties properties) {
        this.frontend = properties.frontend();
    }

    public Mono<Void> toSuccess(ServerWebExchange exchange) {
        return redirectStrategy.sendRedirect(exchange, frontend.loginSuccessUrl());
    }

    public Mono<Void> toFailure(ServerWebExchange exchange, LoginErrorCode error) {
        var uri = UriComponentsBuilder.fromUri(frontend.loginFailureUrl())
                .queryParam("error", error.code())
                .build(true)
                .toUri();
        return redirectStrategy.sendRedirect(exchange, uri);
    }
}
