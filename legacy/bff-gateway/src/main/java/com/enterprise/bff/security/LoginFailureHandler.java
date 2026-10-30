package com.enterprise.bff.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.ServerAuthenticationFailureHandler;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

/** Errore nel flusso OIDC (state non valido, utente che annulla, IAM non raggiungibile...). */
@Component
public class LoginFailureHandler implements ServerAuthenticationFailureHandler {

    private static final Logger log = LoggerFactory.getLogger(LoginFailureHandler.class);

    private final LoginRedirects redirects;

    public LoginFailureHandler(LoginRedirects redirects) {
        this.redirects = redirects;
    }

    @Override
    public Mono<Void> onAuthenticationFailure(WebFilterExchange webFilterExchange, AuthenticationException exception) {
        log.warn("Login OIDC fallito: {}", exception.getMessage());
        return redirects.toFailure(webFilterExchange.getExchange(), LoginErrorCode.LOGIN_FAILED);
    }
}
