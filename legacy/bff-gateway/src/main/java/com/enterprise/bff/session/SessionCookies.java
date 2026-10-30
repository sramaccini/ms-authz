package com.enterprise.bff.session;

import com.enterprise.bff.config.BffProperties;
import org.springframework.http.HttpCookie;
import org.springframework.http.ResponseCookie;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.time.Duration;
import java.util.Optional;

/** Creazione e lettura del cookie di sessione con le flag obbligatorie (specifica par. 3.1). */
@Component
public class SessionCookies {

    private final BffProperties.Session config;

    public SessionCookies(BffProperties properties) {
        this.config = properties.session();
    }

    public ResponseCookie create(String sessionId) {
        return base(sessionId).maxAge(config.ttl()).build();
    }

    public ResponseCookie expire() {
        return base("").maxAge(Duration.ZERO).build();
    }

    public Optional<String> read(ServerHttpRequest request) {
        return Optional.ofNullable(request.getCookies().getFirst(config.cookieName()))
                .map(HttpCookie::getValue)
                .filter(StringUtils::hasText);
    }

    private ResponseCookie.ResponseCookieBuilder base(String value) {
        ResponseCookie.ResponseCookieBuilder builder = ResponseCookie.from(config.cookieName(), value)
                .httpOnly(true)
                .secure(config.cookieSecure())
                .sameSite("Strict")
                .path("/");
        if (StringUtils.hasText(config.cookieDomain())) {
            builder.domain(config.cookieDomain());
        }
        return builder;
    }
}
