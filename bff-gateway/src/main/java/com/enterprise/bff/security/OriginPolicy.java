package com.enterprise.bff.security;

import com.enterprise.bff.config.BffProperties;
import org.springframework.http.HttpMethod;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;

import java.util.Set;

/**
 * Difesa CSRF in aggiunta a SameSite=Strict: le richieste non idempotenti sono ammesse solo
 * se l'header Origin appartiene a bff.frontend.allowed-origins.
 * Usata sia dalle rotte del gateway (SessionRelayGlobalFilter) sia dagli endpoint /bff/**.
 */
@Component
public class OriginPolicy {

    private static final Set<HttpMethod> SAFE_METHODS =
            Set.of(HttpMethod.GET, HttpMethod.HEAD, HttpMethod.OPTIONS);

    private final Set<String> allowedOrigins;

    public OriginPolicy(BffProperties properties) {
        this.allowedOrigins = Set.copyOf(properties.frontend().allowedOrigins());
    }

    public boolean isAllowed(ServerHttpRequest request) {
        if (SAFE_METHODS.contains(request.getMethod())) {
            return true;
        }
        String origin = request.getHeaders().getOrigin();
        // Assenza di Origin su richieste non idempotenti: i browser moderni la inviano sempre
        // per fetch/XHR cross e same-origin con body; si rifiuta per sicurezza.
        return origin != null && allowedOrigins.contains(origin);
    }
}
