package com.enterprise.bff.filter;

import com.enterprise.bff.security.OriginPolicy;
import com.enterprise.bff.session.SessionCookies;
import com.enterprise.bff.session.SessionIdGenerator;
import com.enterprise.bff.session.SessionStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;

/**
 * Applicato a TUTTE le rotte del gateway (passi 9-10 del sequence diagram):
 * - rimuove dalla richiesta gli header interni eventualmente inviati dal client (anti-spoofing)
 *   e le credenziali del client (Cookie, Authorization): verso valle l'unica credenziale e' X-Session-ID;
 * - per i metodi non idempotenti verifica l'header Origin (difesa CSRF in aggiunta a SameSite=Strict);
 * - valida il cookie SESSION_ID su Redis -> 401 se assente/scaduto, 503 se Redis non risponde;
 * - inoltra a valle con l'header X-Session-ID.
 */
@Component
public class SessionRelayGlobalFilter implements GlobalFilter, Ordered {

    public static final String SESSION_HEADER = "X-Session-ID";

    private static final Logger log = LoggerFactory.getLogger(SessionRelayGlobalFilter.class);
    private static final List<String> INTERNAL_HEADERS =
            List.of(SESSION_HEADER, "X-Username", "X-User-Roles", "X-Tenant-ID");

    private enum SessionCheck { VALID, INVALID, STORE_UNAVAILABLE }

    private final SessionStore sessionStore;
    private final SessionCookies cookies;
    private final SessionIdGenerator idGenerator;
    private final OriginPolicy originPolicy;

    public SessionRelayGlobalFilter(SessionStore sessionStore, SessionCookies cookies,
                                    SessionIdGenerator idGenerator, OriginPolicy originPolicy) {
        this.sessionStore = sessionStore;
        this.cookies = cookies;
        this.idGenerator = idGenerator;
        this.originPolicy = originPolicy;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();

        if (!originPolicy.isAllowed(request)) {
            return reject(exchange, HttpStatus.FORBIDDEN, "Origin non ammessa", false);
        }

        String sessionId = cookies.read(request).orElse(null);
        if (!idGenerator.isWellFormed(sessionId)) {
            return reject(exchange, HttpStatus.UNAUTHORIZED, "Sessione assente o non valida", sessionId != null);
        }

        return sessionStore.exists(sessionId)
                .map(exists -> exists ? SessionCheck.VALID : SessionCheck.INVALID)
                .onErrorResume(e -> {
                    log.error("Session store non raggiungibile: {}", e.toString());
                    return Mono.just(SessionCheck.STORE_UNAVAILABLE);
                })
                .flatMap(check -> switch (check) {
                    case VALID -> chain.filter(exchange.mutate().request(relay(request, sessionId)).build());
                    case INVALID -> reject(exchange, HttpStatus.UNAUTHORIZED, "Sessione scaduta o revocata", true);
                    case STORE_UNAVAILABLE -> reject(exchange, HttpStatus.SERVICE_UNAVAILABLE,
                            "Servizio temporaneamente non disponibile", false);
                });
    }

    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE + 100;
    }

    private ServerHttpRequest relay(ServerHttpRequest request, String sessionId) {
        return request.mutate()
                .headers(headers -> {
                    INTERNAL_HEADERS.forEach(headers::remove);
                    headers.remove(HttpHeaders.COOKIE); // il cookie del browser resta nel perimetro del BFF
                    headers.remove(HttpHeaders.AUTHORIZATION); // nessun token del client verso i servizi interni
                    headers.set(SESSION_HEADER, sessionId);
                })
                .build();
    }

    private Mono<Void> reject(ServerWebExchange exchange, HttpStatus status, String detail, boolean expireCookie) {
        ServerHttpResponse response = exchange.getResponse();
        if (expireCookie) {
            response.addCookie(cookies.expire());
        }
        return ProblemResponses.write(response, status, detail);
    }
}
