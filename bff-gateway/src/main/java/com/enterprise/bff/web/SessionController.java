package com.enterprise.bff.web;

import com.enterprise.bff.security.OriginPolicy;
import com.enterprise.bff.session.SessionCookies;
import com.enterprise.bff.session.SessionData;
import com.enterprise.bff.session.SessionIdGenerator;
import com.enterprise.bff.session.SessionStore;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;

/**
 * Endpoint di sessione per la SPA.
 * GET  /bff/session -> contesto utente per la UI (il SESSION_ID non viene mai esposto al JavaScript)
 * POST /bff/logout  -> revoca immediata della sessione su Redis e scadenza del cookie (Origin verificata)
 */
@RestController
public class SessionController {

    public record SessionView(String username,
                              String email,
                              @JsonProperty("tenant_id") String tenantId,
                              List<String> roles,
                              List<String> permissions,
                              @JsonProperty("expires_at") String expiresAt) {

        static SessionView of(SessionData s) {
            return new SessionView(s.username(), s.email(), s.tenantId(), s.roles(), s.permissions(), s.expiresAt());
        }
    }

    private final SessionStore sessionStore;
    private final SessionCookies cookies;
    private final SessionIdGenerator idGenerator;
    private final OriginPolicy originPolicy;

    public SessionController(SessionStore sessionStore, SessionCookies cookies, SessionIdGenerator idGenerator,
                             OriginPolicy originPolicy) {
        this.sessionStore = sessionStore;
        this.cookies = cookies;
        this.idGenerator = idGenerator;
        this.originPolicy = originPolicy;
    }

    @GetMapping("/bff/session")
    public Mono<ResponseEntity<SessionView>> currentSession(ServerWebExchange exchange) {
        return cookies.read(exchange.getRequest())
                .filter(idGenerator::isWellFormed)
                .map(id -> sessionStore.find(id)
                        .map(s -> ResponseEntity.ok()
                                .header(HttpHeaders.CACHE_CONTROL, "no-store")
                                .body(SessionView.of(s))))
                .orElseGet(Mono::empty)
                .switchIfEmpty(Mono.fromSupplier(() -> this.<SessionView>unauthorized(exchange)));
    }

    @PostMapping("/bff/logout")
    public Mono<ResponseEntity<Void>> logout(ServerWebExchange exchange) {
        if (!originPolicy.isAllowed(exchange.getRequest())) {
            return Mono.just(ResponseEntity.status(HttpStatus.FORBIDDEN).build());
        }
        exchange.getResponse().addCookie(cookies.expire());
        return cookies.read(exchange.getRequest())
                .filter(idGenerator::isWellFormed)
                .map(sessionStore::delete)
                .orElseGet(() -> Mono.just(false))
                .thenReturn(ResponseEntity.noContent().build());
    }

    private <T> ResponseEntity<T> unauthorized(ServerWebExchange exchange) {
        exchange.getResponse().addCookie(cookies.expire());
        return ResponseEntity.status(401).build();
    }
}
