package com.enterprise.bff.web;

import com.enterprise.bff.security.IamLogout;
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
 * POST /bff/logout  -> revoca immediata della sessione su Redis e scadenza del cookie (Origin verificata);
 *                      risponde con l'URL di logout sullo IAM, verso cui la SPA naviga per chiudere anche l'SSO
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

    /** URL verso cui la SPA naviga per chiudere anche la sessione SSO sullo IAM. */
    public record LogoutResult(@JsonProperty("logout_url") String logoutUrl) {
    }

    private final SessionStore sessionStore;
    private final SessionCookies cookies;
    private final SessionIdGenerator idGenerator;
    private final OriginPolicy originPolicy;
    private final IamLogout iamLogout;

    public SessionController(SessionStore sessionStore, SessionCookies cookies, SessionIdGenerator idGenerator,
                             OriginPolicy originPolicy, IamLogout iamLogout) {
        this.sessionStore = sessionStore;
        this.cookies = cookies;
        this.idGenerator = idGenerator;
        this.originPolicy = originPolicy;
        this.iamLogout = iamLogout;
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

    /**
     * Chiude la sessione applicativa e restituisce l'URL di logout sullo IAM: la SPA ci naviga
     * (window.location), perche' un fetch non puo' seguire un redirect verso un'altra origine.
     */
    @PostMapping("/bff/logout")
    public Mono<ResponseEntity<LogoutResult>> logout(ServerWebExchange exchange) {
        if (!originPolicy.isAllowed(exchange.getRequest())) {
            return Mono.just(ResponseEntity.status(HttpStatus.FORBIDDEN).build());
        }
        exchange.getResponse().addCookie(cookies.expire());
        // "" = nessun ID token (sessione assente o login senza OIDC)
        Mono<String> idToken = cookies.read(exchange.getRequest())
                .filter(idGenerator::isWellFormed)
                .map(id -> sessionStore.takeIdToken(id)
                        .defaultIfEmpty("")
                        .flatMap(token -> sessionStore.delete(id).thenReturn(token)))
                .orElseGet(() -> Mono.just(""));
        return idToken
                .flatMap(token -> iamLogout.logoutUrl(token.isEmpty() ? null : token))
                .map(url -> ResponseEntity.ok()
                        .header(HttpHeaders.CACHE_CONTROL, "no-store")
                        .body(new LogoutResult(url)));
    }

    private <T> ResponseEntity<T> unauthorized(ServerWebExchange exchange) {
        exchange.getResponse().addCookie(cookies.expire());
        return ResponseEntity.status(401).build();
    }
}
