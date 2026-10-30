package com.enterprise.bff.web;

import com.enterprise.bff.security.OriginPolicy;
import com.enterprise.bff.session.SessionCookies;
import com.enterprise.bff.session.SessionData;
import com.enterprise.bff.session.SessionIdGenerator;
import com.enterprise.bff.session.SessionStore;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.regex.Pattern;

/**
 * Revoca immediata delle sessioni di un utente (specifica par. 5), ad es. utente disattivato o compromesso.
 * DELETE /bff/admin/users/{username}/sessions
 * - session:revoke-global -> tutte le sessioni dell'utente;
 * - session:revoke        -> solo quelle aperte sul tenant dell'amministratore (admin delegato).
 * I servizi di dominio smettono di accettare la sessione entro il TTL della loro cache L1.
 */
@RestController
public class SessionAdminController {

    public static final String REVOKE_TENANT = "session:revoke";
    public static final String REVOKE_GLOBAL = "session:revoke-global";

    public record RevocationResult(String username,
                                   @JsonProperty("tenant_id") String tenantId,
                                   @JsonProperty("revoked_sessions") long revokedSessions) {
    }

    private static final Logger log = LoggerFactory.getLogger(SessionAdminController.class);
    private static final Pattern USERNAME_FORMAT = Pattern.compile("^[A-Za-z0-9._@-]{1,150}$");

    private final SessionStore sessionStore;
    private final SessionCookies cookies;
    private final SessionIdGenerator idGenerator;
    private final OriginPolicy originPolicy;

    public SessionAdminController(SessionStore sessionStore, SessionCookies cookies, SessionIdGenerator idGenerator,
                                  OriginPolicy originPolicy) {
        this.sessionStore = sessionStore;
        this.cookies = cookies;
        this.idGenerator = idGenerator;
        this.originPolicy = originPolicy;
    }

    @DeleteMapping("/bff/admin/users/{username}/sessions")
    public Mono<ResponseEntity<RevocationResult>> revoke(@PathVariable String username, ServerWebExchange exchange) {
        if (!originPolicy.isAllowed(exchange.getRequest())) {
            return Mono.just(ResponseEntity.status(HttpStatus.FORBIDDEN).build());
        }
        if (!USERNAME_FORMAT.matcher(username).matches()) {
            return Mono.just(ResponseEntity.badRequest().build());
        }
        return cookies.read(exchange.getRequest())
                .filter(idGenerator::isWellFormed)
                .map(sessionStore::find)
                .orElseGet(Mono::empty)
                .flatMap(caller -> revokeAs(caller, username))
                .defaultIfEmpty(ResponseEntity.status(HttpStatus.UNAUTHORIZED).build());
    }

    private Mono<ResponseEntity<RevocationResult>> revokeAs(SessionData caller, String username) {
        String tenantScope;
        if (caller.permissions().contains(REVOKE_GLOBAL)) {
            tenantScope = null;
        } else if (caller.permissions().contains(REVOKE_TENANT)) {
            tenantScope = caller.tenantId();
        } else {
            log.warn("Revoca sessioni negata: utente={} senza permesso, destinatario={}", caller.username(), username);
            return Mono.just(ResponseEntity.status(HttpStatus.FORBIDDEN).build());
        }
        return sessionStore.revokeUserSessions(username, tenantScope)
                .map(count -> {
                    log.info("Revoca sessioni: amministratore={} tenant_amministratore={} destinatario={} ambito={} revocate={}",
                            caller.username(), caller.tenantId(), username,
                            tenantScope == null ? "GLOBALE" : tenantScope, count);
                    return ResponseEntity.ok(new RevocationResult(username, tenantScope, count));
                });
    }
}
