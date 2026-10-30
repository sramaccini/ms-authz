package com.enterprise.authz.bff;

import java.net.URI;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Pattern;

import com.enterprise.authz.session.SessionContext;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.session.FindByIndexNameSessionRepository;
import org.springframework.session.Session;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/** Endpoint /bff/**: ingresso del login, utente corrente, logout, revoca delle sessioni. */
public final class BffControllers {

    /** Percorsi da lasciare pubblici nella SecurityFilterChain dell'applicazione. */
    public static final String[] PUBLIC_PATHS = {"/bff/login", "/bff/session", "/bff/logout"};

    private static final Pattern TENANT = Pattern.compile("^[A-Za-z0-9_-]{1,50}$");
    private static final Pattern USERNAME = Pattern.compile("^[A-Za-z0-9._@-]{1,150}$");

    private BffControllers() {
    }

    @RestController
    public static class LoginController {

        private final String registrationId;

        public LoginController(BffProperties properties) {
            this.registrationId = properties.oidc().registrationId();
        }

        /** Avvia il login OIDC; il tenant facoltativo viene ricordato in sessione fino al ritorno dallo IAM. */
        @GetMapping("/bff/login")
        public ResponseEntity<Void> login(@RequestParam(required = false) String tenant, HttpServletRequest request) {
            if (tenant != null && !TENANT.matcher(tenant).matches()) {
                return ResponseEntity.badRequest().build();
            }
            HttpSession session = request.getSession();
            if (tenant != null) {
                session.setAttribute(LoginSupport.TENANT_HINT, tenant);
            } else {
                session.removeAttribute(LoginSupport.TENANT_HINT);
            }
            return ResponseEntity.status(HttpStatus.FOUND)
                    .location(URI.create("/oauth2/authorization/" + registrationId)).build();
        }
    }

    @RestController
    public static class SessionController {

        private final LoginSupport.IamLogout iamLogout;

        public SessionController(LoginSupport.IamLogout iamLogout) {
            this.iamLogout = iamLogout;
        }

        /** Contesto utente per la UI: l'identificativo di sessione non viene mai esposto al JavaScript. */
        @GetMapping("/bff/session")
        public ResponseEntity<SessionView> current(HttpServletRequest request) {
            return SessionContext.from(request)
                    .map(s -> ResponseEntity.ok(new SessionView(s.username(), s.email(), s.tenantId(),
                            s.roles(), s.permissions(), s.expiresAt().toString())))
                    .orElseGet(() -> ResponseEntity.status(HttpStatus.UNAUTHORIZED).build());
        }

        /**
         * Chiude la sessione (Spring Session cancella la chiave su Redis e fa scadere il cookie) e risponde con
         * l'URL di logout sullo IAM, verso cui la SPA naviga per chiudere anche l'SSO.
         */
        @PostMapping("/bff/logout")
        public Map<String, String> logout(HttpServletRequest request) {
            HttpSession session = request.getSession(false);
            String idToken = null;
            if (session != null) {
                idToken = session.getAttribute(LoginSupport.ID_TOKEN) instanceof String t ? t : null;
                session.invalidate();
            }
            return Map.of("logout_url", iamLogout.logoutUrl(idToken));
        }

        public record SessionView(String username, String email, @JsonProperty("tenant_id") String tenantId,
                                  List<String> roles, List<String> permissions,
                                  @JsonProperty("expires_at") String expiresAt) {
        }
    }

    /**
     * Revoca immediata delle sessioni di un utente, con l'indice per username standard di Spring Session
     * (repository "indexed"). session:revoke: solo le sessioni sul tenant dell'amministratore;
     * session:revoke-global: tutte.
     */
    @RestController
    public static class SessionAdminController {

        public static final String REVOKE = "session:revoke";
        public static final String REVOKE_GLOBAL = "session:revoke-global";

        private final ObjectProvider<FindByIndexNameSessionRepository<? extends Session>> sessions;

        public SessionAdminController(ObjectProvider<FindByIndexNameSessionRepository<? extends Session>> sessions) {
            this.sessions = sessions;
        }

        @DeleteMapping("/bff/admin/users/{username}/sessions")
        public ResponseEntity<?> revoke(@PathVariable String username, @AuthenticationPrincipal SessionContext admin) {
            if (!USERNAME.matcher(username).matches()) {
                return ResponseEntity.badRequest().build();
            }
            boolean global = admin.hasPermission(REVOKE_GLOBAL);
            if (!global && !admin.hasPermission(REVOKE)) {
                return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
            }
            FindByIndexNameSessionRepository<? extends Session> repository = sessions.getIfAvailable();
            if (repository == null) {
                return ResponseEntity.of(ProblemDetail.forStatusAndDetail(HttpStatus.NOT_IMPLEMENTED,
                        "Revoca non disponibile: configurare spring.session.redis.repository-type=indexed")).build();
            }
            int revoked = 0;
            for (Map.Entry<String, ? extends Session> entry : repository.findByPrincipalName(username).entrySet()) {
                SessionContext target = entry.getValue().getAttribute(SessionContext.ATTRIBUTE);
                if (global || (target != null && Objects.equals(target.tenantId(), admin.tenantId()))) {
                    repository.deleteById(entry.getKey());
                    revoked++;
                }
            }
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("username", username);
            body.put("tenant_id", global ? null : admin.tenantId());
            body.put("revoked_sessions", revoked);
            return ResponseEntity.ok(body);
        }
    }
}
