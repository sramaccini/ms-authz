package com.enterprise.authz.session;

import java.io.Serial;
import java.io.Serializable;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;

/**
 * Contesto di sicurezza dell'utente, salvato come attributo della sessione HTTP (Spring Session su Redis)
 * al termine del login. Sostituisce il payload {@code session:<SESSION_ID>} scritto a mano dal vecchio BFF.
 *
 * @param expiresAt scadenza assoluta: la sessione scade per inattivita' (timeout standard di Spring Session)
 *                  oppure a questa data, anche se l'utente resta attivo
 */
public record SessionContext(String username,
                             String email,
                             String tenantId,
                             List<String> roles,
                             List<String> permissions,
                             Instant createdAt,
                             Instant expiresAt) implements Serializable {

    @Serial
    private static final long serialVersionUID = 1L;

    /** Nome dell'attributo di sessione che contiene il contesto. */
    public static final String ATTRIBUTE = SessionContext.class.getName();

    public SessionContext {
        roles = roles == null ? List.of() : List.copyOf(roles);
        permissions = permissions == null ? List.of() : List.copyOf(permissions);
    }

    public boolean hasPermission(String permission) {
        return permissions.contains(permission);
    }

    public boolean isExpiredAt(Instant now) {
        return expiresAt != null && !now.isBefore(expiresAt);
    }

    /** Contesto della sessione corrente, senza crearne una nuova. */
    public static Optional<SessionContext> from(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        return session == null ? Optional.empty() : from(session);
    }

    public static Optional<SessionContext> from(HttpSession session) {
        return session.getAttribute(ATTRIBUTE) instanceof SessionContext context
                ? Optional.of(context) : Optional.empty();
    }
}
