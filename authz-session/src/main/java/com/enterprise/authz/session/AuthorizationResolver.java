package com.enterprise.authz.session;

import java.util.List;

/**
 * Risolve ruoli e permessi di un utente al login. Implementato in-process da {@code authz-rbac};
 * un'applicazione puo' fornirne uno proprio (per esempio un client verso un servizio remoto).
 */
public interface AuthorizationResolver {

    /**
     * @param requestedTenant tenant scelto dall'utente, null se non indicato
     * @throws UserNotAuthorizedException       utente inesistente, disattivato o senza ruoli
     * @throws TenantSelectionRequiredException l'utente opera su piu' tenant e non ne ha scelto uno
     */
    Resolved resolve(String username, String requestedTenant);

    record Resolved(String username, String email, String tenantId,
                    List<String> roles, List<String> permissions) {
    }
}
