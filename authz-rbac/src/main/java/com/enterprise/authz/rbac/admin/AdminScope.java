package com.enterprise.authz.rbac.admin;

import com.enterprise.authz.session.SessionContext;

import java.util.Set;

/**
 * Ambito dell'amministratore, ricavato dalla sessione del BFF.
 * - rbac:manage        -> amministratore delegato: solo il tenant della propria sessione;
 * - rbac:manage-global -> amministratore globale: tutti i tenant, definizione di ruoli e tenant, stato utenti.
 */
public record AdminScope(String username, String tenantId, Set<String> permissions) {

    public static final String MANAGE = "rbac:manage";
    public static final String MANAGE_GLOBAL = "rbac:manage-global";

    public static AdminScope of(SessionContext session) {
        return new AdminScope(session.username(), session.tenantId(), Set.copyOf(session.permissions()));
    }

    public boolean isGlobal() {
        return permissions.contains(MANAGE_GLOBAL);
    }

    public boolean canManageTenant(String tenant) {
        return isGlobal() || (permissions.contains(MANAGE) && tenantId.equals(tenant));
    }

    void requireGlobal() {
        if (!isGlobal()) {
            throw AdminProblem.forbidden("global-admin-required", "Operazione riservata all'amministratore globale");
        }
    }

    void requireTenant(String tenant) {
        if (!canManageTenant(tenant)) {
            throw AdminProblem.forbidden("tenant-out-of-scope", "Tenant fuori dall'ambito dell'amministratore");
        }
    }

    void requireNotSelf(String targetUsername) {
        if (username.equals(targetUsername)) {
            throw AdminProblem.forbidden("self-modification", "Non e' consentito modificare la propria utenza");
        }
    }
}
