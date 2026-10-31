package com.logicwarez.authz.rbac.service;

import java.util.SortedMap;
import java.util.SortedSet;

/**
 * Contesto di autorizzazione risolto per un utente su un tenant.
 *
 * @param availableTenants tenant su cui l'utente ha ruoli: codice -> etichetta da mostrare
 */
public record AuthorizationContext(
        String username,
        String email,
        String tenantId,
        SortedSet<String> roles,
        SortedSet<String> permissions,
        SortedMap<String, String> availableTenants) {
}
