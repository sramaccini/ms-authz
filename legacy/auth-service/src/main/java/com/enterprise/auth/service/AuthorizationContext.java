package com.enterprise.auth.service;

import java.util.SortedSet;

/** Contesto di autorizzazione risolto per un utente su un tenant. */
public record AuthorizationContext(
        String username,
        String email,
        String tenantId,
        SortedSet<String> roles,
        SortedSet<String> permissions,
        SortedSet<String> availableTenants) {
}
