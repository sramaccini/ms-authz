package com.enterprise.auth.api;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.SortedSet;

/**
 * Payload di output: ruoli, permessi fine-grained e contesto organizzativo dell'utente
 * per il tenant risolto. I nomi JSON sono allineati alla struttura della sessione Redis.
 */
public record EnrichResponse(
        String username,
        String email,
        @JsonProperty("tenant_id") String tenantId,
        SortedSet<String> roles,
        SortedSet<String> permissions,
        @JsonProperty("available_tenants") SortedSet<String> availableTenants) {
}
