package com.enterprise.session.context;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.Instant;
import java.util.List;

/**
 * Contesto di sicurezza letto da Redis alla chiave {@code session:<SESSION_ID>}, scritto dal BFF.
 * Contratto JSON della specifica par. 3.4: i campi sconosciuti vengono ignorati, cosi' il BFF puo'
 * aggiungere campi senza rompere i servizi gia' in esercizio.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record SessionContext(
        @JsonProperty("session_id") String sessionId,
        @JsonProperty("username") String username,
        @JsonProperty("email") String email,
        @JsonProperty("tenant_id") String tenantId,
        @JsonProperty("roles") List<String> roles,
        @JsonProperty("permissions") List<String> permissions,
        @JsonProperty("created_at") String createdAt,
        @JsonProperty("expires_at") String expiresAt) {

    public SessionContext {
        roles = roles == null ? List.of() : List.copyOf(roles);
        permissions = permissions == null ? List.of() : List.copyOf(permissions);
    }

    public boolean hasPermission(String permission) {
        return permissions.contains(permission);
    }

    boolean isExpiredAt(Instant now) {
        return expiresAt != null && Instant.parse(expiresAt).isBefore(now);
    }
}
