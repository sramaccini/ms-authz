package com.enterprise.bff.session;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

/**
 * Struttura della sessione salvata in Redis alla chiave {@code session:<SESSION_ID>}.
 * Formato JSON condiviso con i microservizi di dominio (specifica par. 3.4): non modificare
 * i nomi dei campi senza versionare il contratto. Le date sono stringhe ISO-8601 UTC.
 */
public record SessionData(
        @JsonProperty("session_id") String sessionId,
        @JsonProperty("username") String username,
        @JsonProperty("email") String email,
        @JsonProperty("tenant_id") String tenantId,
        @JsonProperty("roles") List<String> roles,
        @JsonProperty("permissions") List<String> permissions,
        @JsonProperty("created_at") String createdAt,
        @JsonProperty("expires_at") String expiresAt) {
}
