package com.enterprise.auth.api;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

/**
 * Payload di input di POST /api/v1/auth/enrich.
 *
 * @param username username dell'utente da arricchire (obbligatorio, come da specifica)
 * @param tenantId tenant richiesto (opzionale, estensione alla specifica: necessario solo se
 *                 l'utente ha ruoli su piu' tenant)
 */
public record EnrichRequest(
        @NotBlank @Size(max = 150) String username,
        @JsonProperty("tenant_id") @Size(max = 50) @Pattern(regexp = "^[A-Za-z0-9_-]+$") String tenantId) {
}
