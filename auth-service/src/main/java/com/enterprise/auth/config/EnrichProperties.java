package com.enterprise.auth.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

/**
 * Parametri di autorizzazione dell'endpoint /enrich.
 *
 * @param usernameClaim    claim JWT con lo username dell'utente autenticato
 * @param serviceAuthority authority che consente a un client di servizio di arricchire qualunque utente
 */
@ConfigurationProperties("auth.enrich")
public record EnrichProperties(
        @DefaultValue("preferred_username") String usernameClaim,
        @DefaultValue("SCOPE_auth:enrich") String serviceAuthority) {
}
