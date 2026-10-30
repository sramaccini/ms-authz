package com.enterprise.authz.bff;

import java.net.URI;
import java.time.Duration;
import java.util.List;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.validation.annotation.Validated;

/**
 * Configurazione del BFF incorporato. Cookie, timeout di inattivita' e Redis sono le proprieta' standard
 * di Spring Boot e Spring Session (server.servlet.session.*, spring.session.*, spring.data.redis.*).
 */
@Validated
@ConfigurationProperties("authz.bff")
public record BffProperties(@Valid @DefaultValue Oidc oidc,
                            @Valid @DefaultValue Session session,
                            @Valid @NotNull Frontend frontend,
                            @Valid @DefaultValue LoginRateLimit loginRateLimit) {

    public record Oidc(@DefaultValue("iam") @NotBlank String registrationId,
                       @DefaultValue("preferred_username") @NotBlank String usernameClaim) {
    }

    /** @param absoluteTimeout durata massima di una sessione anche se l'utente resta attivo */
    public record Session(@DefaultValue("10h") @NotNull Duration absoluteTimeout) {
    }

    public record Frontend(@NotNull URI loginSuccessUrl,
                           @NotNull URI loginFailureUrl,
                           @NotNull URI postLogoutUrl,
                           @DefaultValue List<String> allowedOrigins) {
    }

    /** Limite per IP sugli ingressi del login OIDC, con contatore condiviso su Redis. */
    public record LoginRateLimit(@DefaultValue("true") boolean enabled,
                                 @DefaultValue("20") @Positive int maxRequests,
                                 @DefaultValue("1m") @NotNull Duration window,
                                 @DefaultValue("authz:ratelimit:login:") @NotBlank String redisKeyPrefix) {
    }
}
