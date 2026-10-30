package com.enterprise.bff.config;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.validation.annotation.Validated;

import java.net.URI;
import java.time.Duration;
import java.util.List;

@Validated
@ConfigurationProperties("bff")
public record BffProperties(@Valid Oidc oidc, @Valid Session session, @Valid Frontend frontend,
                            @Valid AuthService authService, @Valid @DefaultValue LoginRateLimit loginRateLimit) {

    public record Oidc(@DefaultValue("iam") String registrationId,
                       @DefaultValue("preferred_username") String usernameClaim) {
    }

    public record Session(@DefaultValue("SESSION_ID") @NotBlank String cookieName,
                          String cookieDomain,
                          @DefaultValue("true") boolean cookieSecure,
                          @DefaultValue("30m") @NotNull Duration ttl,
                          @DefaultValue("session:") @NotBlank String redisKeyPrefix,
                          @DefaultValue("user_sessions:") @NotBlank String userIndexPrefix,
                          @DefaultValue("bff:id_token:") @NotBlank String idTokenKeyPrefix) {
    }

    public record Frontend(@NotNull URI loginSuccessUrl,
                           @NotNull URI loginFailureUrl,
                           @NotNull URI postLogoutUrl,
                           @DefaultValue List<String> allowedOrigins) {
    }

    public record AuthService(@NotBlank String baseUrl,
                              @DefaultValue("3s") Duration timeout) {
    }

    /** Limite per IP sugli ingressi del login OIDC: ogni richiesta crea stato su Redis (WebSession). */
    public record LoginRateLimit(@DefaultValue("true") boolean enabled,
                                 @DefaultValue("20") @Positive int maxRequests,
                                 @DefaultValue("1m") @NotNull Duration window,
                                 @DefaultValue("ratelimit:login:") @NotBlank String redisKeyPrefix) {
    }
}
