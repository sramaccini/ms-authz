package com.enterprise.bff.config;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.validation.annotation.Validated;

import java.net.URI;
import java.time.Duration;
import java.util.List;

@Validated
@ConfigurationProperties("bff")
public record BffProperties(@Valid Oidc oidc, @Valid Session session, @Valid Frontend frontend,
                            @Valid AuthService authService) {

    public record Oidc(@DefaultValue("iam") String registrationId,
                       @DefaultValue("preferred_username") String usernameClaim) {
    }

    public record Session(@DefaultValue("SESSION_ID") @NotBlank String cookieName,
                          String cookieDomain,
                          @DefaultValue("true") boolean cookieSecure,
                          @DefaultValue("30m") @NotNull Duration ttl,
                          @DefaultValue("session:") @NotBlank String redisKeyPrefix) {
    }

    public record Frontend(@NotNull URI loginSuccessUrl,
                           @NotNull URI loginFailureUrl,
                           @DefaultValue List<String> allowedOrigins) {
    }

    public record AuthService(@NotBlank String baseUrl,
                              @DefaultValue("3s") Duration timeout) {
    }
}
