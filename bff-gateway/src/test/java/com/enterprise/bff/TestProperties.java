package com.enterprise.bff;

import com.enterprise.bff.config.BffProperties;

import java.net.URI;
import java.time.Duration;
import java.util.List;

/** BffProperties di test, allineate ai default di application.yml. */
public final class TestProperties {

    public static final String FRONTEND = "http://localhost:4200";

    private TestProperties() {
    }

    public static BffProperties bff() {
        return new BffProperties(
                new BffProperties.Oidc("iam", "preferred_username"),
                new BffProperties.Session("SESSION_ID", null, true, Duration.ofMinutes(30), "session:",
                        "user_sessions:", "bff:id_token:"),
                new BffProperties.Frontend(URI.create(FRONTEND + "/"), URI.create(FRONTEND + "/login-error"),
                        URI.create(FRONTEND + "/"),
                        List.of(FRONTEND)),
                new BffProperties.AuthService("http://localhost:8081", Duration.ofSeconds(3)),
                new BffProperties.LoginRateLimit(true, 20, Duration.ofMinutes(1), "ratelimit:login:"));
    }
}
