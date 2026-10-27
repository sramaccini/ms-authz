package com.enterprise.bff.session;

import org.springframework.stereotype.Component;

import java.util.UUID;
import java.util.regex.Pattern;

/**
 * SESSION_ID come UUID v4 (UUID.randomUUID usa SecureRandom: 122 bit di entropia).
 * La validazione del formato evita lookup su Redis con valori arbitrari forniti dal client.
 */
@Component
public class SessionIdGenerator {

    private static final Pattern UUID_V4 =
            Pattern.compile("^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$");

    public String newSessionId() {
        return UUID.randomUUID().toString();
    }

    public boolean isWellFormed(String sessionId) {
        return sessionId != null && UUID_V4.matcher(sessionId).matches();
    }
}
