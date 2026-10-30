package com.enterprise.session.context;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

import java.time.Duration;

/**
 * @param headerName     header con cui il BFF inoltra la sessione
 * @param redisKeyPrefix prefisso della chiave Redis (contratto con il BFF)
 * @param cache          cache locale L1: il TTL e' anche il ritardo massimo con cui una revoca ha effetto
 */
@ConfigurationProperties("session-context")
public record SessionContextProperties(@DefaultValue("X-Session-ID") String headerName,
                                       @DefaultValue("session:") String redisKeyPrefix,
                                       @DefaultValue Cache cache) {

    public record Cache(@DefaultValue("5s") Duration ttl,
                        @DefaultValue("10000") long maxSize) {
    }
}
