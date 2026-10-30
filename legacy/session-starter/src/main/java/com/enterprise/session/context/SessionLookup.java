package com.enterprise.session.context;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import org.springframework.dao.DataAccessException;
import org.springframework.data.redis.core.StringRedisTemplate;
import tools.jackson.databind.json.JsonMapper;

import java.time.Clock;
import java.util.Optional;
import java.util.regex.Pattern;

/**
 * Lookup della sessione a due livelli (specifica par. 4):
 * L1 Caffeine con TTL breve, L2 Redis. Le sessioni assenti non vengono messe in cache,
 * quindi una sessione appena creata dal BFF e' subito visibile.
 */
public class SessionLookup {

    private static final Pattern UUID_V4 =
            Pattern.compile("^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$");

    private final StringRedisTemplate redis;
    private final JsonMapper jsonMapper;
    private final String keyPrefix;
    private final Cache<String, SessionContext> l1;
    private final Clock clock;

    public SessionLookup(StringRedisTemplate redis, JsonMapper jsonMapper, SessionContextProperties properties) {
        this.redis = redis;
        this.jsonMapper = jsonMapper;
        this.keyPrefix = properties.redisKeyPrefix();
        this.l1 = Caffeine.newBuilder()
                .expireAfterWrite(properties.cache().ttl())
                .maximumSize(properties.cache().maxSize())
                .build();
        this.clock = Clock.systemUTC();
    }

    /**
     * @throws SessionStoreUnavailableException se Redis non risponde
     */
    public Optional<SessionContext> find(String sessionId) {
        if (sessionId == null || !UUID_V4.matcher(sessionId).matches()) {
            return Optional.empty(); // nessun lookup su Redis con valori arbitrari forniti dal chiamante
        }
        return Optional.ofNullable(l1.get(sessionId, this::loadFromRedis))
                .filter(session -> !session.isExpiredAt(clock.instant()));
    }

    private SessionContext loadFromRedis(String sessionId) {
        String json;
        try {
            json = redis.opsForValue().get(keyPrefix + sessionId);
        } catch (DataAccessException e) {
            throw new SessionStoreUnavailableException(e);
        }
        return json == null ? null : jsonMapper.readValue(json, SessionContext.class);
    }
}
