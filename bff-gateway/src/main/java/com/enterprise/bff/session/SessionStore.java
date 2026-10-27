package com.enterprise.bff.session;

import com.enterprise.bff.config.BffProperties;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;
import tools.jackson.databind.json.JsonMapper;

import java.time.Duration;

/** Session store distribuito su Redis, accesso completamente non bloccante. */
@Component
public class SessionStore {

    private final ReactiveStringRedisTemplate redis;
    private final JsonMapper jsonMapper;
    private final String keyPrefix;

    public SessionStore(ReactiveStringRedisTemplate redis, JsonMapper jsonMapper, BffProperties properties) {
        this.redis = redis;
        this.jsonMapper = jsonMapper;
        this.keyPrefix = properties.session().redisKeyPrefix();
    }

    public Mono<Void> save(SessionData session, Duration ttl) {
        String json = jsonMapper.writeValueAsString(session);
        return redis.opsForValue()
                .set(key(session.sessionId()), json, ttl)
                .flatMap(ok -> ok ? Mono.<Void>empty()
                        : Mono.error(new IllegalStateException("Scrittura sessione su Redis non riuscita")));
    }

    public Mono<SessionData> find(String sessionId) {
        return redis.opsForValue()
                .get(key(sessionId))
                .map(json -> jsonMapper.readValue(json, SessionData.class));
    }

    public Mono<Boolean> exists(String sessionId) {
        return redis.hasKey(key(sessionId));
    }

    public Mono<Boolean> delete(String sessionId) {
        return redis.delete(key(sessionId)).map(deleted -> deleted > 0);
    }

    private String key(String sessionId) {
        return keyPrefix + sessionId;
    }
}
