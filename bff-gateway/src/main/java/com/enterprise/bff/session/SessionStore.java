package com.enterprise.bff.session;

import com.enterprise.bff.config.BffProperties;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;
import tools.jackson.databind.json.JsonMapper;

import java.time.Duration;

/**
 * Session store distribuito su Redis, accesso completamente non bloccante.
 * Oltre a session:<id> mantiene l'indice user_sessions:<username> (set di SESSION_ID) per la revoca
 * di tutte le sessioni di un utente (specifica par. 5). Solo comandi su una chiave: compatibile con Redis Cluster.
 */
@Component
public class SessionStore {

    private final ReactiveStringRedisTemplate redis;
    private final JsonMapper jsonMapper;
    private final String keyPrefix;
    private final String userIndexPrefix;

    public SessionStore(ReactiveStringRedisTemplate redis, JsonMapper jsonMapper, BffProperties properties) {
        this.redis = redis;
        this.jsonMapper = jsonMapper;
        this.keyPrefix = properties.session().redisKeyPrefix();
        this.userIndexPrefix = properties.session().userIndexPrefix();
    }

    public Mono<Void> save(SessionData session, Duration ttl) {
        String json = jsonMapper.writeValueAsString(session);
        String indexKey = indexKey(session.username());
        // Prima l'indice, poi la sessione: non puo' esistere una sessione non revocabile.
        // Il TTL dell'indice segue la sessione piu' recente; le voci gia' scadute vengono ripulite alla revoca.
        return redis.opsForSet().add(indexKey, session.sessionId())
                .then(redis.expire(indexKey, ttl))
                .then(redis.opsForValue().set(key(session.sessionId()), json, ttl))
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

    /**
     * Revoca le sessioni dell'utente: tutte se tenantId e' null, altrimenti solo quelle aperte su quel tenant.
     *
     * @return numero di sessioni revocate
     */
    public Mono<Long> revokeUserSessions(String username, String tenantId) {
        String indexKey = indexKey(username);
        return redis.opsForSet().members(indexKey)
                .concatMap(id -> find(id)
                        .flatMap(session -> tenantId == null || tenantId.equals(session.tenantId())
                                ? delete(id).then(redis.opsForSet().remove(indexKey, id)).thenReturn(1L)
                                : Mono.just(0L))
                        .switchIfEmpty(Mono.defer(() -> redis.opsForSet().remove(indexKey, id).thenReturn(0L))))
                .reduce(0L, Long::sum);
    }

    private String key(String sessionId) {
        return keyPrefix + sessionId;
    }

    private String indexKey(String username) {
        return userIndexPrefix + username;
    }
}
