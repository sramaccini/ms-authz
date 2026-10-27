package com.enterprise.bff.security;

import com.enterprise.bff.config.BffProperties;
import com.enterprise.bff.filter.ProblemResponses;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.data.redis.core.script.RedisScript;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.net.InetSocketAddress;
import java.time.Clock;
import java.util.List;

/**
 * Limite di frequenza per IP sugli ingressi del login OIDC (/bff/login, /oauth2/authorization/**,
 * /login/oauth2/code/**): ognuno puo' creare una WebSession su Redis, quindi senza limite un client
 * anonimo potrebbe saturare la memoria di Redis.
 * Finestra fissa con contatore su Redis, condiviso tra le istanze; una sola chiave per script,
 * quindi compatibile con Redis Cluster. Se Redis non risponde la richiesta passa (fail-open):
 * il login fallirebbe comunque e il limitatore non deve diventare un'ulteriore causa di disservizio.
 * L'IP e' quello visto dal BFF: dietro un proxy configurare server.forward-headers-strategy
 * solo se il proxy e' fidato, altrimenti X-Forwarded-For permetterebbe di aggirare il limite.
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 50) // prima della catena di Spring Security, che crea la WebSession
public class LoginRateLimitWebFilter implements WebFilter {

    private static final Logger log = LoggerFactory.getLogger(LoginRateLimitWebFilter.class);
    private static final RedisScript<Long> INCREMENT = RedisScript.of("""
            local count = redis.call('INCR', KEYS[1])
            if count == 1 then redis.call('PEXPIRE', KEYS[1], ARGV[1]) end
            return count""", Long.class);

    private final ReactiveStringRedisTemplate redis;
    private final BffProperties.LoginRateLimit limit;
    private final Clock clock = Clock.systemUTC();

    public LoginRateLimitWebFilter(ReactiveStringRedisTemplate redis, BffProperties properties) {
        this.redis = redis;
        this.limit = properties.loginRateLimit();
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        if (!limit.enabled() || !isLoginPath(exchange.getRequest().getPath().value())) {
            return chain.filter(exchange);
        }
        long windowMillis = limit.window().toMillis();
        long now = clock.millis();
        long windowIndex = now / windowMillis;
        String key = limit.redisKeyPrefix() + clientIp(exchange) + ":" + windowIndex;

        return redis.execute(INCREMENT, List.of(key), List.of(Long.toString(windowMillis)))
                .next()
                .onErrorResume(e -> {
                    log.warn("Rate limit login non verificabile, richiesta ammessa: {}", e.toString());
                    return Mono.empty();
                })
                .flatMap(count -> count > limit.maxRequests()
                        ? tooManyRequests(exchange, (windowIndex + 1) * windowMillis - now).thenReturn(true)
                        : Mono.just(false))
                .defaultIfEmpty(false)
                .flatMap(rejected -> rejected ? Mono.empty() : chain.filter(exchange));
    }

    static boolean isLoginPath(String path) {
        return path.equals("/bff/login")
                || path.startsWith("/oauth2/authorization/")
                || path.startsWith("/login/oauth2/code/");
    }

    private static String clientIp(ServerWebExchange exchange) {
        InetSocketAddress remote = exchange.getRequest().getRemoteAddress();
        return remote != null && remote.getAddress() != null ? remote.getAddress().getHostAddress() : "unknown";
    }

    private Mono<Void> tooManyRequests(ServerWebExchange exchange, long retryAfterMillis) {
        log.warn("Rate limit login superato da ip={}", clientIp(exchange));
        ServerHttpResponse response = exchange.getResponse();
        response.getHeaders().set(HttpHeaders.RETRY_AFTER, Long.toString(Math.max(1, (retryAfterMillis + 999) / 1000)));
        return ProblemResponses.write(response, HttpStatus.TOO_MANY_REQUESTS,
                "Troppi tentativi di accesso, riprovare piu' tardi");
    }
}
