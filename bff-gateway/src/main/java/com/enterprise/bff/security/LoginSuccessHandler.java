package com.enterprise.bff.security;

import com.enterprise.bff.client.AuthServiceClient;
import com.enterprise.bff.client.AuthServiceClient.EnrichResponse;
import com.enterprise.bff.config.BffProperties;
import com.enterprise.bff.session.SessionCookies;
import com.enterprise.bff.session.SessionData;
import com.enterprise.bff.session.SessionIdGenerator;
import com.enterprise.bff.session.SessionStore;
import com.enterprise.bff.web.LoginController;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.ServerAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebSession;
import reactor.core.publisher.Mono;

import java.time.Clock;
import java.time.Instant;
import java.util.List;

/**
 * Passi 3-8 del sequence diagram: dopo il login OIDC
 * 1. estrae lo username dal token dello IAM;
 * 2. invoca l'Auth-Service per ruoli/permessi;
 * 3. genera il SESSION_ID e salva la sessione su Redis con TTL;
 * 4. imposta il cookie HttpOnly/Secure/SameSite=Strict e rimanda al frontend.
 * Lo stato temporaneo del flusso OAuth2 (WebSession, authorized client) viene poi eliminato:
 * i token dello IAM non restano nel BFF.
 */
@Component
public class LoginSuccessHandler implements ServerAuthenticationSuccessHandler {

    private static final Logger log = LoggerFactory.getLogger(LoginSuccessHandler.class);

    private final ServerOAuth2AuthorizedClientRepository authorizedClients;
    private final AuthServiceClient authServiceClient;
    private final SessionStore sessionStore;
    private final SessionIdGenerator idGenerator;
    private final SessionCookies cookies;
    private final LoginRedirects redirects;
    private final BffProperties properties;
    private final Clock clock;

    public LoginSuccessHandler(ServerOAuth2AuthorizedClientRepository authorizedClients,
                               AuthServiceClient authServiceClient,
                               SessionStore sessionStore,
                               SessionIdGenerator idGenerator,
                               SessionCookies cookies,
                               LoginRedirects redirects,
                               BffProperties properties) {
        this.authorizedClients = authorizedClients;
        this.authServiceClient = authServiceClient;
        this.sessionStore = sessionStore;
        this.idGenerator = idGenerator;
        this.cookies = cookies;
        this.redirects = redirects;
        this.properties = properties;
        this.clock = Clock.systemUTC();
    }

    @Override
    public Mono<Void> onAuthenticationSuccess(WebFilterExchange webFilterExchange, Authentication authentication) {
        ServerWebExchange exchange = webFilterExchange.getExchange();
        if (!(authentication instanceof OAuth2AuthenticationToken oauth)) {
            return redirects.toFailure(exchange, LoginErrorCode.LOGIN_FAILED);
        }

        String registrationId = oauth.getAuthorizedClientRegistrationId();
        String username = oauth.getPrincipal().getAttribute(properties.oidc().usernameClaim());
        if (username == null || username.isBlank()) {
            log.warn("Claim '{}' assente nel token IAM", properties.oidc().usernameClaim());
            return cleanup(exchange, registrationId, oauth)
                    .then(redirects.toFailure(exchange, LoginErrorCode.LOGIN_FAILED));
        }

        Mono<String> tenantHint = exchange.getSession()
                .mapNotNull(s -> s.<String>getAttribute(LoginController.TENANT_HINT_ATTRIBUTE))
                .defaultIfEmpty("");

        return authorizedClients.<OAuth2AuthorizedClient>loadAuthorizedClient(registrationId, oauth, exchange)
                .switchIfEmpty(Mono.error(new IllegalStateException("Authorized client non disponibile")))
                .zipWith(tenantHint)
                .flatMap(t -> authServiceClient.enrich(
                        username,
                        t.getT2().isEmpty() ? null : t.getT2(),
                        t.getT1().getAccessToken().getTokenValue()))
                .flatMap(enriched -> createSession(exchange, enriched))
                .then(Mono.defer(() -> cleanup(exchange, registrationId, oauth)))
                .then(Mono.defer(() -> redirects.toSuccess(exchange)))
                .onErrorResume(error -> cleanup(exchange, registrationId, oauth)
                        .then(redirects.toFailure(exchange, mapError(username, error))));
    }

    private Mono<Void> createSession(ServerWebExchange exchange, EnrichResponse enriched) {
        Instant now = clock.instant();
        Instant expiresAt = now.plus(properties.session().ttl());
        String sessionId = idGenerator.newSessionId();

        SessionData session = new SessionData(
                sessionId,
                enriched.username(),
                enriched.email(),
                enriched.tenantId(),
                nullSafe(enriched.roles()),
                nullSafe(enriched.permissions()),
                now.toString(),
                expiresAt.toString());

        // Anti session-fixation: l'eventuale sessione precedente del browser viene sempre invalidata
        Mono<Boolean> dropPrevious = cookies.read(exchange.getRequest())
                .filter(idGenerator::isWellFormed)
                .map(sessionStore::delete)
                .orElseGet(() -> Mono.just(false));

        return dropPrevious
                .then(sessionStore.save(session, properties.session().ttl()))
                .doOnSuccess(v -> {
                    exchange.getResponse().addCookie(cookies.create(sessionId));
                    log.info("Sessione creata per utente={} tenant={}", enriched.username(), enriched.tenantId());
                });
    }

    /** Rimuove token IAM e WebSession usata solo per lo state/nonce del flusso OAuth2. */
    private Mono<Void> cleanup(ServerWebExchange exchange, String registrationId, Authentication authentication) {
        return authorizedClients.removeAuthorizedClient(registrationId, authentication, exchange)
                .then(exchange.getSession().flatMap(WebSession::invalidate))
                .onErrorResume(e -> {
                    log.debug("Cleanup stato OAuth2 non riuscito: {}", e.getMessage());
                    return Mono.empty();
                });
    }

    private static LoginErrorCode mapError(String username, Throwable error) {
        if (error instanceof WebClientResponseException http) {
            HttpStatus status = HttpStatus.resolve(http.getStatusCode().value());
            if (status == HttpStatus.FORBIDDEN) {
                log.info("Utente {} non abilitato dall'Auth-Service", username);
                return LoginErrorCode.ACCESS_DENIED;
            }
            if (status == HttpStatus.CONFLICT) {
                return LoginErrorCode.TENANT_SELECTION_REQUIRED;
            }
        }
        log.error("Creazione sessione fallita per utente {}: {}", username, error.toString());
        return LoginErrorCode.AUTH_SERVICE_UNAVAILABLE;
    }

    private static List<String> nullSafe(List<String> values) {
        return values == null ? List.of() : List.copyOf(values);
    }
}
