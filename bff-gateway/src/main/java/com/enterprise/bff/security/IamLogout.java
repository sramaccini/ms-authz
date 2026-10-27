package com.enterprise.bff.security;

import com.enterprise.bff.config.BffProperties;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;
import reactor.core.publisher.Mono;

/**
 * URL di logout sullo IAM (OIDC RP-Initiated Logout 1.0): end_session_endpoint dalla discovery del provider,
 * con id_token_hint (logout senza pagina di conferma), client_id e post_logout_redirect_uri.
 * Se lo IAM non pubblica l'endpoint, si torna direttamente al frontend: resta chiusa solo la sessione applicativa.
 */
@Component
public class IamLogout {

    private static final String END_SESSION_ENDPOINT = "end_session_endpoint";

    private final ReactiveClientRegistrationRepository registrations;
    private final String registrationId;
    private final String postLogoutUrl;

    public IamLogout(ReactiveClientRegistrationRepository registrations, BffProperties properties) {
        this.registrations = registrations;
        this.registrationId = properties.oidc().registrationId();
        this.postLogoutUrl = properties.frontend().postLogoutUrl().toString();
    }

    /** @param idToken ID token della sessione, null se non disponibile (lo IAM chiedera' conferma all'utente) */
    public Mono<String> logoutUrl(String idToken) {
        return registrations.findByRegistrationId(registrationId)
                .mapNotNull(registration -> buildUrl(registration, idToken))
                .defaultIfEmpty(postLogoutUrl);
    }

    private String buildUrl(ClientRegistration registration, String idToken) {
        Object endpoint = registration.getProviderDetails().getConfigurationMetadata().get(END_SESSION_ENDPOINT);
        if (endpoint == null) {
            return null;
        }
        UriComponentsBuilder url = UriComponentsBuilder.fromUriString(endpoint.toString())
                .queryParam("client_id", registration.getClientId())
                .queryParam("post_logout_redirect_uri", postLogoutUrl);
        if (idToken != null) {
            url.queryParam("id_token_hint", idToken);
        }
        return url.encode().build().toUriString();
    }
}
