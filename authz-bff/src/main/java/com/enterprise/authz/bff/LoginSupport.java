package com.enterprise.authz.bff;

import java.io.IOException;
import java.time.Clock;
import java.time.Instant;
import java.util.Set;

import com.enterprise.authz.session.AuthorizationResolver;
import com.enterprise.authz.session.SessionContext;
import com.enterprise.authz.session.TenantSelectionRequiredException;
import com.enterprise.authz.session.UserNotAuthorizedException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.http.HttpMethod;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.session.FindByIndexNameSessionRepository;
import org.springframework.web.util.UriComponentsBuilder;

/** Componenti del login OIDC e del logout: redirect, gestori di esito, URL di logout sullo IAM, controllo Origin. */
public final class LoginSupport {

    /** Attributi di sessione riservati al BFF. */
    static final String TENANT_HINT = "authz.bff.tenant";
    static final String ID_TOKEN = "authz.bff.id_token";

    private LoginSupport() {
    }

    /** Codici restituiti al frontend come ?error= sulla pagina di errore del login. */
    public enum LoginErrorCode {
        ACCESS_DENIED("access_denied"),
        TENANT_SELECTION_REQUIRED("tenant_selection_required"),
        AUTH_SERVICE_UNAVAILABLE("auth_service_unavailable"),
        LOGIN_FAILED("login_failed");

        private final String code;

        LoginErrorCode(String code) {
            this.code = code;
        }

        public String code() {
            return code;
        }
    }

    /** Redirect verso URL del frontend fissi da configurazione (nessun open redirect). */
    public static class LoginRedirects {

        private final BffProperties.Frontend frontend;

        public LoginRedirects(BffProperties properties) {
            this.frontend = properties.frontend();
        }

        void toSuccess(HttpServletResponse response) throws IOException {
            response.sendRedirect(frontend.loginSuccessUrl().toString());
        }

        void toFailure(HttpServletResponse response, LoginErrorCode error) throws IOException {
            response.sendRedirect(UriComponentsBuilder.fromUri(frontend.loginFailureUrl())
                    .queryParam("error", error.code()).build(true).toUriString());
        }
    }

    /**
     * Dopo il login OIDC: risolve ruoli e permessi in-process, salva il {@link SessionContext} nella sessione
     * (gia' rigenerata da Spring Security contro la session fixation), indicizza la sessione per username
     * (revoca) e conserva solo l'ID token per il logout sullo IAM. Access e refresh token vengono eliminati.
     */
    public static class LoginSuccessHandler implements AuthenticationSuccessHandler {

        private static final Logger log = LoggerFactory.getLogger(LoginSuccessHandler.class);

        private final AuthorizationResolver resolver;
        private final ObjectProvider<OAuth2AuthorizedClientRepository> authorizedClients;
        private final LoginRedirects redirects;
        private final BffProperties properties;
        private final Clock clock;

        public LoginSuccessHandler(AuthorizationResolver resolver,
                                   ObjectProvider<OAuth2AuthorizedClientRepository> authorizedClients,
                                   LoginRedirects redirects, BffProperties properties, Clock clock) {
            this.resolver = resolver;
            this.authorizedClients = authorizedClients;
            this.redirects = redirects;
            this.properties = properties;
            this.clock = clock;
        }

        @Override
        public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                            Authentication authentication) throws IOException {
            HttpSession session = request.getSession();
            Object tenant = session.getAttribute(TENANT_HINT);
            session.removeAttribute(TENANT_HINT);
            if (!(authentication instanceof OAuth2AuthenticationToken oauth)) {
                fail(request, response, LoginErrorCode.LOGIN_FAILED);
                return;
            }
            removeAuthorizedClient(oauth, request, response);
            String username = oauth.getPrincipal().getAttribute(properties.oidc().usernameClaim());
            if (username == null || username.isBlank()) {
                log.warn("Claim '{}' assente nel token IAM", properties.oidc().usernameClaim());
                fail(request, response, LoginErrorCode.LOGIN_FAILED);
                return;
            }
            AuthorizationResolver.Resolved resolved;
            try {
                resolved = resolver.resolve(username, tenant instanceof String t ? t : null);
            } catch (UserNotAuthorizedException e) {
                log.info("Utente {} non abilitato", username);
                fail(request, response, LoginErrorCode.ACCESS_DENIED);
                return;
            } catch (TenantSelectionRequiredException e) {
                fail(request, response, LoginErrorCode.TENANT_SELECTION_REQUIRED);
                return;
            } catch (RuntimeException e) {
                log.error("Risoluzione dei permessi fallita per {}: {}", username, e.toString());
                fail(request, response, LoginErrorCode.AUTH_SERVICE_UNAVAILABLE);
                return;
            }
            Instant now = clock.instant();
            session.setAttribute(SessionContext.ATTRIBUTE, new SessionContext(resolved.username(), resolved.email(),
                    resolved.tenantId(), resolved.roles(), resolved.permissions(),
                    now, now.plus(properties.session().absoluteTimeout())));
            session.setAttribute(FindByIndexNameSessionRepository.PRINCIPAL_NAME_INDEX_NAME, resolved.username());
            if (oauth.getPrincipal() instanceof OidcUser oidc) {
                session.setAttribute(ID_TOKEN, oidc.getIdToken().getTokenValue());
            }
            log.info("Sessione creata per utente={} tenant={}", resolved.username(), resolved.tenantId());
            redirects.toSuccess(response);
        }

        private void removeAuthorizedClient(OAuth2AuthenticationToken oauth, HttpServletRequest request,
                                            HttpServletResponse response) {
            OAuth2AuthorizedClientRepository repository = authorizedClients.getIfAvailable();
            if (repository != null) {
                repository.removeAuthorizedClient(oauth.getAuthorizedClientRegistrationId(), oauth, request, response);
            }
        }

        private void fail(HttpServletRequest request, HttpServletResponse response, LoginErrorCode code)
                throws IOException {
            HttpSession session = request.getSession(false);
            if (session != null) {
                session.invalidate();
            }
            redirects.toFailure(response, code);
        }
    }

    /** Login OIDC fallito prima di arrivare all'esito (errore dello IAM, state non valido...). */
    public static class LoginFailureHandler implements AuthenticationFailureHandler {

        private final LoginRedirects redirects;

        public LoginFailureHandler(LoginRedirects redirects) {
            this.redirects = redirects;
        }

        @Override
        public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
                                            AuthenticationException exception) throws IOException {
            redirects.toFailure(response, LoginErrorCode.LOGIN_FAILED);
        }
    }

    /**
     * URL di logout sullo IAM (OIDC RP-Initiated Logout): end_session_endpoint con id_token_hint, client_id e
     * post_logout_redirect_uri. Senza endpoint pubblicato dallo IAM si torna direttamente al frontend.
     */
    public static class IamLogout {

        private final ClientRegistrationRepository registrations;
        private final String registrationId;
        private final String postLogoutUrl;

        public IamLogout(ClientRegistrationRepository registrations, BffProperties properties) {
            this.registrations = registrations;
            this.registrationId = properties.oidc().registrationId();
            this.postLogoutUrl = properties.frontend().postLogoutUrl().toString();
        }

        public String logoutUrl(String idToken) {
            ClientRegistration registration = registrations.findByRegistrationId(registrationId);
            Object endpoint = registration == null ? null
                    : registration.getProviderDetails().getConfigurationMetadata().get("end_session_endpoint");
            if (endpoint == null) {
                return postLogoutUrl;
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

    /** Le richieste non idempotenti sono ammesse solo da un'origine del frontend (difesa CSRF con SameSite). */
    public static class OriginPolicy {

        private static final Set<String> SAFE_METHODS =
                Set.of(HttpMethod.GET.name(), HttpMethod.HEAD.name(), HttpMethod.OPTIONS.name());

        private final Set<String> allowedOrigins;

        public OriginPolicy(BffProperties properties) {
            this.allowedOrigins = Set.copyOf(properties.frontend().allowedOrigins());
        }

        public boolean isAllowed(HttpServletRequest request) {
            if (SAFE_METHODS.contains(request.getMethod())) {
                return true;
            }
            String origin = request.getHeader("Origin");
            return origin != null && allowedOrigins.contains(origin);
        }
    }
}
