package com.enterprise.auth.api;

import com.enterprise.auth.config.EnrichProperties;
import com.enterprise.auth.service.AuthorizationContext;
import com.enterprise.auth.service.AuthorizationService;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {

    private static final Logger log = LoggerFactory.getLogger(AuthController.class);

    private final AuthorizationService authorizationService;
    private final EnrichProperties properties;

    public AuthController(AuthorizationService authorizationService, EnrichProperties properties) {
        this.authorizationService = authorizationService;
        this.properties = properties;
    }

    /**
     * Restituisce ruoli e permessi dell'utente. Il chiamante puo' arricchire:
     * - se stesso (claim username del JWT == username richiesto), tipico del BFF che inoltra
     *   l'access token dell'utente appena autenticato;
     * - qualunque utente, solo se e' un client di servizio con l'authority configurata.
     */
    @PostMapping("/enrich")
    public EnrichResponse enrich(@Valid @RequestBody EnrichRequest request, JwtAuthenticationToken authentication) {
        assertCallerMayEnrich(request.username(), authentication);

        AuthorizationContext ctx = authorizationService.resolve(request.username(), request.tenantId());
        return new EnrichResponse(ctx.username(), ctx.email(), ctx.tenantId(),
                ctx.roles(), ctx.permissions(), ctx.availableTenants());
    }

    private void assertCallerMayEnrich(String requestedUsername, JwtAuthenticationToken authentication) {
        String tokenUsername = authentication.getToken().getClaimAsString(properties.usernameClaim());
        boolean isSelf = requestedUsername.equals(tokenUsername);
        boolean isTrustedService = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .anyMatch(properties.serviceAuthority()::equals);

        if (!isSelf && !isTrustedService) {
            log.warn("Enrich negato: subject={} ha richiesto un utente diverso", authentication.getName());
            throw new AccessDeniedException("Il chiamante non e' autorizzato ad arricchire questo utente");
        }
    }
}
