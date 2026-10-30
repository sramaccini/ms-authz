package com.enterprise.authz.session;

import java.time.Clock;

import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextHolderFilter;
import org.springframework.security.web.util.matcher.AnyRequestMatcher;

/**
 * Collega il {@link SessionContext} a una SecurityFilterChain:
 * <pre>
 * http.with(SessionContextConfigurer.sessionContext(), Customizer.withDefaults())
 *     .authorizeHttpRequests(auth -> auth.anyRequest().authenticated());
 * </pre>
 * Il SecurityContext non viene salvato in sessione: si ricostruisce a ogni richiesta dal SessionContext,
 * cosi' in sessione c'e' un solo oggetto, piccolo e serializzabile. 401 senza sessione, 403 senza permesso,
 * scritti direttamente (senza error dispatch verso /error, che potrebbe cambiare lo status).
 */
public class SessionContextConfigurer extends AbstractHttpConfigurer<SessionContextConfigurer, HttpSecurity> {

    public static SessionContextConfigurer sessionContext() {
        return new SessionContextConfigurer();
    }

    @Override
    public void init(HttpSecurity http) {
        http.securityContext(c -> c.securityContextRepository(new RequestAttributeSecurityContextRepository()))
            .exceptionHandling(e -> e
                .defaultAuthenticationEntryPointFor(
                    new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED), AnyRequestMatcher.INSTANCE)
                .defaultAccessDeniedHandlerFor(
                    (request, response, denied) -> response.setStatus(HttpStatus.FORBIDDEN.value()),
                    AnyRequestMatcher.INSTANCE));
    }

    @Override
    public void configure(HttpSecurity http) {
        http.addFilterAfter(new SessionContextFilter(Clock.systemUTC()), SecurityContextHolderFilter.class);
    }
}
