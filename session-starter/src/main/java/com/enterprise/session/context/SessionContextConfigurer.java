package com.enterprise.session.context;

import org.springframework.context.ApplicationContext;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.context.SecurityContextHolderFilter;
import org.springframework.security.web.util.matcher.AnyRequestMatcher;

/**
 * Collega la sessione del BFF a una SecurityFilterChain:
 * <pre>
 * http.with(SessionContextConfigurer.sessionContext(), Customizer.withDefaults())
 *     .authorizeHttpRequests(auth -> auth.anyRequest().authenticated());
 * </pre>
 * Imposta anche una catena stateless, 401 per le richieste non autenticate e 403 per quelle senza permesso.
 * Entrambe le risposte sono scritte direttamente, senza sendError: un error dispatch verso /error finirebbe
 * in un'altra SecurityFilterChain del servizio, che potrebbe trasformare il 403 in un 401 fuorviante.
 */
public class SessionContextConfigurer extends AbstractHttpConfigurer<SessionContextConfigurer, HttpSecurity> {

    public static SessionContextConfigurer sessionContext() {
        return new SessionContextConfigurer();
    }

    @Override
    public void init(HttpSecurity http) {
        http.sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .exceptionHandling(e -> e
                .defaultAuthenticationEntryPointFor(
                    new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED), AnyRequestMatcher.INSTANCE)
                .defaultAccessDeniedHandlerFor(
                    (request, response, denied) -> response.setStatus(HttpStatus.FORBIDDEN.value()),
                    AnyRequestMatcher.INSTANCE));
    }

    @Override
    public void configure(HttpSecurity http) {
        ApplicationContext context = http.getSharedObject(ApplicationContext.class);
        SessionLookup lookup = context.getBean(SessionLookup.class);
        SessionContextProperties properties = context.getBean(SessionContextProperties.class);
        http.addFilterAfter(new SessionAuthenticationFilter(lookup, properties.headerName()),
                SecurityContextHolderFilter.class);
    }
}
