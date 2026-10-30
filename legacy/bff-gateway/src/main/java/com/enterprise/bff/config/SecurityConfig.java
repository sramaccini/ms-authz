package com.enterprise.bff.config;

import com.enterprise.bff.security.LoginFailureHandler;
import com.enterprise.bff.security.LoginSuccessHandler;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.HttpStatusServerEntryPoint;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;

/**
 * Spring Security nel BFF gestisce SOLO il flusso OIDC di login (/oauth2/**, /login/oauth2/**).
 * L'autenticazione delle chiamate applicative non usa il SecurityContext di Spring ma la
 * sessione applicativa su Redis (cookie SESSION_ID), verificata da SessionRelayGlobalFilter
 * per le rotte del gateway e da SessionController per gli endpoint /bff/**.
 */
@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    @Bean
    SecurityWebFilterChain bffSecurity(ServerHttpSecurity http,
                                       LoginSuccessHandler successHandler,
                                       LoginFailureHandler failureHandler) {
        return http
            .authorizeExchange(ex -> ex.anyExchange().permitAll())
            .oauth2Login(login -> login
                .authenticationSuccessHandler(successHandler)
                .authenticationFailureHandler(failureHandler)
                // Nessun SecurityContext persistito: l'unica sessione valida e' quella su Redis
                .securityContextRepository(NoOpServerSecurityContextRepository.getInstance()))
            .securityContextRepository(NoOpServerSecurityContextRepository.getInstance())
            // CSRF: mitigato da cookie SameSite=Strict + controllo Origin (OriginPolicy) su rotte e /bff/logout
            .csrf(ServerHttpSecurity.CsrfSpec::disable)
            .httpBasic(ServerHttpSecurity.HttpBasicSpec::disable)
            .formLogin(ServerHttpSecurity.FormLoginSpec::disable)
            .logout(ServerHttpSecurity.LogoutSpec::disable) // logout applicativo in SessionController
            .exceptionHandling(e -> e.authenticationEntryPoint(new HttpStatusServerEntryPoint(HttpStatus.UNAUTHORIZED)))
            .headers(h -> h.contentSecurityPolicy(csp -> csp.policyDirectives("default-src 'none'; frame-ancestors 'none'")))
            .build();
    }
}
