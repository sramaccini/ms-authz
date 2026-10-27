package com.enterprise.auth.config;

import com.enterprise.auth.admin.AdminScope;
import com.enterprise.session.context.SessionContextConfigurer;
import jakarta.servlet.DispatcherType;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Due catene stateless:
 * - /api/v1/admin/**: chiamate del frontend instradate dal BFF, autenticate con la sessione del BFF
 *   (X-Session-ID letto da Redis, starter session-context). Raggiungibile solo dalla rete interna del BFF.
 * - tutto il resto (es. /api/v1/auth/enrich): Resource Server con JWT dello IAM
 *   (firma, issuer e scadenza verificati tramite JWKS).
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    @Order(1)
    SecurityFilterChain adminApiSecurity(HttpSecurity http) throws Exception {
        http
            .securityMatcher("/api/v1/admin/**")
            .with(SessionContextConfigurer.sessionContext(), Customizer.withDefaults())
            .authorizeHttpRequests(auth -> auth
                .anyRequest().hasAnyAuthority(AdminScope.MANAGE, AdminScope.MANAGE_GLOBAL))
            // Nessun cookie: la credenziale e' l'header X-Session-ID aggiunto dal BFF, che verifica anche l'Origin
            .csrf(csrf -> csrf.disable())
            .httpBasic(basic -> basic.disable())
            .formLogin(form -> form.disable());
        return http.build();
    }

    @Bean
    @Order(2)
    SecurityFilterChain apiSecurity(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                // Error dispatch verso /error: lo status originale resta quello deciso dalla catena che l'ha prodotto
                .dispatcherTypeMatchers(DispatcherType.ERROR).permitAll()
                .requestMatchers("/actuator/health/**", "/actuator/info").permitAll()
                // Definizione OpenAPI: esiste solo se springdoc.api-docs.enabled=true (sviluppo)
                .requestMatchers("/v3/api-docs", "/v3/api-docs.yaml", "/v3/api-docs/**").permitAll()
                .anyRequest().authenticated())
            .oauth2ResourceServer(rs -> rs.jwt(Customizer.withDefaults()))
            .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .csrf(csrf -> csrf.disable()) // API stateless con Bearer token: nessun cookie, nessun rischio CSRF
            .httpBasic(basic -> basic.disable())
            .formLogin(form -> form.disable());
        return http.build();
    }
}
