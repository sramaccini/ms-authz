package com.logicwarez.authz.demo;

import com.logicwarez.authz.bff.BffConfigurer;
import com.logicwarez.authz.bff.BffControllers;
import com.logicwarez.authz.rbac.RbacAdminSecurity;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

/** Una sola catena: BFF, amministrazione RBAC e API di dominio nello stesso deployable. */
@Configuration
@EnableMethodSecurity
public class SecurityConfig {

    @Bean
    SecurityFilterChain security(HttpSecurity http) throws Exception {
        http.with(BffConfigurer.bff(), Customizer.withDefaults())
            .authorizeHttpRequests(auth -> RbacAdminSecurity.adminApi(auth
                    .requestMatchers(BffControllers.PUBLIC_PATHS).permitAll()
                    .requestMatchers("/actuator/health/**", "/actuator/info").permitAll())
                .anyRequest().authenticated());
        return http.build();
    }
}
