package com.logicwarez.authz.bff;

import java.time.Clock;

import com.logicwarez.authz.session.AuthorizationResolver;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;

/** Componenti del BFF incorporato; si collegano alla sicurezza con {@link BffConfigurer}. */
@AutoConfiguration
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@EnableConfigurationProperties(BffProperties.class)
@Import({BffControllers.LoginController.class, BffControllers.SessionController.class,
        BffControllers.SessionAdminController.class, AuthzController.class})
public class BffAutoConfiguration {

    @Bean
    LoginSupport.LoginRedirects loginRedirects(BffProperties properties) {
        return new LoginSupport.LoginRedirects(properties);
    }

    @Bean
    LoginSupport.Origins origins(BffProperties properties) {
        return new LoginSupport.Origins(properties);
    }

    @Bean
    LoginSupport.OriginPolicy originPolicy(LoginSupport.Origins origins) {
        return new LoginSupport.OriginPolicy(origins);
    }

    @Bean
    LoginSupport.IamLogout iamLogout(ClientRegistrationRepository registrations, BffProperties properties) {
        return new LoginSupport.IamLogout(registrations, properties);
    }

    @Bean
    LoginSupport.LoginSuccessHandler loginSuccessHandler(AuthorizationResolver resolver,
                                                         ObjectProvider<OAuth2AuthorizedClientRepository> clients,
                                                         LoginSupport.LoginRedirects redirects,
                                                         BffProperties properties) {
        return new LoginSupport.LoginSuccessHandler(resolver, clients, redirects, properties, Clock.systemUTC());
    }

    @Bean
    LoginSupport.LoginFailureHandler loginFailureHandler(LoginSupport.LoginRedirects redirects) {
        return new LoginSupport.LoginFailureHandler(redirects);
    }
}
