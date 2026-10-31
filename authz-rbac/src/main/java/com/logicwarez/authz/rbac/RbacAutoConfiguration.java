package com.logicwarez.authz.rbac;

import javax.sql.DataSource;

import com.logicwarez.authz.rbac.admin.RbacAdminController;
import com.logicwarez.authz.rbac.admin.RbacAdminExceptionHandler;
import com.logicwarez.authz.rbac.admin.RbacAdminRepository;
import com.logicwarez.authz.rbac.admin.RbacAdminService;
import com.logicwarez.authz.rbac.repository.AuthorizationRepository;
import com.logicwarez.authz.rbac.service.AuthorizationContext;
import com.logicwarez.authz.rbac.service.AuthorizationService;
import com.logicwarez.authz.session.AuthorizationResolver;
import com.logicwarez.authz.session.SessionContext;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.jdbc.autoconfigure.DataSourceAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;

/**
 * Modello RBAC in-process: ruoli e permessi per tenant, API di amministrazione /api/v1/admin/**,
 * migrazioni dello schema con una history Flyway propria. La protezione delle rotte di amministrazione
 * resta all'applicazione (vedi {@link RbacAdminSecurity}).
 */
@AutoConfiguration(after = DataSourceAutoConfiguration.class)
@EnableConfigurationProperties(RbacProperties.class)
@Import({AuthorizationRepository.class, AuthorizationService.class,
        RbacAdminRepository.class, RbacAdminService.class,
        RbacAdminController.class, RbacAdminExceptionHandler.class})
public class RbacAutoConfiguration {

    @Bean
    RbacSchemaMigrator rbacSchemaMigrator(DataSource dataSource, RbacProperties properties) {
        return new RbacSchemaMigrator(dataSource, properties.flyway());
    }

    @Bean
    @ConditionalOnMissingBean
    AuthorizationResolver authorizationResolver(AuthorizationService service) {
        return (username, tenant) -> {
            AuthorizationContext ctx = service.resolve(username, tenant);
            return new AuthorizationResolver.Resolved(ctx.username(), ctx.email(), ctx.tenantId(),
                    ctx.availableTenants().entrySet().stream()
                            .map(t -> new SessionContext.Tenant(t.getKey(), t.getValue())).toList(),
                    ctx.roles().stream().toList(), ctx.permissions().stream().toList());
        };
    }
}
