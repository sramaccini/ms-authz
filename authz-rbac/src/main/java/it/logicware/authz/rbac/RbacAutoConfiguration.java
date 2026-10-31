package it.logicware.authz.rbac;

import javax.sql.DataSource;

import it.logicware.authz.rbac.admin.RbacAdminController;
import it.logicware.authz.rbac.admin.RbacAdminExceptionHandler;
import it.logicware.authz.rbac.admin.RbacAdminRepository;
import it.logicware.authz.rbac.admin.RbacAdminService;
import it.logicware.authz.rbac.repository.AuthorizationRepository;
import it.logicware.authz.rbac.service.AuthorizationContext;
import it.logicware.authz.rbac.service.AuthorizationService;
import it.logicware.authz.session.AuthorizationResolver;
import it.logicware.authz.session.SessionContext;
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
