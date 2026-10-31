package com.logicwarez.authz.rbac;

import com.logicwarez.authz.rbac.admin.AdminScope;
import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer;

/**
 * Regola di accesso alle API di amministrazione, da aggiungere alla SecurityFilterChain dell'applicazione:
 * <pre>
 * .authorizeHttpRequests(auth -> RbacAdminSecurity.adminApi(auth).anyRequest().authenticated())
 * </pre>
 */
public final class RbacAdminSecurity {

    public static final String ADMIN_API = "/api/v1/admin/**";

    private RbacAdminSecurity() {
    }

    public static AuthorizeHttpRequestsConfigurer<?>.AuthorizationManagerRequestMatcherRegistry adminApi(
            AuthorizeHttpRequestsConfigurer<?>.AuthorizationManagerRequestMatcherRegistry auth) {
        return auth.requestMatchers(ADMIN_API).hasAnyAuthority(AdminScope.MANAGE, AdminScope.MANAGE_GLOBAL);
    }
}
