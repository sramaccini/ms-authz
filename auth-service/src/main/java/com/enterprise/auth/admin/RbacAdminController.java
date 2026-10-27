package com.enterprise.auth.admin;

import com.enterprise.auth.admin.AdminApi.AuditEntry;
import com.enterprise.auth.admin.AdminApi.PermissionView;
import com.enterprise.auth.admin.AdminApi.RoleAssignmentRequest;
import com.enterprise.auth.admin.AdminApi.RoleCreateRequest;
import com.enterprise.auth.admin.AdminApi.RoleUpdateRequest;
import com.enterprise.auth.admin.AdminApi.RoleView;
import com.enterprise.auth.admin.AdminApi.TenantCreateRequest;
import com.enterprise.auth.admin.AdminApi.TenantUserView;
import com.enterprise.auth.admin.AdminApi.TenantView;
import com.enterprise.auth.admin.AdminApi.UserCreateRequest;
import com.enterprise.auth.admin.AdminApi.UserUpdateRequest;
import com.enterprise.auth.admin.AdminApi.UserView;
import com.enterprise.session.context.SessionContext;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Pattern;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * API di amministrazione RBAC per il frontend, raggiunta tramite il BFF (rotta /api/v1/admin/**)
 * e autenticata con la sessione del BFF (X-Session-ID). Contratto: docs/openapi-admin.yaml.
 */
@RestController
@RequestMapping("/api/v1/admin")
@Validated
public class RbacAdminController {

    private final RbacAdminService service;

    public RbacAdminController(RbacAdminService service) {
        this.service = service;
    }

    @GetMapping("/permissions")
    public List<PermissionView> permissions() {
        return service.permissions();
    }

    @GetMapping("/roles")
    public List<RoleView> roles() {
        return service.roles();
    }

    @PostMapping("/roles")
    @ResponseStatus(HttpStatus.CREATED)
    public RoleView createRole(@AuthenticationPrincipal SessionContext session,
                               @Valid @RequestBody RoleCreateRequest request) {
        return service.createRole(AdminScope.of(session), request);
    }

    @PutMapping("/roles/{code}")
    public RoleView updateRole(@AuthenticationPrincipal SessionContext session,
                               @PathVariable @Pattern(regexp = AdminApi.ROLE_CODE) String code,
                               @Valid @RequestBody RoleUpdateRequest request) {
        return service.updateRole(AdminScope.of(session), code, request);
    }

    @DeleteMapping("/roles/{code}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void deleteRole(@AuthenticationPrincipal SessionContext session,
                           @PathVariable @Pattern(regexp = AdminApi.ROLE_CODE) String code) {
        service.deleteRole(AdminScope.of(session), code);
    }

    @GetMapping("/tenants")
    public List<TenantView> tenants(@AuthenticationPrincipal SessionContext session) {
        return service.tenants(AdminScope.of(session));
    }

    @PostMapping("/tenants")
    @ResponseStatus(HttpStatus.CREATED)
    public TenantView createTenant(@AuthenticationPrincipal SessionContext session,
                                   @Valid @RequestBody TenantCreateRequest request) {
        return service.createTenant(AdminScope.of(session), request);
    }

    @GetMapping("/tenants/{tenant}/users")
    public List<TenantUserView> tenantUsers(@AuthenticationPrincipal SessionContext session,
                                            @PathVariable @Pattern(regexp = AdminApi.TENANT_CODE) String tenant,
                                            @RequestParam(defaultValue = "50") int limit,
                                            @RequestParam(defaultValue = "0") int offset) {
        return service.tenantUsers(AdminScope.of(session), tenant, limit, offset);
    }

    @PutMapping("/tenants/{tenant}/users/{username}/roles")
    public UserView replaceUserRoles(@AuthenticationPrincipal SessionContext session,
                                     @PathVariable @Pattern(regexp = AdminApi.TENANT_CODE) String tenant,
                                     @PathVariable @Pattern(regexp = AdminApi.USERNAME) String username,
                                     @Valid @RequestBody RoleAssignmentRequest request) {
        return service.replaceUserRoles(AdminScope.of(session), tenant, username, request);
    }

    @GetMapping("/users/{username}")
    public UserView user(@AuthenticationPrincipal SessionContext session,
                         @PathVariable @Pattern(regexp = AdminApi.USERNAME) String username) {
        return service.user(AdminScope.of(session), username);
    }

    @PostMapping("/users")
    @ResponseStatus(HttpStatus.CREATED)
    public UserView createUser(@AuthenticationPrincipal SessionContext session,
                               @Valid @RequestBody UserCreateRequest request) {
        return service.createUser(AdminScope.of(session), request);
    }

    @PatchMapping("/users/{username}")
    public UserView updateUser(@AuthenticationPrincipal SessionContext session,
                               @PathVariable @Pattern(regexp = AdminApi.USERNAME) String username,
                               @Valid @RequestBody UserUpdateRequest request) {
        return service.updateUser(AdminScope.of(session), username, request);
    }

    @GetMapping("/audit")
    public List<AuditEntry> audit(@AuthenticationPrincipal SessionContext session,
                                  @RequestParam(required = false) @Pattern(regexp = AdminApi.TENANT_CODE) String tenant,
                                  @RequestParam(defaultValue = "50") int limit,
                                  @RequestParam(defaultValue = "0") int offset) {
        return service.audit(AdminScope.of(session), tenant, limit, offset);
    }
}
