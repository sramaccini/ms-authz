package com.enterprise.authz.rbac.admin;

import com.enterprise.authz.rbac.admin.AdminApi.AuditEntry;
import com.enterprise.authz.rbac.admin.AdminApi.PermissionView;
import com.enterprise.authz.rbac.admin.AdminApi.RoleAssignmentRequest;
import com.enterprise.authz.rbac.admin.AdminApi.RoleCreateRequest;
import com.enterprise.authz.rbac.admin.AdminApi.RoleUpdateRequest;
import com.enterprise.authz.rbac.admin.AdminApi.RoleView;
import com.enterprise.authz.rbac.admin.AdminApi.TenantCreateRequest;
import com.enterprise.authz.rbac.admin.AdminApi.TenantUserView;
import com.enterprise.authz.rbac.admin.AdminApi.TenantView;
import com.enterprise.authz.rbac.admin.AdminApi.UserCreateRequest;
import com.enterprise.authz.rbac.admin.AdminApi.UserUpdateRequest;
import com.enterprise.authz.rbac.admin.AdminApi.UserView;
import com.enterprise.authz.rbac.admin.RbacAdminRepository.UserRow;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tools.jackson.databind.json.JsonMapper;

import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.SortedMap;
import java.util.SortedSet;
import java.util.TreeMap;
import java.util.TreeSet;

/**
 * Amministrazione RBAC con le regole di sicurezza:
 * - l'amministratore delegato opera solo sul tenant della propria sessione;
 * - ruoli, tenant e stato degli utenti sono riservati all'amministratore globale (valgono per tutti i tenant);
 * - i permessi "-global" stanno solo nei ruoli di sistema e un amministratore delegato non puo' assegnare
 *   ne' togliere ruoli che li contengono: nessuna promozione ad amministratore globale;
 * - nessuno modifica la propria utenza: insieme alla regola precedente garantisce che resti sempre
 *   almeno un amministratore globale;
 * - ogni modifica e' registrata in rbac_audit nella stessa transazione.
 * Le modifiche hanno effetto al login successivo degli utenti coinvolti (ruoli e permessi sono copiati
 * nella sessione al login); per un effetto immediato si revocano le sessioni tramite il BFF.
 */
@Service
public class RbacAdminService {

    private static final Logger log = LoggerFactory.getLogger(RbacAdminService.class);
    private static final String GLOBAL_SUFFIX = "-global";
    private static final int MAX_PAGE = 200;

    private final RbacAdminRepository repository;
    private final JsonMapper json;

    public RbacAdminService(RbacAdminRepository repository, JsonMapper json) {
        this.repository = repository;
        this.json = json;
    }

    // --- Catalogo e ruoli ---

    @Transactional(readOnly = true)
    public List<PermissionView> permissions() {
        return repository.listPermissions();
    }

    @Transactional(readOnly = true)
    public List<RoleView> roles() {
        return repository.listRoles();
    }

    @Transactional
    public RoleView createRole(AdminScope actor, RoleCreateRequest request) {
        actor.requireGlobal();
        if (repository.findRole(request.code()).isPresent()) {
            throw AdminProblem.conflict("role-exists", "Ruolo gia' esistente");
        }
        Set<String> permissions = validatePermissions(request.permissions());
        repository.insertRole(request.code(), request.description());
        repository.replaceRolePermissions(request.code(), permissions);
        RoleView created = repository.findRole(request.code()).orElseThrow();
        audit(actor, "ROLE_CREATED", "ROLE", request.code(), null, null, created);
        return created;
    }

    @Transactional
    public RoleView updateRole(AdminScope actor, String code, RoleUpdateRequest request) {
        actor.requireGlobal();
        RoleView before = existingCustomRole(code);
        Set<String> permissions = validatePermissions(request.permissions());
        if (!repository.updateRole(code, request.description(), request.version())) {
            throw AdminProblem.conflict("version-mismatch",
                    "Il ruolo e' stato modificato da un altro amministratore: ricaricare e riprovare");
        }
        repository.replaceRolePermissions(code, permissions);
        RoleView after = repository.findRole(code).orElseThrow();
        audit(actor, "ROLE_UPDATED", "ROLE", code, null, before, after);
        return after;
    }

    @Transactional
    public void deleteRole(AdminScope actor, String code) {
        actor.requireGlobal();
        RoleView before = existingCustomRole(code);
        if (repository.isRoleAssigned(code)) {
            throw AdminProblem.conflict("role-assigned", "Ruolo ancora assegnato: rimuovere prima le assegnazioni");
        }
        repository.deleteRole(code);
        audit(actor, "ROLE_DELETED", "ROLE", code, null, before, null);
    }

    // --- Tenant ---

    @Transactional(readOnly = true)
    public List<TenantView> tenants(AdminScope actor) {
        return repository.listTenants().stream()
                .filter(t -> actor.canManageTenant(t.code()))
                .toList();
    }

    @Transactional
    public TenantView createTenant(AdminScope actor, TenantCreateRequest request) {
        actor.requireGlobal();
        if (repository.findTenant(request.code()).isPresent()) {
            throw AdminProblem.conflict("tenant-exists", "Tenant gia' esistente");
        }
        repository.insertTenant(request.code(), request.description());
        TenantView created = new TenantView(request.code(), request.description());
        audit(actor, "TENANT_CREATED", "TENANT", request.code(), request.code(), null, created);
        return created;
    }

    @Transactional(readOnly = true)
    public List<TenantUserView> tenantUsers(AdminScope actor, String tenant, int limit, int offset) {
        actor.requireTenant(tenant);
        existingTenant(tenant);
        return repository.tenantUsers(tenant, Math.clamp(limit, 1, MAX_PAGE), Math.max(offset, 0));
    }

    // --- Utenti ---

    @Transactional(readOnly = true)
    public UserView user(AdminScope actor, String username) {
        return view(actor, existingUser(username));
    }

    @Transactional
    public UserView createUser(AdminScope actor, UserCreateRequest request) {
        if (repository.findUser(request.username()).isPresent()) {
            throw AdminProblem.conflict("user-exists", "Utente gia' esistente");
        }
        repository.insertUser(request.username(), request.email());
        UserView created = view(actor, existingUser(request.username()));
        audit(actor, "USER_CREATED", "USER", request.username(), actor.tenantId(), null, created);
        return created;
    }

    @Transactional
    public UserView updateUser(AdminScope actor, String username, UserUpdateRequest request) {
        actor.requireGlobal();
        actor.requireNotSelf(username);
        UserRow before = existingUser(username);
        boolean active = request.active() != null ? request.active() : before.active();
        String email = request.email() != null ? request.email() : before.email();
        repository.updateUser(username, active, email);
        UserRow after = existingUser(username);
        audit(actor, "USER_UPDATED", "USER", username, null,
                Map.of("active", before.active(), "email", String.valueOf(before.email())),
                Map.of("active", after.active(), "email", String.valueOf(after.email())));
        return view(actor, after);
    }

    /** Sostituisce i ruoli dell'utente su un tenant (lista vuota = nessun ruolo su quel tenant). */
    @Transactional
    public UserView replaceUserRoles(AdminScope actor, String tenant, String username, RoleAssignmentRequest request) {
        actor.requireTenant(tenant);
        actor.requireNotSelf(username);
        if (!repository.lockTenant(tenant)) {
            throw AdminProblem.notFound("Tenant inesistente");
        }
        UserRow user = existingUser(username);
        SortedSet<String> before = repository.userAssignments(user.id()).getOrDefault(tenant, new TreeSet<>());
        SortedSet<String> after = new TreeSet<>(request.roles());

        Set<String> touched = new HashSet<>(before);
        touched.addAll(after);
        Map<String, SortedSet<String>> permissionsByRole = repository.rolePermissions(touched);
        Set<String> unknown = new TreeSet<>(after);
        unknown.removeAll(permissionsByRole.keySet());
        if (!unknown.isEmpty()) {
            throw AdminProblem.invalid("unknown-role", "Ruoli inesistenti: " + unknown);
        }
        if (!actor.isGlobal()) {
            Set<String> changed = new HashSet<>(touched);
            changed.removeAll(intersection(before, after));
            boolean escalation = changed.stream()
                    .anyMatch(role -> permissionsByRole.getOrDefault(role, new TreeSet<>()).stream()
                            .anyMatch(p -> p.endsWith(GLOBAL_SUFFIX)));
            if (escalation) {
                throw AdminProblem.forbidden("global-role",
                        "Ruoli con permessi globali gestibili solo dall'amministratore globale");
            }
        }

        repository.replaceUserRoles(user.id(), tenant, after);
        audit(actor, "USER_ROLES_REPLACED", "USER", username, tenant,
                Map.of("roles", before), Map.of("roles", after));
        return view(actor, user);
    }

    // --- Audit ---

    @Transactional(readOnly = true)
    public List<AuditEntry> audit(AdminScope actor, String tenant, int limit, int offset) {
        String scope = tenant;
        if (!actor.isGlobal()) {
            scope = actor.tenantId(); // l'amministratore delegato vede solo il proprio tenant
        }
        return repository.listAudit(scope, Math.clamp(limit, 1, MAX_PAGE), Math.max(offset, 0));
    }

    // --- Supporto ---

    private UserView view(AdminScope actor, UserRow user) {
        SortedMap<String, SortedSet<String>> visible = new TreeMap<>();
        repository.userAssignments(user.id()).forEach((tenant, roles) -> {
            if (actor.canManageTenant(tenant)) {
                visible.put(tenant, roles);
            }
        });
        return new UserView(user.username(), user.email(), user.active(), visible);
    }

    private UserRow existingUser(String username) {
        return repository.findUser(username).orElseThrow(() -> AdminProblem.notFound("Utente inesistente"));
    }

    private void existingTenant(String tenant) {
        repository.findTenant(tenant).orElseThrow(() -> AdminProblem.notFound("Tenant inesistente"));
    }

    private RoleView existingCustomRole(String code) {
        RoleView role = repository.findRole(code).orElseThrow(() -> AdminProblem.notFound("Ruolo inesistente"));
        if (role.system()) {
            throw AdminProblem.forbidden("system-role",
                    "Ruolo di sistema: si modifica solo con le migrazioni del database");
        }
        return role;
    }

    /** Permessi esistenti nel catalogo e non riservati ai ruoli di sistema. */
    private Set<String> validatePermissions(List<String> requested) {
        Set<String> permissions = new TreeSet<>(requested);
        Set<String> global = new TreeSet<>();
        permissions.stream().filter(p -> p.endsWith(GLOBAL_SUFFIX)).forEach(global::add);
        if (!global.isEmpty()) {
            throw AdminProblem.invalid("global-permission",
                    "Permessi globali riservati al ruolo di sistema GLOBAL_ADMIN: " + global);
        }
        Set<String> unknown = new TreeSet<>(permissions);
        unknown.removeAll(repository.existingPermissions(permissions));
        if (!unknown.isEmpty()) {
            throw AdminProblem.invalid("unknown-permission", "Permessi non presenti nel catalogo: " + unknown);
        }
        return permissions;
    }

    private void audit(AdminScope actor, String action, String targetType, String target, String tenantId,
                       Object before, Object after) {
        repository.insertAudit(actor, action, targetType, target, tenantId,
                before == null ? null : json.writeValueAsString(before),
                after == null ? null : json.writeValueAsString(after));
        log.info("Audit RBAC: azione={} amministratore={} oggetto={}:{} tenant={}",
                action, actor.username(), targetType, target, tenantId);
    }

    private static Set<String> intersection(Set<String> a, Set<String> b) {
        Set<String> result = new HashSet<>(a);
        result.retainAll(b);
        return result;
    }
}
