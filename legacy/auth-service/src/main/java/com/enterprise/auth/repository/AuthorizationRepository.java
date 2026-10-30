package com.enterprise.auth.repository;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Accesso al modello RBAC con JdbcClient: una sola query in join per recuperare
 * tutte le coppie (tenant, ruolo, permesso) dell'utente, sfruttando gli indici di PK.
 */
@Repository
public class AuthorizationRepository {

    public record ActiveUser(UUID id, String username, String email) {
    }

    public record GrantRow(String tenantId, String roleCode, String permissionCode) {
    }

    private static final String FIND_ACTIVE_USER = """
            SELECT id, username, email
              FROM app_user
             WHERE username = :username
               AND is_active = TRUE
            """;

    private static final String FIND_GRANTS = """
            SELECT ur.tenant_id, r.role_code, p.permission_code
              FROM user_role ur
              JOIN app_role r             ON r.id = ur.role_id
              LEFT JOIN role_permission rp ON rp.role_id = r.id
              LEFT JOIN app_permission p   ON p.id = rp.permission_id
             WHERE ur.user_id = :userId
            """;

    private final JdbcClient jdbc;

    public AuthorizationRepository(JdbcClient jdbc) {
        this.jdbc = jdbc;
    }

    public Optional<ActiveUser> findActiveUser(String username) {
        return jdbc.sql(FIND_ACTIVE_USER)
                .param("username", username)
                .query((rs, n) -> new ActiveUser(
                        rs.getObject("id", UUID.class),
                        rs.getString("username"),
                        rs.getString("email")))
                .optional();
    }

    public List<GrantRow> findGrants(UUID userId) {
        return jdbc.sql(FIND_GRANTS)
                .param("userId", userId)
                .query((rs, n) -> new GrantRow(
                        rs.getString("tenant_id"),
                        rs.getString("role_code"),
                        rs.getString("permission_code")))
                .list();
    }
}
