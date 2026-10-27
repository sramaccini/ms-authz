package com.enterprise.auth;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.transaction.annotation.Transactional;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Instant;
import java.util.Arrays;
import java.util.UUID;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.hasKey;
import static org.hamcrest.Matchers.not;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * API di amministrazione RBAC su PostgreSQL e Redis reali. Le sessioni sono scritte su Redis come le
 * scrive il BFF; ogni test gira in una transazione annullata alla fine (MockMvc usa lo stesso thread).
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "AUTH_DB_PASSWORD=unused",
        "spring.flyway.locations=classpath:db/migration,classpath:db/seed"
})
@AutoConfigureMockMvc
@Testcontainers
@Transactional
class AdminApiIntegrationTest {

    @Container
    @ServiceConnection
    static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:17");

    @Container
    @ServiceConnection(name = "redis")
    static final GenericContainer<?> REDIS = new GenericContainer<>("redis:7.4").withExposedPorts(6379);

    @Autowired
    MockMvc mvc;

    @Autowired
    StringRedisTemplate redis;

    @LocalServerPort
    int port;

    // --- Autenticazione e ambito ---

    @Test
    void requestsWithoutValidAdminSessionAreRejected() throws Exception {
        mvc.perform(get("/api/v1/admin/roles")).andExpect(status().isUnauthorized());
        mvc.perform(get("/api/v1/admin/roles").header("X-Session-ID", UUID.randomUUID().toString()))
                .andExpect(status().isUnauthorized());
        mvc.perform(get("/api/v1/admin/roles").header("X-Session-ID", session("mario.rossi", "TENANT_A", "patient:read")))
                .andExpect(status().isForbidden());
    }

    /** Su Tomcat reale (non MockMvc): il 403 non deve diventare 401 passando per l'error dispatch. */
    @Test
    void nonAdminGetsForbiddenOverRealHttp() throws Exception {
        HttpResponse<String> response = HttpClient.newHttpClient().send(
                HttpRequest.newBuilder(URI.create("http://localhost:" + port + "/api/v1/admin/roles"))
                        .header("X-Session-ID", session("mario.rossi", "TENANT_A", "patient:read"))
                        .build(),
                HttpResponse.BodyHandlers.ofString());

        assertThat(response.statusCode()).isEqualTo(403);
    }

    @Test
    void tenantAdminSeesOnlyOwnTenant() throws Exception {
        String admin = tenantAdminA();

        perform(get("/api/v1/admin/tenants/TENANT_A/users"), admin)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[*].username", hasItem("mario.rossi")));
        perform(get("/api/v1/admin/tenants/TENANT_B/users"), admin)
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.type").value("urn:problem:auth-service:tenant-out-of-scope"));
        perform(get("/api/v1/admin/tenants"), admin)
                .andExpect(jsonPath("$[*].code", contains("TENANT_A")));
        perform(get("/api/v1/admin/users/anna.bianchi"), admin)
                .andExpect(jsonPath("$.assignments", hasKey("TENANT_A")))
                .andExpect(jsonPath("$.assignments", not(hasKey("TENANT_B"))));
    }

    // --- Assegnazioni ---

    @Test
    void tenantAdminAssignsRolesAndChangeAppliesAtNextLogin() throws Exception {
        perform(put("/api/v1/admin/tenants/TENANT_A/users/anna.bianchi/roles"), tenantAdminA(), """
                {"roles":["CUP_OPERATOR","DOCTOR"]}""")
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.assignments.TENANT_A", contains("CUP_OPERATOR", "DOCTOR")));

        // Il login successivo (enrich chiamato dal BFF) riceve i nuovi permessi
        mvc.perform(post("/api/v1/auth/enrich")
                        .with(jwt().jwt(j -> j.claim("preferred_username", "anna.bianchi")))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"username":"anna.bianchi","tenant_id":"TENANT_A"}"""))
                .andExpect(jsonPath("$.roles", contains("CUP_OPERATOR", "DOCTOR")))
                .andExpect(jsonPath("$.permissions", hasItem("prescription:create")));

        perform(get("/api/v1/admin/audit"), tenantAdminA())
                .andExpect(jsonPath("$[0].action").value("USER_ROLES_REPLACED"))
                .andExpect(jsonPath("$[0].actor").value("admin.tenant.a"))
                .andExpect(jsonPath("$[0].before_state.roles", contains("CUP_OPERATOR")))
                .andExpect(jsonPath("$[0].after_state.roles", contains("CUP_OPERATOR", "DOCTOR")));
    }

    @Test
    void tenantAdminCannotPromoteToGlobalAdmin() throws Exception {
        perform(put("/api/v1/admin/tenants/TENANT_A/users/mario.rossi/roles"), tenantAdminA(), """
                {"roles":["DOCTOR","GLOBAL_ADMIN"]}""")
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.type").value("urn:problem:auth-service:global-role"));
    }

    @Test
    void tenantAdminCannotRemoveGlobalAdminRole() throws Exception {
        perform(put("/api/v1/admin/tenants/TENANT_A/users/admin.globale/roles"), tenantAdminA(), """
                {"roles":[]}""")
                .andExpect(status().isForbidden());
    }

    @Test
    void nobodyCanChangeOwnAssignments() throws Exception {
        perform(put("/api/v1/admin/tenants/TENANT_A/users/admin.globale/roles"), globalAdmin(), """
                {"roles":[]}""")
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.type").value("urn:problem:auth-service:self-modification"));
    }

    @Test
    void unknownRolesAreRejected() throws Exception {
        perform(put("/api/v1/admin/tenants/TENANT_A/users/mario.rossi/roles"), tenantAdminA(), """
                {"roles":["NON_ESISTE"]}""")
                .andExpect(status().isBadRequest());
    }

    // --- Ruoli: solo amministratore globale ---

    @Test
    void globalAdminManagesCustomRolesWithOptimisticLocking() throws Exception {
        String admin = globalAdmin();

        perform(post("/api/v1/admin/roles"), admin, """
                {"code":"NURSE","description":"Infermiere","permissions":["patient:read"]}""")
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.version").value(0));

        perform(put("/api/v1/admin/roles/NURSE"), admin, """
                {"description":"Infermiere","permissions":["patient:read","booking:manage"],"version":0}""")
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.version").value(1))
                .andExpect(jsonPath("$.permissions", contains("booking:manage", "patient:read")));

        perform(put("/api/v1/admin/roles/NURSE"), admin, """
                {"description":"Modifica concorrente","permissions":[],"version":0}""")
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.type").value("urn:problem:auth-service:version-mismatch"));

        perform(delete("/api/v1/admin/roles/NURSE"), admin, null).andExpect(status().isNoContent());
    }

    @Test
    void globalPermissionsAndSystemRolesAreProtected() throws Exception {
        String admin = globalAdmin();

        perform(post("/api/v1/admin/roles"), admin, """
                {"code":"SUPER","permissions":["rbac:manage-global"]}""")
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.type").value("urn:problem:auth-service:global-permission"));
        perform(post("/api/v1/admin/roles"), admin, """
                {"code":"FAKE","permissions":["inventato:read"]}""")
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.type").value("urn:problem:auth-service:unknown-permission"));
        perform(put("/api/v1/admin/roles/GLOBAL_ADMIN"), admin, """
                {"permissions":[],"version":0}""")
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.type").value("urn:problem:auth-service:system-role"));
        perform(delete("/api/v1/admin/roles/DOCTOR"), admin, null)
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.type").value("urn:problem:auth-service:role-assigned"));
    }

    @Test
    void tenantAdminCannotManageRolesTenantsOrUserStatus() throws Exception {
        String admin = tenantAdminA();

        perform(post("/api/v1/admin/roles"), admin, """
                {"code":"NURSE","permissions":["patient:read"]}""")
                .andExpect(status().isForbidden());
        perform(post("/api/v1/admin/tenants"), admin, """
                {"code":"TENANT_C"}""")
                .andExpect(status().isForbidden());
        perform(patch("/api/v1/admin/users/mario.rossi"), admin, """
                {"active":false}""")
                .andExpect(status().isForbidden());
    }

    // --- Utenti ---

    @Test
    void tenantAdminOnboardsNewUserInOwnTenant() throws Exception {
        String admin = tenantAdminA();

        perform(post("/api/v1/admin/users"), admin, """
                {"username":"nuovo.utente","email":"nuovo.utente@example.org"}""")
                .andExpect(status().isCreated());
        perform(put("/api/v1/admin/tenants/TENANT_A/users/nuovo.utente/roles"), admin, """
                {"roles":["CUP_OPERATOR"]}""")
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.assignments.TENANT_A", contains("CUP_OPERATOR")));
        perform(post("/api/v1/admin/users"), admin, """
                {"username":"nuovo.utente"}""")
                .andExpect(status().isConflict());
    }

    @Test
    void globalAdminDeactivatesUserWhoIsDeniedAtNextLogin() throws Exception {
        perform(patch("/api/v1/admin/users/mario.rossi"), globalAdmin(), """
                {"active":false}""")
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.active").value(false));

        mvc.perform(post("/api/v1/auth/enrich")
                        .with(jwt().jwt(j -> j.claim("preferred_username", "mario.rossi")))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"username":"mario.rossi"}"""))
                .andExpect(status().isForbidden());

        perform(patch("/api/v1/admin/users/admin.globale"), globalAdmin(), """
                {"active":false}""")
                .andExpect(status().isForbidden());
    }

    // --- Supporto ---

    private String tenantAdminA() {
        return session("admin.tenant.a", "TENANT_A", "rbac:manage", "session:revoke");
    }

    private String globalAdmin() {
        return session("admin.globale", "TENANT_A",
                "rbac:manage", "rbac:manage-global", "session:revoke", "session:revoke-global");
    }

    /** Scrive su Redis una sessione nel formato del BFF (specifica par. 3.4). */
    private String session(String username, String tenant, String... permissions) {
        String id = UUID.randomUUID().toString();
        String perms = Arrays.stream(permissions).map(p -> "\"" + p + "\"").collect(Collectors.joining(","));
        redis.opsForValue().set("session:" + id, """
                {"session_id":"%s","username":"%s","email":null,"tenant_id":"%s","roles":[],
                 "permissions":[%s],"created_at":"%s","expires_at":"%s"}"""
                .formatted(id, username, tenant, perms, Instant.now(), Instant.now().plusSeconds(1800)));
        return id;
    }

    private ResultActions perform(MockHttpServletRequestBuilder request, String sessionId) throws Exception {
        return perform(request, sessionId, null);
    }

    private ResultActions perform(MockHttpServletRequestBuilder request, String sessionId, String body)
            throws Exception {
        request.header("X-Session-ID", sessionId);
        if (body != null) {
            request.contentType(MediaType.APPLICATION_JSON).content(body);
        }
        return mvc.perform(request);
    }
}
