package com.enterprise.auth;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.RequestPostProcessor;
import org.springframework.test.web.servlet.ResultActions;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;

import static org.hamcrest.Matchers.contains;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * POST /api/v1/auth/enrich su PostgreSQL reale: schema Flyway V1 + dati demo (db/seed).
 * Il JWT dello IAM e' simulato (firma non verificata): qui si testano le regole di autorizzazione e le query.
 */
@SpringBootTest(properties = {
        "AUTH_DB_PASSWORD=unused", // sostituita dalla ServiceConnection del container
        "spring.flyway.locations=classpath:db/migration,classpath:db/seed"
})
@AutoConfigureMockMvc
@Testcontainers
class EnrichIntegrationTest {

    @Container
    @ServiceConnection
    static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:17");

    @Autowired
    MockMvc mvc;

    @Test
    void userWithSingleTenantIsEnriched() throws Exception {
        enrich("""
                {"username":"mario.rossi"}""", asUser("mario.rossi"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.tenant_id").value("TENANT_A"))
                .andExpect(jsonPath("$.roles").value(contains("CUP_OPERATOR", "DOCTOR")))
                .andExpect(jsonPath("$.permissions")
                        .value(contains("booking:manage", "patient:read", "patient:write", "prescription:create")));
    }

    @Test
    void userWithManyTenantsMustChooseOne() throws Exception {
        enrich("""
                {"username":"anna.bianchi"}""", asUser("anna.bianchi"))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.available_tenants").value(contains("TENANT_A", "TENANT_B")));

        enrich("""
                {"username":"anna.bianchi","tenant_id":"TENANT_B"}""", asUser("anna.bianchi"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.tenant_id").value("TENANT_B"));
    }

    @Test
    void tenantWithoutRolesIsForbidden() throws Exception {
        enrich("""
                {"username":"mario.rossi","tenant_id":"TENANT_B"}""", asUser("mario.rossi"))
                .andExpect(status().isForbidden());
    }

    @Test
    void unknownUserGetsSameAnswerAsUnauthorizedUser() throws Exception {
        enrich("""
                {"username":"nessuno"}""", asUser("nessuno"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.type").value("urn:problem:auth-service:user-not-authorized"));
    }

    @Test
    void userCannotEnrichSomeoneElse() throws Exception {
        enrich("""
                {"username":"anna.bianchi","tenant_id":"TENANT_A"}""", asUser("mario.rossi"))
                .andExpect(status().isForbidden());
    }

    @Test
    void serviceClientWithScopeCanEnrichAnyUser() throws Exception {
        enrich("""
                {"username":"anna.bianchi","tenant_id":"TENANT_A"}""",
                jwt().jwt(j -> j.subject("service-account"))
                        .authorities(new SimpleGrantedAuthority("SCOPE_auth:enrich")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("anna.bianchi"));
    }

    @Test
    void missingTokenIsUnauthorized() throws Exception {
        mvc.perform(post("/api/v1/auth/enrich").contentType(MediaType.APPLICATION_JSON).content("""
                        {"username":"mario.rossi"}"""))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void invalidTenantFormatIsRejected() throws Exception {
        enrich("""
                {"username":"mario.rossi","tenant_id":"A' OR '1'='1"}""", asUser("mario.rossi"))
                .andExpect(status().isBadRequest());
    }

    private ResultActions enrich(String body, RequestPostProcessor auth) throws Exception {
        return mvc.perform(post("/api/v1/auth/enrich")
                .with(auth)
                .contentType(MediaType.APPLICATION_JSON)
                .content(body));
    }

    private static RequestPostProcessor asUser(String username) {
        return jwt().jwt(j -> j.subject("sub-" + username).claim("preferred_username", username));
    }
}
