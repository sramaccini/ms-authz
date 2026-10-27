package com.enterprise.auth.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import io.swagger.v3.oas.models.servers.Server;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.util.List;

/**
 * Definizione OpenAPI dell'API di amministrazione, generata dal codice da springdoc: GET /v3/api-docs.
 * Abilitata solo dove serve (springdoc.api-docs.enabled, attiva nel profilo dev): in produzione non si
 * pubblica la mappa delle API. Il server indicato e' il BFF, perche' la SPA chiama sempre tramite il BFF
 * con il cookie di sessione; /api/v1/auth/enrich e' interno e resta fuori dalla definizione.
 */
@Configuration
@ConditionalOnProperty(name = "springdoc.api-docs.enabled", havingValue = "true")
public class OpenApiConfig {

    static final String SESSION_COOKIE = "sessionCookie";

    private static final String DESCRIPTION = """
            API per l'interfaccia di amministrazione della SPA, esposte dal BFF (stessa origine della SPA).

            **Autenticazione**: cookie `SESSION_ID` impostato dal BFF al login (nessun token nel JavaScript).
            Le richieste non idempotenti (POST, PUT, PATCH, DELETE) devono avere un header `Origin` ammesso.

            **Ambiti**
            - `rbac:manage` (ruolo `TENANT_ADMIN`): amministratore delegato, solo il tenant della propria sessione.
            - `rbac:manage-global` (ruolo `GLOBAL_ADMIN`): tutti i tenant; in esclusiva definisce ruoli,
              crea tenant, attiva/disattiva utenti.

            **Regole**
            - Il catalogo dei permessi e i ruoli di sistema (`system: true`) si modificano solo con le migrazioni.
            - I permessi `*-global` esistono solo in `GLOBAL_ADMIN`; un amministratore delegato non assegna ne'
              toglie ruoli che li contengono.
            - Nessuno puo' modificare le proprie assegnazioni o disattivare se stesso.
            - Le modifiche hanno effetto al login successivo degli utenti coinvolti; per un effetto immediato
              si revocano le sessioni con `DELETE /bff/admin/users/{username}/sessions` (endpoint del BFF).
            - Ogni modifica e' registrata nell'audit.

            **Errori**: `application/problem+json` (RFC 9457), `type` = `urn:problem:auth-service:<codice>`:
            `tenant-out-of-scope`, `global-admin-required`, `global-role`, `self-modification`, `system-role` (403);
            `unknown-role`, `unknown-permission`, `global-permission` (400); `not-found` (404);
            `version-mismatch`, `role-exists`, `role-assigned`, `tenant-exists`, `user-exists` (409).
            """;

    @Bean
    OpenAPI adminOpenApi(@Value("${auth.openapi.server-url}") String serverUrl) {
        return new OpenAPI()
                .info(new Info()
                        .title("ms-authz - API di amministrazione RBAC")
                        .version("1.0.0")
                        .description(DESCRIPTION))
                .servers(List.of(new Server().url(serverUrl).description("BFF")))
                .components(new Components().addSecuritySchemes(SESSION_COOKIE, new SecurityScheme()
                        .type(SecurityScheme.Type.APIKEY)
                        .in(SecurityScheme.In.COOKIE)
                        .name("SESSION_ID")))
                .addSecurityItem(new SecurityRequirement().addList(SESSION_COOKIE));
    }

    /** Lettura della definizione da strumenti su un'altra origine (es. Swagger UI locale): solo GET, senza credenziali. */
    @Bean
    WebMvcConfigurer openApiCors(@Value("${auth.openapi.cors-allowed-origins:}") List<String> allowedOrigins) {
        return new WebMvcConfigurer() {
            @Override
            public void addCorsMappings(CorsRegistry registry) {
                if (!allowedOrigins.isEmpty()) {
                    for (String path : List.of("/v3/api-docs/**", "/v3/api-docs.yaml")) {
                        registry.addMapping(path)
                                .allowedOrigins(allowedOrigins.toArray(String[]::new))
                                .allowedMethods("GET");
                    }
                }
            }
        };
    }
}
