package com.enterprise.bff.client;

import com.enterprise.bff.config.BffProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.List;

/** Client verso l'Auth-Service: POST /api/v1/auth/enrich (specifica par. 3.3). */
@Component
public class AuthServiceClient {

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record EnrichRequest(String username, @JsonProperty("tenant_id") String tenantId) {
    }

    public record EnrichResponse(String username,
                                 String email,
                                 @JsonProperty("tenant_id") String tenantId,
                                 List<String> roles,
                                 List<String> permissions,
                                 @JsonProperty("available_tenants") List<String> availableTenants) {
    }

    private final WebClient webClient;
    private final Duration timeout;

    public AuthServiceClient(ObjectProvider<WebClient.Builder> builderProvider, BffProperties properties) {
        WebClient.Builder builder = builderProvider.getIfAvailable(WebClient::builder);
        this.webClient = builder.baseUrl(properties.authService().baseUrl()).build();
        this.timeout = properties.authService().timeout();
    }

    /**
     * Arricchisce l'utente appena autenticato inoltrando il SUO access token: l'Auth-Service
     * verifica che lo username richiesto coincida con quello del token.
     * Gli errori HTTP emergono come WebClientResponseException (403, 409, ...).
     */
    public Mono<EnrichResponse> enrich(String username, String tenantId, String accessToken) {
        return webClient.post()
                .uri("/api/v1/auth/enrich")
                .headers(h -> h.setBearerAuth(accessToken))
                .bodyValue(new EnrichRequest(username, tenantId))
                .retrieve()
                .bodyToMono(EnrichResponse.class)
                .timeout(timeout);
    }
}
