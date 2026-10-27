package com.enterprise.bff.web;

import com.enterprise.bff.config.BffProperties;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.util.regex.Pattern;

/**
 * Punto di ingresso del login per la SPA: GET /bff/login[?tenant=XYZ].
 * Memorizza l'eventuale tenant scelto e avvia il flusso OIDC verso lo IAM.
 */
@RestController
public class LoginController {

    public static final String TENANT_HINT_ATTRIBUTE = "BFF_TENANT_HINT";
    private static final Pattern TENANT_FORMAT = Pattern.compile("^[A-Za-z0-9_-]{1,50}$");

    private final String authorizationPath;

    public LoginController(BffProperties properties) {
        this.authorizationPath = "/oauth2/authorization/" + properties.oidc().registrationId();
    }

    @GetMapping("/bff/login")
    public Mono<ResponseEntity<Void>> login(@RequestParam(name = "tenant", required = false) String tenant,
                                            ServerWebExchange exchange) {
        if (tenant != null && !TENANT_FORMAT.matcher(tenant).matches()) {
            return Mono.just(ResponseEntity.badRequest().build());
        }
        return exchange.getSession()
                .doOnNext(session -> {
                    if (tenant != null) {
                        session.getAttributes().put(TENANT_HINT_ATTRIBUTE, tenant);
                    } else {
                        session.getAttributes().remove(TENANT_HINT_ATTRIBUTE);
                    }
                })
                .thenReturn(ResponseEntity.status(HttpStatus.FOUND).location(URI.create(authorizationPath)).build());
    }
}
