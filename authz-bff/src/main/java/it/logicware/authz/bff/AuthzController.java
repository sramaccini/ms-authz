package it.logicware.authz.bff;

import java.util.List;
import java.util.regex.Pattern;

import it.logicware.authz.session.SessionContext;
import com.fasterxml.jackson.annotation.JsonInclude;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Contratto di autorizzazione di Quadrava (contracts/authz.yaml) sui permessi della sessione: la UI li usa solo
 * per nascondere o disabilitare parti dell'interfaccia, il controllo vero resta su ogni API. I permessi sono quelli
 * del tenant della sessione, fissati al login o al cambio di tenant; {@code app} e' richiesto dal contratto ma non
 * filtra (un'applicazione per back end).
 */
@RestController
public class AuthzController {

    static final String VERSION_HEADER = "X-Permissions-Version";
    /** Numero massimo di controlli in un batch (maxItems del contratto). */
    static final int MAX_CHECKS = 200;
    private static final Pattern PERMISSION = Pattern.compile("^[a-z0-9]+\\.[a-z0-9]+\\.[a-z0-9]+$");

    @GetMapping("/authz/capabilities")
    public ResponseEntity<?> capabilities(@RequestParam(required = false) String app,
                                          @AuthenticationPrincipal SessionContext session) {
        if (app == null || app.isBlank()) {
            return BffControllers.problem(HttpStatus.BAD_REQUEST, "Parametro app mancante");
        }
        String version = session.permissionsVersion();
        return ResponseEntity.ok().header(VERSION_HEADER, version)
                .body(new Capabilities(session.permissions().stream().sorted().toList(), version));
    }

    @PostMapping("/authz/check")
    public ResponseEntity<?> check(@RequestBody(required = false) CheckRequest request,
                                   @AuthenticationPrincipal SessionContext session) {
        if (request == null || request.checks() == null) {
            return BffControllers.problem(HttpStatus.BAD_REQUEST, "Elenco dei controlli mancante");
        }
        if (request.checks().size() > MAX_CHECKS) {
            return BffControllers.problem(HttpStatus.BAD_REQUEST,
                    "Troppi controlli in un batch (al massimo " + MAX_CHECKS + ")");
        }
        for (CheckItem item : request.checks()) {
            if (item == null || item.permission() == null || !PERMISSION.matcher(item.permission()).matches()) {
                return BffControllers.problem(HttpStatus.BAD_REQUEST,
                        "Permesso non valido: il formato e' dominio.risorsa.azione, minuscolo");
            }
        }
        List<CheckResult> results = request.checks().stream()
                .map(c -> new CheckResult(c.permission(), c.resource(), session.hasPermission(c.permission())))
                .toList();
        return ResponseEntity.ok().header(VERSION_HEADER, session.permissionsVersion())
                .body(new CheckResponse(results));
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    ResponseEntity<ProblemDetail> unreadable() {
        return BffControllers.problem(HttpStatus.BAD_REQUEST, "Corpo della richiesta non valido");
    }

    public record Capabilities(List<String> permissions, String version) {
    }

    public record ResourceRef(String type, String id) {
    }

    public record CheckItem(String permission, ResourceRef resource) {
    }

    public record CheckRequest(List<CheckItem> checks) {
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record CheckResult(String permission, ResourceRef resource, boolean allowed) {
    }

    public record CheckResponse(List<CheckResult> results) {
    }
}
