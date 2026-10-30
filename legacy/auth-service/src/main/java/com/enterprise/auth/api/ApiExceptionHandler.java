package com.enterprise.auth.api;

import com.enterprise.auth.admin.AdminProblem;
import com.enterprise.auth.service.TenantSelectionRequiredException;
import com.enterprise.auth.service.UserNotAuthorizedException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.net.URI;

/** Errori in formato RFC 9457 (application/problem+json), senza dettagli interni. */
@RestControllerAdvice
public class ApiExceptionHandler {

    @ExceptionHandler(UserNotAuthorizedException.class)
    ProblemDetail userNotAuthorized(UserNotAuthorizedException ex) {
        // Stesso esito per utente inesistente, disattivato o senza ruoli: evita user enumeration
        return problem(HttpStatus.FORBIDDEN, "user-not-authorized", "Utente non abilitato all'applicazione");
    }

    @ExceptionHandler(TenantSelectionRequiredException.class)
    ProblemDetail tenantSelectionRequired(TenantSelectionRequiredException ex) {
        ProblemDetail pd = problem(HttpStatus.CONFLICT, "tenant-selection-required",
                "L'utente opera su piu' tenant: specificare tenant_id");
        pd.setProperty("available_tenants", ex.availableTenants());
        return pd;
    }

    @ExceptionHandler(AdminProblem.class)
    ProblemDetail adminProblem(AdminProblem ex) {
        return problem(ex.status(), ex.code(), ex.getMessage());
    }

    @ExceptionHandler(AccessDeniedException.class)
    ProblemDetail accessDenied(AccessDeniedException ex) {
        return problem(HttpStatus.FORBIDDEN, "access-denied", ex.getMessage());
    }

    private static ProblemDetail problem(HttpStatus status, String code, String detail) {
        ProblemDetail pd = ProblemDetail.forStatusAndDetail(status, detail);
        pd.setType(URI.create("urn:problem:auth-service:" + code));
        return pd;
    }
}
