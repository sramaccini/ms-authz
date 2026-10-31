package com.logicwarez.authz.rbac.admin;

import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.net.URI;

/** Errori in formato RFC 9457 (application/problem+json), senza dettagli interni. */
@RestControllerAdvice(assignableTypes = RbacAdminController.class)
public class RbacAdminExceptionHandler {

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
