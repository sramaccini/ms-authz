package com.logicwarez.authz.rbac.admin;

import org.springframework.http.HttpStatus;

/** Errore dell'API di amministrazione, tradotto in application/problem+json da ApiExceptionHandler. */
public class AdminProblem extends RuntimeException {

    private final HttpStatus status;
    private final String code;

    private AdminProblem(HttpStatus status, String code, String detail) {
        super(detail);
        this.status = status;
        this.code = code;
    }

    public HttpStatus status() {
        return status;
    }

    public String code() {
        return code;
    }

    static AdminProblem forbidden(String code, String detail) {
        return new AdminProblem(HttpStatus.FORBIDDEN, code, detail);
    }

    static AdminProblem notFound(String detail) {
        return new AdminProblem(HttpStatus.NOT_FOUND, "not-found", detail);
    }

    static AdminProblem conflict(String code, String detail) {
        return new AdminProblem(HttpStatus.CONFLICT, code, detail);
    }

    static AdminProblem invalid(String code, String detail) {
        return new AdminProblem(HttpStatus.BAD_REQUEST, code, detail);
    }
}
