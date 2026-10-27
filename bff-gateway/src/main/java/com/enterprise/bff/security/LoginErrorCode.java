package com.enterprise.bff.security;

/** Codici di errore restituiti al frontend come query param ?error= sulla pagina di login-error. */
public enum LoginErrorCode {
    ACCESS_DENIED("access_denied"),
    TENANT_SELECTION_REQUIRED("tenant_selection_required"),
    AUTH_SERVICE_UNAVAILABLE("auth_service_unavailable"),
    LOGIN_FAILED("login_failed");

    private final String code;

    LoginErrorCode(String code) {
        this.code = code;
    }

    public String code() {
        return code;
    }
}
