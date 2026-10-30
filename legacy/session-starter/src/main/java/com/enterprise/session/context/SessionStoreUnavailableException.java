package com.enterprise.session.context;

/** Redis non raggiungibile: la richiesta va rifiutata con 503, non trattata come sessione assente. */
public class SessionStoreUnavailableException extends RuntimeException {

    public SessionStoreUnavailableException(Throwable cause) {
        super("Session store non raggiungibile", cause);
    }
}
