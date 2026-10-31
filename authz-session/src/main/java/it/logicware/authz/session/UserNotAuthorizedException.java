package it.logicware.authz.session;

/** Utente inesistente, disattivato o privo di ruoli sul tenant richiesto. */
public class UserNotAuthorizedException extends RuntimeException {

    public UserNotAuthorizedException(String message) {
        super(message);
    }
}
