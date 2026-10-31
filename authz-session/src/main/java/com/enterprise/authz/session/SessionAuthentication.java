package com.enterprise.authz.session;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.List;
import java.util.stream.Stream;

/**
 * Utente autenticato tramite la sessione del BFF.
 * Authority: i permessi cosi' come sono (es. "clinical.patient.read") e i ruoli con prefisso "ROLE_",
 * quindi hasAuthority('clinical.patient.read') e hasRole('DOCTOR') funzionano entrambi.
 */
public class SessionAuthentication extends AbstractAuthenticationToken {

    private final SessionContext session;

    public SessionAuthentication(SessionContext session) {
        super(authorities(session));
        this.session = session;
        setAuthenticated(true);
    }

    @Override
    public SessionContext getPrincipal() {
        return session;
    }

    @Override
    public Object getCredentials() {
        return null; // il SESSION_ID non viene esposto
    }

    @Override
    public String getName() {
        return session.username();
    }

    private static List<GrantedAuthority> authorities(SessionContext session) {
        return Stream.concat(
                        session.permissions().stream().map(SimpleGrantedAuthority::new),
                        session.roles().stream().map(role -> new SimpleGrantedAuthority("ROLE_" + role)))
                .map(GrantedAuthority.class::cast)
                .toList();
    }
}
