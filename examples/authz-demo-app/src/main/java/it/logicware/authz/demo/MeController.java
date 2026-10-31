package it.logicware.authz.demo;

import it.logicware.authz.session.SessionContext;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/** Esempio di API di dominio: utente e permessi arrivano dalla sessione, senza chiamate in rete. */
@RestController
public class MeController {

    @GetMapping("/api/v1/me")
    public SessionContext me(@AuthenticationPrincipal SessionContext session) {
        return session;
    }

    @GetMapping("/api/v1/patients")
    @PreAuthorize("hasAuthority('clinical.patient.read')")
    public String patients() {
        return "[]";
    }
}
