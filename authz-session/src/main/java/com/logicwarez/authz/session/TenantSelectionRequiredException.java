package com.logicwarez.authz.session;

import java.util.SortedSet;

/** L'utente ha ruoli su piu' tenant e non e' stato indicato quale usare. */
public class TenantSelectionRequiredException extends RuntimeException {

    private final SortedSet<String> availableTenants;

    public TenantSelectionRequiredException(SortedSet<String> availableTenants) {
        super("Selezione del tenant richiesta");
        this.availableTenants = availableTenants;
    }

    public SortedSet<String> availableTenants() {
        return availableTenants;
    }
}
