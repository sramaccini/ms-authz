package com.enterprise.auth.service;

import com.enterprise.auth.repository.AuthorizationRepository;
import com.enterprise.auth.repository.AuthorizationRepository.ActiveUser;
import com.enterprise.auth.repository.AuthorizationRepository.GrantRow;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.SortedSet;
import java.util.TreeSet;
import java.util.stream.Collectors;

@Service
public class AuthorizationService {

    private final AuthorizationRepository repository;

    public AuthorizationService(AuthorizationRepository repository) {
        this.repository = repository;
    }

    /**
     * Risolve ruoli e permessi dell'utente.
     * Regola di scelta del tenant: tenant richiesto (se l'utente vi ha ruoli), altrimenti
     * l'unico tenant disponibile; con piu' tenant e nessuna richiesta -> selezione obbligatoria.
     */
    @Transactional(readOnly = true)
    public AuthorizationContext resolve(String username, String requestedTenant) {
        ActiveUser user = repository.findActiveUser(username)
                .orElseThrow(() -> new UserNotAuthorizedException("Utente non trovato o non attivo"));

        List<GrantRow> grants = repository.findGrants(user.id());
        SortedSet<String> tenants = grants.stream()
                .map(GrantRow::tenantId)
                .collect(Collectors.toCollection(TreeSet::new));

        if (tenants.isEmpty()) {
            throw new UserNotAuthorizedException("Nessun ruolo assegnato");
        }

        String tenant = selectTenant(requestedTenant, tenants);

        SortedSet<String> roles = new TreeSet<>();
        SortedSet<String> permissions = new TreeSet<>();
        for (GrantRow grant : grants) {
            if (grant.tenantId().equals(tenant)) {
                roles.add(grant.roleCode());
                if (grant.permissionCode() != null) {
                    permissions.add(grant.permissionCode());
                }
            }
        }

        return new AuthorizationContext(user.username(), user.email(), tenant,
                Collections.unmodifiableSortedSet(roles),
                Collections.unmodifiableSortedSet(permissions),
                Collections.unmodifiableSortedSet(tenants));
    }

    private static String selectTenant(String requestedTenant, SortedSet<String> tenants) {
        if (requestedTenant != null && !requestedTenant.isBlank()) {
            if (!tenants.contains(requestedTenant)) {
                throw new UserNotAuthorizedException("Nessun ruolo sul tenant richiesto");
            }
            return requestedTenant;
        }
        if (tenants.size() == 1) {
            return Objects.requireNonNull(tenants.first());
        }
        throw new TenantSelectionRequiredException(tenants);
    }
}
