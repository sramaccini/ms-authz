package com.enterprise.authz.rbac;

import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

/**
 * @param flyway migrazioni dello schema RBAC, indipendenti da quelle dell'applicazione che incorpora la libreria
 */
@ConfigurationProperties("authz.rbac")
public record RbacProperties(@DefaultValue Flyway flyway) {

    /**
     * @param locations  script SQL; in sviluppo si aggiungono i dati demo (es. classpath:db/authz/seed)
     * @param table      history table dedicata: le versioni non si scontrano con quelle dell'applicazione
     * @param outOfOrder ammesso solo in sviluppo, quando i seed hanno versioni piu' alte dello schema
     */
    public record Flyway(@DefaultValue("true") boolean enabled,
                         @DefaultValue("classpath:db/authz/migration") List<String> locations,
                         @DefaultValue("authz_schema_history") String table,
                         @DefaultValue("false") boolean outOfOrder) {
    }
}
