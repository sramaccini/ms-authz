-- Amministrazione RBAC da frontend: tenant censiti, ruoli di sistema, permessi di amministrazione, audit.

-- Tenant censiti: finora erano stringhe libere in user_role.tenant_id.
CREATE TABLE tenant (
    code        VARCHAR(50) PRIMARY KEY,
    description VARCHAR(255),
    created_at  TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO tenant (code, description) VALUES ('DEFAULT', 'Tenant di default');
INSERT INTO tenant (code) SELECT DISTINCT tenant_id FROM user_role ON CONFLICT (code) DO NOTHING;

ALTER TABLE user_role
    ADD CONSTRAINT fk_user_role_tenant FOREIGN KEY (tenant_id) REFERENCES tenant (code);

-- Elenco utenti per tenant (la PK inizia da user_id, non copre questa ricerca)
CREATE INDEX idx_user_role_tenant ON user_role (tenant_id);

-- version: blocco ottimistico sulle modifiche concorrenti; is_system: ruoli definiti dagli sviluppatori,
-- non modificabili ne' cancellabili da interfaccia.
ALTER TABLE app_role
    ADD COLUMN version   INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN is_system BOOLEAN NOT NULL DEFAULT FALSE;

-- Catalogo dei permessi di amministrazione (il catalogo e' gestito solo dagli sviluppatori, via migrazioni).
-- I permessi "-global" possono stare solo nel ruolo di sistema GLOBAL_ADMIN (regola applicata dal servizio).
INSERT INTO app_permission (permission_code, description) VALUES
    ('rbac:manage', 'Gestione degli utenti e delle loro assegnazioni di ruolo nel proprio tenant'),
    ('rbac:manage-global', 'Gestione di ruoli, tenant e assegnazioni su tutti i tenant'),
    ('session:revoke', 'Revoca delle sessioni degli utenti nel proprio tenant'),
    ('session:revoke-global', 'Revoca delle sessioni degli utenti su tutti i tenant')
ON CONFLICT (permission_code) DO NOTHING;

INSERT INTO app_role (role_code, description, is_system) VALUES
    ('TENANT_ADMIN', 'Amministratore delegato di tenant', TRUE),
    ('GLOBAL_ADMIN', 'Amministratore globale', TRUE)
ON CONFLICT (role_code) DO UPDATE SET is_system = TRUE;

INSERT INTO role_permission (role_id, permission_id)
SELECT r.id, p.id FROM app_role r JOIN app_permission p ON
    (r.role_code = 'TENANT_ADMIN' AND p.permission_code IN ('rbac:manage', 'session:revoke')) OR
    (r.role_code = 'GLOBAL_ADMIN' AND p.permission_code IN
        ('rbac:manage', 'rbac:manage-global', 'session:revoke', 'session:revoke-global'))
ON CONFLICT DO NOTHING;

-- Registro di audit in sola aggiunta (GDPR / ISO 27001): chi ha cambiato cosa, quando, prima e dopo.
CREATE TABLE rbac_audit (
    id           BIGSERIAL PRIMARY KEY,
    occurred_at  TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    actor        VARCHAR(150) NOT NULL,
    actor_tenant VARCHAR(50),
    action       VARCHAR(50)  NOT NULL,
    target_type  VARCHAR(30)  NOT NULL,
    target       VARCHAR(150) NOT NULL,
    tenant_id    VARCHAR(50),
    before_state JSONB,
    after_state  JSONB
);

CREATE INDEX idx_rbac_audit_target ON rbac_audit (target_type, target);
CREATE INDEX idx_rbac_audit_tenant_time ON rbac_audit (tenant_id, occurred_at DESC);

-- Primo amministratore globale in produzione (una tantum, da eseguire a cura dell'esercizio):
--   INSERT INTO app_user (username, email) VALUES ('<username>', '<email>') ON CONFLICT DO NOTHING;
--   INSERT INTO user_role (user_id, role_id, tenant_id)
--   SELECT u.id, r.id, '<tenant>' FROM app_user u, app_role r
--    WHERE u.username = '<username>' AND r.role_code = 'GLOBAL_ADMIN';
