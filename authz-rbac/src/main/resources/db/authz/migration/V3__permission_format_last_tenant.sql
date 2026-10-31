-- Contratto di autorizzazione di Quadrava (contracts/authz.yaml): codici dei permessi nel formato
-- dominio.risorsa.azione, minuscolo, senza altri separatori. I permessi riservati all'amministratore globale
-- hanno un'azione che finisce in "global" (prima avevano il suffisso "-global").
UPDATE app_permission SET permission_code = 'authz.rbac.manage'         WHERE permission_code = 'rbac:manage';
UPDATE app_permission SET permission_code = 'authz.rbac.manageglobal'   WHERE permission_code = 'rbac:manage-global';
UPDATE app_permission SET permission_code = 'authz.session.revoke'       WHERE permission_code = 'session:revoke';
UPDATE app_permission SET permission_code = 'authz.session.revokeglobal' WHERE permission_code = 'session:revoke-global';

-- NOT VALID: vale per i permessi nuovi o modificati; quelli gia' presenti in un altro formato vanno convertiti
-- con una migrazione dell'applicazione (poi: ALTER TABLE app_permission VALIDATE CONSTRAINT ck_permission_code_format).
ALTER TABLE app_permission
    ADD CONSTRAINT ck_permission_code_format
    CHECK (permission_code ~ '^[a-z0-9]+\.[a-z0-9]+\.[a-z0-9]+$') NOT VALID;

-- Ultimo tenant usato: al login l'utente con piu' tenant entra su questo, senza domande (contracts/bff.yaml).
ALTER TABLE app_user
    ADD COLUMN last_tenant_id VARCHAR(50) REFERENCES tenant (code) ON DELETE SET NULL;
