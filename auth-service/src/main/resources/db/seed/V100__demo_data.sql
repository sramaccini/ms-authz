-- Dati DEMO caricati solo con il profilo "dev". Utenti e codici sono segnaposto.
INSERT INTO app_role (role_code, description) VALUES
    ('DOCTOR', 'Medico'),
    ('CUP_OPERATOR', 'Operatore CUP'),
    ('ADMIN', 'Amministratore');

INSERT INTO app_permission (permission_code, description) VALUES
    ('patient:read', 'Lettura anagrafica paziente'),
    ('patient:write', 'Modifica anagrafica paziente'),
    ('prescription:create', 'Creazione prescrizione'),
    ('booking:manage', 'Gestione prenotazioni');

INSERT INTO role_permission (role_id, permission_id)
SELECT r.id, p.id FROM app_role r JOIN app_permission p ON
    (r.role_code = 'DOCTOR'       AND p.permission_code IN ('patient:read', 'patient:write', 'prescription:create')) OR
    (r.role_code = 'CUP_OPERATOR' AND p.permission_code IN ('patient:read', 'booking:manage')) OR
    (r.role_code = 'ADMIN');

INSERT INTO app_user (username, email) VALUES
    ('mario.rossi', 'mario.rossi@example.org'),
    ('anna.bianchi', 'anna.bianchi@example.org');

-- mario.rossi: un solo tenant
INSERT INTO user_role (user_id, role_id, tenant_id)
SELECT u.id, r.id, 'TENANT_A' FROM app_user u, app_role r
WHERE u.username = 'mario.rossi' AND r.role_code IN ('DOCTOR', 'CUP_OPERATOR');

-- anna.bianchi: due tenant -> serve la selezione del tenant al login
INSERT INTO user_role (user_id, role_id, tenant_id)
SELECT u.id, r.id, t.tenant FROM app_user u, app_role r, (VALUES ('TENANT_A'), ('TENANT_B')) AS t(tenant)
WHERE u.username = 'anna.bianchi' AND r.role_code = 'CUP_OPERATOR';
