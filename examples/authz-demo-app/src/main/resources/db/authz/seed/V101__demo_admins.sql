-- Dati DEMO caricati solo con il profilo "dev": amministratori di esempio (utenti segnaposto).
INSERT INTO app_user (username, email) VALUES
    ('admin.tenant.a', 'admin.tenant.a@example.org'),
    ('admin.globale', 'admin.globale@example.org');

-- admin.tenant.a: amministratore delegato del solo TENANT_A
INSERT INTO user_role (user_id, role_id, tenant_id)
SELECT u.id, r.id, 'TENANT_A' FROM app_user u, app_role r
WHERE u.username = 'admin.tenant.a' AND r.role_code = 'TENANT_ADMIN';

-- admin.globale: amministratore globale (accede scegliendo TENANT_A)
INSERT INTO user_role (user_id, role_id, tenant_id)
SELECT u.id, r.id, 'TENANT_A' FROM app_user u, app_role r
WHERE u.username = 'admin.globale' AND r.role_code = 'GLOBAL_ADMIN';

-- Il ruolo demo ADMIN di V100 riceve tutti i permessi del catalogo: i permessi con azione "...global" pero'
-- possono stare solo nel ruolo di sistema GLOBAL_ADMIN.
DELETE FROM role_permission
 WHERE role_id = (SELECT id FROM app_role WHERE role_code = 'ADMIN')
   AND permission_id IN (SELECT id FROM app_permission WHERE permission_code LIKE '%global');
