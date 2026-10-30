-- Dati DEMO caricati solo con il profilo "dev": tenant usati dai dati demo (V100+).
-- Su un DB nuovo gira dopo V2 (che introduce la tabella tenant e la FK) e prima di V100.
INSERT INTO tenant (code, description) VALUES
    ('TENANT_A', 'Tenant demo A'),
    ('TENANT_B', 'Tenant demo B')
ON CONFLICT (code) DO UPDATE SET description = EXCLUDED.description;
