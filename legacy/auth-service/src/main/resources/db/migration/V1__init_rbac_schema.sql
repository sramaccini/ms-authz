-- Schema RBAC come da specifica architetturale (par. 6).
-- Nota: gen_random_uuid() e' nativa da PostgreSQL 13, l'estensione uuid-ossp non e' necessaria
-- (e la sua creazione richiede privilegi elevati), per questo e' stata omessa.

CREATE TABLE app_user (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username    VARCHAR(150) UNIQUE NOT NULL,
    email       VARCHAR(255),
    is_active   BOOLEAN NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE app_role (
    id          SERIAL PRIMARY KEY,
    role_code   VARCHAR(100) UNIQUE NOT NULL,
    description VARCHAR(255)
);

CREATE TABLE app_permission (
    id              SERIAL PRIMARY KEY,
    permission_code VARCHAR(100) UNIQUE NOT NULL, -- es: "patient:read"
    description     VARCHAR(255)
);

CREATE TABLE role_permission (
    role_id       INTEGER REFERENCES app_role(id) ON DELETE CASCADE,
    permission_id INTEGER REFERENCES app_permission(id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
);

CREATE TABLE user_role (
    user_id   UUID REFERENCES app_user(id) ON DELETE CASCADE,
    role_id   INTEGER REFERENCES app_role(id) ON DELETE CASCADE,
    tenant_id VARCHAR(50) NOT NULL DEFAULT 'DEFAULT', -- NOT NULL: e' parte della PK
    PRIMARY KEY (user_id, role_id, tenant_id)
);

-- Gli indici idx_user_role_user e idx_app_user_username della specifica sono ridondanti:
-- PK (user_id, ...) e UNIQUE(username) creano gia' indici con la stessa colonna iniziale.
-- Si aggiunge invece l'indice utile alla join role_permission -> app_permission.
CREATE INDEX idx_role_permission_permission ON role_permission(permission_id);
