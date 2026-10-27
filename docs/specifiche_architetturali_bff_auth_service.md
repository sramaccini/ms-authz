# Specifica Architetturale: Pattern Backend-for-Frontend (BFF) con Session Store e Microservizio di Autorizzazione

## 1. Panoramica dell'Architettura

Questa architettura implementa un modello di sicurezza **Stateful / Session-Based** verso il Frontend (Browser/SPA) e un approccio **Distributed Session Look-up** verso i microservizi interni di dominio. 

Il sistema separa nettamente le responsabilità:
* **IAM Centrale (es. Keycloak, Entra ID):** Gestisce l'autenticazione dell'utente (identità, credenziali, MFA).
* **BFF (Backend-for-Frontend):** Gestisce la sessione browser via cookie sicuri, effettua il Token Exchange / Login tramite lo IAM e gestisce la delega dell'autorizzazione.
* **Microservizio di Autorizzazione (Auth-Service):** Gestisce il modello di dati dei ruoli/permessi fine-grained e popola lo stato della sessione su Redis.
* **Redis Cluster:** Fungerà da **Distributed Session Store** contenente i ruoli, i permessi e il contesto utente.
* **Microservizi di Dominio:** Validano le richieste in arrivo recuperando il contesto di sicurezza da Redis (con caching locale L1).

---

## 2. Diagramma di Flusso (Sequence Diagram)

```
[ Frontend (SPA) ]     [ BFF Gateway ]     [ IAM (Identity) ]     [ Auth-Service ]     [ Redis Cluster ]     [ Domain Service ]
        |                    |                    |                     |                     |                    |
        |--- 1. Login ------>|                    |                     |                     |                    |
        |                    |--- 2. Auth OAuth ->|                     |                     |                    |
        |                    |<-- 3. Access Token-|                     |                     |                    |
        |                    |                     |                    |                     |                    |
        |                    |--- 4. Arricchimento Ruoli (Username) --->|                     |                    |
        |                    |                                          |--- 5. Query DB ---->|                    |
        |                    |                                          |<-- 6. Ruoli/Perm. --|                    |
        |                    |--- 7. Crea Sessione (SessionID, Ruoli, Context) --------------->|                    |
        |<-- 8. Set-Cookie --|                                                                |                    |
        |    (HttpOnly)      |                                                                |                    |
        |                    |                                                                |                    |
        |--- 9. Request ---->|                                                                |                    |
        |  (Cookie Session)  |--- 10. Forward Request (Header: X-Session-ID) ------------------------------------>|
        |                    |                                                                |<-- 11. Fetch Auth -|
        |                    |                                                                |--- 12. Context --->|
        |<-- 13. Response ---|<-----------------------------------------------------------------------------------|
```

---

## 3. Specifiche Tecniche dei Componenti

### 3.1. Frontend <-> BFF
* **Autenticazione:** Cookie `SESSION_ID` gestito con le seguenti flag obbligatorie:
  * `HttpOnly = true` (Protezione totale da attacchi XSS).
  * `Secure = true` (Trasmesso solo su HTTPS).
  * `SameSite = Strict` (Protezione da attacchi CSRF).
* **Cross-Origin:** Il BFF e la SPA devono risiedere sotto lo stesso dominio primario (es. `app.azienda.it` e `api.azienda.it`).

### 3.2. BFF (Backend-for-Frontend)
Il BFF agisce da orchestratore della sessione:
1. Intercetta la risposta dello IAM a seguito dell'autenticazione ed estrae l'identità (Username/Subject).
2. Invoca l'**Auth-Service** per recuperare l'albero completo dei ruoli e permessi associati allo username.
3. Genera un `SESSION_ID` univo (UUID v4 / Cryptographically Secure Random String).
4. Salva in **Redis** la struttura dati della sessione con un Time-To-Live (TTL) configurabile (es. 30-60 minuti).
5. Risponde al Frontend impostando il cookie di sessione.
6. Per tutte le chiamate applicative successive, valida il cookie di sessione e inoltra la richiesta verso i microservizi downstream aggiungendo l'header HTTP:
   `X-Session-ID: <UUID_SESSIONE>`

### 3.3. Microservizio di Autorizzazione (Auth-Service)
* **Scopo:** Gestire il dominio dei ruoli e dei permessi applicativi.
* **Database:** RDBMS Relazionale (PostgreSQL) con modello RBAC (Role-Based Access Control).
* **API Esposta:** 
  * `POST /api/v1/auth/enrich`
  * **Input Payload:** `{"username": "string"}`
  * **Output Payload:** JSON contenente la lista dei ruoli, permessi fine-grained e contesto organizzativo (tenant/ASL).

### 3.4. Gestione della Cache (Redis)
I dati salvati in Redis devono rispettare una struttura JSON / Hash standard per consentire l'accesso condiviso tra BFF e Microservizi.

**Struttura della Chiave Redis:** `session:<SESSION_ID>`

**Esempio di Payload della Sessione in Redis:**
```json
{
  "session_id": "c83b860d-4581-4246-86d7-e07584bd3bc1",
  "username": "mario.rossi",
  "email": "mario.rossi@azienda.it",
  "tenant_id": "ASL_MILANO_1",
  "roles": [
    "DOCTOR",
    "CUP_OPERATOR"
  ],
  "permissions": [
    "patient:read",
    "patient:write",
    "prescription:create"
  ],
  "created_at": "2026-10-27T10:00:00Z",
  "expires_at": "2026-10-27T10:30:00Z"
}
```

---

## 4. Strategia nei Microservizi di Dominio (L1 / L2 Cache)

Per evitare che Redis diventi il punto singolo di fallimento o un collo di bottiglia di i/o:

1. **L2 Cache (Redis):** Il microservizio riceve `X-Session-ID`, interroga Redis e scarica il payload della sessione.
2. **L1 Cache (In-Memory Local Cache):**
   * Il microservizio memorizza in un frammento di cache locale (es. Caffeine per Java, node-cache per Node.js) il contesto della sessione abbinato al `X-Session-ID`.
   * **TTL L1 Cache:** Estremamente ridotto (es. **5 - 10 secondi**).
   * **Beneficio:** Se la stessa sessione effettua 50 chiamate in parallelo per caricare una dashboard, solo 1 richiesta colpisce Redis, le altre 49 usano la memoria locale.

---

## 5. Revoca della Sessione e Logout

* **Logout Utente:** Quando l'utente effettua il logout, il BFF elimina immediatamente la chiave `session:<SESSION_ID>` da Redis e invalida il cookie nel browser.
* **Revoca immediata dei permessi:** Un amministratore o un evento di sistema può cancellare la chiave da Redis. Entro un intervallo massimo pari al TTL della cache L1 (massimo 5-10 secondi), l'utente perde l'accesso su tutti i microservizi dell'architettura.

---

## 6. Schema DDL del Database di Autorizzazione (PostgreSQL)

```sql
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE app_user (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(150) UNIQUE NOT NULL,
    email VARCHAR(255),
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE app_role (
    id SERIAL PRIMARY KEY,
    role_code VARCHAR(100) UNIQUE NOT NULL,
    description VARCHAR(255)
);

CREATE TABLE app_permission (
    id SERIAL PRIMARY KEY,
    permission_code VARCHAR(100) UNIQUE NOT NULL, -- es: "patient:read"
    description VARCHAR(255)
);

CREATE TABLE role_permission (
    role_id INTEGER REFERENCES app_role(id) ON DELETE CASCADE,
    permission_id INTEGER REFERENCES app_permission(id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
);

CREATE TABLE user_role (
    user_id UUID REFERENCES app_user(id) ON DELETE CASCADE,
    role_id INTEGER REFERENCES app_role(id) ON DELETE CASCADE,
    tenant_id VARCHAR(50) DEFAULT 'DEFAULT',
    PRIMARY KEY (user_id, role_id, tenant_id)
);

CREATE INDEX idx_user_role_user ON user_role(user_id);
CREATE INDEX idx_app_user_username ON app_user(username);
```

---

## 7. Requisiti di Implementazione per i Dev / AI Codegen

Chi riceve questo documento per implementare il sistema deve:
1. **BFF Microservice:**
   * Esporre l'endpoint di callback OAuth2/OIDC.
   * Integrare un client Redis ad alte prestazioni.
   * Implementare la gestione delle eccezioni per `401 Unauthorized` in caso di sessione scaduta o assente in Redis.
2. **Auth Microservice:**
   * Esporre un endpoint REST performante e protetto per il caricamento dei ruoli tramite username.
   * Gestire le query SQL in join ottimizzate sugli indici descritti nel DDL.