# ms-auth — BFF + Auth-Service

Implementazione della *Specifica Architetturale: Pattern BFF con Session Store e Microservizio di Autorizzazione*.

| Progetto | Stack | Porta | Responsabilità |
|---|---|---|---|
| `auth-service` | Java 25, Spring Boot 4.0 (MVC + Virtual Threads), JdbcClient, Flyway, PostgreSQL | 8081 | Modello RBAC, `POST /api/v1/auth/enrich` protetto da JWT |
| `bff-gateway` | Java 25, Spring Boot 4.0, Spring Cloud Gateway (WebFlux) 2025.1, Redis reactive | 8080 | Login OIDC, sessione su Redis, cookie `SESSION_ID`, relay `X-Session-ID` |

## Flusso

1. La SPA naviga su `GET /bff/login[?tenant=XYZ]` → redirect allo IAM.
2. Callback `/login/oauth2/code/iam` → il BFF chiama `auth-service /enrich` **con l'access token dell'utente**.
3. Il BFF genera il `SESSION_ID` (UUID v4), salva `session:<id>` su Redis con TTL e imposta il cookie
   `HttpOnly; Secure; SameSite=Strict`; i token dello IAM vengono scartati.
4. Ogni chiamata `/api/**` instradata dal gateway: header interni ripuliti, verifica Origin sulle richieste
   non idempotenti, verifica sessione su Redis, inoltro con `X-Session-ID`.
5. `GET /bff/session` restituisce il contesto utente alla UI; `POST /bff/logout` cancella la chiave Redis.

Errori di login → redirect a `FRONTEND_URL/login-error?error=access_denied|tenant_selection_required|auth_service_unavailable|login_failed`.

## Avvio locale

Il realm Keycloak `enterprise` viene importato all'avvio da `keycloak/import/enterprise-realm.json`:
client confidenziale `bff-gateway` (PKCE S256) e utenti demo `mario.rossi` / `anna.bianchi`, allineati
ai dati demo dell'auth-service. Secret del client e password degli utenti arrivano da `.env` (gitignored).

```bash
cp .env.example .env   # poi sostituire i segnaposto
docker compose up -d

cd auth-service
mvn spring-boot:run -Dspring-boot.run.profiles=dev

cd ../bff-gateway
set -a; . ../.env; set +a
IAM_CLIENT_SECRET="$BFF_CLIENT_SECRET" mvn spring-boot:run
```

L'import usa la strategia `OVERWRITE_EXISTING`: modifiche fatte a mano dalla console admin vengono perse
al riavvio del container.

**Windows**: se l'avvio fallisce con `Unable to establish loopback connection` (selector NIO), la cartella
temp ha un percorso in formato corto 8.3 (es. `C:\Users\ABCDEF~1\...`) dove il JDK non riesce a creare il
socket AF_UNIX. Aggiungere `"-Dspring-boot.run.jvmArguments=-Djdk.net.unixdomain.tmpdir=C:\tmp\ud"`
(cartella esistente, percorso senza `~`).

Variabili principali: `IAM_ISSUER_URI`, `IAM_CLIENT_ID`, `IAM_CLIENT_SECRET`, `AUTH_DB_URL`, `AUTH_DB_USER`,
`AUTH_DB_PASSWORD`, `REDIS_HOST`, `REDIS_PORT`, `REDIS_PASSWORD`, `AUTH_SERVICE_URL`, `FRONTEND_URL`,
`BFF_COOKIE_DOMAIN`, `CLINICAL_SERVICE_URI`.

## Scelte da validare prima della produzione

- **BFF multi-istanza**: lo stato del login OIDC (`state`/`nonce`/PKCE e tenant scelto) è in una WebSession
  su Redis (Spring Session, chiavi `bff:login:sessions:*`, cookie `BFF_LOGIN` `SameSite=Lax`, TTL 10 min,
  invalidata a fine login): nessuna sticky session richiesta. Ogni `GET /bff/login` anonimo crea una chiave:
  in produzione serve rate limiting su `/bff/login` (gateway o WAF) e una policy `maxmemory` su Redis.
- **`X-Session-ID` verso valle**: è un credenziale equivalente al cookie. Rete interna con mTLS, mai loggarlo,
  e i servizi a valle non devono essere raggiungibili dall'esterno.
- **TTL assoluto** (30 min, no sliding): valutare il rinnovo su attività e un limite di durata massima.
- **Revoca per utente** (par. 5): per revocare tutte le sessioni di un utente serve un indice `user_sessions:<username>`.
- **Audience JWT** nell'auth-service: abilitare `spring.security.oauth2.resourceserver.jwt.audiences`.
- **Logout IAM** (RP-initiated logout) non incluso: oggi il logout chiude solo la sessione applicativa.
- I microservizi di dominio (lookup Redis + cache L1 Caffeine, par. 4) non fanno parte di questi due progetti.
