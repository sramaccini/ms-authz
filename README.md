# ms-auth — BFF + Auth-Service

Implementazione della *Specifica Architetturale: Pattern BFF con Session Store e Microservizio di Autorizzazione*.

| Progetto | Stack | Porta | Responsabilità |
|---|---|---|---|
| `auth-service` | Java 25, Spring Boot 4.0 (MVC + Virtual Threads), JdbcClient, Flyway, PostgreSQL | 8081 | Modello RBAC, `POST /api/v1/auth/enrich` protetto da JWT, API di amministrazione `/api/v1/admin/**` |
| `bff-gateway` | Java 25, Spring Boot 4.0, Spring Cloud Gateway (WebFlux) 2025.1, Redis reactive, Spring Session | 8080 | Login OIDC, sessione su Redis, cookie `SESSION_ID`, relay `X-Session-ID`, rate limiting, revoca sessioni |
| `session-starter` | Libreria Spring Boot (MVC + Security), Redis, Caffeine | — | Per i servizi di dominio: `X-Session-ID` → sessione Redis con cache L1 (par. 4) |

Il `pom.xml` nella radice è solo un aggregatore: `mvn install` dalla radice compila e testa tutto nell'ordine giusto.

## Flusso

1. La SPA naviga su `GET /bff/login[?tenant=XYZ]` → redirect allo IAM.
2. Callback `/login/oauth2/code/iam` → il BFF chiama `auth-service /enrich` **con l'access token dell'utente**.
3. Il BFF genera il `SESSION_ID` (UUID v4), salva `session:<id>` su Redis con TTL e imposta il cookie
   `HttpOnly; Secure; SameSite=Strict`; i token dello IAM vengono scartati.
4. Ogni chiamata `/api/**` instradata dal gateway: header interni ripuliti, verifica Origin sulle richieste
   non idempotenti, verifica sessione su Redis, inoltro con `X-Session-ID`.
5. `GET /bff/session` restituisce il contesto utente alla UI; `POST /bff/logout` cancella la chiave Redis.

Errori di login → redirect a `FRONTEND_URL/login-error?error=access_denied|tenant_selection_required|auth_service_unavailable|login_failed`.

## Amministrazione di ruoli e permessi

Contratto per la SPA: [docs/openapi-admin.yaml](docs/openapi-admin.yaml). Tutte le chiamate passano dal BFF
con il cookie di sessione; l'auth-service le autentica con `X-Session-ID` tramite lo starter.

| Chi | Permesso | Può |
|---|---|---|
| Amministratore delegato (`TENANT_ADMIN`) | `rbac:manage`, `session:revoke` | censire utenti, assegnare/togliere ruoli e revocare sessioni **solo nel tenant della propria sessione**, leggere l'audit del proprio tenant |
| Amministratore globale (`GLOBAL_ADMIN`) | `rbac:manage-global`, `session:revoke-global` (+ i precedenti) | tutto su tutti i tenant, più definire ruoli, creare tenant, attivare/disattivare utenti |

- Il catalogo dei permessi e i ruoli di sistema si modificano solo con le migrazioni Flyway.
- Nessuno può modificare la propria utenza; i ruoli con permessi `*-global` li gestisce solo il globale.
- Le modifiche valgono **dal login successivo** dell'utente. Per un effetto immediato:
  `DELETE /bff/admin/users/{username}/sessions` (l'utente rientra con l'SSO dello IAM).
- Ogni modifica è registrata in `rbac_audit` (chi, quando, stato prima e dopo).

## Servizi di dominio: uso dello starter

```xml
<dependency>
    <groupId>com.enterprise.session</groupId>
    <artifactId>session-context-spring-boot-starter</artifactId>
    <version>1.0.0-SNAPSHOT</version>
</dependency>
```

```java
http.with(SessionContextConfigurer.sessionContext(), Customizer.withDefaults())
    .authorizeHttpRequests(auth -> auth.anyRequest().authenticated());
// poi: @PreAuthorize("hasAuthority('patient:read')"), @AuthenticationPrincipal SessionContext session
```

Proprietà: `session-context.cache.ttl` (default 5 s: è anche il ritardo massimo di una revoca),
`session-context.cache.max-size`, `session-context.header-name`, `session-context.redis-key-prefix`.

## Avvio locale

Il realm Keycloak `enterprise` viene importato all'avvio da `keycloak/import/enterprise-realm.json`:
client confidenziale `bff-gateway` (PKCE S256) e utenti demo allineati ai dati demo dell'auth-service:
`mario.rossi` (TENANT_A), `anna.bianchi` (TENANT_A e TENANT_B), `admin.tenant.a` (amministratore delegato di
TENANT_A), `admin.globale` (amministratore globale). Secret del client e password degli utenti arrivano da
`.env` (gitignored).

```bash
cp .env.example .env   # poi sostituire i segnaposto
docker compose up -d
mvn install            # dalla radice: build e test (i test di integrazione richiedono Docker)

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
(cartella esistente, percorso senza `~`); per i test `JAVA_TOOL_OPTIONS=-Djdk.net.unixdomain.tmpdir=C:\tmp\ud`.

Variabili principali: `IAM_ISSUER_URI`, `IAM_CLIENT_ID`, `IAM_CLIENT_SECRET`, `AUTH_DB_URL`, `AUTH_DB_USER`,
`AUTH_DB_PASSWORD`, `REDIS_HOST`, `REDIS_PORT`, `REDIS_PASSWORD`, `AUTH_SERVICE_URL`, `FRONTEND_URL`,
`BFF_COOKIE_DOMAIN`, `CLINICAL_SERVICE_URI`, `BFF_LOGIN_RATE_LIMIT_MAX`, `BFF_LOGIN_RATE_LIMIT_WINDOW`,
`BFF_LOGIN_SESSION_TIMEOUT`, `GATEWAY_CONNECT_TIMEOUT_MS`.

## Scelte da validare prima della produzione

- **BFF multi-istanza**: lo stato del login OIDC (`state`/`nonce`/PKCE e tenant scelto) è in una WebSession
  su Redis (Spring Session, chiavi `bff:login:sessions:*`, cookie `BFF_LOGIN` `SameSite=Lax`, TTL 10 min,
  invalidata a fine login): nessuna sticky session richiesta. Gli ingressi del login hanno un limite per IP
  (20/min, contatore su Redis); in produzione serve comunque una policy `maxmemory` su Redis e, dietro un load
  balancer, `server.forward-headers-strategy` solo con proxy fidato (altrimenti il limite vale per il proxy).
- **`X-Session-ID` verso valle**: è una credenziale equivalente al cookie. Rete interna con mTLS, mai loggarlo,
  e i servizi a valle (auth-service compreso, per `/api/v1/admin/**`) non devono essere raggiungibili dall'esterno.
- **TTL assoluto** (30 min, no sliding): valutare il rinnovo su attività e un limite di durata massima.
- **Audit RBAC**: definire conservazione e accesso al registro `rbac_audit` (GDPR).
- **Audience JWT** nell'auth-service: abilitare `spring.security.oauth2.resourceserver.jwt.audiences`.
- **Logout IAM** (RP-initiated logout) non incluso: oggi il logout chiude solo la sessione applicativa.
- **Primo amministratore globale** in produzione: SQL una tantum (commento in fondo a `V2__rbac_administration.sql`).
