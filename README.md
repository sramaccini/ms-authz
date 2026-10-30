# ms-authz — librerie BFF + autorizzazioni

Dalla versione 2.0 ms-authz è un insieme di **librerie Spring Boot da incorporare** in un'applicazione
(per esempio un monolite modulare), non più tre servizi separati. Il codice precedente è in [legacy/](legacy/),
fuori dal build normale (`mvn install -Plegacy` per compilarlo).

| Modulo | Contenuto | Sostituisce |
|---|---|---|
| `authz-session` | `SessionContext` salvato in una sessione **Spring Session Data Redis** standard; filtro e `SessionContextConfigurer` per Spring Security; interfaccia `AuthorizationResolver` | `session-starter`, payload `session:<id>` scritto a mano |
| `authz-rbac` | Modello RBAC su PostgreSQL, risoluzione in-process al login, API `/api/v1/admin/**`, migrazioni Flyway con history propria (`authz_schema_history`) | `auth-service` |
| `authz-bff` | Login OIDC (servlet), `/bff/login`, `/bff/session`, `/bff/logout`, revoca `/bff/admin/users/{username}/sessions`, controllo `Origin`, rate limiting del login | `bff-gateway` |
| `examples/authz-demo-app` | Un solo deployable che assembla le tre librerie | i tre servizi |

Spring Boot 4.1.2, Java 25. `mvn install` dalla radice compila e testa librerie ed esempio.

## Integrazione in un'applicazione

```java
http.with(BffConfigurer.bff(), Customizer.withDefaults())
    .authorizeHttpRequests(auth -> RbacAdminSecurity.adminApi(auth
            .requestMatchers(BffControllers.PUBLIC_PATHS).permitAll())
        .anyRequest().authenticated());
// nelle API: @PreAuthorize("hasAuthority('patient:read')"), @AuthenticationPrincipal SessionContext session
```

Configurazione completa in `examples/authz-demo-app/src/main/resources/application.yml`.

## Cosa cambia rispetto alla versione a servizi

- **Sessione standard**: Spring Session su Redis (`repository-type: indexed`) al posto del session store scritto a
  mano. Cookie, timeout e namespace sono proprietà standard (`server.servlet.session.*`, `spring.session.*`).
- **Revoca** con l'indice per username di Spring Session (`FindByIndexNameSessionRepository`), al posto di
  `user_sessions:<username>`. Effetto immediato, senza la cache L1 di 5 s.
- **Niente `X-Session-ID` e niente gateway**: BFF e API sono nello stesso processo, nessuna credenziale viaggia
  sulla rete interna. `/enrich` non è più un endpoint HTTP: il BFF chiama l'RBAC in-process.
- **Cookie `SameSite=Lax`** (prima `Strict`): con un solo cookie di sessione, `Strict` lo farebbe perdere al
  ritorno dallo IAM. Le scritture restano protette dal controllo `Origin`.
- **Durata**: timeout di inattività scorrevole (30 min nell'esempio) più una scadenza assoluta
  (`authz.bff.session.absolute-timeout`, 10 h), al posto dei 30 min assoluti.
- **Non ancora portato**: test di integrazione con Testcontainers, export della definizione OpenAPI nel build,
  sessione degli altri servizi che leggevano `session:<id>` da Redis.

---

# Versione precedente (legacy/)

## ms-auth — BFF + Auth-Service

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
5. `GET /bff/session` restituisce il contesto utente alla UI.
6. `POST /bff/logout` (con `Origin` ammessa) cancella la sessione su Redis e risponde
   `200 {"logout_url": "..."}`: la SPA naviga a quell'URL (`window.location`) per chiudere anche la sessione
   SSO sullo IAM (OIDC RP-Initiated Logout con `id_token_hint`), che poi rimanda a `FRONTEND_URL/`.

Errori di login → redirect a `FRONTEND_URL/login-error?error=access_denied|tenant_selection_required|auth_service_unavailable|login_failed`.

## Amministrazione di ruoli e permessi

Definizione OpenAPI **generata dal codice** dall'auth-service (springdoc), solo per `/api/v1/admin/**`:

- `GET http://localhost:8081/v3/api-docs` (JSON) e `/v3/api-docs.yaml` (YAML), utilizzabili anche per generare
  il client della SPA. Il server indicato nella definizione è il BFF (`OPENAPI_SERVER_URL`, default
  `http://localhost:8080`), perché la SPA chiama sempre tramite il BFF con il cookie di sessione.
- Attiva nel profilo `dev`; altrove è disattivata (`OPENAPI_DOCS_ENABLED=true` per abilitarla).
- **Export automatico nel build**: `mvn verify` (o `install`) dell'auth-service avvia il servizio con PostgreSQL e
  Redis in container (`TestAuthServiceApplication`, serve Docker), scarica la definizione e la scrive in
  `auth-service/target/openapi/authz-admin-openapi-spec.json`, poi lo arresta e la copia in
  [docs/authz-admin-openapi-spec.json](docs/authz-admin-openapi-spec.json) (versionata: committarla quando cambia). Saltato con `-DskipTests` o
  `-Dopenapi.export.skip=true`. Lo stesso launcher avvia il servizio senza docker compose:
  `mvn spring-boot:test-run` dalla cartella `auth-service`.
- Swagger UI su http://localhost:8090 (servizio `swagger-ui` di docker compose) legge la definizione dal vivo:
  solo consultazione, il "Try it out" non passa dal BFF.
- La revoca delle sessioni è un endpoint del BFF e non compare nella definizione generata: vedi sotto.

Tutte le chiamate passano dal BFF con il cookie di sessione; l'auth-service le autentica con `X-Session-ID`
tramite lo starter.

| Chi | Permesso | Può |
|---|---|---|
| Amministratore delegato (`TENANT_ADMIN`) | `rbac:manage`, `session:revoke` | censire utenti, assegnare/togliere ruoli e revocare sessioni **solo nel tenant della propria sessione**, leggere l'audit del proprio tenant |
| Amministratore globale (`GLOBAL_ADMIN`) | `rbac:manage-global`, `session:revoke-global` (+ i precedenti) | tutto su tutti i tenant, più definire ruoli, creare tenant, attivare/disattivare utenti |

- Il catalogo dei permessi e i ruoli di sistema si modificano solo con le migrazioni Flyway.
- Nessuno può modificare la propria utenza; i ruoli con permessi `*-global` li gestisce solo il globale.
- Le modifiche valgono **dal login successivo** dell'utente. Per un effetto immediato:
  `DELETE /bff/admin/users/{username}/sessions` (l'utente rientra con l'SSO dello IAM).
- Ogni modifica è registrata in `rbac_audit` (chi, quando, stato prima e dopo).

### Revoca delle sessioni (endpoint del BFF)

`DELETE /bff/admin/users/{username}/sessions` chiude subito le sessioni di un utente (specifica par. 5), ad
esempio dopo averlo disattivato o se l'account è compromesso. L'utente deve rifare il login; i servizi di dominio
smettono di accettare la sessione entro il TTL della loro cache locale (5 s).

- **Autenticazione**: cookie `SESSION_ID` dell'amministratore e header `Origin` ammesso (come ogni richiesta non
  idempotente verso il BFF).
- **Ambito**: con `session:revoke` vengono revocate solo le sessioni dell'utente aperte sul tenant della sessione
  dell'amministratore; con `session:revoke-global` tutte.
- **`username`**: `^[A-Za-z0-9._@-]{1,150}$`.

| Esito | Significato |
|---|---|
| `200` | `{"username": "...", "tenant_id": "TENANT_A" \| null, "revoked_sessions": 2}`; `tenant_id` è `null` per la revoca globale. `revoked_sessions` può essere `0` |
| `400` | `username` non valido |
| `401` | sessione dell'amministratore assente o scaduta |
| `403` | permesso mancante oppure `Origin` non ammessa |

Esempio dalla SPA (stessa origine del BFF: il browser invia cookie e `Origin` da solo):

```js
const res = await fetch(`/bff/admin/users/${encodeURIComponent(username)}/sessions`, { method: 'DELETE' });
const { revoked_sessions } = await res.json();
```

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
- **Audience JWT**: l'auth-service accetta solo token con `aud` = `auth-service` (`AUTH_JWT_AUDIENCE`). Sullo IAM
  serve un audience mapper su ogni client che lo chiama (nel realm demo: `bff-gateway`).
- **Logout IAM**: il post logout redirect URI (`FRONTEND_URL/`) va registrato sul client dello IAM. Il logout
  avviato altrove (altra applicazione, console IAM) non chiude le sessioni del BFF: per questo serve il
  back-channel logout (non incluso).
- **Primo amministratore globale** in produzione: SQL una tantum (commento in fondo a `V2__rbac_administration.sql`).
