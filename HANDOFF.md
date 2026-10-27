# HANDOFF — ms-auth (BFF + Auth-Service)

Note per chi continua il lavoro. Leggi prima `README.md` (flusso, avvio locale, punti aperti).
Fonte dei requisiti: `docs/specifiche_architetturali_bff_auth_service.md`.
L'utente è Simone. Lavora in italiano, tono tecnico.

## Stato

- Tre progetti Maven autonomi, compilati insieme dall'aggregatore `pom.xml` nella radice
  (`mvn install` dalla radice, nell'ordine giusto):
  - `session-starter/`: starter per i servizi di dominio (X-Session-ID -> Redis + cache L1 Caffeine 5 s);
  - `auth-service/` (porta 8081): RBAC, `/api/v1/auth/enrich` (JWT) e API di amministrazione `/api/v1/admin/**`;
  - `bff-gateway/` (porta 8080): login OIDC, sessioni, gateway, rate limiting, revoca sessioni.
  Più `docker-compose.yml` (Postgres 17, Redis 7.4, Keycloak 26 su 8180).
- 2026-10-27: 65 test verdi (`mvn install` dalla radice): starter 10, auth-service 27, BFF 28, compresi i test
  di integrazione su Postgres e Redis reali con Testcontainers (serve Docker).
- 2026-10-27: amministrazione RBAC verificata end-to-end tramite il BFF con login OIDC reale (script curl):
  ambito per tenant, escalation bloccata, ruoli solo al globale, audit filtrato per tenant, effetto al login
  successivo, revoca sessioni per tenant e globale. Contratto per la SPA: `docs/authz-admin-openapi-spec.json`
  (generato dal build) più l'endpoint di revoca del BFF descritto nel README.
- 2026-10-27: **verificato end-to-end in locale** (docker compose + realm importato da `keycloak/import/`,
  valori di test in `.env`). Tutte le parti "a rischio" della prima stesura (starter Boot 4, Spring Cloud
  2025.1.2, prefisso rotte `server.webflux`, `JsonMapper` Jackson 3, DSL Security 7, authorized client
  repository) funzionano a runtime. Esiti:
  - login `mario.rossi` → chiave `session:<uuid>` su Redis, payload snake_case conforme al par. 3.4, TTL 30 min;
  - cookie `SESSION_ID` con `Secure; HttpOnly; SameSite=Strict`, non leggibile da JS;
  - `anna.bianchi` senza tenant → `login-error?error=tenant_selection_required`; con `?tenant=TENANT_B` → OK;
  - rotta gateway: `X-Session-ID` falsificato sostituito, cookie non propagato, POST con Origin estranea → 403;
  - sessione assente/inesistente → 401; `/enrich` senza token → 401;
  - logout → chiave Redis eliminata, cookie scaduto, `/bff/session` → 401; nuovo login revoca la sessione
    precedente (anti session-fixation).
- La specifica è in `docs/`. Repository git su `master`, remote `origin` = github.com/sramaccini/ms-authz,
  `.env` escluso. Commit solo a nome dell'utente (s.ramaccini@gmail.com), senza attribuzione a Claude.

## Ambiente di questa macchina

- JDK 25: `C:\Program Files\Eclipse Adoptium\jdk-25.0.5.8-hotspot` (non è nel PATH: `java` è la 8 e
  Maven usa il 21). `export JAVA_HOME="/c/Program Files/Eclipse Adoptium/jdk-25.0.5.8-hotspot"`.
- `TEMP` è in formato corto 8.3 (`SRAMAC~1`): il JDK non riesce a creare lì il socket AF_UNIX del
  selector NIO e Tomcat/Netty non partono (`Unable to establish loopback connection`). Avviare i servizi con
  `"-Dspring-boot.run.jvmArguments=-Djdk.net.unixdomain.tmpdir=C:\tmp\ud"` (cartella già creata).
  Anche i test (Lettuce/Netty) ne hanno bisogno: `export JAVA_TOOL_OPTIONS='-Djdk.net.unixdomain.tmpdir=C:\tmp\ud'`
  prima di `mvn install`. È un problema di questa macchina: non va messo nei pom.

## Problemi emersi dal test end-to-end

Corretti il 2026-10-27 (test unitari BFF 15/15, verificati anche a runtime salvo il 502):
1. ~~`Authorization` del client inoltrato a valle~~ → `SessionRelayGlobalFilter` rimuove `Authorization`
   insieme a `Cookie`: verso valle l'unica credenziale e' `X-Session-ID` (decisione 2).
2. ~~`POST /bff/logout` senza controllo `Origin`~~ → regola estratta in `security/OriginPolicy`, usata dal
   filtro e da `SessionController`; Origin estranea o assente → 403 senza toccare la sessione (decisione 8).
3. ~~Servizio a valle irraggiungibile → 500~~ → `DownstreamErrorGlobalFilter` (filtro piu' esterno):
   connessione non stabilita → 503, connessione caduta durante lo scambio → 502, body problem+json.
   Aggiunto `httpclient.connect-timeout` (default 2 s, `GATEWAY_CONNECT_TIMEOUT_MS`). Il timeout di
   risposta non e' configurato: se lo si imposta, il gateway risponde 504.

Ancora aperti:
4. Minore: `created_at`/`expires_at` con precisione al nanosecondo; valutare il troncamento ai secondi
   come nell'esempio della specifica, per semplificare il parsing nei servizi di dominio.
5. ~~Logout solo applicativo~~ → risolto il 2026-10-27 con l'RP-initiated logout (decisione 15).

## Decisioni prese (non cambiarle senza parlarne con l'utente)

1. **Si segue la specifica, non gli snippet incollati dall'utente nella prima richiesta.** È il BFF a creare
   la sessione su Redis. L'auth-service espone `POST /api/v1/auth/enrich` e, dal 2026-10-27, l'API di
   amministrazione: per autenticarla **legge** Redis (sola lettura, tramite lo starter); non scrive mai sessioni.
2. Nomi dalla specifica: cookie `SESSION_ID` (`HttpOnly; Secure; SameSite=Strict`), chiave Redis
   `session:<uuid>`, header verso valle solo `X-Session-ID`. Payload Redis in snake_case con date ISO-8601
   come stringhe (par. 3.4): è un contratto condiviso con i microservizi di dominio.
3. Il BFF chiama `/enrich` inoltrando **l'access token dell'utente**. L'auth-service accetta la richiesta
   solo se lo username coincide con il claim `preferred_username`, oppure se il chiamante ha l'authority
   `SCOPE_auth:enrich` (client di servizio).
4. Estensione alla specifica: `tenant_id` opzionale in input. Più tenant senza scelta → `409` con
   `available_tenants`. La SPA passa il tenant con `GET /bff/login?tenant=XYZ`.
5. Utente inesistente, disattivato o senza ruoli → sempre `403` (niente user enumeration).
6. Accesso al DB con JdbcClient (niente JPA). Schema con Flyway `V1`; dati demo in `db/seed`, caricati solo con il profilo `dev`.
   Nel `V1` sono stati tolti l'estensione `uuid-ossp` e i due indici ridondanti della specifica (motivo nei commenti SQL).
7. Spring Security nel BFF gestisce solo il flusso OIDC. Nessun SecurityContext persistito; WebSession,
   access token e refresh token dello IAM vengono eliminati dopo il login (l'ID token si conserva: decisione 15). Le rotte del gateway sono protette da `SessionRelayGlobalFilter`
   (GlobalFilter, quindi vale per ogni rotta); gli endpoint `/bff/**` controllano il cookie da soli.
8. CSRF di Spring disabilitato. Al suo posto: SameSite=Strict + controllo `Origin` sui metodi non idempotenti
   (`bff.frontend.allowed-origins`).
9. TTL della sessione assoluto (30 min), senza rinnovo su attività.
10. **BFF multi-istanza** (richiesto dall'utente per resilienza e scalabilità): Spring Session su Redis
    (`spring-boot-starter-session-data-redis`) per la sola WebSession del login OIDC. Namespace `bff:login`,
    repository `default` (TTL Redis, niente keyspace events), timeout 10 min (`BFF_LOGIN_SESSION_TIMEOUT`),
    cookie `BFF_LOGIN` `HttpOnly; Secure; SameSite=Lax` (Lax obbligato: il callback dello IAM è cross-site).
    I token dello IAM restano nel repository in memoria della singola richiesta di callback e non vanno su Redis.
    Verificato a runtime: login avviato sull'istanza A, A terminata, callback gestito da una nuova istanza B
    con tenant e PKCE recuperati da Redis. Il traffico normale non crea WebSession.
    Da sapere: serializzazione JDK degli attributi (default di Spring Session): un aggiornamento di versione di
    Spring Security durante un rolling deploy può far fallire i login in corso (l'utente ripete il login).
11. **Amministrazione RBAC da frontend** (decisioni dell'utente del 2026-10-27):
    - amministratori **delegati per tenant** (`TENANT_ADMIN`, `rbac:manage`) oltre al globale
      (`GLOBAL_ADMIN`, `rbac:manage-global`). Il delegato gestisce utenti e assegnazioni del solo tenant della
      propria sessione; ruoli, tenant e stato degli utenti valgono per tutti i tenant e restano al globale;
    - il **catalogo dei permessi lo gestiscono solo gli sviluppatori** (migrazioni Flyway); i ruoli di sistema
      (`is_system`) non sono modificabili da interfaccia;
    - le modifiche hanno effetto **al login successivo**; per escludere subito qualcuno si revocano le sessioni.
    Regole di sicurezza: permessi `*-global` solo in `GLOBAL_ADMIN`; il delegato non assegna né toglie ruoli che
    li contengono; nessuno modifica la propria utenza (insieme garantiscono che resti sempre un globale);
    lock sulla riga del tenant per le assegnazioni, `version` sui ruoli; audit in `rbac_audit` nella stessa
    transazione. Primo amministratore globale in produzione: SQL una tantum, vedi commento in fondo a `V2`.
    In sviluppo `spring.flyway.out-of-order` e' attivo perche' i seed hanno versioni alte (V99+).
12. **Revoca sessioni** (par. 5): indice `user_sessions:<username>` scritto dal BFF prima della sessione;
    `DELETE /bff/admin/users/{username}/sessions` con `session:revoke` (solo sessioni sul proprio tenant) o
    `session:revoke-global`. Solo comandi su una chiave: compatibile con Redis Cluster.
13. **Rate limiting del login**: 20 richieste/minuto per IP su `/bff/login`, `/oauth2/authorization/**`,
    `/login/oauth2/code/**`, contatore su Redis condiviso tra le istanze, fail-open se Redis non risponde.
    Dietro un load balancer configurare `server.forward-headers-strategy` solo con proxy fidato.
14. **Starter per i servizi di dominio** (par. 4): `http.with(SessionContextConfigurer.sessionContext(), ...)`;
    authority = permessi (`patient:read`) e ruoli (`ROLE_DOCTOR`); 401 senza sessione, 403 senza permesso,
    503 se Redis non risponde. 401/403 scritti direttamente: con `sendError` l'error dispatch verso `/error`
    finiva in un'altra catena e il 403 diventava 401 (bug trovato nel test end-to-end, coperto da un test HTTP).
15. **Logout sullo IAM e audience** (2026-10-27):
    - `POST /bff/logout` risponde `200 {"logout_url"}` (prima `204`): la SPA naviga all'end_session_endpoint
      dello IAM con `id_token_hint`, `client_id` e `post_logout_redirect_uri` (`bff.frontend.post-logout-url`).
    - Per l'`id_token_hint` il BFF **conserva l'ID token** in `bff:id_token:<SESSION_ID>` (stesso TTL della
      sessione, letto con GETDEL al logout, cancellato anche da revoca e anti-fixation). Non fa parte del
      contratto `session:*`. Senza ID token lo IAM chiede conferma all'utente.
    - L'auth-service accetta solo `aud` = `auth-service` (audience mapper sul client `bff-gateway`): un ID token
      (aud = `bff-gateway`) usato come Bearer viene rifiutato. Test con token firmati e JWKS locale.
    Verificato a runtime su Keycloak: logout senza pagina di conferma, `/bff/login` successivo chiede la password,
    anche con ID token scaduto (5 min) usato come hint, che e' il caso normale con sessioni da 30 min. Con un altro
    IAM verificare che accetti hint scaduti; altrimenti lo IAM chiedera' conferma all'utente.
16. **Definizione OpenAPI generata dal codice** (richiesta dell'utente, 2026-10-27): springdoc 3.0.3 (linea per
    Boot 4.0; la 3.1+ richiede Boot 4.1) nell'auth-service, `GET /v3/api-docs` e `/v3/api-docs.yaml`, solo
    `/api/v1/admin/**`. Attiva nel profilo dev, disattivata per default (non si pubblica la mappa delle API in
    produzione). Server = BFF, sicurezza = cookie `SESSION_ID`, descrizione con regole e codici di errore in
    `OpenApiConfig`. CORS in sola lettura per la Swagger UI locale (8090), che ora legge la definizione dal vivo.
    Il vecchio `docs/openapi-admin.yaml` scritto a mano e' stato eliminato su indicazione dell'utente: la fonte
    unica e' il codice. L'endpoint di revoca del BFF e' descritto nel README; le risposte di errore non sono
    dichiarate per singola operazione, solo elencate nella descrizione generale (`OpenApiConfig`).
    Export nel build (richiesta dell'utente): spring-boot:start (pre-integration-test) avvia
    `TestAuthServiceApplication` (test classpath, Testcontainers) su porta 18081 / JMX 19001,
    springdoc-openapi-maven-plugin 1.5 scrive `target/openapi/authz-admin-openapi-spec.json` (formattato),
    spring-boot:stop (post-integration-test), maven-resources-plugin copia il file in `docs/authz-admin-openapi-spec.json`
    (versionato). Skip legato a `skipTests` (`openapi.export.skip`).
    Nota Boot 4: il goal `start` non ha piu' `directories`, si usa `additionalClasspathElements`.

## Prossimi passi suggeriti (in ordine)

Fatti il 2026-10-27: test di integrazione Testcontainers, rate limiting del login, revoca sessioni per utente,
starter per i servizi di dominio, API di amministrazione RBAC con audit e contratto OpenAPI.

1. Back-channel logout (OIDC): se l'utente esce dallo IAM da un'altra applicazione, oggi le sessioni del BFF
   restano valide fino al TTL. Endpoint che riceve il logout_token e revoca le sessioni (indice per `sid`).
2. Rete: `auth-service` e i servizi di dominio raggiungibili solo dal BFF (`X-Session-ID` è una credenziale):
   mTLS o network policy.
3. Dockerfile, pipeline CI (con Docker per i test Testcontainers), observability.
4. Valutare il rinnovo del TTL su attività, con una durata massima assoluta.
5. Retention e protezione del registro di audit (GDPR): durata di conservazione, accesso in sola lettura.
6. Opzionali: versione reattiva dello starter (servizi WebFlux); test di contratto tra `SessionData` del BFF e
   `SessionContext` dello starter (oggi il formato JSON è definito in due punti); date troncate ai secondi.
