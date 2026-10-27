# HANDOFF — ms-auth (BFF + Auth-Service)

Note per chi continua il lavoro. Leggi prima `README.md` (flusso, avvio locale, punti aperti).
Fonte dei requisiti: `docs/specifiche_architetturali_bff_auth_service.md`.
L'utente è Simone. Lavora in italiano, tono tecnico.

## Stato

- Creati due progetti Maven indipendenti: `auth-service/` (porta 8081) e `bff-gateway/` (porta 8080),
  più `docker-compose.yml` (Postgres 17, Redis 7.4, Keycloak 26 su 8180).
- 2026-10-27: `mvn clean verify` con JDK 25 OK su entrambi i progetti (test unitari 6/6 e 5/5).
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
- La specifica è in `docs/`. Repository git locale su `master` (nessun remote), `.env` escluso.

## Ambiente di questa macchina

- JDK 25: `C:\Program Files\Eclipse Adoptium\jdk-25.0.5.8-hotspot` (non è nel PATH: `java` è la 8 e
  Maven usa il 21). `export JAVA_HOME="/c/Program Files/Eclipse Adoptium/jdk-25.0.5.8-hotspot"`.
- `TEMP` è in formato corto 8.3 (`SRAMAC~1`): il JDK non riesce a creare lì il socket AF_UNIX del
  selector NIO e Tomcat/Netty non partono (`Unable to establish loopback connection`). Avviare i servizi con
  `"-Dspring-boot.run.jvmArguments=-Djdk.net.unixdomain.tmpdir=C:\tmp\ud"` (cartella già creata).

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
5. Conferma del limite noto "logout IAM": dopo `/bff/logout` un nuovo `/bff/login` rientra senza password
   grazie alla sessione SSO di Keycloak.

## Decisioni prese (non cambiarle senza parlarne con l'utente)

1. **Si segue la specifica, non gli snippet incollati dall'utente nella prima richiesta.** È il BFF a creare
   la sessione su Redis; l'auth-service espone solo `POST /api/v1/auth/enrich` e non usa Redis.
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
7. Spring Security nel BFF gestisce solo il flusso OIDC. Nessun SecurityContext persistito; WebSession e
   token IAM vengono eliminati dopo il login. Le rotte del gateway sono protette da `SessionRelayGlobalFilter`
   (GlobalFilter, quindi vale per ogni rotta); gli endpoint `/bff/**` controllano il cookie da soli.
8. CSRF di Spring disabilitato. Al suo posto: SameSite=Strict + controllo `Origin` sui metodi non idempotenti
   (`bff.frontend.allowed-origins`).
9. TTL della sessione assoluto (30 min), senza rinnovo su attività.

## Prossimi passi suggeriti (in ordine)

1. Test di integrazione con Testcontainers (Postgres per l'auth-service, Redis per il BFF).
2. Stato OAuth2 multi-istanza: Spring Session su Redis oppure sticky session sul solo path di login.
3. Revoca di tutte le sessioni di un utente: indice `user_sessions:<username>` + endpoint admin (par. 5).
4. Logout anche sullo IAM (RP-initiated logout) e validazione dell'audience JWT nell'auth-service.
5. Valutare il rinnovo del TTL su attività, con una durata massima assoluta.
6. Libreria o starter condiviso per i microservizi di dominio: lookup su Redis + cache L1 Caffeine 5-10 s (par. 4).
7. Dockerfile, pipeline CI, configurazione di observability.
