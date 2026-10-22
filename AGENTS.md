# AGENTS.md — secretSharingFramework

Guidance for AI coding agents (and humans) working in this repo.

## What this is

Shamir-style secret splitting over HTTP: split a secret into `n` shares
(`k` needed to recover), with RSA/SHA-256 signing of shares.
Originally a Sequoia/ PasswordSafe-style demo; backend is being kept as a
portfolio-showcase project alongside `traffic-monitor-api` and
`catalog-eshop-demo`.

## IMPORTANT — what is real in this repo

- **`backend/` is canonical.** Spring Boot 4.1.2, Java 21, WebFlux
  (functional/reactive routing), springdoc-openapi 3.x (no Lombok).
- The three frontend directories are **dist-only husks, untracked**: they
  contain only `dist/` build output and editor configs — there are no
  `package.json` files. Do **not** `npm install` there, do not "fix" missing
  manifests. The actual Angular sources of the frontend live in a separate
  repo, `secretSharingFramework-Frontend` (sibling in the repos folder).
- `target/` and `dist/` are gitignored build outputs anywhere they appear.

## Commands

Local toolchain (verified 2026-10-22): JDK 25.0.4.1 at
`C:\Program Files\Eclipse Adoptium\jdk-25.0.4.101-hotspot`. Agent shells
often don't inherit `JAVA_HOME`/`PATH`, so set them per command when needed.
Prefer the committed Maven wrapper:

```powershell
$env:JAVA_HOME='C:\Program Files\Eclipse Adoptium\jdk-25.0.4.101-hotspot'
$env:Path="$env:JAVA_HOME\bin;$env:Path"
cd backend; ./mvnw test
```

```bash
cd backend
./mvnw test            # unit + WebFlux tests
./mvnw clean verify    # full build + tests
./mvnw spring-boot:run # run locally (port from application.yml)
```

## Code map (backend)

```
backend/src/main/java/org/secretsharing/
├── SecretSharingApplication.java     @SpringBootApplication entry point
├── config/
│   ├── RouterConfiguration.java      functional routes + sanitized errors
│   ├── CorsConfigurationBeans.java   configurable CORS
│   ├── RecoverRateLimitWebFilter.java
│   ├── CryptographyConfiguration.java
│   └── SerializerConfiguration.java
├── model/SecretShareDTO.java
├── service/
│   ├── SecretSharing.java            interface (splitSecret / recoverSecret)
│   └── SecretSharingImpl.java        crypto implementation
└── utils/NotBlankAnnotation.java, NotBlankValidator.java   custom bean validation
backend/src/test/java/org/secretsharing/    Application, Controller, Impl tests
```

## API surface

| Method | Path | I/O |
|---|---|---|
| GET | `/api/v1/splitSecret?k=&n=&secret=` | → JSON: shares (each: index/value/signature) |
| POST | `/api/v1/recoverSecret` | Body: JSON array of shares → `text/plain`: recovered secret |
| GET | `/actuator/health` | → `{ "status": "UP" }` |

OpenAPI: `/v3/api-docs`, Swagger UI: `/swagger-ui.html`. Algorithm parameters live in
`backend/src/main/resources/application.yml` under `secret-sharing.*`.

## Conventions

- **Functional routing**, not `@RestController`: endpoints are declared in
  `RouterConfiguration` (`RouterFunctions.route()`), handlers return
  `Mono<ServerResponse>` / `Flux`. Follow this style for new endpoints.
- Logging uses `java.util.logging.Logger` (no Lombok). Do **not** log secrets,
  shares, or raw exception messages that may contain them.
- Validation is the custom `@NotBlank` annotation in `utils/` plus explicit
  `1 <= k <= n <= maxShares` checks in the router.
- Error handling is centralized in `RouterConfiguration.handleException` and
  returns **sanitized** client messages (`400` / `403` / `500`).

## Gotchas

- Share index `0` evaluates the polynomial at `x=0`, so that share equals the
  secret constant term. Prefer non-zero indexes in threshold/negative tests.
- Putting the secret in a **GET query string** is demo-friendly and unsafe for
  real deployments (proxy/access logs).
- `@CrossOrigin` is not used; CORS comes from `secret-sharing.cors.allowed-origins`.

## Improvement backlog

1. ~~**README.md**~~ — done.
2. ~~**CI**~~ — done (`./mvnw verify`, JDK 21/25).
3. ~~**Error handling**~~ — done (sanitized 400/403/500).
4. ~~**Security hardening**~~ — done (CORS allow-list, recover rate-limit,
   codec size cap, no secret-bearing error logs).
5. **Frontend decision**: either (a) promote the Angular app from
   `secretSharingFramework-Frontend` into this monorepo with real sources +
   build, or (b) delete the three dist-only frontend dirs here. Keep one
   source of truth.
6. ~~**Crypto tests**~~ — done (random k-subsets, insufficient shares,
   maxShares rejection, known-index round-trip).
7. ~~**Actuator**~~ — done (`/actuator/health` exposed + tested).
8. ~~**Docs polish**~~ — done (README links + `@RouterOperation` response tables).
