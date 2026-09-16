# Secret Sharing API

Reactive [Shamir's Secret Sharing](https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing) service built with **Spring WebFlux**.

This repository’s **main** line is the reactive API under `backend/` (historically developed on the `reactive` branch). Experimental variants are documented in [BRANCHES.md](BRANCHES.md).

## Requirements

- **Java 21**
- Docker / Docker Compose (optional, for containers)
- Maven Wrapper is included (`backend/mvnw`)

## Quick start (local)

```bash
cd backend
./mvnw test
./mvnw spring-boot:run
```

- API base path: `http://localhost:8080/api/v1`
- Swagger UI: [http://localhost:8080/swagger-ui.html](http://localhost:8080/swagger-ui.html)
- OpenAPI JSON: [http://localhost:8080/v3/api-docs](http://localhost:8080/v3/api-docs)
- Health: [http://localhost:8080/actuator/health](http://localhost:8080/actuator/health)

## API

| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/api/v1/splitSecret` | Split a secret into `n` signed shares (threshold `k`) |
| `POST` | `/api/v1/recoverSecret` | Reconstruct the secret from at least `k` valid shares |

### Split

```bash
curl -s -X POST http://localhost:8080/api/v1/splitSecret \
  -H 'Content-Type: application/json' \
  -d '{"k":3,"n":5,"secret":"for-your-eyes-only"}'
```

Shares use indexes **1..n** (never `0`, which would be the secret polynomial value).

### Recover

```bash
curl -s -X POST http://localhost:8080/api/v1/recoverSecret \
  -H 'Content-Type: application/json' \
  -d '[{"index":1,"share":"...","signature":"..."},{"index":2,"share":"...","signature":"..."},{"index":3,"share":"...","signature":"..."}]'
```

## Docker / Compose

Run commands from **`backend/`** (where `Dockerfile` and `compose.yml` live):

```bash
cd backend
docker compose build
docker compose up -d
docker compose logs -f
```

Or:

```bash
cd backend
docker build -t secret-sharing-api:latest .
docker run --rm -p 8080:8080 -e SECRET_SHARING_CORS_ALLOWED_ORIGINS='*' secret-sharing-api:latest
```

The image is a multi-stage **Java 21** build that runs the packaged JAR (not `mvn spring-boot:run`).

## Configuration

| Property | Default | Notes |
|----------|---------|--------|
| `secret-sharing.maxShares` | `60` | Upper bound for `n` |
| `secret-sharing.bitSize` | `2048` | Field size for the modular polynomial |
| `secret-sharing.keyPairBitSize` | `2048` | RSA key used to sign shares |
| `secret-sharing.hashAlgorithm` | `SHA256withRSA` | Signature algorithm |
| `secret-sharing.cors.allowed-origins` | `[]` | Empty = no browser CORS; set `*` only for demos |

Compose sets `SECRET_SHARING_CORS_ALLOWED_ORIGINS=*` for local demos.

Actuator exposes **health** and **info** only; details stay closed.

## Threat model (short)

- Split/recover is **in-process**: shares are not persisted by this service.
- Each share is **RSA-signed** with a key pair generated at startup. Signatures prove issuance by **this process instance**; restart rotates keys and old signatures will fail verification.
- This is **not** a multi-party authenticity or key-distribution protocol. Treat it as a demo / educational API unless you replace key management and add authn/authz.

## License

See [LICENSE](LICENSE).
