# Secret Sharing API (`reactive`)

Reactive [Shamir's Secret Sharing](https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing) service
built with **Spring Boot 4.1.2** / **WebFlux** (`@RestController`).

Split a UTF-8 secret into `n` RSA-signed shares such that any `k` of them recover the secret.
Shares are evaluated at \(x = 1..n\) (the secret is \(P(0)\) and is never emitted as a share).

SSS algorithm aligned with the reviewed `pojo` library branch.

## Requirements

- **Java 21+**
- Maven Wrapper (`backend/mvnw`)
- Docker / Compose (optional)

## Quick start

```bash
cd backend
./mvnw test
./mvnw spring-boot:run
```

- API: `http://localhost:8080/api/v1`
- Health: [http://localhost:8080/actuator/health](http://localhost:8080/actuator/health)
- OpenAPI: [http://localhost:8080/v3/api-docs](http://localhost:8080/v3/api-docs)
- Swagger UI: [http://localhost:8080/swagger-ui.html](http://localhost:8080/swagger-ui.html)

## API

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/api/v1/splitSecret?k=&n=&secret=` | Split a secret into `n` signed shares |
| `POST` | `/api/v1/recoverSecret` | Reconstruct the secret from signed shares |
| `GET` | `/api/v1/secretShares` | Last in-memory share set from this process |
| `GET` | `/actuator/health` | Health probe |

### Split

```bash
curl -sG 'http://localhost:8080/api/v1/splitSecret' \
  --data-urlencode 'k=2' \
  --data-urlencode 'n=3' \
  --data-urlencode 'secret=for-your-eyes-only'
```

### Recover

```bash
curl -s -X POST 'http://localhost:8080/api/v1/recoverSecret' \
  -H 'Content-Type: application/json' \
  -d '[{"index":1,"share":"...","signature":"..."},{"index":2,"share":"...","signature":"..."}]'
```

### Errors (sanitized)

| Status | When |
|--------|------|
| `400` | Invalid / missing params, blank secret, empty shares |
| `403` | Share signature verification failed |
| `429` | Too many `/recoverSecret` calls |
| `500` | Unexpected server failure |

## Docker / Compose

```bash
cd backend
docker compose build
docker compose up -d
docker compose logs -f
```

## Configuration

| Property | Default | Notes |
|----------|---------|-------|
| `secret-sharing.maxShares` | `60` | Upper bound for `n` |
| `secret-sharing.bitSize` | `2048` | SSS field size |
| `secret-sharing.keyPairBitSize` | `2048` | RSA signing key size |
| `secret-sharing.cors.allowed-origins` | localhost:4200–4202 | Comma-separated origins |
| `secret-sharing.rate-limit.recover.capacity` | `30` | Recover calls per window |
| `spring.codec.max-in-memory-size` | `256KB` | Request body cap |

Learning/reference service — not a production crypto package.

## Related branches

| Branch | What it is |
|--------|------------|
| `main` / `reactive` | **This line** — annotated `@RestController` WebFlux API |
| `reactive-functional` | Functional `RouterFunction` style |
| `reactive-mongo` | WebFlux + Reactive MongoDB |
| `rest` | Spring MVC (servlet) experiment |
| `pojo` | Plain Java SSS library (algorithm reference) |

## License

See [LICENSE](LICENSE).
