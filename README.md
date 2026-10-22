# Secret Sharing API (`reactive-mongo`)

Reactive [Shamir's Secret Sharing](https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing) service
built with **Spring Boot 4.1.2** / **WebFlux** + **Reactive MongoDB**.

Same k-of-n split/recover contract as `reactive`, with Mongo wiring for share persistence.
Shares are evaluated at \(x = 1..n\) (secret is \(P(0)\), never emitted). SSS algorithm aligned
with the reviewed `pojo` library branch.

## Requirements

- **Java 21+**
- Maven Wrapper (`backend/mvnw`)
- MongoDB (see `backend/compose.yml`) / Docker for Testcontainers IT

## Quick start

```bash
cd backend
docker compose up -d   # Mongo
./mvnw test
./mvnw spring-boot:run
```

- API: `http://localhost:8080/api/v1`
- Health: [http://localhost:8080/actuator/health](http://localhost:8080/actuator/health)
- Swagger UI: [http://localhost:8080/swagger-ui.html](http://localhost:8080/swagger-ui.html)

## API

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/api/v1/splitSecret?k=&n=&secret=` | Split a secret into `n` signed shares |
| `POST` | `/api/v1/recoverSecret` | Reconstruct the secret from signed shares |
| `GET` | `/api/v1/secretShares` | Last persisted share set in MongoDB |
| `GET` | `/actuator/health` | Health probe |

Sanitized errors: `400` / `403` / `429` / `500` (same policy as `reactive`).

## Configuration

| Property | Default | Notes |
|----------|---------|-------|
| `secret-sharing.maxShares` | `60` | Upper bound for `n` |
| `secret-sharing.bitSize` | `2048` | SSS field size |
| `secret-sharing.keyPairBitSize` | `2048` | RSA signing key size |
| `secret-sharing.cors.allowed-origins` | localhost:4200–4202 | CORS allow-list |
| `secret-sharing.rate-limit.recover.*` | 30 / 60s | Recover rate limit |
| `spring.data.mongodb.uri` | local user/password URI | Override with `SPRING_DATA_MONGODB_URI` (Compose sets this) |
| `spring.codec.max-in-memory-size` | `256KB` | Request body cap |

Learning/reference service — not a production crypto package.

## Related branches

| Branch | What it is |
|--------|------------|
| `main` / `reactive` | Annotated `@RestController` WebFlux API |
| `reactive-functional` | Functional `RouterFunction` style |
| `reactive-mongo` | **This branch** — WebFlux + Reactive MongoDB |
| `rest` | Spring MVC (servlet) experiment |
| `pojo` | Plain Java SSS library (algorithm reference) |

## License

See [LICENSE](LICENSE).
