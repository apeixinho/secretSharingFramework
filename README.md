# Secret Sharing API (`reactive-mongo`)

Reactive [Shamir's Secret Sharing](https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing) service
built with **Spring Boot 4** / **WebFlux** + **Reactive MongoDB**.

Same k-of-n split/recover contract as `reactive`, with Mongo wiring for share persistence experiments.

## Requirements

- **Java 21+**
- Maven Wrapper (`backend/mvnw`)
- MongoDB (see `backend/compose.yml`)

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
| `secret-sharing.cors.allowed-origins` | localhost:4200–4202 | CORS allow-list |
| `secret-sharing.rate-limit.recover.*` | 30 / 60s | Recover rate limit |
| `spring.data.mongodb.uri` | local user/password URI | Override with `SPRING_DATA_MONGODB_URI` (Compose sets this) |
| `spring.codec.max-in-memory-size` | `256KB` | Request body cap |

## License

See [LICENSE](LICENSE).
