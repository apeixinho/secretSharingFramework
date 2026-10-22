# Secret Sharing API (`rest`)

Servlet [Shamir's Secret Sharing](https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing) service
built with **Spring Boot 4.1.2** / **Spring MVC**.

Split a UTF-8 secret into `n` RSA-signed shares such that any `k` of them recover the secret.
Shares are evaluated at \(x = 1..n\) (the secret is \(P(0)\) and is never emitted as a share).

SSS algorithm aligned with the reviewed `pojo` library branch. No Lombok.

## Requirements

- **Java 21+**
- Maven Wrapper (`backend/mvnw`)
- Docker (optional; see `backend/Dockerfile`)

## Quick start

```bash
cd backend
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
| `GET` | `/actuator/health` | Health probe |

Sanitized errors: `400` / `403` / `500`.

## Configuration

| Property | Default | Notes |
|----------|---------|-------|
| `secret-sharing.maxShares` | `60` | Upper bound for `n` |
| `secret-sharing.bitSize` | `2048` | SSS field size |
| `secret-sharing.keyPairBitSize` | `2048` | RSA signing key size |

Learning/reference service — not a production crypto package.

## Related branches

| Branch | What it is |
|--------|------------|
| `main` / `reactive` | WebFlux `@RestController` API |
| `reactive-functional` | Functional `RouterFunction` style |
| `reactive-mongo` | WebFlux + Reactive MongoDB |
| `rest` | **This branch** — Spring MVC (servlet) |
| `pojo` | Plain Java SSS library (algorithm reference) |

## License

See [LICENSE](LICENSE).
