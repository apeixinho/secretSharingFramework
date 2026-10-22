# Secret Sharing API

Reactive [Shamir's Secret Sharing](https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing) service
built with **Spring Boot 4** / **WebFlux** (functional routing).

Split a UTF-8 secret into `n` RSA-signed shares such that any `k` of them recover the secret.
Fewer than `k` shares (excluding the degenerate `x=0` share) must not reconstruct it.

## Requirements

- **Java 21+** (local toolchain may be newer; the project targets 21)
- Maven Wrapper is included (`backend/mvnw`)

## Quick start

```bash
cd backend
./mvnw test
./mvnw spring-boot:run
```

- API base: `http://localhost:8080/api/v1`
- Health: [http://localhost:8080/actuator/health](http://localhost:8080/actuator/health)
- OpenAPI JSON: [http://localhost:8080/v3/api-docs](http://localhost:8080/v3/api-docs)
- Swagger UI: [http://localhost:8080/swagger-ui.html](http://localhost:8080/swagger-ui.html)

## How k-of-n works

1. Choose threshold `k` and total shares `n` with `1 <= k <= n <= maxShares` (default `maxShares=60`).
2. `GET /splitSecret` builds a degree-`(k-1)` polynomial over a large prime field, evaluates it at
   `n` points, and RSA-signs each share value.
3. Distribute the shares. Any coalition with at least `k` valid shares can `POST /recoverSecret`.
4. Signatures are verified before interpolation; shares from another process instance (different
   RSA key) are rejected.

## API

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/api/v1/splitSecret?k=&n=&secret=` | Split a secret into `n` signed shares |
| `POST` | `/api/v1/recoverSecret` | Reconstruct the secret from signed shares |
| `GET` | `/actuator/health` | Liveness/readiness style health probe |

### Split

```bash
curl -sG 'http://localhost:8080/api/v1/splitSecret' \
  --data-urlencode 'k=2' \
  --data-urlencode 'n=3' \
  --data-urlencode 'secret=for-your-eyes-only'
```

Response: JSON array of `{ "index", "share", "signature" }` (`share` as decimal string,
`signature` as Base64).

### Recover

```bash
curl -s -X POST 'http://localhost:8080/api/v1/recoverSecret' \
  -H 'Content-Type: application/json' \
  -d '[{"index":1,"share":"...","signature":"..."},{"index":2,"share":"...","signature":"..."}]'
```

Response: `text/plain` recovered secret.

### Errors (sanitized)

| Status | When |
|--------|------|
| `400` | Missing/invalid query params, blank secret, `k/n` out of range, empty shares |
| `403` | Share signature verification failed |
| `429` | Too many `/recoverSecret` calls from the same client |
| `500` | Unexpected server failure |

## Configuration

| Property | Default | Notes |
|----------|---------|-------|
| `secret-sharing.maxShares` | `60` | Upper bound for `n` |
| `secret-sharing.bitSize` | `2048` | Field size for the modular polynomial |
| `secret-sharing.keyPairBitSize` | `2048` | RSA key used to sign shares |
| `secret-sharing.hashAlgorithm` | `SHA256withRSA` | Signature algorithm |
| `secret-sharing.cors.allowed-origins` | localhost:4200–4202 | Comma-separated browser origins |
| `secret-sharing.rate-limit.recover.capacity` | `30` | Max recover calls per window per client |
| `secret-sharing.rate-limit.recover.window-seconds` | `60` | Rate-limit window |
| `spring.codec.max-in-memory-size` | `256KB` | Caps in-memory request body buffering |

Actuator exposes **health** and **info** only; details stay closed.

## Threat model (short)

- Split/recover is **in-process**: shares are not persisted by this service.
- Each share is **RSA-signed** with a key pair generated at startup. Restart rotates keys;
  old signatures fail verification.
- Putting the secret in a **GET query string** is convenient for demos and leaks via logs/proxies —
  treat this branch as educational unless you change the contract.
- This is **not** a multi-party authenticity or key-distribution protocol.

## License

See [LICENSE](LICENSE).
