# Secret Sharing (`pojo`)

Standalone Java library implementing [Shamir's Secret Sharing](https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing):
split a UTF-8 secret into `n` RSA-signed shares such that any `k` of them recover it.

Maven artifact: `org.secretsharing:secret-sharing`.

This branch is the **pure algorithm / library** line (no Spring, no HTTP). Server and UI variants live on other branches (see below).

## Requirements

- **Java 21+**
- Maven is optional — use the included wrapper (`./mvnw` / `mvnw.cmd`)

## Quick start

```bash
./mvnw -B test
./mvnw -B package
```

On Windows (cmd/PowerShell): `mvnw.cmd -B test` / `mvnw.cmd -B package`.

### Library usage

```java
SecretSharing sss = new SecretSharingImpl();          // default 2048-bit field / RSA
// SecretSharing sss = new SecretSharingImpl(4096);   // optional bit size (1024–4096)

List<SecretShareDTO> shares = sss.splitSecret(3, 5, "top secret");
String recovered = sss.recoverSecret(shares.subList(0, 3));
```

| Type | Role |
|------|------|
| `SecretSharing` | Split / recover contract |
| `SecretSharingImpl` | Polynomial SSS + RSA share signatures |
| `SecretShareDTO` | Share record (`index`, `share`, `signature`) |

Unit tests: `src/test/java/org/secretsharing/tests/`.

## Related branches

| Branch | What it is |
|--------|------------|
| **`main`** | Canonical **Spring Boot WebFlux** API under `backend/` plus Angular / React / TypeScript frontends. Prefer this for the HTTP service and UIs. |
| `reactive` | Annotated `@RestController` WebFlux stack (aligned with `main`). |
| `reactive-functional` | Same reactive API with **functional** `RouterFunction` handlers instead of annotated controllers. |
| `reactive-mongo` | WebFlux API + **Reactive MongoDB** persistence for shares (Compose + Testcontainers). |
| `rest` | **Spring MVC** (servlet) REST experiment. |
| `pojo` | **This branch** — plain Java library only (no Spring HTTP stack). |

For other implementations, checkout corresponding branches with `git checkout <branch>`.

## Notes / known limitations

- Shares are evaluated at \(x = 1..n\); the secret is the constant term \(P(0)\) and is not emitted as a share.
- RSA key size is tied to the SSS field `bitSize` (minimum 1024). Prefer the default 2048+ for anything beyond local experiments.
- Intended as a learning/reference implementation, not a production crypto package.

## License

See [LICENSE](LICENSE).
