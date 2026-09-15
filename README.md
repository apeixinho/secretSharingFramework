# Secret Sharing Framework API

Java library implementing [Shamir's Secret Sharing](https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing) (split a secret into shares; reconstruct with a threshold). Maven artifact `org.secretsharing:secret-sharing`.

## Requirements

- **Java 21**
- Maven 3.8+

## Quick start

```bash
mvn -B test
mvn -B package
```

Core types live under `src/main/java/org/secretsharing/` (`SecretSharing`, `SecretSharingImpl`, `SecretShareDTO`). Unit tests: `src/test/java/org/secretsharing/tests/`.

