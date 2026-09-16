# Branches

| Branch | Role |
|--------|------|
| **`main`** | Canonical **reactive WebFlux** API (this line). Prefer cloning/PRs against `main`. |
| `reactive` | Historical development branch for the WebFlux stack; kept in sync with `main` after alignment. Prefer `main` for new work. |
| `pojo` | Standalone Java library (no Spring HTTP). Useful as a pure algorithm reference. |
| `rest` | Spring MVC (servlet) variant; source of ideas for exception handling. |
| `reactive-functional` | WebFlux functional router style experiment. |
| `reactive-mongo` | WebFlux + Mongo persistence experiment (share groups/users). |

## Consolidation policy

- New features and fixes land on **`main`** (reactive annotated controllers).
- Experimental branches are **not** deleted immediately, but are not the default delivery line.
- Persistence, alternative router styles, or MVC ports should either stay clearly experimental or be proposed as optional modules—not parallel “default” apps.

## Layout

```
backend/          Spring Boot WebFlux application
  src/main/java   API, crypto config, validation
  Dockerfile      Multi-stage Java 21 image
  compose.yml     Local container run
```
