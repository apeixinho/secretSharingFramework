# Secret Sharing Frontend

Polished Angular frontend for the reactive
[Secret Sharing API](https://github.com/apeixinho/secretSharingFramework).

Split a secret into RSA-signed shares, keep them in a browser-local vault, and recover the secret when enough selected shares are available.

## Requirements

- Node.js 20+
- The backend API running locally on `http://localhost:8080` (or configure your reverse proxy)

## Quick start

```bash
npm install
npm start
```

Open [http://localhost:4200](http://localhost:4200).

Dev server proxies:

- `/api` → `http://localhost:8080/api`
- `/actuator` → `http://localhost:8080/actuator`

## Scripts

| Command | Purpose |
|---------|---------|
| `npm start` | Dev server with API proxy |
| `npm run build` | Production build to `dist/` |
| `npm test` | Unit tests (watch off; use `npm run test:watch` locally) |

## Backend contract

| Method | Path | Body | Result |
|--------|------|------|--------|
| `POST` | `/api/v1/splitSecret` | `{ k, n, secret }` | Share array |
| `POST` | `/api/v1/recoverSecret` | `[shares…]` | Recovered secret string |

Constraints from the API:

- `k` and `n` are integers from 1–60 (`n >= k`)
- `secret` length is 3–300
- Share indexes are `1..n`
- Signatures are Base64; share values are decimal strings

## Notes

- Shares persist in `localStorage` under `ssf.share-vault.v1`
- Restarting the backend rotates signing keys; previously issued signatures will fail verification
- Set `SECRET_SHARING_CORS_ALLOWED_ORIGINS` on the API if you serve the frontend without the dev proxy
- Sibling UIs: [react-frontend](../react-frontend/) (`:4201`), [typescript-frontend](../typescript-frontend/) (`:4202`)
- Requires the reactive POST API; older `GET /splitSecret` backends are not compatible
