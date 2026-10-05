# Secret Sharing · TypeScript + Tailwind

Vanilla TypeScript (Vite) frontend styled with Tailwind CSS for the reactive
[Secret Sharing API](https://github.com/apeixinho/secretSharingFramework).

Split a secret into RSA-signed shares, keep them in a browser-local vault, and recover the secret when enough selected shares are available.

## Requirements

- Node.js 20+
- Backend API on `http://localhost:8080` (or configure the Vite proxy / CORS)

## Quick start

```bash
npm install
npm start
```

Open [http://localhost:4202](http://localhost:4202).

Dev server proxies:

- `/api` → `http://localhost:8080/api`
- `/actuator` → `http://localhost:8080/actuator`

## Scripts

| Command | Purpose |
|---------|---------|
| `npm start` | Dev server on port 4202 with API proxy |
| `npm test` | Unit tests (Vitest) |
| `npm run build` | Production build to `dist/` |
| `npm run preview` | Serve the production build |

## Backend contract

| Method | Path | Body | Result |
|--------|------|------|--------|
| `POST` | `/api/v1/splitSecret` | `{ k, n, secret }` | Share array |
| `POST` | `/api/v1/recoverSecret` | `[shares…]` | Recovered secret string |
| `GET` | `/actuator/health` | — | `{ "status": "UP" }` |

Constraints from the API:

- `k` and `n` are integers from 1–60 (`n >= k`)
- `secret` length is 3–300
- Share indexes are `1..n`
- Signatures are Base64; share values are decimal strings

Requires the reactive POST API (current `main` / hardening line). Older branches that only expose `GET /splitSecret` are not compatible.

## Notes

- Shares persist in `localStorage` under `ssf.share-vault.v1`
- Restarting the backend rotates signing keys; previously issued signatures will fail verification
- Set `SECRET_SHARING_CORS_ALLOWED_ORIGINS` on the API if you serve the frontend without the dev proxy
- UI is rendered with plain DOM (no React/Angular); styling uses Tailwind v4 via `@tailwindcss/vite`
- Form fields update in place; the page re-renders only when vault/API/UI state changes
