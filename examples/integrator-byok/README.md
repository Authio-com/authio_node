# Integrator BYOK example

Minimal Next.js reference for a **multi-tenant SaaS** that pulls Authio identity data via customer-supplied Management API keys.

This is **not** a production app — it demonstrates the pattern documented at [Connect Authio (BYOK)](https://docs.authio.com/guides/connect-external-app).

## What it shows

| Piece | Location |
| --- | --- |
| Settings UI (paste `sk_live_`) | `app/settings/connect-authio/` |
| Validate via `GET /v1/projects/me` | `lib/authio.ts` |
| Encrypt at rest (AES-256-GCM) | `lib/crypto.ts` |
| File-backed connection store | `lib/store.ts` (swap for your DB) |
| Sync now (`GET /v1/users`) | `app/settings/connect-authio/actions.ts` |

## Run

```bash
cd examples/integrator-byok
cp .env.example .env.local
# Set INTEGRATOR_CREDS_KEY (openssl rand -base64 32)
pnpm install
pnpm dev
# → http://localhost:3020/settings/connect-authio
```

Paste a real `sk_live_` or `sk_test_` key from an Authio project. The key is validated server-side, sealed with `INTEGRATOR_CREDS_KEY`, and written to `.data/authio-connections.json` (gitignored).

## Security notes

- Never expose `sk_` keys to the browser after the initial POST.
- Replace the file store with your database + KMS-backed master key in production.
- See the docs security checklist and the planned [integrator OAuth roadmap](https://docs.authio.com/concepts/integrator-apps).
