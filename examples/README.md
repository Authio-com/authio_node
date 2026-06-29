# @useauthio/node examples

Four minimal, runnable backends that demonstrate verifying Authio sessions and managing organizations + memberships against the live Management API.

| Directory | Stack | What it shows |
|---|---|---|
| [`express`](./express) | Express 4 | Bearer-token verification, list memberships, create organization |
| [`hono`](./hono) | Hono on Node | Same as Express but with the Hono ergonomics |
| [`nextjs-route-handler`](./nextjs-route-handler) | Next.js 15 App Router | Pure server-side handlers; pairs with `@useauthio/nextjs` for middleware |
| [`integrator-byok`](./integrator-byok) | Next.js 15 App Router | Multi-tenant BYOK: validate, encrypt, store `sk_live_`, sync users |

## Run any of them

Each example assumes you have a `sk_live_…` (or `sk_test_…`) API key. Mint one via the [provisioning quickstart](https://docs.authio.com/quickstart/provisioning) if you don't.

```bash
cd examples/express      # or hono / nextjs-route-handler
cp .env.example .env      # paste your key
pnpm install
pnpm dev
```

Then exercise:

```bash
# list memberships for a user (replace user_id)
curl http://localhost:4000/users/user_01HX.../memberships

# create an organization
curl -X POST http://localhost:4000/organizations \
  -H "content-type: application/json" \
  -d '{"name":"Acme Corp","slug":"acme"}'

# verify a session JWT (paste from your browser cookie)
curl http://localhost:4000/whoami \
  -H "Authorization: Bearer <Authio access JWT>"
```

## Pattern

All three examples share the same shape:

1. Construct a single `new Authio(...)` at boot; reuse for every request.
2. For session verification, call `authio.sessions.verify(token)` — it caches JWKS internally so verification is constant-time after the first call.
3. For Management API calls, just await the typed methods. Errors surface as `AuthioError` with a stable `code`.

If you need integration testing, see the linked guide on the docs site for spinning up `auth-core` in docker-compose.
