# Next.js Route Handler example

This is the smallest possible Next.js 15 App Router service that uses `@useauthio/node` for Management API calls and pairs with `@useauthio/nextjs` for edge session verification.

In a real project you'd put these route handlers next to your pages. We split them out here so the example file structure is easy to read.

```
app/
  api/
    whoami/route.ts            <- session verification via @useauthio/nextjs `auth()`
    users/[id]/memberships/route.ts
    organizations/route.ts
```

See [`server.ts`](./server.ts) for a single-file alternative if you'd rather scaffold without Next.

## Run

```bash
pnpm install
cp .env.example .env
pnpm dev
```

The route handlers are intentionally split — copy the bits you need into your own app's `app/api/`.
