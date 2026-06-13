<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset=".github/logo-dark.png">
    <img alt="Authio" src=".github/logo-light.png" width="220">
  </picture>
</p>

# @useauthio/node

> Part of **[Authio Lobby](https://authio.com/products/lobby)** —
> Authio's drop-in passwordless authentication. Learn more at
> https://authio.com/products/lobby.

Server-side TypeScript SDK for Authio. Use it from any Node.js / Bun / Deno backend (Express, Fastify, Hono, NestJS, Next.js Route Handlers, ...) to verify sessions, manage users, organizations, memberships, invitations, and connections.

## Recent additions

These additions extend what your BFF can do without changing the SDK
contract for existing code. The new endpoints are reachable via the
standard `Authio` client and via the public `JwtVerifier` for verifying
widget JWTs:

- **Verifying a widget token** — pull `JwtVerifier`, look for
  `claims.kind === "widget"`, then check `claims.widget_origins[]`,
  `claims.widget_scope[]`, `claims.organization_id`, and
  `claims.tenant_id`. Full walkthrough on the docs site at
  [`/widgets/tokens`](https://docs.authio.com/widgets/tokens) and
  [`/sdks/node`](https://docs.authio.com/sdks/node).
- **Calling an Action handler** — verify the HMAC envelope on every
  inbound `POST /authio-action` request with the standard
  `node:crypto` `createHmac` + `timingSafeEqual` idiom; reject any
  request older than ±5 minutes. Snippets in
  [`/actions/signature-verification`](https://docs.authio.com/actions/signature-verification)
  and the end-to-end Pattern 3 walkthrough in
  [`/actions/pattern-3-customer-roles`](https://docs.authio.com/actions/pattern-3-customer-roles).
- **Registering an OAuth client (RFC 7591 DCR)** — `POST` to
  `/oauth2/register` with the project's `X-Authio-Project` header
  and (when the project is in `initial_access_token` mode) an
  `Authorization: Bearer iatk_…`. The response carries the raw
  `client_secret` and `registration_access_token` exactly once;
  store both server-side. Reference in
  [`/concepts/dynamic-client-registration`](https://docs.authio.com/concepts/dynamic-client-registration)
  and [`/concepts/client-id-metadata-document`](https://docs.authio.com/concepts/client-id-metadata-document).
- **Roles + permissions catalog** — every `access_token` for a
  customer-tenant project now carries `roles` (string in single-role
  mode, array in multi-role mode) and `permissions` (always an
  array). Both are reserved-claim names; the only path to
  customer-controlled overrides is the Pattern 3 Actions hook gated
  by `projects.roles_action_override`. Concept page:
  [`/concepts/roles-and-permissions`](https://docs.authio.com/concepts/roles-and-permissions).

The OpenAPI source of truth (with every new endpoint, schema, and
error code) is published in [`authio_proto`](https://github.com/authio-com/authio_proto).

## Install

```bash
pnpm add @useauthio/node
# or: npm i @useauthio/node / yarn add @useauthio/node
```

## Quick start

```ts
import { Authio } from "@useauthio/node";

const authio = new Authio({ apiKey: process.env.AUTHIO_SECRET_KEY! });

export async function handler(req: Request) {
  const session = await authio.sessions.verify(
    req.headers.get("cookie") ?? "",
  );
  if (!session) return new Response("Unauthorized", { status: 401 });

  // session.userId is always set; session.orgId is set only after the
  // user has selected an organization (multi-org users may have many).
  const memberships = await authio.users.listMemberships(session.userId);
  return Response.json({ user: session.userId, memberships });
}
```

## Multi-org-aware

`session.orgId` represents the currently-active organization for the request. A session is *user-scoped* — `session.userId` is the same regardless of which org the user is in. To switch:

```ts
await authio.sessions.switchOrg(sessionId, { organizationId: "org_..." });
```

This mints a new session bound to a different org without re-authenticating the user.

## Refresh tokens (BFF cookie auto-renewal)

Authio mints two tokens at sign-in:

- A **short-lived access JWT** (`access_token`, ~15 min) — what your `verify()` call checks.
- A **long-lived refresh token** (`refresh_token`, default 30 days, capped per org-policy `refresh_window_min`) — used to mint a new access JWT silently.

A typical BFF (Next.js / Express / Hono) stashes the access token in a short-lived cookie and the refresh token in a long-lived cookie, then rotates the access cookie before it expires using `Authio.sessions.refresh`:

```ts
import { Authio, AuthioError } from "@useauthio/node";

const authio = new Authio({ apiKey: process.env.AUTHIO_SECRET_KEY! });

// Inside your /api/auth/refresh handler (or middleware):
async function silentRenew(req: Request, res: Response) {
  try {
    const env = await authio.sessions.refresh({
      refreshToken: req.cookies["authio_refresh"],
    });
    res.cookie("authio_session", env.access_token, {
      httpOnly: true,
      secure: true,
      sameSite: "none",
      maxAge: 15 * 60 * 1000,
    });
    res.cookie("authio_refresh", env.refresh_token, {
      httpOnly: true,
      secure: true,
      sameSite: "none",
      maxAge: 30 * 24 * 60 * 60 * 1000,
    });
  } catch (err) {
    if (err instanceof AuthioError) {
      // Auth-core enforces three lifecycle knobs from the org-policy
      // engine. Surface stable codes back to your caller so
      // they can render the right "your admin requires re-auth" copy:
      //   policy_violation_session_idle      — idle gap > policy
      //   policy_violation_session_absolute  — session past absolute max
      //   policy_violation_session_refresh_window — past refresh window
      //   invalid_refresh_token              — revoked / unknown / raced
      res.clearCookie("authio_session");
      res.clearCookie("authio_refresh");
      res.redirect(`/sign-in?err=${encodeURIComponent(err.code)}`);
      return;
    }
    throw err;
  }
}
```

The OLD refresh token is single-use — auth-core's rotation is atomic, so a stolen refresh can be replayed at most once. The session row's `expires_at` is also clamped to `issued_at + refresh_window_min` when an org-policy is configured, so refresh chains can never outlive the policy.

## Session lifecycle policy

Customers can configure three knobs per organization on the dashboard `/orgs/<id>/security` page:

| Knob | Meaning | Typical value |
|---|---|---|
| `session_idle_timeout_min` | Max gap from last activity before forcing re-auth | 30 (high-security) / 480 (consumer) |
| `session_absolute_max_min` | Absolute max session lifetime since sign-in | 1440 (24h) / 14400 (10d) |
| `refresh_window_min` | Cap on the rolling refresh-token chain | 720 (12h) / 10080 (7d) |

A zero value on any knob means "inherit the project default". The strictest non-zero gate wins on every refresh.

## License

MIT
