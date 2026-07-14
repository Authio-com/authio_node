import { AuthioError } from "./errors";
import { JwtVerifier } from "./jwks";
import type {
  ClientCredentialsInput,
  Membership,
  Organization,
  Session,
  SessionEnvelope,
  TokenResponse,
  User,
} from "./types";

export interface AuthioOptions {
  apiKey: string;
  apiUrl?: string;
  /**
   * The auth-core base URL (where /v1/auth/.well-known/jwks.json and
   * /v1/auth/token live). Defaults to the issuer. In production
   * Authio runs `https://identity.authio.com` here; the management
   * API at `apiUrl` runs separately at `https://manage.authio.com`.
   */
  authCoreUrl?: string;
  /** JWT issuer to require. Defaults to the production issuer. */
  jwtIssuer?: string;
  /** JWT audience to require. */
  jwtAudience?: string;
  fetch?: typeof fetch;
}

const DEFAULT_API_URL = "https://manage.authio.com";
const DEFAULT_ISSUER = "https://identity.authio.com";
const DEFAULT_AUDIENCE = "authio";

export class Authio {
  readonly users = new UsersAPI(this);
  readonly organizations = new OrganizationsAPI(this);
  readonly memberships = new MembershipsAPI(this);
  readonly locate = new LocateAPI(this);
  readonly portal = new PortalAPI(this);
  readonly events = new EventsAPI(this);
  readonly flags = new FlagsAPI(this);
  readonly sessions: SessionsAPI;

  /** The auth-core base URL used for the JWKS + token endpoint. */
  readonly authCoreUrl: string;

  private readonly verifier: JwtVerifier;

  constructor(public readonly options: AuthioOptions) {
    if (!options.apiKey) {
      throw new Error(
        "Authio: apiKey is required. Pass it directly or set AUTHIO_SECRET_KEY.",
      );
    }
    const apiUrl = options.apiUrl ?? DEFAULT_API_URL;
    // auth-core lives at a different origin than management-api in
    // production (api.authio.com vs auth-api.authio.com). Callers
    // may pass an explicit authCoreUrl; otherwise we derive from
    // the issuer (which is auth-core's public origin by convention).
    this.authCoreUrl = (options.authCoreUrl ?? options.jwtIssuer ?? DEFAULT_ISSUER).replace(
      /\/$/,
      "",
    );
    this.verifier = new JwtVerifier(
      this.authCoreUrl,
      options.jwtIssuer ?? DEFAULT_ISSUER,
      options.jwtAudience ?? DEFAULT_AUDIENCE,
    );
    this.sessions = new SessionsAPI(this, this.verifier);
  }

  /**
   * Exchange OAuth client credentials for a short-lived access token.
   * Targets auth-core's `POST /v1/auth/token` (RFC 6749 §4.4).
   *
   * Example:
   *
   * ```ts
   * const authio = new Authio({ apiKey: "sk_live_..." });
   * const { access_token } = await authio.token({
   *   grant_type: "client_credentials",
   *   client_id: "mci_...",
   *   client_secret: "msc_...",
   *   scope: "users:read",
   * });
   * ```
   *
   * The returned `access_token` is a Bearer JWT; pass it through
   * `authio.sessions.verify` to typecheck the claims.
   */
  async token(input: ClientCredentialsInput): Promise<TokenResponse> {
    const fetchFn = this.options.fetch ?? globalThis.fetch;
    const res = await fetchFn(`${this.authCoreUrl}/v1/auth/token`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "user-agent": "authio-node/0.1.0",
      },
      body: JSON.stringify(input),
    });
    if (!res.ok) {
      const data = (await res.json().catch(() => ({}))) as {
        error?: string;
        error_description?: string;
      };
      throw new AuthioError({
        code: data.error ?? "token_request_failed",
        message:
          data.error_description ?? `Token endpoint returned status ${res.status}`,
        status: res.status,
      });
    }
    return (await res.json()) as TokenResponse;
  }

  async request<T>(
    method: string,
    path: string,
    body?: unknown,
  ): Promise<T> {
    const url = (this.options.apiUrl ?? DEFAULT_API_URL) + path;
    const fetchFn = this.options.fetch ?? globalThis.fetch;
    const res = await fetchFn(url, {
      method,
      headers: {
        "content-type": "application/json",
        "user-agent": "authio-node/0.1.0",
        authorization: `Bearer ${this.options.apiKey}`,
      },
      body: body ? JSON.stringify(body) : undefined,
    });
    if (!res.ok) {
      const data = (await res.json().catch(() => ({}))) as {
        code?: string;
        message?: string;
        request_id?: string;
      };
      throw new AuthioError({
        code: data.code ?? "request_failed",
        message: data.message ?? `Request failed with status ${res.status}`,
        status: res.status,
        requestId: data.request_id,
      });
    }
    if (res.status === 204) return undefined as T;
    return (await res.json()) as T;
  }

  async authCoreRequest<T>(
    method: string,
    path: string,
    accessToken: string,
    body?: unknown,
  ): Promise<T> {
    if (!accessToken) {
      throw new Error("Authio: a user access token is required");
    }
    const fetchFn = this.options.fetch ?? globalThis.fetch;
    const res = await fetchFn(`${this.authCoreUrl}${path}`, {
      method,
      headers: {
        "content-type": "application/json",
        "user-agent": "authio-node/0.2.0",
        authorization: `Bearer ${accessToken}`,
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    if (!res.ok) {
      const data = (await res.json().catch(() => ({}))) as {
        code?: string;
        error?: string;
        message?: string;
        error_description?: string;
        request_id?: string;
      };
      throw new AuthioError({
        code: data.code ?? data.error ?? "request_failed",
        message:
          data.message ??
          data.error_description ??
          `Request failed with status ${res.status}`,
        status: res.status,
        requestId: data.request_id,
      });
    }
    if (res.status === 204) return undefined as T;
    return (await res.json()) as T;
  }
}

class UsersAPI {
  constructor(private readonly client: Authio) {}
  get(userId: string) {
    return this.client.request<User>("GET", `/v1/users/${userId}`);
  }
  listMemberships(userId: string) {
    return this.client.request<Membership[]>(
      "GET",
      `/v1/users/${userId}/memberships`,
    );
  }
}

class OrganizationsAPI {
  constructor(private readonly client: Authio) {}
  list() {
    return this.client.request<Organization[]>("GET", "/v1/organizations");
  }
  create(input: { name: string; slug?: string; domain?: string }) {
    return this.client.request<Organization>("POST", "/v1/organizations", input);
  }
  get(orgId: string) {
    return this.client.request<Organization>("GET", `/v1/organizations/${orgId}`);
  }
}

class MembershipsAPI {
  constructor(private readonly client: Authio) {}
  listForOrganization(orgId: string) {
    return this.client.request<Membership[]>(
      "GET",
      `/v1/organizations/${orgId}/memberships`,
    );
  }
  add(orgId: string, input: { userId: string; role: string }) {
    return this.client.request<Membership>(
      "POST",
      `/v1/organizations/${orgId}/memberships`,
      { user_id: input.userId, role: input.role },
    );
  }
  remove(orgId: string, membershipId: string) {
    return this.client.request<void>(
      "DELETE",
      `/v1/organizations/${orgId}/memberships/${membershipId}`,
    );
  }
}

export interface GenerateLinkInput {
  /** The organization the IT admin will configure. */
  organizationId: string;
  /** `"sso"` (configure SSO) or `"scim"` (configure directory sync). */
  intent: "sso" | "scim";
  /** Optional https URL the portal's "Return" link points at. */
  returnUrl?: string;
  /** Optional https URL the admin is redirected to after a successful save. */
  successUrl?: string;
  /** Optional IT-contact addresses to also email the link to. */
  itContactEmails?: string[];
  /** Link lifetime in minutes. Defaults to 5; max 10080 (7 days). */
  expiresInMinutes?: number;
}

export interface GenerateLinkResult {
  /** The ready-to-redirect setup-portal URL. */
  link: string;
  /** ISO-8601 expiry. */
  expires_at: string;
}

/**
 * Admin Portal link generation (`generate_link`). Mint a
 * one-time, organization-scoped SSO/SCIM setup link from your backend and
 * redirect a logged-in IT admin straight to it — no Authio dashboard
 * access required.
 *
 * ```ts
 * const authio = new Authio({ apiKey: process.env.AUTHIO_SECRET_KEY! });
 * const { link } = await authio.portal.generateLink({
 *   organizationId: "org_123",
 *   intent: "sso",
 *   successUrl: "https://app.example.com/settings/sso?done=1",
 * });
 * res.redirect(link);
 * ```
 */
class PortalAPI {
  constructor(private readonly client: Authio) {}

  generateLink(input: GenerateLinkInput) {
    return this.client.request<GenerateLinkResult>(
      "POST",
      "/v1/portal/setup-links",
      {
        organization_id: input.organizationId,
        intent: input.intent,
        ...(input.returnUrl !== undefined ? { return_url: input.returnUrl } : {}),
        ...(input.successUrl !== undefined ? { success_url: input.successUrl } : {}),
        ...(input.itContactEmails !== undefined
          ? { it_contact_emails: input.itContactEmails }
          : {}),
        ...(input.expiresInMinutes !== undefined
          ? { expires_in_minutes: input.expiresInMinutes }
          : {}),
      },
    );
  }
}

export interface AuthioEvent {
  /** Opaque event id (`evt_…`). */
  id: string;
  /** The event action, e.g. `user.created`, `session.created`. */
  event: string;
  /** ISO-8601 timestamp the event occurred. */
  created_at: string;
  /** Event payload: org/user/target ids + your custom metadata. */
  data: {
    organization_id: string | null;
    user_id: string | null;
    actor_type: string;
    actor_id: string | null;
    target_type: string | null;
    target_id: string | null;
    metadata: Record<string, unknown>;
  };
}

export interface ListEventsInput {
  /** Filter to these event actions (e.g. `["user.created"]`). */
  events?: string[];
  /** Inclusive lower bound on `created_at` (ISO-8601). */
  rangeStart?: string;
  /** Inclusive upper bound on `created_at` (ISO-8601). */
  rangeEnd?: string;
  /** Page size, 1..100 (default 100). */
  limit?: number;
  /** Opaque cursor from a previous response's `listMetadata.after`. */
  after?: string;
}

export interface ListEventsResult {
  data: AuthioEvent[];
  listMetadata: { after: string | null };
}

function buildEventsQuery(input: ListEventsInput): string {
  const qs = new URLSearchParams();
  for (const e of input.events ?? []) qs.append("events[]", e);
  if (input.rangeStart !== undefined) qs.set("range_start", input.rangeStart);
  if (input.rangeEnd !== undefined) qs.set("range_end", input.rangeEnd);
  if (input.limit !== undefined) qs.set("limit", String(input.limit));
  if (input.after !== undefined) qs.set("after", input.after);
  const s = qs.toString();
  return s ? `?${s}` : "";
}

/**
 * Events API. Cursor-paginated, project-scoped
 * read over your audit events.
 *
 * ```ts
 * const authio = new Authio({ apiKey: process.env.AUTHIO_SECRET_KEY! });
 *
 * // One page:
 * const { data, listMetadata } = await authio.events.list({
 *   events: ["user.created", "session.created"],
 *   limit: 50,
 * });
 *
 * // Or stream every event with no gaps/dupes (handles cursoring for you):
 * for await (const event of authio.events.iterate({ events: ["user.created"] })) {
 *   console.log(event.id, event.event, event.created_at);
 * }
 * ```
 */
class EventsAPI {
  constructor(private readonly client: Authio) {}

  /** Fetch a single page of events. */
  async list(input: ListEventsInput = {}): Promise<ListEventsResult> {
    const raw = await this.client.request<{
      data: AuthioEvent[];
      list_metadata: { after: string | null };
    }>("GET", `/v1/events${buildEventsQuery(input)}`);
    return { data: raw.data, listMetadata: { after: raw.list_metadata.after } };
  }

  /**
   * Auto-paginating async iterator. Walks `after` cursors until the API
   * returns no more rows, yielding each event once. Keyset pagination on
   * `(created_at, id)` guarantees no gaps and no duplicates even if new
   * events arrive while you iterate.
   */
  async *iterate(input: ListEventsInput = {}): AsyncGenerator<AuthioEvent, void, void> {
    let after: string | null = input.after ?? null;
    // Use the largest page the API allows unless the caller pinned a size.
    const limit = input.limit ?? 100;
    for (;;) {
      const page: ListEventsResult = await this.list({
        ...input,
        limit,
        ...(after !== null ? { after } : {}),
      });
      for (const ev of page.data) yield ev;
      after = page.listMetadata.after;
      if (!after || page.data.length === 0) return;
    }
  }
}

export interface EvaluateFlagsInput {
  /** Resolve org-targeting rules for this organization. */
  organizationId?: string;
  /** Resolve user-targeting rules for this user. */
  userId?: string;
}

export interface EvaluateFlagsResult {
  organizationId: string | null;
  userId: string | null;
  /** Every non-archived flag → its resolved boolean for this (org, user). */
  flags: Record<string, boolean>;
  /** Sorted list of the flag slugs that resolved ON. */
  enabled: string[];
}

/**
 * Feature Flags API. Evaluate a project's flags for a given
 * (org, user) WITHOUT minting a new access token — for server-side
 * checks in cron jobs, webhooks, or SSR.
 *
 * ```ts
 * const authio = new Authio({ apiKey: process.env.AUTHIO_SECRET_KEY! });
 * const { enabled, flags } = await authio.flags.evaluate({
 *   organizationId: "org_123",
 *   userId: "user_456",
 * });
 * if (flags["new_billing"]) { ... }
 * ```
 *
 * For the request-path check (no round-trip), read the flags embedded
 * in the verified session JWT via `hasFlag(session, "new_billing")`.
 */
class FlagsAPI {
  constructor(private readonly client: Authio) {}

  async evaluate(input: EvaluateFlagsInput = {}): Promise<EvaluateFlagsResult> {
    const qs = new URLSearchParams();
    if (input.organizationId !== undefined) qs.set("organization_id", input.organizationId);
    if (input.userId !== undefined) qs.set("user_id", input.userId);
    const suffix = qs.toString() ? `?${qs.toString()}` : "";
    const raw = await this.client.request<{
      organization_id: string | null;
      user_id: string | null;
      flags: Record<string, boolean>;
      enabled: string[];
    }>("GET", `/v1/flags/evaluate${suffix}`);
    return {
      organizationId: raw.organization_id,
      userId: raw.user_id,
      flags: raw.flags,
      enabled: raw.enabled,
    };
  }
}

/**
 * Check whether a feature flag is enabled for a verified session,
 * reading the `flags` claim embedded in the access JWT (no network
 * round-trip). The slug must be marked include_in_token in the
 * dashboard to appear here; for flags excluded from the token, use
 * `authio.flags.evaluate()` instead.
 *
 * ```ts
 * const session = await authio.sessions.verify(accessToken);
 * if (session && hasFlag(session, "new_billing")) { ... }
 * ```
 */
export function hasFlag(
  session: Pick<Session, "flags"> | null | undefined,
  slug: string,
): boolean {
  if (!session || !Array.isArray(session.flags)) return false;
  return session.flags.includes(slug);
}

// Standard JWT + Authio reserved claim names — never copied into Session.claims.
const RESERVED_JWT_CLAIMS = new Set([
  "iss",
  "sub",
  "aud",
  "exp",
  "iat",
  "jti",
  "nbf",
  "scope",
  "scopes",
  "sid",
  "act_org",
  "act_role",
  "client_id",
  "token_type",
  "project_id",
  "is_impersonation",
  "impersonator_user_id",
  "impersonator_email",
  "imp_grant_id",
  // The feature-flags claim is surfaced on session.flags (and via
  // hasFlag), not merged into the custom-claims bag.
  "flags",
]);

class SessionsAPI {
  constructor(
    private readonly client: Authio,
    private readonly verifier: JwtVerifier,
  ) {}

  /**
   * Verify an Authio access token (JWT). Returns the typed Session, or
   * null when the token is invalid/expired.
   *
   * `session.userId` is always set; `session.orgId` may be null when the
   * user has authenticated but not yet selected an organization (multi-org
   * users coming straight out of /v1/auth/passkey/login/verify).
   *
   * `TClaims` is the type of the customer's custom claims; pass
   * an explicit type argument to get typed access via `session.claims`.
   */
  async verify<TClaims extends Record<string, unknown> = Record<string, never>>(
    accessToken: string,
  ): Promise<Session<TClaims> | null> {
    if (!accessToken) return null;
    try {
      const claims = await this.verifier.verify<TClaims>(accessToken);
      const merged: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(claims)) {
        if (RESERVED_JWT_CLAIMS.has(k)) continue;
        merged[k] = v;
      }
      return {
        sessionId: claims.sid ?? "",
        userId: claims.sub,
        orgId: claims.act_org ? claims.act_org : null,
        role: claims.act_role ? claims.act_role : null,
        expiresAt: claims.exp
          ? new Date(claims.exp * 1000).toISOString()
          : new Date().toISOString(),
        claims: merged as TClaims,
        flags: Array.isArray(claims.flags) ? claims.flags : [],
        isImpersonation: claims.is_impersonation === true ? true : undefined,
        impersonatorEmail: claims.impersonator_email ?? undefined,
      };
    } catch {
      return null;
    }
  }

  /**
   * Pivot the current user session into another organization.
   *
   * The first argument is the user's access JWT, not a session ID or the
   * Authio secret key. Auth-core authorizes the pivot from that JWT.
   */
  switchOrg(accessToken: string, input: { organizationId: string }) {
    return this.client.authCoreRequest<Session>(
      "POST",
      "/v1/sessions/switch-org",
      accessToken,
      { organization_id: input.organizationId },
    );
  }

  /**
   * Revoke the session represented by a user access JWT.
   *
   * @deprecated Passing a session ID was never securely actionable from this
   * SDK. Pass the session's access token instead.
   */
  revoke(accessToken: string) {
    return this.client.authCoreRequest<void>(
      "POST",
      "/v1/sessions/revoke",
      accessToken,
      {},
    );
  }

  /**
   * Phase 2 — exchange a long-lived refresh token for a new access
   * + rotated refresh token. Targets auth-core's
   * `POST /v1/auth/refresh` (which is an alias of
   * `/v1/sessions/refresh`).
   *
   * BFFs (Next.js / Express / etc.) call this with the refresh token
   * they stashed at sign-in to silently rotate their scoped cookies
   * before the access JWT expires. The OLD refresh token is
   * one-shot — auth-core's RotateRefreshToken atomically rotates the
   * stored hash, so a stolen refresh can be replayed at most once.
   *
   * Throws `AuthioError` on:
   *   - `invalid_refresh_token` — token unknown / revoked / expired,
   *     or another concurrent refresh already rotated it.
   *   - `policy_violation_session_idle` — gap from last_active_at
   *     exceeds the org's session_idle_timeout_min.
   *   - `policy_violation_session_absolute` — session past the org's
   *     session_absolute_max_min since IssuedAt.
   *   - `policy_violation_session_refresh_window` — refresh chain
   *     past the org's refresh_window_min since IssuedAt.
   *
   * Pass the returned `access_token` to `Authio.sessions.verify` to
   * decode the merged JWT claims.
   *
   * Example:
   *
   * ```ts
   * import { Authio, AuthioError } from "@useauthio/node";
   *
   * const authio = new Authio({ apiKey: process.env.AUTHIO_SECRET_KEY! });
   * try {
   *   const env = await authio.sessions.refresh({
   *     refreshToken: req.cookies["authio_refresh"],
   *   });
   *   res.cookie("authio_session", env.access_token, { httpOnly: true });
   *   res.cookie("authio_refresh", env.refresh_token, { httpOnly: true });
   * } catch (err) {
   *   if (err instanceof AuthioError && err.code.startsWith("policy_violation_")) {
   *     // Surface "your admin requires re-auth" copy and bounce to /sign-in.
   *   }
   *   throw err;
   * }
   * ```
   */
  async refresh(input: { refreshToken: string }): Promise<SessionEnvelope> {
    if (!input?.refreshToken) {
      throw new AuthioError({
        code: "missing_refresh_token",
        message: "Authio.sessions.refresh: refreshToken is required",
        status: 400,
      });
    }
    const fetchFn = this.client.options.fetch ?? globalThis.fetch;
    const res = await fetchFn(`${this.client.authCoreUrl}/v1/auth/refresh`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "user-agent": "authio-node/0.1.0",
      },
      body: JSON.stringify({ refresh_token: input.refreshToken }),
    });
    if (!res.ok) {
      const body = (await res.json().catch(() => ({}))) as {
        code?: string;
        error?: string;
        message?: string;
        request_id?: string;
      };
      throw new AuthioError({
        code: body.code ?? body.error ?? "refresh_failed",
        message:
          body.message ?? `Refresh request failed with status ${res.status}`,
        status: res.status,
        requestId: body.request_id,
      });
    }
    return (await res.json()) as SessionEnvelope;
  }
}

export interface LocateVerifyInput {
  user_id?: string;
  organization_id?: string;
  action?: string;
  ip?: string;
  cf_country?: string;
  idempotency_key?: string;
  risk_decision_id?: string;
  context?: Record<string, unknown>;
  client_location?: {
    latitude: number;
    longitude: number;
    accuracy_m?: number;
    captured_at?: string;
    source?: string;
  };
}

export interface LocateVerifyResult {
  verification_id: string;
  decision: "allow" | "block" | "challenge";
  confidence: number;
  method: string;
  location: { country: string; region: string; city: string };
  ip_location: { country: string; region: string };
  evasion_signals: string[];
  occurred_at: string;
}

class LocateAPI {
  constructor(private readonly client: Authio) {}

  /** Run a standalone Locate verification (management API). */
  verify(input: LocateVerifyInput) {
    return this.client.request<LocateVerifyResult>("POST", "/v1/locate/verify", input);
  }

  /** IP geo lookup via the Locate service (management API proxy). */
  lookup(ip: string) {
    return this.client.request<Record<string, unknown>>(
      "GET",
      `/v1/locate/lookup?ip=${encodeURIComponent(ip)}`,
    );
  }

  getPolicy() {
    return this.client.request<Record<string, unknown>>("GET", "/v1/locate/policy");
  }

  updatePolicy(body: Record<string, unknown>) {
    return this.client.request<{ ok: true }>("PUT", "/v1/locate/policy", body);
  }
}
