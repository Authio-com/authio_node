export interface User {
  id: string;
  projectId: string;
  email: string;
  emailVerified: boolean;
  name?: string;
  avatarUrl?: string;
  defaultOrganizationId: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface Organization {
  id: string;
  projectId: string;
  name: string;
  slug: string;
  createdAt: string;
}

export type MembershipStatus =
  | "invited"
  | "active"
  | "suspended"
  | "deactivated";

export interface Membership {
  id: string;
  projectId: string;
  userId: string;
  organizationId: string;
  role: string;
  status: MembershipStatus;
  joinedAt: string;
  invitedBy: string | null;
  lastActiveAt: string | null;
  preferredLoginMethod: "passkey" | "magic_link" | "oauth" | "sso" | null;
}

/**
 * A verified Authio session.
 *
 * The session always identifies the *user* (`userId`); the active
 * organization (`orgId`) is only set after the user has selected one of
 * their memberships. A user with multiple memberships may move between
 * orgs in-session without re-authenticating.
 *
 * Generic over `TClaims` so customers using the custom-claims
 * feature get typed access to their merged claims via `claims`.
 */
export interface Session<TClaims extends Record<string, unknown> = Record<string, never>> {
  sessionId: string;
  userId: string;
  orgId: string | null;
  role: string | null;
  expiresAt: string;
  /** Custom claims merged into the token. Empty when the project has no custom claims. */
  claims: TClaims;
  /**
   * Enabled feature-flag slugs embedded in the token (the flags
   * marked include_in_token that resolved ON for this user/org). Empty
   * when the project has no flags. Use the `hasFlag(session, slug)`
   * helper to check membership.
   */
  flags: string[];
  /** True when the session was minted by an Authio operator impersonating the user. */
  isImpersonation?: boolean;
  /** Admin email when isImpersonation is true. */
  impersonatorEmail?: string;
}

/**
 * Response shape for `Authio.token({ grant_type: "client_credentials" })`
 * — the OAuth 2.0 §5.1 envelope.
 */
export interface TokenResponse {
  access_token: string;
  token_type: "Bearer";
  expires_in: number;
  scope?: string;
}

export interface ClientCredentialsInput {
  grant_type: "client_credentials";
  client_id: string;
  client_secret: string;
  /** Space-separated subset of the client's registered scopes. */
  scope?: string;
}

/**
 * Envelope returned by `Authio.sessions.refresh({ refreshToken })` —
 * mirrors auth-core's session.Envelope JSON shape.
 *
 * Phase 2 cookie auto-renewal: BFFs (Next.js dashboards, etc.) call
 * `refresh()` with the long-lived refresh token they stashed at sign-
 * in and use the rotated tokens to update their scoped cookies.
 *
 * The org-policy gate (idle / absolute / refresh-window / IP / geo)
 * is enforced server-side by auth-core; on a violation the call
 * throws `AuthioError` with a `policy_violation_*` code so callers
 * can render the appropriate "your admin requires re-auth" copy.
 */
export interface SessionEnvelope {
  /** Auth-core session id. Stable across rotations. */
  session_id: string;
  /** New short-lived access JWT. Stash in your access cookie. */
  access_token: string;
  /** Rotated refresh token. The OLD token is now invalid. */
  refresh_token: string;
  /** ISO timestamp the access JWT expires. Use to schedule the next refresh. */
  expires_at: string;
  /** User snapshot. Convenience — same fields as Authio.users.get. */
  user: User | null;
  /** Resolved active organization, when the session has pivoted into one. */
  active_organization?: Organization | null;
  /** Active role within active_organization, when set. */
  active_role?: string;
  /** All active memberships for this user. */
  memberships?: Array<{
    id: string;
    project_id: string;
    user_id: string;
    organization_id: string;
    role: string;
    status: MembershipStatus;
  }>;
}
