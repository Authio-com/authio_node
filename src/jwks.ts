import { createRemoteJWKSet, jwtVerify, type JWTPayload } from "jose";
import type { SessionDenylist } from "./webhook";

/**
 * Authio access-token claim shape.
 *
 * Generic over `TClaims` so customers using the custom-claims
 * feature get typed access to their own merged claims:
 *
 *   const claims = await verifier.verify<{
 *     stripe_customer_id: string;
 *     plan: "free" | "pro" | "enterprise";
 *   }>(token);
 *   claims.stripe_customer_id; // typed string
 *
 * For user tokens, `sub` is the user_id and `sid` carries the session
 * id. For M2M tokens (client-credentials grant) `sub` is the
 * client_id, `token_type` is "m2m", and `scopes` carries the granted
 * scope set.
 */
export type AuthioClaims<TClaims extends Record<string, unknown> = Record<string, never>> =
  JWTPayload & {
    sub: string;
    /** The active organization for this token. Empty string if the user has not yet selected an org. */
    act_org?: string;
    /** The active role within `act_org`. */
    act_role?: string;
    /** Session ID. Absent on M2M tokens. */
    sid?: string;
    /** "m2m" for client-credentials tokens; undefined / "user" otherwise. */
    token_type?: "user" | "m2m";
    /** Public client_id on M2M tokens (also stamped into `sub`). */
    client_id?: string;
    /**
     * The Authio project (tenant) this token was minted for.
     *
     * Present on M2M tokens, and on user tokens issued after the
     * 2026-07 auth-core release. Configure `projectId` on the client
     * to have the SDK check it — see {@link JwtVerifier}.
     */
    project_id?: string;
    /** Array form of OAuth-2 scopes on M2M tokens. */
    scopes?: string[];
    /** Space-joined OAuth-2 scope claim on M2M tokens. */
    scope?: string;
    /** True when the session was minted by an Authio operator impersonating the user. */
    is_impersonation?: boolean;
    /** Admin's user_id when is_impersonation is true. */
    impersonator_user_id?: string;
    /** Admin's email when is_impersonation is true. */
    impersonator_email?: string;
    /** impersonation_grants row id when is_impersonation is true. */
    imp_grant_id?: string;
    /**
     * Feature Flags. The enabled, include_in_token flag slugs for
     * this (project, org, user) at mint time. Absent when the project
     * has no flags configured. Read it via the `hasFlag(session, slug)`
     * helper rather than poking at the raw claim.
     */
    flags?: string[];
  } & TClaims;

/**
 * Verifier wraps a remote JWKS fetcher with caching. Spawn one per
 * `apiUrl` and reuse — fetching JWKS on every request is wasteful.
 *
 * ## Why you should set `projectId`
 *
 * Authio signs every tenant's tokens with the same key, issuer and
 * audience. Signature, `iss` and `aud` therefore prove the token came
 * from Authio — they do NOT prove it was minted for *your* project.
 * Without a tenant check, someone who signs up for their own Authio
 * project, creates a user called `ceo@your-company.com` there, and
 * sends you that token passes every other check in this verifier.
 *
 * Passing `projectId` closes that: a token naming a different project
 * is rejected. Leave it unset and you keep the old behaviour, with a
 * one-time warning.
 */
export class JwtVerifier {
  private readonly jwks: ReturnType<typeof createRemoteJWKSet>;
  /** One-time warning latches, so a busy server logs once, not per request. */
  private warnedNoProjectConfigured = false;
  private warnedClaimAbsent = false;

  constructor(
    private readonly apiUrl: string,
    private readonly issuer: string,
    private readonly audience: string,
    private readonly projectId?: string,
    /**
     * Session denylist fed by `handleAuthioWebhook` on session.revoked
     * webhooks (revocation-signals Phase 1). When set, a structurally
     * valid token whose `sid` is denylisted is rejected — closing the
     * window where an offline-verified JWT outlives its revoked Authio
     * session. Use a shared adapter (Redis) on multi-instance deploys.
     */
    private readonly sessionDenylist?: SessionDenylist,
  ) {
    this.jwks = createRemoteJWKSet(
      new URL(this.apiUrl.replace(/\/$/, "") + "/v1/auth/.well-known/jwks.json"),
      {
        cooldownDuration: 30_000,
        cacheMaxAge: 600_000,
      },
    );
  }

  /**
   * Verify an Authio access token. `TClaims` is the type of the
   * customer's custom claims. Defaults to an empty record
   * for callers that haven't configured custom claims.
   */
  async verify<TClaims extends Record<string, unknown> = Record<string, never>>(
    token: string,
  ): Promise<AuthioClaims<TClaims>> {
    const { payload } = await jwtVerify(token, this.jwks, {
      issuer: this.issuer,
      audience: this.audience,
      algorithms: ["EdDSA"],
    });
    if (!payload.sub) {
      throw new Error("authio: token missing sub claim");
    }
    this.assertTenant(payload);
    // Revocation-signals Phase 1: refuse tokens whose session was
    // revoked (session.revoked webhook → denylist). Only when a
    // denylist was configured; absent one, behaviour is unchanged.
    if (
      this.sessionDenylist &&
      typeof payload.sid === "string" &&
      payload.sid &&
      (await this.sessionDenylist.has(payload.sid))
    ) {
      throw new Error("authio: session revoked");
    }
    return payload as AuthioClaims<TClaims>;
  }

  /**
   * Tenant binding.
   *
   * A MISMATCH is rejected outright: the token demonstrably belongs to
   * another project, which is the cross-tenant forgery this check
   * exists for, and no legitimate token for your project can look like
   * that.
   *
   * An ABSENT claim only warns. Tokens minted before the auth-core
   * release that added `project_id` do not carry it, and they are
   * still live until every session issued before that deploy has
   * expired. Failing them would sign out real users to defend against
   * a token an attacker cannot actually obtain any more. This softness
   * is temporary — a later release turns it into a rejection once
   * those tokens have aged out.
   */
  private assertTenant(payload: JWTPayload): void {
    const claimed = typeof payload.project_id === "string" ? payload.project_id : undefined;

    if (!this.projectId) {
      if (!this.warnedNoProjectConfigured) {
        this.warnedNoProjectConfigured = true;
        console.warn(
          "authio: no projectId configured, so tokens are not checked against your tenant. " +
            "Any Authio-issued token will verify here, including one minted in someone else's project. " +
            "Pass projectId to the Authio client to enable the check.",
        );
      }
      return;
    }

    if (claimed === undefined) {
      if (!this.warnedClaimAbsent) {
        this.warnedClaimAbsent = true;
        console.warn(
          "authio: token carries no project_id claim, so it could not be checked against your tenant. " +
            "This is expected for sessions issued before 2026-07 and stops once they expire. " +
            "A future SDK release will reject these.",
        );
      }
      return;
    }

    if (claimed !== this.projectId) {
      throw new Error(
        `authio: token was issued for project ${claimed}, not ${this.projectId}`,
      );
    }
  }
}
