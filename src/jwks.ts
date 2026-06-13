import { createRemoteJWKSet, jwtVerify, type JWTPayload } from "jose";

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
    /** Project_id on M2M tokens. */
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
 */
export class JwtVerifier {
  private readonly jwks: ReturnType<typeof createRemoteJWKSet>;

  constructor(
    private readonly apiUrl: string,
    private readonly issuer: string,
    private readonly audience: string,
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
    return payload as AuthioClaims<TClaims>;
  }
}
