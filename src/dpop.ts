/**
 * DPoP (RFC 9449) helpers: sender-constrained refresh tokens.
 *
 * Generate a per-session P-256 keypair, present a proof when the
 * session is created (binding the key's RFC 7638 thumbprint to the
 * session in auth-core), then pass the key to
 * `authio.sessions.refresh({ refreshToken, dpopKey })` so every
 * rotation proves possession — a refresh token leaked through logs,
 * URLs, or backups is useless without the key.
 *
 * Storage is the integrator's call (this SDK never manages cookies):
 * keep the private JWK wherever the refresh token lives, encrypted at
 * rest, and treat the pair as one credential.
 */

import { SignJWT, generateKeyPair, exportJWK, importJWK, type JWK } from "jose";

/** An EC P-256 private JWK. `d` is the private scalar — never send it. */
export interface DPoPKey {
  kty: string;
  crv: string;
  x: string;
  y: string;
  d: string;
}

/** Generate a fresh extractable P-256 keypair for one session. */
export async function generateDPoPKey(): Promise<DPoPKey> {
  const { privateKey } = await generateKeyPair("ES256", {
    extractable: true,
  });
  const jwk = await exportJWK(privateKey);
  return {
    kty: jwk.kty!,
    crv: jwk.crv!,
    x: jwk.x!,
    y: jwk.y!,
    d: jwk.d!,
  };
}

/** The public half of the key, as embedded in every proof's header. */
export function publicJWK(key: DPoPKey): JWK {
  return { kty: key.kty, crv: key.crv, x: key.x, y: key.y };
}

/**
 * Mint a DPoP proof JWT for one HTTP request (RFC 9449 §4):
 * `typ: dpop+jwt`, ES256, public JWK in the header, htm/htu/iat/jti
 * claims. Auth-core canonicalises htu as scheme://host/path (no
 * query), so the query string is stripped here.
 */
export async function createDPoPProof(
  key: DPoPKey,
  htm: string,
  url: string,
): Promise<string> {
  const u = new URL(url);
  const htu = `${u.protocol}//${u.host}${u.pathname}`;
  const privateKey = await importJWK(key as JWK, "ES256");
  return await new SignJWT({
    htm: htm.toUpperCase(),
    htu,
    jti: crypto.randomUUID(),
  })
    .setProtectedHeader({
      alg: "ES256",
      typ: "dpop+jwt",
      jwk: publicJWK(key),
    })
    .setIssuedAt()
    .sign(privateKey);
}
