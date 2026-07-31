import { createServer, type Server } from "node:http";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { SignJWT, exportJWK, generateKeyPair } from "jose";
import { JwtVerifier } from "../src/jwks";

/**
 * Authio signs every tenant's tokens with the same key, issuer and
 * audience. Signature + iss + aud therefore prove a token came from
 * Authio, not that it was minted for the customer verifying it.
 *
 * These tests use REAL Ed25519 keys and REAL jose verification against
 * a stubbed JWKS endpoint, so they exercise the same code path a
 * customer's backend runs — not a reimplementation of it.
 */

const ISSUER = "https://identity.authio.com";
const AUDIENCE = "authio";

let privateKey: CryptoKey;
let server: Server;
// A real JWKS endpoint on loopback: jose's Node build fetches the key
// set over http(s) rather than through global fetch, so serving it for
// real is what makes this exercise the customer's actual code path.
let apiUrl: string;

beforeEach(async () => {
  const { privateKey: priv, publicKey } = await generateKeyPair("EdDSA", {
    crv: "Ed25519",
    extractable: true,
  });
  privateKey = priv as CryptoKey;
  const jwk = await exportJWK(publicKey);
  jwk.kid = "test-kid";
  jwk.alg = "EdDSA";
  jwk.use = "sig";
  const jwksBody = JSON.stringify({ keys: [jwk] });

  server = createServer((req, res) => {
    if (req.url?.includes("jwks.json")) {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(jwksBody);
      return;
    }
    res.writeHead(404);
    res.end();
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address();
  if (typeof addr === "string" || addr === null) throw new Error("no port");
  apiUrl = `http://127.0.0.1:${addr.port}`;
});

afterEach(async () => {
  vi.restoreAllMocks();
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

async function mint(claims: Record<string, unknown>): Promise<string> {
  return new SignJWT(claims)
    .setProtectedHeader({ alg: "EdDSA", kid: "test-kid" })
    .setIssuer(ISSUER)
    .setAudience(AUDIENCE)
    .setIssuedAt()
    .setExpirationTime("5m")
    .sign(privateKey);
}

describe("JwtVerifier tenant binding", () => {
  it("rejects a token minted for another project", async () => {
    // The attack: sign up for your own Authio project, create
    // ceo@victim-customer.com in it, send the token to the victim.
    // Everything except project_id looks perfect.
    const token = await mint({
      sub: "user_attacker",
      sid: "sess_1",
      email: "ceo@victim-customer.com",
      project_id: "proj_attacker",
    });
    const verifier = new JwtVerifier(apiUrl, ISSUER, AUDIENCE, "proj_victim");

    await expect(verifier.verify(token)).rejects.toThrow(
      /issued for project proj_attacker, not proj_victim/,
    );
  });

  it("accepts a token minted for the configured project", async () => {
    const token = await mint({
      sub: "user_real",
      sid: "sess_1",
      project_id: "proj_victim",
    });
    const verifier = new JwtVerifier(apiUrl, ISSUER, AUDIENCE, "proj_victim");

    const claims = await verifier.verify(token);
    expect(claims.sub).toBe("user_real");
    expect(claims.project_id).toBe("proj_victim");
  });

  it("warns but still accepts a token with no project_id claim", async () => {
    // Sessions issued before auth-core started stamping the claim are
    // still live. Rejecting them would sign real users out to defend
    // against a token that can no longer be obtained.
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const token = await mint({ sub: "user_legacy", sid: "sess_1" });
    const verifier = new JwtVerifier(apiUrl, ISSUER, AUDIENCE, "proj_victim");

    const claims = await verifier.verify(token);
    expect(claims.sub).toBe("user_legacy");
    expect(warn).toHaveBeenCalledWith(expect.stringMatching(/no project_id claim/));
  });

  it("warns only once about an absent claim, not per request", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const verifier = new JwtVerifier(apiUrl, ISSUER, AUDIENCE, "proj_victim");
    for (let i = 0; i < 3; i++) {
      await verifier.verify(await mint({ sub: "user_legacy", sid: `sess_${i}` }));
    }
    expect(warn).toHaveBeenCalledTimes(1);
  });

  it("warns when no projectId is configured, and stays permissive", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const token = await mint({ sub: "user_x", project_id: "proj_anyone" });
    const verifier = new JwtVerifier(apiUrl, ISSUER, AUDIENCE);

    const claims = await verifier.verify(token);
    expect(claims.sub).toBe("user_x");
    expect(warn).toHaveBeenCalledWith(expect.stringMatching(/no projectId configured/));
  });

  it("still enforces issuer and audience", async () => {
    const wrongIssuer = await new SignJWT({ sub: "u", project_id: "proj_victim" })
      .setProtectedHeader({ alg: "EdDSA", kid: "test-kid" })
      .setIssuer("https://evil.example.com")
      .setAudience(AUDIENCE)
      .setIssuedAt()
      .setExpirationTime("5m")
      .sign(privateKey);
    const verifier = new JwtVerifier(apiUrl, ISSUER, AUDIENCE, "proj_victim");

    await expect(verifier.verify(wrongIssuer)).rejects.toThrow();
  });
});
