import { describe, expect, it, vi } from "vitest";
import { jwtVerify, EmbeddedJWK, calculateJwkThumbprint, type JWK } from "jose";
import { generateDPoPKey, createDPoPProof, publicJWK } from "../src/dpop";
import { Authio } from "../src/client";

/** Verify a proof the way auth-core does: signature by the embedded key. */
async function verifyProof(proof: string) {
  const { payload, protectedHeader } = await jwtVerify(proof, EmbeddedJWK, {
    typ: "dpop+jwt",
  });
  return { payload, protectedHeader };
}

describe("dpop helpers", () => {
  it("generates a P-256 private JWK", async () => {
    const key = await generateDPoPKey();
    expect(key.kty).toBe("EC");
    expect(key.crv).toBe("P-256");
    expect(key.d).toBeTruthy();
  });

  it("mints a verifiable RFC 9449 proof", async () => {
    const key = await generateDPoPKey();
    const proof = await createDPoPProof(
      key,
      "post",
      "https://auth.test/v1/auth/refresh?x=1",
    );
    const { payload, protectedHeader } = await verifyProof(proof);
    expect(protectedHeader.alg).toBe("ES256");
    expect(protectedHeader.typ).toBe("dpop+jwt");
    expect((protectedHeader.jwk as JWK).d).toBeUndefined();
    expect(payload.htm).toBe("POST");
    expect(payload.htu).toBe("https://auth.test/v1/auth/refresh");
    expect(typeof payload.jti).toBe("string");
    expect(typeof payload.iat).toBe("number");
  });

  it("uses a fresh jti per proof", async () => {
    const key = await generateDPoPKey();
    const a = await verifyProof(
      await createDPoPProof(key, "POST", "https://auth.test/v1/auth/refresh"),
    );
    const b = await verifyProof(
      await createDPoPProof(key, "POST", "https://auth.test/v1/auth/refresh"),
    );
    expect(a.payload.jti).not.toBe(b.payload.jti);
  });
});

describe("sessions.refresh — dpop", () => {
  it("attaches a DPoP proof signed by the given key", async () => {
    const key = await generateDPoPKey();
    const fetchMock = vi.fn(
      async () =>
        new Response(
          JSON.stringify({ access_token: "at", refresh_token: "rt" }),
          { status: 200, headers: { "content-type": "application/json" } },
        ),
    );
    const authio = new Authio({
      apiKey: "ak_test",
      authCoreUrl: "https://auth.test",
      fetch: fetchMock as unknown as typeof fetch,
    });
    await authio.sessions.refresh({ refreshToken: "rt", dpopKey: key });

    const init = fetchMock.mock.calls[0]![1] as RequestInit;
    const proof = (init.headers as Record<string, string>).DPoP;
    expect(proof).toBeTruthy();
    const { payload, protectedHeader } = await verifyProof(proof);
    expect(payload.htm).toBe("POST");
    expect(payload.htu).toBe("https://auth.test/v1/auth/refresh");
    expect(await calculateJwkThumbprint(protectedHeader.jwk as JWK)).toBe(
      await calculateJwkThumbprint(publicJWK(key) as JWK),
    );
  });

  it("sends no DPoP header without a key", async () => {
    const fetchMock = vi.fn(
      async () =>
        new Response(JSON.stringify({ access_token: "at" }), {
          status: 200,
          headers: { "content-type": "application/json" },
        }),
    );
    const authio = new Authio({
      apiKey: "ak_test",
      authCoreUrl: "https://auth.test",
      fetch: fetchMock as unknown as typeof fetch,
    });
    await authio.sessions.refresh({ refreshToken: "rt" });
    const init = fetchMock.mock.calls[0]![1] as RequestInit;
    expect((init.headers as Record<string, string>).DPoP).toBeUndefined();
  });
});
