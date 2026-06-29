import { describe, expect, it } from "vitest";
import {
  decryptApiKey,
  encryptApiKey,
} from "../examples/integrator-byok/lib/crypto";

describe("integrator BYOK crypto", () => {
  const master = "test-master-key-for-unit-tests-only!!";

  it("round-trips an sk_live_ key", () => {
    const plain = "sk_live_abc123secret";
    const sealed = encryptApiKey(plain, master);
    expect(decryptApiKey(sealed, master)).toBe(plain);
  });

  it("fails decrypt with wrong master", () => {
    const sealed = encryptApiKey("sk_live_x", master);
    expect(() => decryptApiKey(sealed, "wrong-key")).toThrow();
  });

  it("requires master key", () => {
    expect(() => encryptApiKey("sk_live_x", "")).toThrow(/INTEGRATOR_CREDS_KEY/);
  });
});
