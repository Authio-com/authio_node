// Revocation-signals Phase 1: webhook verification + denylist (Node
// mirror of the nextjs SDK module). Pins the Authio-Signature HMAC
// contract and handleAuthioWebhook's status/denylist behaviour.
import { createHmac } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  handleAuthioWebhook,
  verifyAuthioWebhookSignature,
  MemorySessionDenylist,
} from "../src/webhook";

function sign(secret: string, body: string, tSec: number) {
  const mac = createHmac("sha256", secret).update(`${tSec}.${body}`).digest("hex");
  return `t=${tSec},v1=${mac}`;
}

const revoked = JSON.stringify({
  id: "evt_1",
  action: "session.revoked",
  created_at: new Date().toISOString(),
  project_id: "proj_x",
  organization_id: null,
  user_id: "user_x",
  target_type: "session",
  target_id: "sess_dead",
  metadata: { reason: "scim_deprovision" },
  actor: { type: "system", id: null },
});

describe("verifyAuthioWebhookSignature", () => {
  it("accepts valid, rejects tampered/stale/missing", () => {
    const now = Math.floor(Date.now() / 1000);
    const header = sign("whsec_test", revoked, now);
    expect(verifyAuthioWebhookSignature(revoked, header, "whsec_test")).toBe(true);
    expect(verifyAuthioWebhookSignature(revoked + " ", header, "whsec_test")).toBe(false);
    expect(verifyAuthioWebhookSignature(revoked, header, "whsec_other")).toBe(false);
    expect(verifyAuthioWebhookSignature(revoked, null, "whsec_test")).toBe(false);
    const stale = sign("whsec_test", revoked, now - 600);
    expect(verifyAuthioWebhookSignature(revoked, stale, "whsec_test")).toBe(false);
  });
});

describe("handleAuthioWebhook", () => {
  it("denylists the sid on session.revoked and returns 200", async () => {
    const denylist = new MemorySessionDenylist();
    const header = sign("whsec_test", revoked, Math.floor(Date.now() / 1000));
    const { status, event } = await handleAuthioWebhook(revoked, header, {
      secret: "whsec_test",
      denylist,
    });
    expect(status).toBe(200);
    expect(event?.action).toBe("session.revoked");
    expect(denylist.has("sess_dead")).toBe(true);
  });

  it("returns 401 on bad signature without touching the denylist", async () => {
    const denylist = new MemorySessionDenylist();
    const { status } = await handleAuthioWebhook(revoked, "t=1,v1=00", {
      secret: "whsec_test",
      denylist,
    });
    expect(status).toBe(401);
    expect(denylist.has("sess_dead")).toBe(false);
  });
});
