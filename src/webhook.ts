/**
 * Authio webhook verification + session denylist (minimal Node mirror
 * of @useauthio/nextjs's webhook module). Revocation-signals program,
 * Phase 1 (2026-09-09).
 *
 * Access JWTs verify offline against the JWKS, so a revoked Authio
 * session keeps "working" at your API until the token expires. Authio
 * emits a `session.revoked` webhook at every death point (sign-out,
 * admin revoke, refresh-reuse family kill, session/network policy,
 * impersonation revoke, SCIM deprovision — `metadata.reason` says
 * which); feed it to a denylist and pass that to `JwtVerifier` to close
 * the gap.
 *
 * Framework-agnostic by design (Express/Fastify/Koa/raw http all differ
 * in body handling): you hand `handleAuthioWebhook` the RAW request
 * body string and the `Authio-Signature` header, it returns the status
 * code to respond with.
 *
 *   app.post("/authio/webhook", express.raw({ type: "application/json" }), async (req, res) => {
 *     const { status } = await handleAuthioWebhook(req.body.toString(), req.get("Authio-Signature"), {
 *       secret: process.env.AUTHIO_WEBHOOK_SECRET!,
 *       denylist,
 *     });
 *     res.sendStatus(status);
 *   });
 *
 * Signature contract (authio_webhooks, Stripe-style):
 *   Authio-Signature: t=<unix-seconds>,v1=<hex-hmac-sha256>
 * computed over `<t>.<raw-body>` with the endpoint's `whsec_…` secret.
 */
import { createHmac, timingSafeEqual } from "node:crypto";

/** Pluggable session-id denylist. Implement with Redis for multi-instance deploys. */
export interface SessionDenylist {
  add(sid: string, expiresAtMs: number): Promise<void> | void;
  has(sid: string): Promise<boolean> | boolean;
}

/** In-memory denylist. Per-process; use a shared adapter on multi-instance deploys. */
export class MemorySessionDenylist implements SessionDenylist {
  private entries = new Map<string, number>();
  private lastSweep = 0;

  add(sid: string, expiresAtMs: number): void {
    if (!sid) return;
    this.entries.set(sid, expiresAtMs);
    const now = Date.now();
    if (now - this.lastSweep > 60_000) {
      this.lastSweep = now;
      for (const [k, exp] of this.entries) {
        if (exp <= now) this.entries.delete(k);
      }
    }
  }

  has(sid: string): boolean {
    const exp = this.entries.get(sid);
    if (exp === undefined) return false;
    if (exp <= Date.now()) {
      this.entries.delete(sid);
      return false;
    }
    return true;
  }
}

/** The delivery body authio_webhooks POSTs. */
export interface AuthioWebhookEvent {
  id: string;
  action: string;
  created_at: string;
  project_id: string;
  organization_id: string | null;
  user_id: string | null;
  target_type: string | null;
  target_id: string | null;
  metadata: Record<string, unknown> | null;
  actor: { type: string | null; id: string | null };
}

/** Verify an `Authio-Signature` header against the raw request body. */
export function verifyAuthioWebhookSignature(
  body: string,
  header: string | null | undefined,
  secret: string,
  opts: { toleranceMs?: number; now?: number } = {},
): boolean {
  if (!header || !secret) return false;
  let t = "";
  let v1 = "";
  for (const part of header.split(",")) {
    const p = part.trim();
    if (p.startsWith("t=")) t = p.slice(2);
    else if (p.startsWith("v1=")) v1 = p.slice(3);
  }
  if (!t || !v1) return false;
  const ts = Number(t);
  if (!Number.isFinite(ts)) return false;
  const toleranceMs = opts.toleranceMs ?? 300_000;
  const now = opts.now ?? Date.now();
  if (Math.abs(now - ts * 1000) > toleranceMs) return false;

  const expected = createHmac("sha256", secret).update(`${t}.${body}`).digest();
  let given: Buffer;
  try {
    given = Buffer.from(v1, "hex");
  } catch {
    return false;
  }
  return given.length === expected.length && timingSafeEqual(given, expected);
}

export interface HandleAuthioWebhookOptions {
  /** The endpoint's signing secret (`whsec_…`). */
  secret: string;
  /** Denylist to feed on `session.revoked`. */
  denylist?: SessionDenylist;
  /** How long a revoked sid stays denylisted, in ms. Default 1h. */
  denylistTtlMs?: number;
  /** Max signature age. Default 5 minutes. */
  toleranceMs?: number;
  /** Called for every verified event. */
  onEvent?: (event: AuthioWebhookEvent) => void | Promise<void>;
}

/**
 * Verify + process one webhook delivery. Returns the HTTP status your
 * route should respond with (401 bad signature, 400 bad JSON, 200
 * otherwise) plus the parsed event when verification succeeded.
 */
export async function handleAuthioWebhook(
  rawBody: string,
  signatureHeader: string | null | undefined,
  opts: HandleAuthioWebhookOptions,
): Promise<{ status: number; event?: AuthioWebhookEvent }> {
  if (
    !verifyAuthioWebhookSignature(rawBody, signatureHeader, opts.secret, {
      toleranceMs: opts.toleranceMs,
    })
  ) {
    return { status: 401 };
  }
  let event: AuthioWebhookEvent;
  try {
    event = JSON.parse(rawBody) as AuthioWebhookEvent;
  } catch {
    return { status: 400 };
  }
  if (
    opts.denylist &&
    event.action === "session.revoked" &&
    event.target_type === "session" &&
    typeof event.target_id === "string" &&
    event.target_id
  ) {
    await opts.denylist.add(
      event.target_id,
      Date.now() + (opts.denylistTtlMs ?? 3_600_000),
    );
  }
  if (opts.onEvent) await opts.onEvent(event);
  return { status: 200, event };
}
