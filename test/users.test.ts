import { describe, expect, it, vi } from "vitest";
import { Authio, AuthioError } from "../src/index";

function client(fetch: ReturnType<typeof vi.fn>) {
  return new Authio({
    apiKey: "sk_test_abc",
    apiUrl: "https://manage.test",
    authCoreUrl: "https://identity.test",
    fetch,
  });
}

describe("authio.users email changes", () => {
  it("update PATCHes snake_case fields and returns the outcome", async () => {
    const fetch = vi.fn(async () =>
      Response.json({ id: "user_1", email: "new@example.com", email_changed: true, sessions_revoked: 2 }),
    );
    const res = await client(fetch).users.update("user_1", {
      email: "new@example.com",
      emailVerified: true,
      revokeSessions: true,
      notifyPreviousEmail: true,
      externalId: "ext_9",
    });
    expect(res.email_changed).toBe(true);
    expect(res.sessions_revoked).toBe(2);
    expect(fetch).toHaveBeenCalledWith(
      "https://manage.test/v1/users/user_1",
      expect.objectContaining({ method: "PATCH" }),
    );
    const init = fetch.mock.calls[0]![1] as RequestInit;
    expect(JSON.parse(init.body as string)).toEqual({
      email: "new@example.com",
      email_verified: true,
      revoke_sessions: true,
      notify_previous_email: true,
      external_id: "ext_9",
    });
  });

  it("update omits fields that were not passed", async () => {
    const fetch = vi.fn(async () => Response.json({ id: "user_1" }));
    await client(fetch).users.update("user_1", { name: "Ada" });
    const init = fetch.mock.calls[0]![1] as RequestInit;
    expect(JSON.parse(init.body as string)).toEqual({ name: "Ada" });
  });

  it("update surfaces email_managed_by_idp as an AuthioError", async () => {
    const fetch = vi.fn(async () =>
      Response.json(
        { code: "email_managed_by_idp", message: "Change it in the IdP." },
        { status: 409 },
      ),
    );
    const err = await client(fetch)
      .users.update("user_1", { email: "new@example.com" })
      .catch((e: unknown) => e);
    expect(err).toBeInstanceOf(AuthioError);
    expect((err as AuthioError).code).toBe("email_managed_by_idp");
    expect((err as AuthioError).status).toBe(409);
  });

  it("requestEmailChange POSTs to the management API", async () => {
    const fetch = vi.fn(async () =>
      Response.json(
        { sent: true, email: "new@example.com", expires_at: "2026-10-11T00:00:00Z" },
        { status: 202 },
      ),
    );
    const res = await client(fetch).users.requestEmailChange("user_1", { email: "new@example.com" });
    expect(res.sent).toBe(true);
    expect(fetch).toHaveBeenCalledWith(
      "https://manage.test/v1/users/user_1/email-change",
      expect.objectContaining({ method: "POST", body: JSON.stringify({ email: "new@example.com" }) }),
    );
  });

  it("requestOwnEmailChange calls auth-core with the user's token, not the secret key", async () => {
    const fetch = vi.fn(async () =>
      Response.json({ sent: true, email: "new@example.com", expires_at: "2026-10-11T00:00:00Z" }),
    );
    await client(fetch).users.requestOwnEmailChange("user-access-jwt", {
      email: "new@example.com",
      code: "123456",
    });
    expect(fetch).toHaveBeenCalledWith(
      "https://identity.test/v1/auth/email/change",
      expect.objectContaining({
        method: "POST",
        headers: expect.objectContaining({ authorization: "Bearer user-access-jwt" }),
        body: JSON.stringify({ email: "new@example.com", code: "123456" }),
      }),
    );
    expect(JSON.stringify(fetch.mock.calls[0])).not.toContain("sk_test_abc");
  });

  it("requestOwnEmailChange leaves out an absent code", async () => {
    const fetch = vi.fn(async () => Response.json({ sent: true }));
    await client(fetch).users.requestOwnEmailChange("jwt", { email: "new@example.com" });
    const init = fetch.mock.calls[0]![1] as RequestInit;
    expect(init.body).toBe(JSON.stringify({ email: "new@example.com" }));
  });
});
