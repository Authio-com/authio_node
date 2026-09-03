import { describe, expect, it, vi } from "vitest";
import { Authio } from "../src/index";

describe("authio.sessions user-authenticated mutations", () => {
  it("switchOrg calls auth-core with the user access token", async () => {
    const fetch = vi.fn(async () =>
      Response.json({
        sessionId: "sess_1",
        userId: "user_1",
        orgId: "org_2",
        role: "member",
        expiresAt: "2099-01-01T00:00:00Z",
        claims: {},
        flags: [],
      }),
    );
    const authio = new Authio({
      apiKey: "sk_must_not_be_sent",
      apiUrl: "https://manage.test",
      authCoreUrl: "https://identity.test",
      fetch,
    });

    await authio.sessions.switchOrg("user-access-jwt", {
      organizationId: "org_2",
    });

    expect(fetch).toHaveBeenCalledWith(
      "https://identity.test/v1/sessions/switch-org",
      expect.objectContaining({
        method: "POST",
        headers: expect.objectContaining({
          authorization: "Bearer user-access-jwt",
        }),
        body: JSON.stringify({ organization_id: "org_2" }),
      }),
    );
    expect(JSON.stringify(fetch.mock.calls[0])).not.toContain(
      "sk_must_not_be_sent",
    );
  });

  it("revoke calls auth-core with an empty body and user access token", async () => {
    const fetch = vi.fn(async () => new Response(null, { status: 204 }));
    const authio = new Authio({
      apiKey: "sk_must_not_be_sent",
      apiUrl: "https://manage.test",
      authCoreUrl: "https://identity.test/",
      fetch,
    });

    await authio.sessions.revoke("user-access-jwt");

    expect(fetch).toHaveBeenCalledWith(
      "https://identity.test/v1/sessions/revoke",
      expect.objectContaining({
        method: "POST",
        headers: expect.objectContaining({
          authorization: "Bearer user-access-jwt",
        }),
        body: "{}",
      }),
    );
  });
});

describe("authio.organizations.getPolicy", () => {
  it("GETs /v1/organizations/:id/policy with the secret key", async () => {
    const fetch = vi.fn(async () =>
      Response.json({
        policy: { organization_id: "org_1", session_idle_timeout_min: 30 },
        effective: {
          session_idle_timeout_min: 30,
          session_absolute_max_min: null,
          refresh_window_min: null,
          access_token_ttl_min: 15,
        },
      }),
    );
    const authio = new Authio({
      apiKey: "sk_test_abc",
      apiUrl: "https://manage.test",
      fetch,
    });
    const res = await authio.organizations.getPolicy("org_1");
    expect(res.effective.session_idle_timeout_min).toBe(30);
    expect(fetch).toHaveBeenCalledWith(
      "https://manage.test/v1/organizations/org_1/policy",
      expect.objectContaining({
        method: "GET",
        headers: expect.objectContaining({
          authorization: "Bearer sk_test_abc",
        }),
      }),
    );
  });
});
