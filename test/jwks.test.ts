import { describe, expect, it } from "vitest";
import { Authio, AuthioError } from "../src/index";

describe("Authio client", () => {
  it("requires an apiKey", () => {
    expect(() => new Authio({ apiKey: "" })).toThrow(/apiKey is required/);
  });

  it("constructs with an apiKey", () => {
    const c = new Authio({ apiKey: "sk_test_abc", apiUrl: "https://api.test" });
    expect(c.users).toBeDefined();
    expect(c.organizations).toBeDefined();
    expect(c.memberships).toBeDefined();
    expect(c.sessions).toBeDefined();
  });

  it("returns null on invalid token", async () => {
    const c = new Authio({
      apiKey: "sk_test_abc",
      apiUrl: "https://api.test",
    });
    const result = await c.sessions.verify("not.a.jwt");
    expect(result).toBeNull();
  });

  it("AuthioError carries code and status", () => {
    const e = new AuthioError({
      code: "test",
      message: "msg",
      status: 418,
      requestId: "req_1",
    });
    expect(e.code).toBe("test");
    expect(e.status).toBe(418);
    expect(e.requestId).toBe("req_1");
  });

  it("token() POSTs to /v1/auth/token with client_credentials", async () => {
    const calls: Array<{ url: string; init: RequestInit | undefined }> = [];
    const fakeFetch: typeof fetch = async (input, init) => {
      calls.push({ url: String(input), init });
      return new Response(
        JSON.stringify({
          access_token: "eyJ.fake.jwt",
          token_type: "Bearer",
          expires_in: 3600,
          scope: "users:read",
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    };
    const c = new Authio({
      apiKey: "sk_test_abc",
      authCoreUrl: "https://auth-api.test",
      fetch: fakeFetch,
    });
    const res = await c.token({
      grant_type: "client_credentials",
      client_id: "mci_abc",
      client_secret: "msc_xyz",
      scope: "users:read",
    });
    expect(res.access_token).toBe("eyJ.fake.jwt");
    expect(res.token_type).toBe("Bearer");
    expect(res.expires_in).toBe(3600);
    expect(calls).toHaveLength(1);
    expect(calls[0]!.url).toBe("https://auth-api.test/v1/auth/token");
    expect(calls[0]!.init?.method).toBe("POST");
    const body = JSON.parse(String(calls[0]!.init?.body));
    expect(body.grant_type).toBe("client_credentials");
    expect(body.client_id).toBe("mci_abc");
  });

  it("token() throws AuthioError on RFC 6749 error envelope", async () => {
    const fakeFetch: typeof fetch = async () =>
      new Response(
        JSON.stringify({
          error: "invalid_client",
          error_description: "unknown client",
        }),
        { status: 401, headers: { "content-type": "application/json" } },
      );
    const c = new Authio({
      apiKey: "sk_test_abc",
      authCoreUrl: "https://auth-api.test",
      fetch: fakeFetch,
    });
    await expect(
      c.token({
        grant_type: "client_credentials",
        client_id: "mci_abc",
        client_secret: "msc_wrong",
      }),
    ).rejects.toMatchObject({ code: "invalid_client", status: 401 });
  });

  it("sessions.refresh() POSTs to /v1/auth/refresh with refresh_token", async () => {
    const calls: Array<{ url: string; init: RequestInit | undefined }> = [];
    const fakeFetch: typeof fetch = async (input, init) => {
      calls.push({ url: String(input), init });
      return new Response(
        JSON.stringify({
          session_id: "sess_abc",
          access_token: "new.access.jwt",
          refresh_token: "new_refresh_value",
          expires_at: new Date(Date.now() + 15 * 60 * 1000).toISOString(),
          user: null,
          memberships: [],
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    };
    const c = new Authio({
      apiKey: "sk_test_abc",
      authCoreUrl: "https://auth-api.test",
      fetch: fakeFetch,
    });
    const env = await c.sessions.refresh({ refreshToken: "old_refresh" });
    expect(env.access_token).toBe("new.access.jwt");
    expect(env.refresh_token).toBe("new_refresh_value");
    expect(env.session_id).toBe("sess_abc");
    expect(calls).toHaveLength(1);
    expect(calls[0]!.url).toBe("https://auth-api.test/v1/auth/refresh");
    expect(calls[0]!.init?.method).toBe("POST");
    const body = JSON.parse(String(calls[0]!.init?.body)) as {
      refresh_token: string;
    };
    expect(body.refresh_token).toBe("old_refresh");
  });

  it("sessions.refresh() throws AuthioError when auth-core surfaces a policy violation", async () => {
    const fakeFetch: typeof fetch = async () =>
      new Response(
        JSON.stringify({
          code: "policy_violation_session_idle",
          message: "session idle longer than organization limit (30 minutes)",
        }),
        { status: 401, headers: { "content-type": "application/json" } },
      );
    const c = new Authio({
      apiKey: "sk_test_abc",
      authCoreUrl: "https://auth-api.test",
      fetch: fakeFetch,
    });
    await expect(
      c.sessions.refresh({ refreshToken: "stale_refresh" }),
    ).rejects.toMatchObject({
      code: "policy_violation_session_idle",
      status: 401,
    });
  });

  it("sessions.refresh() throws missing_refresh_token when no token supplied", async () => {
    const c = new Authio({
      apiKey: "sk_test_abc",
      authCoreUrl: "https://auth-api.test",
    });
    await expect(c.sessions.refresh({ refreshToken: "" })).rejects.toMatchObject(
      { code: "missing_refresh_token" },
    );
  });
});
