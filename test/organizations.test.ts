import { describe, expect, it, vi } from "vitest";
import { Authio } from "../src/index";

describe("authio.organizations.getPolicy", () => {
  it("GETs /v1/organizations/:id/policy with the secret key", async () => {
    const fetch = vi.fn(async () =>
      Response.json({
        policy: {
          organization_id: "org_1",
          project_id: "proj_1",
          require_sso: false,
          require_mfa: false,
          require_passkey: false,
          session_idle_timeout_min: 30,
          session_absolute_max_min: 0,
          refresh_window_min: 0,
          access_token_ttl_min: 0,
          allowed_ip_cidrs: [],
          blocked_countries: [],
          disabled_methods: [],
          mfa_allowed_methods: [],
          allow_signup: false,
          updated_at: "2026-08-30T00:00:00.000Z",
          updated_by: null,
        },
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
    expect(res.effective.access_token_ttl_min).toBe(15);
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
