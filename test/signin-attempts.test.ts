import { describe, expect, it } from "vitest";
import { Authio } from "../src/index";

function stubFetch(
  body: unknown,
  captured: { url: string; method: string }[],
): typeof fetch {
  return (async (url: string, init?: RequestInit) => {
    captured.push({ url, method: (init?.method ?? "GET").toUpperCase() });
    return {
      ok: true,
      status: 200,
      json: async () => body,
    } as Response;
  }) as unknown as typeof fetch;
}

describe("authio.signinAttempts", () => {
  it("lists with filters including has_hop_anomaly", async () => {
    const captured: { url: string; method: string }[] = [];
    const authio = new Authio({
      apiKey: "sk_test",
      apiUrl: "https://api.test",
      fetch: stubFetch({ data: [], next_cursor: null }, captured),
    });
    await authio.signinAttempts.list({
      user_id: "user_1",
      has_hop_anomaly: true,
      limit: 5,
    });
    expect(captured).toHaveLength(1);
    expect(captured[0]!.method).toBe("GET");
    const u = new URL(captured[0]!.url);
    expect(u.pathname).toBe("/v1/signin-attempts");
    expect(u.searchParams.get("user_id")).toBe("user_1");
    expect(u.searchParams.get("has_hop_anomaly")).toBe("1");
    expect(u.searchParams.get("limit")).toBe("5");
  });

  it("gets a single attempt by id", async () => {
    const captured: { url: string; method: string }[] = [];
    const authio = new Authio({
      apiKey: "sk_test",
      apiUrl: "https://api.test",
      fetch: stubFetch(
        { id: "sia_1", hops: [], hop_anomalies: [] },
        captured,
      ),
    });
    const res = await authio.signinAttempts.get("sia_1");
    expect(res.id).toBe("sia_1");
    expect(captured[0]!.url).toBe("https://api.test/v1/signin-attempts/sia_1");
  });
});
