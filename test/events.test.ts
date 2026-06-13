import { describe, expect, it } from "vitest";
import { Authio, type AuthioEvent } from "../src/index";

/**
 * Tests for authio.events. A fetch stub stands in for the
 * management-API GET /v1/events, returning cursor-paginated pages so we can
 * assert the query serialization, the camelCase result mapping, and the
 * auto-paginating iterator's no-gap/no-dup cursor walk.
 */

interface Page {
  data: AuthioEvent[];
  list_metadata: { after: string | null };
}

function makeEvent(id: string, event = "user.created"): AuthioEvent {
  return {
    id,
    event,
    created_at: "2026-06-11T00:00:00.000Z",
    data: {
      organization_id: "org_1",
      user_id: "user_1",
      actor_type: "user",
      actor_id: "user_1",
      target_type: "user",
      target_id: "user_1",
      metadata: {},
    },
  };
}

function stubFetch(
  pages: Page[],
  captured: string[],
): typeof fetch {
  let call = 0;
  return (async (url: string) => {
    captured.push(url);
    const body = pages[Math.min(call, pages.length - 1)]!;
    call++;
    return {
      ok: true,
      status: 200,
      json: async () => body,
    } as Response;
  }) as unknown as typeof fetch;
}

describe("authio.events.list", () => {
  it("serializes events[]/range/limit/after and maps list_metadata→listMetadata", async () => {
    const captured: string[] = [];
    const authio = new Authio({
      apiKey: "sk_test",
      apiUrl: "https://api.test",
      fetch: stubFetch([{ data: [makeEvent("evt_1")], list_metadata: { after: "cur1" } }], captured),
    });
    const res = await authio.events.list({
      events: ["user.created", "session.created"],
      rangeStart: "2026-06-01T00:00:00Z",
      rangeEnd: "2026-06-11T00:00:00Z",
      limit: 50,
      after: "abc",
    });
    expect(res.data).toHaveLength(1);
    expect(res.listMetadata.after).toBe("cur1");
    const u = new URL(captured[0]!);
    expect(u.pathname).toBe("/v1/events");
    expect(u.searchParams.getAll("events[]")).toEqual(["user.created", "session.created"]);
    expect(u.searchParams.get("range_start")).toBe("2026-06-01T00:00:00Z");
    expect(u.searchParams.get("range_end")).toBe("2026-06-11T00:00:00Z");
    expect(u.searchParams.get("limit")).toBe("50");
    expect(u.searchParams.get("after")).toBe("abc");
  });

  it("omits the query string entirely when no options are given", async () => {
    const captured: string[] = [];
    const authio = new Authio({
      apiKey: "sk_test",
      apiUrl: "https://api.test",
      fetch: stubFetch([{ data: [], list_metadata: { after: null } }], captured),
    });
    await authio.events.list();
    expect(captured[0]).toBe("https://api.test/v1/events");
  });
});

describe("authio.events.iterate", () => {
  it("walks every page once, following after cursors until null", async () => {
    const captured: string[] = [];
    const pages: Page[] = [
      { data: [makeEvent("evt_1"), makeEvent("evt_2")], list_metadata: { after: "c1" } },
      { data: [makeEvent("evt_3"), makeEvent("evt_4")], list_metadata: { after: "c2" } },
      { data: [makeEvent("evt_5")], list_metadata: { after: null } },
    ];
    let call = 0;
    const fetchFn = (async (url: string) => {
      captured.push(url);
      const body = pages[call++]!;
      return { ok: true, status: 200, json: async () => body } as Response;
    }) as unknown as typeof fetch;

    const authio = new Authio({ apiKey: "sk_test", apiUrl: "https://api.test", fetch: fetchFn });
    const seen: string[] = [];
    for await (const ev of authio.events.iterate({ events: ["user.created"] })) {
      seen.push(ev.id);
    }
    expect(seen).toEqual(["evt_1", "evt_2", "evt_3", "evt_4", "evt_5"]);
    expect(new Set(seen).size).toBe(5);
    // First page has no `after`; subsequent pages carry the prior cursor.
    expect(new URL(captured[0]!).searchParams.get("after")).toBeNull();
    expect(new URL(captured[1]!).searchParams.get("after")).toBe("c1");
    expect(new URL(captured[2]!).searchParams.get("after")).toBe("c2");
  });

  it("stops cleanly on an empty first page", async () => {
    const captured: string[] = [];
    const authio = new Authio({
      apiKey: "sk_test",
      apiUrl: "https://api.test",
      fetch: stubFetch([{ data: [], list_metadata: { after: null } }], captured),
    });
    const seen: AuthioEvent[] = [];
    for await (const ev of authio.events.iterate()) seen.push(ev);
    expect(seen).toHaveLength(0);
    expect(captured).toHaveLength(1);
  });
});
