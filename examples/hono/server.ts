import { Hono } from "hono";
import { serve } from "@hono/node-server";
import { Authio, AuthioError } from "@useauthio/node";

const authio = new Authio({
  apiKey: process.env.AUTHIO_SECRET_KEY!,
  apiUrl: process.env.AUTHIO_API_URL,
});

const app = new Hono();

app.get("/whoami", async (c) => {
  const auth = c.req.header("authorization") ?? "";
  const m = /^Bearer\s+(.+)$/.exec(auth);
  if (!m) return c.json({ code: "missing_token" }, 401);
  const session = await authio.sessions.verify(m[1]!);
  if (!session) return c.json({ code: "invalid_token" }, 401);
  return c.json(session);
});

app.get("/users/:id/memberships", async (c) => {
  try {
    const memberships = await authio.users.listMemberships(c.req.param("id"));
    return c.json(memberships);
  } catch (err) {
    if (err instanceof AuthioError) {
      return c.json({ code: err.code, message: err.message }, err.status as 400);
    }
    throw err;
  }
});

app.post("/organizations", async (c) => {
  const body = (await c.req.json().catch(() => null)) as
    | { name: string; slug?: string; domain?: string }
    | null;
  if (!body?.name) {
    return c.json({ code: "missing_name" }, 400);
  }
  try {
    const org = await authio.organizations.create(body);
    return c.json(org, 201);
  } catch (err) {
    if (err instanceof AuthioError) {
      return c.json({ code: err.code, message: err.message }, err.status as 400);
    }
    throw err;
  }
});

const port = Number(process.env.PORT ?? 4000);
serve({ fetch: app.fetch, port }, (info) => {
  console.log(`authio-example-hono listening on :${info.port}`);
});
