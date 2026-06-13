import express from "express";
import { Authio, AuthioError } from "@useauthio/node";

const authio = new Authio({
  apiKey: process.env.AUTHIO_SECRET_KEY!,
  apiUrl: process.env.AUTHIO_API_URL,
});

const app = express();
app.use(express.json());

app.get("/whoami", async (req, res) => {
  const auth = req.header("authorization") ?? "";
  const m = /^Bearer\s+(.+)$/.exec(auth);
  if (!m) return res.status(401).json({ code: "missing_token" });
  const session = await authio.sessions.verify(m[1]!);
  if (!session) return res.status(401).json({ code: "invalid_token" });
  res.json(session);
});

app.get("/users/:id/memberships", async (req, res) => {
  try {
    const memberships = await authio.users.listMemberships(req.params.id);
    res.json(memberships);
  } catch (err) {
    if (err instanceof AuthioError) {
      return res.status(err.status).json({ code: err.code, message: err.message });
    }
    throw err;
  }
});

app.post("/organizations", async (req, res) => {
  try {
    const org = await authio.organizations.create(req.body);
    res.status(201).json(org);
  } catch (err) {
    if (err instanceof AuthioError) {
      return res.status(err.status).json({ code: err.code, message: err.message });
    }
    throw err;
  }
});

const port = Number(process.env.PORT ?? 4000);
app.listen(port, () => {
  console.log(`authio-example-express listening on :${port}`);
});
