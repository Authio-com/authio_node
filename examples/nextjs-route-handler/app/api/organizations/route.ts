import { Authio, AuthioError } from "@useauthio/node";

const authio = new Authio({
  apiKey: process.env.AUTHIO_SECRET_KEY!,
  apiUrl: process.env.AUTHIO_API_URL,
});

export async function POST(req: Request) {
  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return Response.json({ code: "invalid_json" }, { status: 400 });
  }
  if (
    !body ||
    typeof body !== "object" ||
    typeof (body as { name?: unknown }).name !== "string"
  ) {
    return Response.json({ code: "missing_name" }, { status: 422 });
  }
  const input = body as { name: string; slug?: string; domain?: string };
  try {
    const org = await authio.organizations.create(input);
    return Response.json(org, { status: 201 });
  } catch (err) {
    if (err instanceof AuthioError) {
      return Response.json(
        { code: err.code, message: err.message },
        { status: err.status },
      );
    }
    throw err;
  }
}
