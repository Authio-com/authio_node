import { Authio, AuthioError } from "@useauthio/node";

const authio = new Authio({
  apiKey: process.env.AUTHIO_SECRET_KEY!,
  apiUrl: process.env.AUTHIO_API_URL,
});

/**
 * Returns the user's memberships across every organization in your project.
 * Multi-org-aware: a single user identity can hold multiple memberships.
 */
export async function GET(
  _req: Request,
  ctx: { params: Promise<{ id: string }> },
) {
  const { id } = await ctx.params;
  try {
    const memberships = await authio.users.listMemberships(id);
    return Response.json(memberships);
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
