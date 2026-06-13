import { auth } from "@useauthio/nextjs/server";

/**
 * Returns the verified session for the current cookie. Returns 401 if no
 * session is present.
 *
 * For lower-latency edge verification, mount @useauthio/nextjs's
 * authMiddleware in middleware.ts; this route then reads the already-
 * verified session via headers().
 */
export async function GET() {
  const { userId, orgId, role, sessionId } = await auth();
  if (!userId) {
    return new Response("Unauthorized", { status: 401 });
  }
  return Response.json({ userId, orgId, role, sessionId });
}
