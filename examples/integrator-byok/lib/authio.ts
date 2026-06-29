import "server-only";
import { Authio, AuthioError } from "@useauthio/node";
import { decryptApiKey } from "./crypto";
import type { AuthioConnection } from "./store";

export interface ProjectMe {
  id: string;
  tenant_id: string;
  name: string;
  environment: string;
  created_at: string;
  tenant: { name: string | null };
}

function apiUrl(): string {
  return process.env.AUTHIO_API_URL ?? "https://api.authio.com";
}

export async function validateApiKey(apiKey: string): Promise<ProjectMe> {
  const authio = new Authio({ apiKey, apiUrl: apiUrl() });
  return authio.request<ProjectMe>("GET", "/v1/projects/me");
}

export function clientForConnection(conn: AuthioConnection): Authio {
  const master = process.env.INTEGRATOR_CREDS_KEY ?? "";
  const apiKey = decryptApiKey(conn.sealedKey, master);
  return new Authio({ apiKey, apiUrl: apiUrl() });
}

export async function syncUsers(conn: AuthioConnection): Promise<number> {
  const authio = clientForConnection(conn);
  const page = await authio.request<{ data: unknown[]; next_cursor: string | null }>(
    "GET",
    "/v1/users?limit=100",
  );
  return page.data.length;
}

export function friendlyAuthioError(err: unknown): string {
  if (err instanceof AuthioError) {
    if (err.status === 401) {
      return "Invalid or revoked API key — ask your customer to reconnect.";
    }
    if (err.status === 403) {
      return "API key lacks required scopes (users:read, etc.).";
    }
    return err.message;
  }
  if (err instanceof Error) return err.message;
  return "Unexpected error";
}
