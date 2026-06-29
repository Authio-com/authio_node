import "server-only";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import type { SealedBlob } from "./crypto";

/** One row per *your* SaaS tenant — maps to Authio project metadata. */
export interface AuthioConnection {
  yourTenantId: string;
  authioProjectId: string;
  authioTenantId: string;
  projectName: string;
  tenantName: string | null;
  environment: string;
  sealedKey: SealedBlob;
  connectedAt: string;
  lastSyncAt: string | null;
  lastSyncUserCount: number | null;
  lastSyncError: string | null;
}

const DATA_DIR = path.join(process.cwd(), ".data");
const STORE_PATH = path.join(DATA_DIR, "authio-connections.json");

async function readAll(): Promise<Record<string, AuthioConnection>> {
  try {
    const raw = await readFile(STORE_PATH, "utf8");
    return JSON.parse(raw) as Record<string, AuthioConnection>;
  } catch {
    return {};
  }
}

async function writeAll(data: Record<string, AuthioConnection>): Promise<void> {
  await mkdir(DATA_DIR, { recursive: true });
  await writeFile(STORE_PATH, JSON.stringify(data, null, 2), "utf8");
}

export async function getConnection(
  yourTenantId: string,
): Promise<AuthioConnection | null> {
  const all = await readAll();
  return all[yourTenantId] ?? null;
}

export async function saveConnection(conn: AuthioConnection): Promise<void> {
  const all = await readAll();
  all[conn.yourTenantId] = conn;
  await writeAll(all);
}

export async function deleteConnection(yourTenantId: string): Promise<void> {
  const all = await readAll();
  delete all[yourTenantId];
  await writeAll(all);
}

export async function updateSyncResult(
  yourTenantId: string,
  result: {
    userCount: number;
    error?: string | null;
  },
): Promise<void> {
  const conn = await getConnection(yourTenantId);
  if (!conn) return;
  conn.lastSyncAt = new Date().toISOString();
  conn.lastSyncUserCount = result.error ? conn.lastSyncUserCount : result.userCount;
  conn.lastSyncError = result.error ?? null;
  await saveConnection(conn);
}
