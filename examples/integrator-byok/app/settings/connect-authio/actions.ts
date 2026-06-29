"use server";

import { revalidatePath } from "next/cache";
import { encryptApiKey } from "@/lib/crypto";
import {
  deleteConnection,
  getConnection,
  saveConnection,
  updateSyncResult,
} from "@/lib/store";
import {
  friendlyAuthioError,
  syncUsers,
  validateApiKey,
} from "@/lib/authio";

const SETTINGS_PATH = "/settings/connect-authio";

function demoTenantId(): string {
  return process.env.DEMO_TENANT_ID ?? "tenant_demo_acme";
}

function credsKey(): string {
  const key = process.env.INTEGRATOR_CREDS_KEY ?? "";
  if (!key) {
    throw new Error(
      "INTEGRATOR_CREDS_KEY is not set — generate a 32+ byte base64 secret.",
    );
  }
  return key;
}

export type ConnectState =
  | { ok: true; message: string }
  | { ok: false; error: string };

export async function connectAuthio(
  _prev: ConnectState | null,
  formData: FormData,
): Promise<ConnectState> {
  const raw = formData.get("apiKey");
  if (typeof raw !== "string" || !raw.startsWith("sk_")) {
    return { ok: false, error: "Paste a valid sk_live_ or sk_test_ key." };
  }

  try {
    const project = await validateApiKey(raw.trim());
    const yourTenantId = demoTenantId();
    const sealedKey = encryptApiKey(raw.trim(), credsKey());

    await saveConnection({
      yourTenantId,
      authioProjectId: project.id,
      authioTenantId: project.tenant_id,
      projectName: project.name,
      tenantName: project.tenant?.name ?? null,
      environment: project.environment,
      sealedKey,
      connectedAt: new Date().toISOString(),
      lastSyncAt: null,
      lastSyncUserCount: null,
      lastSyncError: null,
    });

    revalidatePath(SETTINGS_PATH);
    return {
      ok: true,
      message: `Connected to ${project.name} (${project.id}).`,
    };
  } catch (err) {
    return { ok: false, error: friendlyAuthioError(err) };
  }
}

export async function disconnectAuthio(): Promise<ConnectState> {
  await deleteConnection(demoTenantId());
  revalidatePath(SETTINGS_PATH);
  return { ok: true, message: "Disconnected Authio." };
}

export async function syncAuthioNow(): Promise<ConnectState> {
  const conn = await getConnection(demoTenantId());
  if (!conn) {
    return { ok: false, error: "No Authio connection — connect a key first." };
  }

  try {
    const userCount = await syncUsers(conn);
    await updateSyncResult(demoTenantId(), { userCount });
    revalidatePath(SETTINGS_PATH);
    return {
      ok: true,
      message: `Synced ${userCount} user(s) from Authio.`,
    };
  } catch (err) {
    const error = friendlyAuthioError(err);
    await updateSyncResult(demoTenantId(), { userCount: 0, error });
    revalidatePath(SETTINGS_PATH);
    return { ok: false, error };
  }
}

export async function loadConnectionForPage() {
  return getConnection(demoTenantId());
}
