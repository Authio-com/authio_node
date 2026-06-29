import Link from "next/link";
import { ConnectAuthioPanel } from "./ConnectAuthioPanel";
import { loadConnectionForPage } from "./actions";

export const dynamic = "force-dynamic";

export default async function ConnectAuthioSettingsPage() {
  const conn = await loadConnectionForPage();

  return (
    <main className="mx-auto max-w-2xl px-6 py-10">
      <p className="text-xs font-medium uppercase tracking-wider text-zinc-500">
        Reference example · integrator BYOK
      </p>
      <h1 className="mt-2 text-2xl font-semibold tracking-tight">
        Connect Authio
      </h1>
      <p className="mt-2 text-sm text-zinc-600">
        Minimal pattern for a multi-tenant SaaS: tenant pastes an{" "}
        <code className="text-xs">sk_live_</code> key, your backend validates
        and stores it encrypted, then syncs identity data. See the{" "}
        <a
          href="https://docs.authio.com/guides/connect-external-app"
          className="underline"
        >
          docs guide
        </a>
        .
      </p>

      <div className="mt-8">
        <ConnectAuthioPanel
          connected={
            conn
              ? {
                  projectName: conn.projectName,
                  authioProjectId: conn.authioProjectId,
                  authioTenantId: conn.authioTenantId,
                  tenantName: conn.tenantName,
                  environment: conn.environment,
                  connectedAt: conn.connectedAt,
                  lastSyncAt: conn.lastSyncAt,
                  lastSyncUserCount: conn.lastSyncUserCount,
                  lastSyncError: conn.lastSyncError,
                }
              : null
          }
        />
      </div>

      <p className="mt-10 text-sm text-zinc-500">
        <Link href="/" className="underline">
          ← Back
        </Link>
      </p>
    </main>
  );
}
