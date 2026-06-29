"use client";

import { useActionState } from "react";
import type { ConnectState } from "./actions";
import {
  connectAuthio,
  disconnectAuthio,
  syncAuthioNow,
} from "./actions";

const initial: ConnectState | null = null;

export function ConnectAuthioPanel({
  connected,
}: {
  connected: {
    projectName: string;
    authioProjectId: string;
    authioTenantId: string;
    tenantName: string | null;
    environment: string;
    connectedAt: string;
    lastSyncAt: string | null;
    lastSyncUserCount: number | null;
    lastSyncError: string | null;
  } | null;
}) {
  const [connectResult, connectAction, connectPending] = useActionState(
    connectAuthio,
    initial,
  );
  const [syncResult, syncAction, syncPending] = useActionState(
    syncAuthioNow,
    initial,
  );
  const [disconnectResult, disconnectAction, disconnectPending] =
    useActionState(disconnectAuthio, initial);

  const flash = connectResult ?? syncResult ?? disconnectResult;

  return (
    <div className="space-y-6">
      {flash && (
        <p
          className={`rounded-md border px-3 py-2 text-sm ${
            flash.ok
              ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-800"
              : "border-red-500/40 bg-red-500/10 text-red-800"
          }`}
        >
          {flash.ok ? flash.message : flash.error}
        </p>
      )}

      {connected ? (
        <section className="rounded-lg border border-zinc-200 bg-zinc-50 p-4">
          <h2 className="text-sm font-semibold text-zinc-900">Connected</h2>
          <dl className="mt-3 grid gap-2 text-sm text-zinc-700">
            <div>
              <dt className="text-zinc-500">Project</dt>
              <dd className="font-medium">{connected.projectName}</dd>
            </div>
            <div>
              <dt className="text-zinc-500">Project ID</dt>
              <dd>
                <code>{connected.authioProjectId}</code>
              </dd>
            </div>
            <div>
              <dt className="text-zinc-500">Tenant</dt>
              <dd>
                {connected.tenantName ?? "—"}{" "}
                <code className="text-xs">({connected.authioTenantId})</code>
              </dd>
            </div>
            <div>
              <dt className="text-zinc-500">Environment</dt>
              <dd>{connected.environment}</dd>
            </div>
            <div>
              <dt className="text-zinc-500">Connected</dt>
              <dd>{new Date(connected.connectedAt).toLocaleString()}</dd>
            </div>
            {connected.lastSyncAt && (
              <div>
                <dt className="text-zinc-500">Last sync</dt>
                <dd>
                  {new Date(connected.lastSyncAt).toLocaleString()}
                  {connected.lastSyncUserCount != null &&
                    ` · ${connected.lastSyncUserCount} users`}
                </dd>
              </div>
            )}
            {connected.lastSyncError && (
              <div>
                <dt className="text-zinc-500">Last sync error</dt>
                <dd className="text-red-700">{connected.lastSyncError}</dd>
              </div>
            )}
          </dl>

          <div className="mt-4 flex flex-wrap gap-2">
            <form action={syncAction}>
              <button
                type="submit"
                disabled={syncPending}
                className="rounded-md bg-zinc-900 px-3 py-1.5 text-sm text-white disabled:opacity-50"
              >
                {syncPending ? "Syncing…" : "Sync now"}
              </button>
            </form>
            <form action={disconnectAction}>
              <button
                type="submit"
                disabled={disconnectPending}
                className="rounded-md border border-zinc-300 px-3 py-1.5 text-sm text-zinc-700 disabled:opacity-50"
              >
                Disconnect
              </button>
            </form>
          </div>
        </section>
      ) : (
        <form action={connectAction} className="space-y-3">
          <label className="block text-sm font-medium text-zinc-800">
            Authio secret key
            <input
              type="password"
              name="apiKey"
              autoComplete="off"
              placeholder="sk_live_…"
              required
              className="mt-1 block w-full max-w-md rounded-md border border-zinc-300 px-3 py-2 font-mono text-sm"
            />
          </label>
          <p className="max-w-lg text-sm text-zinc-600">
            Your customer creates this in Authio → Settings → API keys. The key
            is validated server-side via{" "}
            <code className="text-xs">GET /v1/projects/me</code>, encrypted, and
            never sent to the browser again.
          </p>
          <button
            type="submit"
            disabled={connectPending}
            className="rounded-md bg-zinc-900 px-4 py-2 text-sm text-white disabled:opacity-50"
          >
            {connectPending ? "Connecting…" : "Connect Authio"}
          </button>
        </form>
      )}
    </div>
  );
}
