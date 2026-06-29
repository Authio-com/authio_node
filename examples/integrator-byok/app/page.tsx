import Link from "next/link";

export default function HomePage() {
  return (
    <main className="mx-auto max-w-xl px-6 py-16 text-center">
      <h1 className="text-2xl font-semibold">Integrator BYOK example</h1>
      <p className="mt-3 text-sm text-zinc-600">
        Runnable reference for third-party apps connecting to Authio via
        customer-supplied Management API keys.
      </p>
      <Link
        href="/settings/connect-authio"
        className="mt-6 inline-block rounded-md bg-zinc-900 px-4 py-2 text-sm text-white"
      >
        Open Connect Authio settings
      </Link>
    </main>
  );
}
