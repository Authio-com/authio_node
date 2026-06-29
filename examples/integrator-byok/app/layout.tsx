import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Integrator BYOK example",
  description: "Reference Connect Authio settings flow for third-party SaaS integrators.",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body className="min-h-screen bg-white text-zinc-900 antialiased">
        {children}
      </body>
    </html>
  );
}
