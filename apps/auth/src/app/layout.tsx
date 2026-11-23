import { AppBackdrop, appearanceInitScript } from "@monorise-team/ui";
import type { Metadata, Viewport } from "next";
import Script from "next/script";
import type { ReactNode } from "react";
import "./globals.css";

export const metadata: Metadata = {
  title: "Monorise — logowanie",
  description: "Jedno logowanie do produktów Monorise.",
  robots: { index: false, follow: false },
};

export const viewport: Viewport = { colorScheme: "dark light" };

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="pl" className="dark" data-theme="mono" suppressHydrationWarning>
      <body className="min-h-dvh">
        {/* Zapisany tryb i motyw przed pierwszym malowaniem, bez mignięcia */}
        <Script id="monorise-appearance" strategy="beforeInteractive">
          {appearanceInitScript}
        </Script>
        <AppBackdrop />
        <main className="relative flex min-h-dvh items-center justify-center p-6">{children}</main>
      </body>
    </html>
  );
}
