"use client";

import type { ApiResponse } from "@core/contracts";
import { Button } from "@monorise-team/ui";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { authClient } from "@/lib/auth-client";

export function DomainActions({ devTrust }: { devTrust: boolean }) {
  const router = useRouter();
  const [message, setMessage] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function verify(trustLocally: boolean) {
    setBusy(true);
    setMessage(null);
    const response = await fetch("/api/organization/domain/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ trustLocally }),
    });
    const body = (await response.json()) as ApiResponse<{ status: string }>;
    setBusy(false);
    if (body.data?.status === "VERIFIED") router.refresh();
    else
      setMessage(
        body.error?.message ??
          "Nie widzimy jeszcze rekordu. Zmiany w DNS potrafią potrwać do kilku godzin; spróbuj później.",
      );
  }

  return (
    <div className="flex flex-col gap-2">
      <div className="flex flex-wrap gap-2">
        <Button variant="primary" disabled={busy} onClick={() => verify(false)}>
          Sprawdź rekord
        </Button>
        {devTrust ? (
          <Button variant="ghost" disabled={busy} onClick={() => verify(true)}>
            Potwierdź bez DNS (tylko lokalnie)
          </Button>
        ) : null}
      </div>
      {message ? <p className="text-sm text-text-tertiary">{message}</p> : null}
    </div>
  );
}

export function ReturnToProductAction({ href, label }: { href: string; label: string }) {
  return (
    <div className="flex flex-col gap-3 rounded-lg bg-bg-tertiary p-4">
      <p className="text-sm text-text-primary">Firma jest gotowa. Możesz wrócić do aplikacji, z której zaczynasz.</p>
      <div>
        <Button asChild variant="primary" size="md">
          <a href={href}>{label}</a>
        </Button>
      </div>
    </div>
  );
}

export function AccountActions() {
  const router = useRouter();
  return (
    <div className="flex justify-end">
      <Button
        variant="secondary"
        onClick={async () => {
          await authClient.signOut();
          router.push("/sign-in");
        }}
      >
        Wyloguj się
      </Button>
    </div>
  );
}
