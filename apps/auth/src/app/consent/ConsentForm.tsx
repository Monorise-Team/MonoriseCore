"use client";

import { Button, Card } from "@monorise-team/ui";
import { useState } from "react";
import { authClient } from "@/lib/auth-client";

const SCOPES: Record<string, string> = {
  openid: "potwierdzenie, kim jesteś",
  profile: "imię i nazwisko",
  email: "adres e-mail",
  offline_access: "dostęp bez ponownego logowania",
};

export function ConsentForm() {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const params = typeof window === "undefined" ? new URLSearchParams() : new URLSearchParams(window.location.search);
  const scopes = (params.get("scope") ?? "").split(" ").filter(Boolean);

  async function decide(accept: boolean) {
    setBusy(true);
    setError(null);
    const { data, error: failure } = await authClient.oauth2.consent({ accept });
    setBusy(false);
    const url = (data as { url?: string } | null)?.url;
    if (url) window.location.href = url;
    else if (failure) setError("Nie udało się zapisać decyzji. Spróbuj zalogować się ponownie.");
  }

  return (
    <Card surface="float" className="mr-enter flex w-full max-w-sm flex-col gap-5 p-6">
      <div className="flex flex-col gap-1">
        <h1 className="font-display text-xl font-semibold">Zgoda na dostęp</h1>
        <p className="text-sm text-text-tertiary">Aplikacja prosi o dostęp do Twojego konta Monorise:</p>
      </div>
      <ul className="flex list-disc flex-col gap-1 pl-5 text-sm text-text-secondary">
        {scopes.map((scope) => (
          <li key={scope}>{SCOPES[scope] ?? scope}</li>
        ))}
      </ul>
      {error ? <p className="text-sm text-danger">{error}</p> : null}
      <div className="flex justify-end gap-2">
        <Button variant="ghost" disabled={busy} onClick={() => decide(false)}>
          Odmów
        </Button>
        <Button variant="primary" disabled={busy} onClick={() => decide(true)}>
          Zezwól
        </Button>
      </div>
    </Card>
  );
}
