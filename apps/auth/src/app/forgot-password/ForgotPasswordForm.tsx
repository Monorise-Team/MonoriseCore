"use client";

import { Button, Card, TextField } from "@monorise-team/ui";
import Link from "next/link";
import { useState, type FormEvent } from "react";
import { authClient } from "@/lib/auth-client";

export function ForgotPasswordForm() {
  const [email, setEmail] = useState("");
  const [submitted, setSubmitted] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const { error: failure } = await authClient.requestPasswordReset({
        email: email.trim(),
        redirectTo: "/reset-password",
      });
      setBusy(false);
      if (failure?.status === 429) {
        setError("Zbyt wiele prób. Spróbuj ponownie za chwilę.");
        return;
      }
      if (failure && failure.status >= 500) {
        setError("Nie udało się wysłać żądania. Spróbuj ponownie.");
        return;
      }
      // Zawsze ten sam komunikat — bez zdradzania, czy konto istnieje (02-identity/flows.md)
      setSubmitted(true);
    } catch {
      setBusy(false);
      setError("Nie udało się połączyć z serwerem. Spróbuj ponownie.");
    }
  }

  if (submitted) {
    return (
      <Card surface="float" className="mr-enter flex w-full max-w-sm flex-col gap-4 p-6">
        <div className="flex flex-col gap-1">
          <h1 className="font-display text-xl font-semibold">Sprawdź skrzynkę</h1>
          <p role="status" className="text-sm text-text-secondary">
            Jeśli konto z tym adresem istnieje, wysłaliśmy link do zmiany hasła. Link jest ważny przez 30 minut.
          </p>
        </div>
        <p className="text-sm text-text-tertiary">
          <Link className="text-accent underline-offset-2 hover:underline" href="/sign-in">
            Wróć do logowania
          </Link>
        </p>
      </Card>
    );
  }

  return (
    <Card surface="float" className="mr-enter flex w-full max-w-sm flex-col gap-5 p-6">
      <div className="flex flex-col gap-1">
        <h1 className="font-display text-xl font-semibold">Nie pamiętasz hasła?</h1>
        <p className="text-sm text-text-tertiary">
          Podaj swój adres e-mail. Wyślemy jednorazowy link do ustawienia nowego hasła.
        </p>
      </div>
      <form className="flex flex-col gap-3" onSubmit={submit}>
        <TextField
          label="Adres e-mail"
          type="email"
          autoComplete="email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          required
        />
        {error ? <p className="text-sm text-danger">{error}</p> : null}
        <Button type="submit" variant="primary" size="lg" disabled={busy}>
          {busy ? "Wysyłanie…" : "Wyślij link do zmiany hasła"}
        </Button>
      </form>
      <p className="text-sm text-text-tertiary">
        Pamiętasz hasło?{" "}
        <Link className="text-accent underline-offset-2 hover:underline" href="/sign-in">
          Zaloguj się
        </Link>
      </p>
    </Card>
  );
}
