"use client";

import type { ApiResponse } from "@core/contracts";
import { Button, Card, TextField } from "@monorise-team/ui";
import Link from "next/link";
import { useState, type FormEvent } from "react";

export function SignUpForm({ clientId }: { clientId?: string }) {
  const [form, setForm] = useState({ organizationName: "", firstName: "", lastName: "", email: "", password: "" });
  const [error, setError] = useState<string | null>(null);
  const [sentTo, setSentTo] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const set = (field: keyof typeof form) => (e: { target: { value: string } }) =>
    setForm((current) => ({ ...current, [field]: e.target.value }));

  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    const response = await fetch("/api/signup", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(clientId ? { ...form, client_id: clientId } : form),
    });
    const body = (await response.json()) as ApiResponse<{ organizationId: string }>;
    setBusy(false);
    if (response.ok) setSentTo(form.email);
    else setError(body.error?.message ?? "Nie udało się założyć konta.");
  }

  if (sentTo) {
    return (
      <Card surface="float" className="mr-enter flex w-full max-w-sm flex-col gap-3 p-6">
        <h1 className="font-display text-xl font-semibold">Sprawdź skrzynkę</h1>
        <p className="text-sm text-text-secondary">
          Wysłaliśmy link na <strong>{sentTo}</strong>. Po potwierdzeniu adresu zalogujesz się i potwierdzisz domenę
          firmy.
        </p>
      </Card>
    );
  }

  return (
    <Card surface="float" className="mr-enter flex w-full max-w-md flex-col gap-5 p-6">
      <div className="flex flex-col gap-1">
        <h1 className="font-display text-xl font-semibold">Załóż konto firmy</h1>
        <p className="text-sm text-text-tertiary">Użyj adresu w domenie firmy, np. anna@acme.com.</p>
      </div>
      <form className="flex flex-col gap-3" onSubmit={submit}>
        <TextField label="Nazwa firmy" value={form.organizationName} onChange={set("organizationName")} required />
        <div className="grid grid-cols-2 gap-3">
          <TextField
            label="Imię"
            autoComplete="given-name"
            value={form.firstName}
            onChange={set("firstName")}
            required
          />
          <TextField
            label="Nazwisko"
            autoComplete="family-name"
            value={form.lastName}
            onChange={set("lastName")}
            required
          />
        </div>
        <TextField
          label="Służbowy adres e-mail"
          type="email"
          autoComplete="email"
          value={form.email}
          onChange={set("email")}
          required
        />
        <TextField
          label="Hasło"
          type="password"
          autoComplete="new-password"
          hint="Co najmniej 12 znaków."
          minLength={12}
          value={form.password}
          onChange={set("password")}
          required
        />
        {error ? <p className="text-sm text-danger">{error}</p> : null}
        <Button type="submit" variant="primary" size="lg" disabled={busy}>
          {busy ? "Zakładanie…" : "Załóż konto"}
        </Button>
      </form>
      <p className="text-sm text-text-tertiary">
        Masz już konto?{" "}
        <Link className="text-accent underline-offset-2 hover:underline" href="/sign-in">
          Zaloguj się
        </Link>
      </p>
    </Card>
  );
}
