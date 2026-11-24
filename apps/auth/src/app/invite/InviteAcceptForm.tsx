"use client";

import type { ApiResponse } from "@core/contracts";
import { Button, Card, TextField } from "@monorise-team/ui";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState, type FormEvent } from "react";

export interface InviteAcceptFormProps {
  token: string;
  organizationName: string;
  email: string;
}

export function InviteAcceptForm({ token, organizationName, email }: InviteAcceptFormProps) {
  const router = useRouter();
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (password.length < 12) {
      setError("Hasło musi mieć co najmniej 12 znaków.");
      return;
    }
    if (password.length > 128) {
      setError("Hasło może mieć co najwyżej 128 znaków.");
      return;
    }
    if (password !== confirmPassword) {
      setError("Hasła muszą być takie same.");
      return;
    }

    setBusy(true);
    setError(null);
    try {
      const response = await fetch("/api/invitations/accept", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token, password }),
      });
      const body = (await response.json()) as ApiResponse<{ activated: boolean }>;
      setBusy(false);
      if (response.ok) {
        router.push("/sign-in?activated=1");
        return;
      }
      setError(body.error?.message ?? "Nie udało się aktywować konta.");
    } catch {
      setBusy(false);
      setError("Nie udało się połączyć z serwerem. Spróbuj ponownie.");
    }
  }

  return (
    <Card surface="float" className="mr-enter flex w-full max-w-sm flex-col gap-5 p-6">
      <div className="flex flex-col gap-1">
        <h1 className="font-display text-xl font-semibold">Aktywuj konto</h1>
        <p className="text-sm text-text-tertiary">
          Zaproszenie do firmy <strong className="font-medium text-text-primary">{organizationName}</strong>.
        </p>
      </div>
      <div className="rounded-lg bg-bg-tertiary px-3 py-2 text-sm text-text-secondary">
        <span className="text-text-tertiary">Adres e-mail: </span>
        <strong className="font-medium text-text-primary">{email}</strong>
      </div>
      <form className="flex flex-col gap-3" onSubmit={submit}>
        <TextField
          label="Hasło"
          type="password"
          autoComplete="new-password"
          hint="Co najmniej 12 znaków."
          minLength={12}
          maxLength={128}
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          required
        />
        <TextField
          label="Powtórz hasło"
          type="password"
          autoComplete="new-password"
          minLength={12}
          maxLength={128}
          value={confirmPassword}
          onChange={(e) => setConfirmPassword(e.target.value)}
          required
        />
        {error ? <p className="text-sm text-danger">{error}</p> : null}
        <Button type="submit" variant="primary" size="lg" disabled={busy}>
          {busy ? "Aktywowanie…" : "Ustaw hasło i aktywuj konto"}
        </Button>
      </form>
      <p className="text-sm text-text-tertiary">
        Masz już aktywne konto?{" "}
        <Link className="text-accent underline-offset-2 hover:underline" href="/sign-in">
          Zaloguj się
        </Link>
      </p>
    </Card>
  );
}
