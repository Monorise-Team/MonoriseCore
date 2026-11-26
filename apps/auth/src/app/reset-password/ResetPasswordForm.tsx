"use client";

import { Button, Card, TextField } from "@monorise-team/ui";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState, type FormEvent } from "react";
import { authClient } from "@/lib/auth-client";

const INVALID_TOKEN_CODES = new Set(["INVALID_TOKEN", "TOKEN_EXPIRED", "USER_NOT_FOUND"]);

export function ExpiredResetLinkCard() {
  return (
    <Card surface="float" className="mr-enter flex w-full max-w-sm flex-col gap-4 p-6">
      <div className="flex flex-col gap-1">
        <h1 className="font-display text-xl font-semibold">Link jest nieaktualny</h1>
        <p className="text-sm text-text-secondary">
          Ten link do zmiany hasła wygasł lub został już użyty. Poproś o nowy link — jest ważny przez 30 minut.
        </p>
      </div>
      <div className="flex flex-col gap-3">
        <Button asChild variant="primary" size="lg">
          <Link href="/forgot-password">Poproś o nowy link</Link>
        </Button>
        <p className="text-sm text-text-tertiary">
          <Link className="text-accent underline-offset-2 hover:underline" href="/sign-in">
            Wróć do logowania
          </Link>
        </p>
      </div>
    </Card>
  );
}

export function ResetPasswordForm({ token }: { token: string }) {
  const router = useRouter();
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [linkExpired, setLinkExpired] = useState(false);
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
      const { error: failure } = await authClient.resetPassword({
        newPassword: password,
        token,
      });
      setBusy(false);
      if (!failure) {
        router.push("/sign-in?reset=1");
        return;
      }
      if (failure.code === "PASSWORD_TOO_SHORT") {
        setError("Hasło musi mieć co najmniej 12 znaków.");
        return;
      }
      if (failure.code === "PASSWORD_TOO_LONG") {
        setError("Hasło może mieć co najwyżej 128 znaków.");
        return;
      }
      if (failure.status === 429) {
        setError("Zbyt wiele prób. Spróbuj ponownie za chwilę.");
        return;
      }
      if ((failure.code && INVALID_TOKEN_CODES.has(failure.code)) || failure.status === 400) {
        setLinkExpired(true);
        return;
      }
      setError("Nie udało się zmienić hasła. Spróbuj ponownie.");
    } catch {
      setBusy(false);
      setError("Nie udało się połączyć z serwerem. Spróbuj ponownie.");
    }
  }

  if (linkExpired) {
    return <ExpiredResetLinkCard />;
  }

  return (
    <Card surface="float" className="mr-enter flex w-full max-w-sm flex-col gap-5 p-6">
      <div className="flex flex-col gap-1">
        <h1 className="font-display text-xl font-semibold">Ustaw nowe hasło</h1>
        <p className="text-sm text-text-tertiary">Po zmianie hasła wszystkie aktywne sesje zostaną zakończone.</p>
      </div>
      <form className="flex flex-col gap-3" onSubmit={submit}>
        <TextField
          label="Nowe hasło"
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
          label="Powtórz nowe hasło"
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
          {busy ? "Zapisywanie…" : "Zmień hasło"}
        </Button>
      </form>
      <p className="text-sm text-text-tertiary">
        <Link className="text-accent underline-offset-2 hover:underline" href="/sign-in">
          Wróć do logowania
        </Link>
      </p>
    </Card>
  );
}
