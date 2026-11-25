"use client";

import { Button, Card, TextField } from "@monorise-team/ui";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState, type FormEvent } from "react";
import { authClient } from "@/lib/auth-client";

export function SignInForm({ activated = false, clientId }: { activated?: boolean; clientId?: string }) {
  const router = useRouter();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const signUpHref = clientId ? `/sign-up?${new URLSearchParams({ client_id: clientId }).toString()}` : "/sign-up";

  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    const { data, error: failure } = await authClient.signIn.email({ email, password });
    setBusy(false);
    if (!failure) {
      // Logowanie z produktu (OAuth): powrót do produktu z kodem; zwykłe logowanie: konto firmy
      const url = (data as { url?: string } | null)?.url;
      if (url) window.location.href = url;
      else router.push("/account");
      return;
    }
    // Komunikaty bez zdradzania, czy konto istnieje (ADR-0019)
    setError(
      failure.status === 403
        ? "Najpierw potwierdź adres e-mail: link jest w wiadomości od Monorise."
        : "Nieprawidłowy adres e-mail albo hasło.",
    );
  }

  return (
    <Card surface="float" className="mr-enter flex w-full max-w-sm flex-col gap-5 p-6">
      <div className="flex flex-col gap-1">
        <h1 className="font-display text-xl font-semibold">Zaloguj się do Monorise</h1>
        <p className="text-sm text-text-tertiary">Jedno konto do wszystkich produktów Twojej firmy.</p>
      </div>
      {activated ? (
        <p role="status" className="rounded-lg bg-bg-tertiary p-3 text-sm text-text-primary">
          Konto zostało aktywowane. Możesz się teraz zalogować.
        </p>
      ) : null}
      <form className="flex flex-col gap-3" onSubmit={submit}>
        <TextField
          label="Adres e-mail"
          type="email"
          autoComplete="email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          required
        />
        <TextField
          label="Hasło"
          type="password"
          autoComplete="current-password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          required
        />
        {error ? <p className="text-sm text-danger">{error}</p> : null}
        <Button type="submit" variant="primary" size="lg" disabled={busy}>
          {busy ? "Logowanie…" : "Zaloguj się"}
        </Button>
      </form>
      <p className="text-sm text-text-tertiary">
        Nowa firma?{" "}
        <Link className="text-accent underline-offset-2 hover:underline" href={signUpHref}>
          Załóż konto firmy
        </Link>
      </p>
    </Card>
  );
}
