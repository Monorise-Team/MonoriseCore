import "server-only";
import { isDevTrustDomainsEnabled, resolveDomainVerificationSecret } from "@core/db";

/** `next build` importuje kod tras, ale ich nie wykonuje: wtedy wystarczą wartości zastępcze. */
const building = process.env.NEXT_PHASE === "phase-production-build";

function required(name: string, buildValue: string): string {
  const value = process.env[name];
  if (value) return value;
  if (building) return buildValue;
  throw new Error(`Brak zmiennej środowiskowej ${name} (lokalnie: pnpm setup:env)`);
}

/** Ustawienia serwera logowania. Lokalnie z apps/auth/.env.local (pnpm setup:env). */
export const config = {
  /** Adres serwera logowania, a zarazem wystawca tokenów (iss): https://auth.monorise.studio */
  authUrl: process.env.BETTER_AUTH_URL ?? "http://localhost:3100",
  get secret(): string {
    return required("BETTER_AUTH_SECRET", "build-time-secret-build-time-secret-0000");
  },
  /**
   * Sekret HMAC-SHA256 współdzielony z Core API do rekordów DNS TXT:
   * na produkcji wymagany (`CORE_DOMAIN_VERIFICATION_SECRET`, min. 32 znaki po przycięciu spacji);
   * poza produkcją może wrócić do `BETTER_AUTH_SECRET`.
   */
  get domainVerificationSecret(): string {
    return resolveDomainVerificationSecret({
      env: process.env,
      fallback: () => this.secret,
      isBuildPhase: building,
    });
  },
  get databaseUrl(): string {
    return required("CORE_DATABASE_URL", "postgresql://build:build@localhost:5432/build");
  },
  /** Dla kogo są tokeny (aud); na razie Core API, produkty dostaną własne przy logowaniu OAuth. */
  tokenAudience: (process.env.CORE_TOKEN_AUDIENCE ?? "http://localhost:3200").split(",").map((s) => s.trim()),
  /** smtp://… albo „memory” (testy: wiadomości zostają w pamięci). */
  smtpUrl: process.env.CORE_SMTP_URL ?? "memory",
  mailFrom: process.env.CORE_MAIL_FROM ?? "Monorise <no-reply@monorise.studio>",
  /** Tylko lokalnie: adresy powrotu produktów po HTTP (localhost i *.localhost), np. aven-mail.localhost:3000. */
  allowLocalHttpRedirects: process.env.NODE_ENV !== "production",
  /** Tylko lokalnie i w testach (`NODE_ENV` = `development` lub `test` oraz `CORE_DEV_TRUST_DOMAINS=1`): bez DNS TXT. */
  get devTrustDomains(): boolean {
    return isDevTrustDomainsEnabled(process.env);
  },
};
