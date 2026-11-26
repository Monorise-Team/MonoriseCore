import { createHash, createHmac, timingSafeEqual } from "node:crypto";
import { PrismaPg } from "@prisma/adapter-pg";
import { PrismaClient, type Prisma } from "./generated/prisma/client.js";
import type { AccountStatus, DomainStatus, OrganizationStatus } from "./generated/prisma/enums.js";

export * from "./generated/prisma/enums.js";
export { Prisma, PrismaClient } from "./generated/prisma/client.js";
export type * from "./generated/prisma/models.js";
export { uuidv7 } from "./ids.js";

const DOMAIN_TXT_PREFIX = "monorise-verification=";
export const MIN_DOMAIN_VERIFICATION_SECRET_LENGTH = 32;

/** Skrót SHA-256 (hex) tokenu (np. weryfikacji domeny lub zaproszenia), przechowywany w bazie zamiast samego tokenu. */
export function hashToken(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

/**
 * Wartość rekordu DNS TXT potwierdzającego domenę firmy (`monorise-verification=<32 znaki base64url>`).
 * Wyliczana deterministycznie z sekretu, identyfikatora firmy i domeny (w małych literach); w bazie
 * przechowujemy wyłącznie jej skrót (`verificationTokenHash`).
 */
export function domainTxtValue(secret: string, organizationId: string, domain: string): string {
  const code = createHmac("sha256", secret).update(`${organizationId}:${domain.toLowerCase()}`).digest("base64url");
  return `${DOMAIN_TXT_PREFIX}${code.slice(0, 32)}`;
}

/**
 * Porównuje skrót SHA-256 rekordu DNS TXT z zapisanym `verificationTokenHash` w stałym czasie
 * (`timingSafeEqual`), dzięki czemu rotacja sekretu nie unieważnia istniejących wierszy w bazie.
 */
export function matchesDomainTokenHash(txtRecord: string, expectedHash: string | null): boolean {
  if (!expectedHash) return false;
  const actual = Buffer.from(hashToken(txtRecord), "utf8");
  const expected = Buffer.from(expectedHash, "utf8");
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}

/**
 * Zbiera zdeduplikowane dopuszczalne skróty SHA-256 rekordu DNS TXT: zapisany w bazie
 * `verificationTokenHash` oraz (gdy podano bieżący sekret) skrót wartości wyliczonej z bieżącego
 * sekretu. Dzięki temu zmiana sekretu nie psuje oczekujących weryfikacji — pasuje zarówno stary
 * (już opublikowany w DNS), jak i nowy (pokazywany obecnie w interfejsie) rekord TXT.
 */
export function expectedDomainTokenHashes(options: {
  storedHash: string | null;
  currentSecret?: string | undefined;
  organizationId: string;
  domain: string;
}): string[] {
  const hashes = new Set<string>();
  if (options.storedHash) {
    hashes.add(options.storedHash);
  }
  const secret = options.currentSecret?.trim();
  if (secret) {
    hashes.add(hashToken(domainTxtValue(secret, options.organizationId, options.domain)));
  }
  return [...hashes];
}

/**
 * Porównuje rekord DNS TXT w stałym czasie z każdym z dopuszczalnych skrótów SHA-256
 * (bez wczesnego przerwania pętli).
 */
export function matchesAnyDomainTokenHash(txtRecord: string, expectedHashes: readonly string[]): boolean {
  let matched = false;
  for (const expectedHash of expectedHashes) {
    if (matchesDomainTokenHash(txtRecord, expectedHash)) {
      matched = true;
    }
  }
  return matched;
}

/**
 * Czy dozwolone jest potwierdzanie domen bez DNS (`trustLocally: true`): wyłącznie gdy
 * `CORE_DEV_TRUST_DOMAINS=1` oraz `NODE_ENV` ma wartość `"development"` albo `"test"`.
 */
export function isDevTrustDomainsEnabled(
  env: { NODE_ENV?: string | undefined; CORE_DEV_TRUST_DOMAINS?: string | undefined } = process.env,
): boolean {
  return env.CORE_DEV_TRUST_DOMAINS === "1" && (env.NODE_ENV === "development" || env.NODE_ENV === "test");
}

/**
 * Wyznacza i waliduje sekret `CORE_DOMAIN_VERIFICATION_SECRET` (po przycięciu spacji):
 * - na produkcji (`NODE_ENV === "production"`) zawsze wymagany i musi mieć co najmniej 32 znaki
 *   (z pominięciem fazy budowania Next.js `isBuildPhase`), bez powrotu do `BETTER_AUTH_SECRET`,
 * - poza produkcją dopuszcza opcjonalny `fallback` (używany w `apps/auth` dla `BETTER_AUTH_SECRET`).
 */
export function resolveDomainVerificationSecret(options: {
  env?: { NODE_ENV?: string | undefined; CORE_DOMAIN_VERIFICATION_SECRET?: string | undefined };
  fallback?: () => string;
  isBuildPhase?: boolean;
}): string {
  const env = options.env ?? process.env;
  const trimmed = env.CORE_DOMAIN_VERIFICATION_SECRET?.trim() ?? "";
  const isProd = env.NODE_ENV === "production";

  if (isProd) {
    if (options.isBuildPhase) {
      return "build-time-domain-verification-secret-0000";
    }
    if (trimmed.length < MIN_DOMAIN_VERIFICATION_SECRET_LENGTH) {
      throw new Error(
        `Zmienna środowiskowa CORE_DOMAIN_VERIFICATION_SECRET jest wymagana na produkcji i musi mieć co najmniej ${MIN_DOMAIN_VERIFICATION_SECRET_LENGTH} znaki`,
      );
    }
    return trimmed;
  }

  if (trimmed.length > 0) {
    return trimmed;
  }
  if (options.fallback) {
    return options.fallback();
  }
  throw new Error("Brak zmiennej środowiskowej CORE_DOMAIN_VERIFICATION_SECRET (lokalnie: pnpm setup:env)");
}

/** Klient transakcji: to samo API co PrismaClient, bez metod sterujących połączeniem. */
export type Tx = Prisma.TransactionClient;

/**
 * Klient bazy monorise_core. Aplikacje łączą się rolą core_app (bez uprawnień właściciela tabel i bez
 * BYPASSRLS), więc dane firm są dostępne tylko przez withOrganization (ADR-0037).
 */
export function createDb(connectionString: string): PrismaClient {
  return new PrismaClient({ adapter: new PrismaPg({ connectionString }) });
}

/**
 * Działanie w imieniu jednej firmy. Ustawia zmienną transakcji app.organization_id, z której korzystają
 * polityki RLS; po zakończeniu transakcji wartość znika, więc nie przecieka między połączeniami z puli.
 * Identyfikator firmy pochodzi zawsze z zaufanego źródła (token, sesja), nigdy z treści żądania.
 */
export async function withOrganization<T>(
  db: PrismaClient,
  organizationId: string,
  fn: (tx: Tx) => Promise<T>,
): Promise<T> {
  return db.$transaction(async (tx) => {
    await tx.$executeRaw`SELECT set_config('app.organization_id', ${organizationId}, true)`;
    return fn(tx);
  });
}

export interface AccountClaims {
  organizationId: string;
  employeeId: string;
  authzRevision: number;
  accountStatus: AccountStatus;
  organizationStatus: OrganizationStatus;
}

/** Dane do tokenu (ADR-0023) po identyfikatorze konta; jedyne wyszukiwanie kont ponad granicą firm. */
export async function accountClaims(db: PrismaClient | Tx, accountId: string): Promise<AccountClaims | null> {
  const rows = await db.$queryRaw<
    {
      organization_id: string;
      employee_id: string;
      authz_revision: number;
      account_status: AccountStatus;
      organization_status: OrganizationStatus;
    }[]
  >`SELECT * FROM public.account_claims(${accountId}::uuid)`;
  const row = rows[0];
  return row
    ? {
        organizationId: row.organization_id,
        employeeId: row.employee_id,
        authzRevision: row.authz_revision,
        accountStatus: row.account_status,
        organizationStatus: row.organization_status,
      }
    : null;
}

/** Do której firmy należy zweryfikowana (`VERIFIED`) domena (samorejestracja, CLI, domeny; ADR-0019). */
export async function domainOwner(
  db: PrismaClient | Tx,
  domain: string,
): Promise<{ organizationId: string; status: DomainStatus } | null> {
  const rows = await db.$queryRaw<{ organization_id: string; domain_status: DomainStatus }[]>`
    SELECT * FROM public.domain_owner(${domain}::citext)`;
  const row = rows[0];
  return row ? { organizationId: row.organization_id, status: row.domain_status } : null;
}

/**
 * Usuwa niezweryfikowane, niegłówne roszczenia innych firm do `domain` w tej samej transakcji
 * `withOrganization`, w której bieżąca firma zweryfikowała domenę (zasada „wygrywa weryfikacja”).
 * Nie usuwa głównych niezweryfikowanych domen innych firm (samorejestracja w toku).
 */
export async function releaseCompetingDomainClaims(tx: Tx, domain: string): Promise<number> {
  const rows = await tx.$queryRaw<{ deleted: number }[]>`
    SELECT "public"."organization_domains_release_competing_claims"(${domain}::citext) AS deleted`;
  return rows[0]?.deleted ?? 0;
}

/** Wyszukiwanie firmy i zaproszenia po skrócie tokenu z linku aktywacyjnego (ADR-0021). */
export async function invitationByTokenHash(
  db: PrismaClient | Tx,
  tokenHash: string,
): Promise<{ organizationId: string; invitationId: string } | null> {
  const rows = await db.$queryRaw<{ organization_id: string; invitation_id: string }[]>`
    SELECT * FROM public.invitation_by_token_hash(${tokenHash}::text)`;
  const row = rows[0];
  return row ? { organizationId: row.organization_id, invitationId: row.invitation_id } : null;
}

/** Usuwa porcję wygasłych kluczy `Idempotency-Key` ponad granicą firm (funkcja `SECURITY DEFINER`). */
export async function cleanupExpiredIdempotencyKeys(db: PrismaClient | Tx, limit = 1000): Promise<number> {
  const rows = await db.$queryRaw<{ deleted: number }[]>`
    SELECT "public"."idempotency_keys_cleanup_expired"(${limit}::integer) AS deleted`;
  return rows[0]?.deleted ?? 0;
}
