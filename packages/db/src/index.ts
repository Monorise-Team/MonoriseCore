import { createHash } from "node:crypto";
import { PrismaPg } from "@prisma/adapter-pg";
import { PrismaClient, type Prisma } from "./generated/prisma/client.js";
import type { AccountStatus, DomainStatus, OrganizationStatus } from "./generated/prisma/enums.js";

export * from "./generated/prisma/enums.js";
export { Prisma, PrismaClient } from "./generated/prisma/client.js";
export type * from "./generated/prisma/models.js";
export { uuidv7 } from "./ids.js";

/** Skrót SHA-256 (hex) tokenu (np. weryfikacji domeny lub zaproszenia), przechowywany w bazie zamiast samego tokenu. */
export function hashToken(value: string): string {
  return createHash("sha256").update(value).digest("hex");
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

/** Do której firmy należy domena (samorejestracja, zaproszenia; ADR-0019). */
export async function domainOwner(
  db: PrismaClient | Tx,
  domain: string,
): Promise<{ organizationId: string; status: DomainStatus } | null> {
  const rows = await db.$queryRaw<{ organization_id: string; domain_status: DomainStatus }[]>`
    SELECT * FROM public.domain_owner(${domain}::citext)`;
  const row = rows[0];
  return row ? { organizationId: row.organization_id, status: row.domain_status } : null;
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
