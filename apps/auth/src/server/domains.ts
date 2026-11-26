import "server-only";
import { resolveTxt as dnsResolveTxt } from "node:dns/promises";
import { isIP } from "node:net";
import {
  canManageOrganizationAssignments,
  domainVerificationHost,
  type DomainStatus,
  type RawRoleAssignmentRecord,
} from "@core/contracts";
import {
  accountClaims,
  domainOwner,
  domainTxtValue as computeDomainTxtValue,
  expectedDomainTokenHashes,
  hashToken,
  matchesAnyDomainTokenHash,
  releaseCompetingDomainClaims,
  uuidv7,
  withOrganization,
  type Tx,
} from "@core/db";
import { config } from "./config";
import { db } from "./db";
import { CoreError, isUniqueViolation } from "./errors";

export { hashToken };

export type ResolveTxtFn = (hostname: string) => Promise<string[][]>;

export const DNS_TXT_TIMEOUT_MS = 5_000;

export interface VerifyPrimaryDomainOptions {
  trustLocally?: boolean | undefined;
  resolveTxt?: ResolveTxtFn | undefined;
  timeoutMs?: number | undefined;
  ipAddress?: string | null | undefined;
  userAgent?: string | null | undefined;
  requestId?: string | null | undefined;
}

export type AccountPendingDomainView =
  | {
      canManage: true;
      domain: string;
      txtHost: string;
      txtValue: string;
      devTrust: boolean;
    }
  | {
      canManage: false;
      domain: string;
    };

function sanitizeIpAddress(value: string | null | undefined): string | null {
  if (!value) return null;
  const candidate = value.split(",")[0]?.trim() ?? "";
  return candidate && isIP(candidate) !== 0 ? candidate : null;
}

async function resolveTxtWithTimeout(
  resolver: ResolveTxtFn,
  hostname: string,
  timeoutMs = DNS_TXT_TIMEOUT_MS,
): Promise<string[][]> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    const timeout = new Promise<never>((_, reject) => {
      timer = setTimeout(() => {
        reject(new Error("Przekroczono limit czasu zapytania DNS TXT"));
      }, timeoutMs);
      timer.unref?.();
    });
    return await Promise.race([resolver(hostname), timeout]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

/**
 * Wartość rekordu TXT potwierdzającego domenę. Wyliczana z sekretu weryfikacji, identyfikatora firmy
 * i domeny, więc nie trzeba jej przechowywać; w bazie jest tylko jej skrót (`verificationTokenHash`).
 */
export function domainTxtValue(organizationId: string, domain: string): string {
  return computeDomainTxtValue(config.domainVerificationSecret, organizationId, domain);
}

/**
 * Sprawdza w bieżącej transakcji `withOrganization`, czy konto ma prawo zarządzać domenami firmy:
 * jest Ownerem albo ma aktywne uprawnienie `core.organization.manage` w zakresie całej firmy
 * (`ORGANIZATION`), oceniane dokładnie tymi samymi regułami `@monorise-team/permissions` co Core API.
 */
export async function canAccountManageOrganization(
  tx: Tx,
  input: {
    accountId: string;
    organizationId: string;
    ownerAccountId: string | null;
    authzRevision: number;
    now?: Date | undefined;
  },
): Promise<boolean> {
  if (input.ownerAccountId === input.accountId) return true;

  const assignments = await tx.roleAssignment.findMany({
    where: { accountId: input.accountId },
    select: {
      scopeType: true,
      scopeId: true,
      validFrom: true,
      validUntil: true,
      role: {
        select: {
          archivedAt: true,
          permissions: {
            select: {
              permission: { select: { key: true, deprecatedAt: true } },
            },
          },
        },
      },
    },
  });

  return canManageOrganizationAssignments({
    accountId: input.accountId,
    organizationId: input.organizationId,
    isOwner: false,
    authzRevision: input.authzRevision,
    assignments: assignments as readonly RawRoleAssignmentRecord[],
    now: input.now,
  });
}

/**
 * Wyznacza widok oczekującej głównej domeny na stronie `/account`:
 * instrukcja TXT i przyciski weryfikacji są pokazywane wyłącznie Ownerowi albo kontu z
 * `core.organization.manage` (`ORGANIZATION`) oraz tylko dla domeny w statusie `PENDING` lub `FAILED`.
 */
export function resolveAccountPendingDomainView(input: {
  organizationId: string;
  domain: string;
  status: DomainStatus;
  canManage: boolean;
  devTrust: boolean;
}): AccountPendingDomainView {
  if (input.canManage && (input.status === "PENDING" || input.status === "FAILED")) {
    return {
      canManage: true,
      domain: input.domain,
      txtHost: domainVerificationHost(input.domain),
      txtValue: domainTxtValue(input.organizationId, input.domain),
      devTrust: input.devTrust,
    };
  }
  return {
    canManage: false,
    domain: input.domain,
  };
}

async function txtRecordMatchesHashes(
  domain: string,
  expectedHashes: readonly string[],
  resolver: ResolveTxtFn = dnsResolveTxt,
  timeoutMs = DNS_TXT_TIMEOUT_MS,
): Promise<boolean> {
  if (expectedHashes.length === 0) return false;
  try {
    const records = await resolveTxtWithTimeout(resolver, domainVerificationHost(domain), timeoutMs);
    return records.some((parts) => matchesAnyDomainTokenHash(parts.join(""), expectedHashes));
  } catch {
    return false;
  }
}

/**
 * Sprawdza rekord TXT głównej domeny firmy zalogowanego konta (Owner lub `core.organization.manage`
 * w zakresie `ORGANIZATION`). Po potwierdzeniu usuwa konkurencyjne niezweryfikowane, niegłówne
 * roszczenia innych firm („wygrywa weryfikacja”), aktywuje firmę wyłącznie ze stanu
 * `PENDING_VERIFICATION` (także gdy główna domena była już wcześniej `VERIFIED`, nigdy nie odblokowuje
 * `SUSPENDED`/`OFFBOARDING`) i zapisuje wpisy audytu `organization.domain.verified` oraz
 * `organization.activated` (ADR-0021, ADR-0039).
 * Lokalnie (`NODE_ENV` = `development`/`test` i `CORE_DEV_TRUST_DOMAINS=1`) działa `trustLocally: true`.
 */
export async function verifyOrganizationDomain(accountId: string, options: VerifyPrimaryDomainOptions = {}) {
  const trustLocally = options.trustLocally ?? false;
  const resolver = options.resolveTxt ?? dnsResolveTxt;
  const timeoutMs = options.timeoutMs ?? DNS_TXT_TIMEOUT_MS;

  const claims = await accountClaims(db, accountId);
  if (!claims) throw new CoreError("UNAUTHENTICATED", 401, "Zaloguj się ponownie");

  const initial = await withOrganization(db, claims.organizationId, async (tx) => {
    const [organization, domain] = await Promise.all([
      tx.organization.findUniqueOrThrow({
        where: { id: claims.organizationId },
        select: { id: true, status: true, ownerAccountId: true },
      }),
      tx.organizationDomain.findFirst({ where: { isPrimary: true } }),
    ]);
    if (!domain) throw new CoreError("NOT_FOUND", 404, "Firma nie ma domeny do potwierdzenia");

    const allowed = await canAccountManageOrganization(tx, {
      accountId,
      organizationId: claims.organizationId,
      ownerAccountId: organization.ownerAccountId,
      authzRevision: claims.authzRevision,
    });
    if (!allowed) {
      throw new CoreError("PERMISSION_DENIED", 403, "Brak uprawnień do potwierdzenia domeny firmy");
    }

    if (domain.status !== "VERIFIED" && domain.status !== "REVOKED") {
      const existingOwner = await domainOwner(tx, domain.domain);
      if (existingOwner && existingOwner.organizationId !== claims.organizationId) {
        throw new CoreError("CONFLICT", 409, "Ta domena została już zweryfikowana przez inną firmę");
      }
    }

    return { organization, domain };
  });

  if (trustLocally && !config.devTrustDomains) {
    throw new CoreError("PERMISSION_DENIED", 403, "Potwierdzenie bez DNS działa tylko lokalnie");
  }
  if (initial.domain.status === "REVOKED") {
    throw new CoreError("CONFLICT", 409, "Nie można zweryfikować cofniętej domeny");
  }
  if (initial.domain.status === "VERIFIED" && initial.organization.status !== "PENDING_VERIFICATION") {
    return { domain: initial.domain.domain, status: initial.domain.status };
  }

  let verified = initial.domain.status === "VERIFIED" || trustLocally;
  if (!verified) {
    const expectedHashes = expectedDomainTokenHashes({
      storedHash: initial.domain.verificationTokenHash,
      currentSecret: config.domainVerificationSecret,
      organizationId: claims.organizationId,
      domain: initial.domain.domain,
    });
    verified = await txtRecordMatchesHashes(initial.domain.domain, expectedHashes, resolver, timeoutMs);
  }

  const ipAddress = sanitizeIpAddress(options.ipAddress);
  const userAgent = options.userAgent && options.userAgent.length > 0 ? options.userAgent : null;
  const domainLockKey = `domain_verify:${initial.domain.domain.toLowerCase()}`;

  return withOrganization(db, claims.organizationId, async (tx) => {
    await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtextextended(${domainLockKey}::text, 0))`;
    await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtextextended('org_domains:' || ${claims.organizationId}::uuid::text, 0))`;

    const domain = await tx.organizationDomain.findUnique({ where: { id: initial.domain.id } });
    if (!domain) throw new CoreError("NOT_FOUND", 404, "Firma nie ma domeny do potwierdzenia");
    if (domain.status === "REVOKED") {
      throw new CoreError("CONFLICT", 409, "Nie można zweryfikować cofniętej domeny");
    }

    const now = new Date();

    if (domain.status === "VERIFIED") {
      const activated = await tx.organization.updateMany({
        where: { id: claims.organizationId, status: "PENDING_VERIFICATION" },
        data: { status: "ACTIVE" },
      });
      if (activated.count > 0) {
        await tx.auditLog.create({
          data: {
            id: uuidv7(now.getTime()),
            organizationId: claims.organizationId,
            actorType: "ACCOUNT",
            actorAccountId: accountId,
            action: "organization.activated",
            resourceType: "organization",
            resourceId: claims.organizationId,
            metadata: {
              previousStatus: "PENDING_VERIFICATION",
              status: "ACTIVE",
              domainId: domain.id,
              domain: domain.domain,
            },
            ipAddress,
            userAgent,
            requestId: options.requestId ?? null,
          },
        });
      }
      return { domain: domain.domain, status: domain.status };
    }

    if (verified) {
      const existingOwner = await domainOwner(tx, domain.domain);
      if (existingOwner && existingOwner.organizationId !== claims.organizationId) {
        throw new CoreError("CONFLICT", 409, "Ta domena została już zweryfikowana przez inną firmę");
      }
    }

    let updated;
    try {
      updated = await tx.organizationDomain.update({
        where: { id: domain.id },
        data: verified ? { status: "VERIFIED", verifiedAt: now, lastCheckedAt: now } : { lastCheckedAt: now },
      });
    } catch (error) {
      if (isUniqueViolation(error)) {
        throw new CoreError("CONFLICT", 409, "Ta domena została już zweryfikowana przez inną firmę");
      }
      throw error;
    }

    if (verified) {
      await releaseCompetingDomainClaims(tx, updated.domain);

      await tx.auditLog.create({
        data: {
          id: uuidv7(now.getTime()),
          organizationId: claims.organizationId,
          actorType: "ACCOUNT",
          actorAccountId: accountId,
          action: "organization.domain.verified",
          resourceType: "organization_domain",
          resourceId: updated.id,
          metadata: {
            domain: updated.domain,
            method: trustLocally ? "DEV_TRUST" : "DNS_TXT",
          },
          ipAddress,
          userAgent,
          requestId: options.requestId ?? null,
        },
      });

      const activated = await tx.organization.updateMany({
        where: { id: claims.organizationId, status: "PENDING_VERIFICATION" },
        data: { status: "ACTIVE" },
      });
      if (activated.count > 0) {
        await tx.auditLog.create({
          data: {
            id: uuidv7(now.getTime()),
            organizationId: claims.organizationId,
            actorType: "ACCOUNT",
            actorAccountId: accountId,
            action: "organization.activated",
            resourceType: "organization",
            resourceId: claims.organizationId,
            metadata: {
              previousStatus: "PENDING_VERIFICATION",
              status: "ACTIVE",
              domainId: updated.id,
              domain: updated.domain,
            },
            ipAddress,
            userAgent,
            requestId: options.requestId ?? null,
          },
        });
      }
    }

    return { domain: updated.domain, status: updated.status };
  });
}
