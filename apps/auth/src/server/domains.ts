import "server-only";
import { resolveTxt as dnsResolveTxt } from "node:dns/promises";
import { isIP } from "node:net";
import { domainVerificationHost } from "@core/contracts";
import {
  accountClaims,
  domainTxtValue as computeDomainTxtValue,
  hashToken,
  matchesDomainTokenHash,
  uuidv7,
  withOrganization,
} from "@core/db";
import { config } from "./config";
import { db } from "./db";
import { CoreError } from "./errors";

export { hashToken };

export type ResolveTxtFn = (hostname: string) => Promise<string[][]>;

const DNS_TXT_TIMEOUT_MS = 5_000;

export interface VerifyPrimaryDomainOptions {
  trustLocally?: boolean | undefined;
  resolveTxt?: ResolveTxtFn | undefined;
  ipAddress?: string | null | undefined;
  userAgent?: string | null | undefined;
  requestId?: string | null | undefined;
}

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

async function txtRecordMatchesHash(
  domain: string,
  expectedHash: string,
  resolver: ResolveTxtFn = dnsResolveTxt,
): Promise<boolean> {
  try {
    const records = await resolveTxtWithTimeout(resolver, domainVerificationHost(domain));
    return records.some((parts) => matchesDomainTokenHash(parts.join(""), expectedHash));
  } catch {
    return false;
  }
}

/**
 * Sprawdza rekord TXT głównej domeny firmy konta. Po potwierdzeniu aktywuje firmę wyłącznie ze stanu
 * `PENDING_VERIFICATION` (nigdy nie odblokowuje firm `SUSPENDED` ani `OFFBOARDING`) i zapisuje wpis
 * audytu `organization.domain.verified` (ADR-0021, ADR-0039).
 * Lokalnie (`CORE_DEV_TRUST_DOMAINS=1`) można potwierdzić domenę bez DNS.
 */
export async function verifyOrganizationDomain(accountId: string, options: VerifyPrimaryDomainOptions = {}) {
  const trustLocally = options.trustLocally ?? false;
  const resolver = options.resolveTxt ?? dnsResolveTxt;

  const claims = await accountClaims(db, accountId);
  if (!claims) throw new CoreError("UNAUTHENTICATED", 401, "Zaloguj się ponownie");

  const initial = await withOrganization(db, claims.organizationId, (tx) =>
    tx.organizationDomain.findFirst({ where: { isPrimary: true } }),
  );
  if (!initial) throw new CoreError("NOT_FOUND", 404, "Firma nie ma domeny do potwierdzenia");
  if (initial.status === "VERIFIED") return { domain: initial.domain, status: initial.status };
  if (trustLocally && !config.devTrustDomains) {
    throw new CoreError("PERMISSION_DENIED", 403, "Potwierdzenie bez DNS działa tylko lokalnie");
  }

  const expectedHash =
    initial.verificationTokenHash ?? hashToken(domainTxtValue(claims.organizationId, initial.domain));
  const verified = trustLocally || (await txtRecordMatchesHash(initial.domain, expectedHash, resolver));

  const ipAddress = sanitizeIpAddress(options.ipAddress);
  const userAgent = options.userAgent && options.userAgent.length > 0 ? options.userAgent : null;

  return withOrganization(db, claims.organizationId, async (tx) => {
    await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtextextended('org_domains:' || ${claims.organizationId}::uuid::text, 0))`;

    const domain = await tx.organizationDomain.findUnique({ where: { id: initial.id } });
    if (!domain) throw new CoreError("NOT_FOUND", 404, "Firma nie ma domeny do potwierdzenia");
    if (domain.status === "VERIFIED") return { domain: domain.domain, status: domain.status };

    const now = new Date();
    const updated = await tx.organizationDomain.update({
      where: { id: domain.id },
      data: verified ? { status: "VERIFIED", verifiedAt: now, lastCheckedAt: now } : { lastCheckedAt: now },
    });

    if (verified) {
      await tx.organization.updateMany({
        where: { id: claims.organizationId, status: "PENDING_VERIFICATION" },
        data: { status: "ACTIVE" },
      });

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
    }

    return { domain: updated.domain, status: updated.status };
  });
}
