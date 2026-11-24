import "server-only";
import { createHmac } from "node:crypto";
import { resolveTxt } from "node:dns/promises";
import { DOMAIN_TXT_PREFIX, domainVerificationHost } from "@core/contracts";
import { accountClaims, hashToken, withOrganization } from "@core/db";
import { config } from "./config";
import { db } from "./db";
import { CoreError } from "./errors";

export { hashToken };

/**
 * Wartość rekordu TXT potwierdzającego domenę. Wyliczana z sekretu, identyfikatora firmy i domeny, więc
 * nie trzeba jej przechowywać; w bazie jest tylko jej skrót (verificationTokenHash).
 */
export function domainTxtValue(organizationId: string, domain: string): string {
  const code = createHmac("sha256", config.secret).update(`${organizationId}:${domain}`).digest("base64url");
  return `${DOMAIN_TXT_PREFIX}${code.slice(0, 32)}`;
}

async function txtRecordMatches(domain: string, expected: string): Promise<boolean> {
  try {
    const records = await resolveTxt(domainVerificationHost(domain));
    return records.some((parts) => parts.join("") === expected);
  } catch {
    return false;
  }
}

/**
 * Sprawdza rekord TXT głównej domeny firmy konta. Po potwierdzeniu firma staje się aktywna (ADR-0021).
 * Lokalnie (CORE_DEV_TRUST_DOMAINS=1) można potwierdzić domenę bez DNS.
 */
export async function verifyOrganizationDomain(accountId: string, { trustLocally = false } = {}) {
  const claims = await accountClaims(db, accountId);
  if (!claims) throw new CoreError("UNAUTHENTICATED", 401, "Zaloguj się ponownie");
  return withOrganization(db, claims.organizationId, async (tx) => {
    const domain = await tx.organizationDomain.findFirst({ where: { isPrimary: true } });
    if (!domain) throw new CoreError("NOT_FOUND", 404, "Firma nie ma domeny do potwierdzenia");
    if (domain.status === "VERIFIED") return { domain: domain.domain, status: domain.status };
    if (trustLocally && !config.devTrustDomains) {
      throw new CoreError("PERMISSION_DENIED", 403, "Potwierdzenie bez DNS działa tylko lokalnie");
    }
    const verified =
      trustLocally || (await txtRecordMatches(domain.domain, domainTxtValue(claims.organizationId, domain.domain)));
    const now = new Date();
    const updated = await tx.organizationDomain.update({
      where: { id: domain.id },
      data: verified ? { status: "VERIFIED", verifiedAt: now, lastCheckedAt: now } : { lastCheckedAt: now },
    });
    if (verified) {
      await tx.organization.update({ where: { id: claims.organizationId }, data: { status: "ACTIVE" } });
    }
    return { domain: updated.domain, status: updated.status };
  });
}
