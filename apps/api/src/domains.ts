import { resolveTxt as dnsResolveTxt } from "node:dns/promises";
import {
  CORE_PERMISSIONS,
  domainVerificationHost,
  isFreeEmailDomain,
  MAX_ORGANIZATION_DOMAINS,
  type ApiErrorBody,
  type CreateOrganizationDomain,
  type DomainStatus,
  type ErrorCode,
  type Organization,
  type OrganizationDomain,
  type OrganizationStatus,
  type UpdateOrganization,
  type VerifyOrganizationDomain,
} from "@core/contracts";
import {
  domainOwner,
  domainTxtValue,
  expectedDomainTokenHashes,
  hashToken,
  matchesAnyDomainTokenHash,
  releaseCompetingDomainClaims,
  uuidv7,
  withOrganization,
  type PrismaClient,
  type Tx,
} from "@core/db";
import type { FastifyRequest } from "fastify";
import { writeAudit, type AuditActorAccount } from "./audit.js";
import {
  assertCorePermission,
  canManageOrganization,
  loadPermissionSnapshot,
  type AuthzSubject,
} from "./authorization.js";

export type ResolveTxtFn = (hostname: string) => Promise<string[][]>;

/** Limit czasu oczekiwania na odpowiedź DNS TXT (ms), wykonywany poza transakcją bazy. */
export const DNS_TXT_TIMEOUT_MS = 5_000;

export class DomainError extends Error {
  constructor(
    readonly status: number,
    readonly code: ErrorCode,
    message: string,
    readonly details: ApiErrorBody["details"] = [],
  ) {
    super(message);
  }
}

export interface DomainServiceOptions {
  /** Sekret HMAC-SHA256 współdzielony z `apps/auth` (`CORE_DOMAIN_VERIFICATION_SECRET`). */
  domainVerificationSecret?: string | undefined;
  /** Czy dozwolona jest ścieżka lokalna `trustLocally: true` (`NODE_ENV` = `development`/`test` i `CORE_DEV_TRUST_DOMAINS=1`). */
  devTrustDomains?: boolean | undefined;
  /** Nadpisanie zapytania DNS TXT (np. w testach). */
  resolveTxt?: ResolveTxtFn | undefined;
}

export interface SerializableOrganizationDomainRow {
  id: string;
  domain: string;
  status: DomainStatus;
  isPrimary: boolean;
  verifiedAt: Date | null;
  lastCheckedAt: Date | null;
}

export interface SerializableOrganizationRow {
  id: string;
  name: string;
  status: OrganizationStatus;
  createdAt: Date;
  domains: readonly SerializableOrganizationDomainRow[];
}

export interface PreparedDomainVerification {
  domainId: string;
  domain: string;
  alreadyVerified: boolean;
  trustLocally: boolean;
}

function isUniqueViolation(error: unknown): boolean {
  const err = error as { code?: string; message?: string } | null;
  if (err?.code === "P2002" || err?.code === "23505") return true;
  return /duplicate key value violates unique constraint/i.test(String(err?.message ?? ""));
}

/**
 * Serializuje operacje na domenach jednej firmy na czas transakcji (limit 20 domen, weryfikacja,
 * zmiana głównej domeny, usuwanie oraz walidacja domeny przy zaproszeniach i `workEmail`).
 */
export async function lockOrganizationDomains(tx: Tx, organizationId: string): Promise<void> {
  await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtextextended('org_domains:' || ${organizationId}::uuid::text, 0))`;
}

/** Serializuje równoległą weryfikację tej samej domeny ponad granicą firm („wygrywa weryfikacja”). */
async function lockDomainVerification(tx: Tx, domain: string): Promise<void> {
  const lockKey = `domain_verify:${domain.toLowerCase()}`;
  await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtextextended(${lockKey}::text, 0))`;
}

/** Odpytuje rekordy DNS TXT z limitem czasu (domyślnie 5 s) bez wycieku timera. */
export async function resolveTxtWithTimeout(
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
 * Aktywuje firmę wyłącznie ze stanu `PENDING_VERIFICATION` (nigdy nie odblokowuje `SUSPENDED` ani
 * `OFFBOARDING`) i zapisuje wpis audytu `organization.activated`, gdy zmiana rzeczywiście zaszła.
 */
async function activateOrganizationIfPending(
  tx: Tx,
  request: FastifyRequest,
  who: AuditActorAccount,
  domain: { id: string; domain: string },
): Promise<void> {
  const activated = await tx.organization.updateMany({
    where: { id: who.organizationId, status: "PENDING_VERIFICATION" },
    data: { status: "ACTIVE" },
  });
  if (activated.count > 0) {
    await writeAudit(tx, request, who, {
      action: "organization.activated",
      resourceType: "organization",
      resourceId: who.organizationId,
      metadata: {
        previousStatus: "PENDING_VERIFICATION",
        status: "ACTIVE",
        domainId: domain.id,
        domain: domain.domain,
      },
    });
  }
}

/**
 * Serializuje domenę firmy do formatu API. Pola `verificationTxtName` i `verificationTxtValue`
 * są zwracane wyłącznie dla domen w statusie `PENDING` lub `FAILED` i tylko wywołującemu z `isOwner`
 * albo `core.organization.manage` w zakresie całej firmy; `verificationTokenHash` nigdy nie opuszcza bazy.
 */
export function serializeOrganizationDomain(
  row: SerializableOrganizationDomainRow,
  options: {
    organizationId: string;
    includeVerificationTxt: boolean;
    domainVerificationSecret?: string | undefined;
  },
): OrganizationDomain {
  const showTxt = (row.status === "PENDING" || row.status === "FAILED") && options.includeVerificationTxt;
  const secret = options.domainVerificationSecret?.trim();
  return {
    id: row.id,
    domain: row.domain,
    status: row.status,
    isPrimary: row.isPrimary,
    verifiedAt: row.verifiedAt ? row.verifiedAt.toISOString() : null,
    lastCheckedAt: row.lastCheckedAt ? row.lastCheckedAt.toISOString() : null,
    verificationTxtName: showTxt ? domainVerificationHost(row.domain) : null,
    verificationTxtValue: showTxt && secret ? domainTxtValue(secret, options.organizationId, row.domain) : null,
  };
}

export function serializeOrganization(
  org: SerializableOrganizationRow,
  options: {
    includeVerificationTxt: boolean;
    domainVerificationSecret?: string | undefined;
  },
): Organization {
  return {
    id: org.id,
    name: org.name,
    status: org.status,
    createdAt: org.createdAt.toISOString(),
    domains: org.domains.map((domain) =>
      serializeOrganizationDomain(domain, {
        organizationId: org.id,
        includeVerificationTxt: options.includeVerificationTxt,
        domainVerificationSecret: options.domainVerificationSecret,
      }),
    ),
  };
}

/** Odczytuje dane firmy i jej domeny, ujawniając instrukcję DNS TXT tylko osobom uprawnionym. */
export async function getOrganizationForCaller(
  tx: Tx,
  who: AuthzSubject,
  options: DomainServiceOptions,
): Promise<Organization> {
  const organization = await tx.organization.findUniqueOrThrow({
    where: { id: who.organizationId },
    include: { domains: { orderBy: [{ createdAt: "asc" }, { id: "asc" }] } },
  });

  const hasPendingOrFailed = organization.domains.some(
    (domain) => domain.status === "PENDING" || domain.status === "FAILED",
  );
  let includeVerificationTxt = false;
  if (hasPendingOrFailed) {
    if (who.isOwner) {
      includeVerificationTxt = true;
    } else {
      const snapshot = await loadPermissionSnapshot(tx, who);
      includeVerificationTxt = canManageOrganization(snapshot);
    }
  }

  return serializeOrganization(organization, {
    includeVerificationTxt,
    domainVerificationSecret: options.domainVerificationSecret,
  });
}

/** Zmienia edytowalne dane firmy (`name`). Zapisuje audyt `organization.updated` tylko przy realnej zmianie. */
export async function updateOrganization(
  tx: Tx,
  request: FastifyRequest,
  who: AuthzSubject & AuditActorAccount,
  input: UpdateOrganization,
  options: DomainServiceOptions,
): Promise<Organization> {
  const snapshot = await loadPermissionSnapshot(tx, who);
  assertCorePermission(snapshot, CORE_PERMISSIONS.keys["organization.manage"], {});

  const organization = await tx.organization.findUniqueOrThrow({
    where: { id: who.organizationId },
    include: { domains: { orderBy: [{ createdAt: "asc" }, { id: "asc" }] } },
  });

  if (input.name === organization.name) {
    return serializeOrganization(organization, {
      includeVerificationTxt: true,
      domainVerificationSecret: options.domainVerificationSecret,
    });
  }

  const updated = await tx.organization.update({
    where: { id: organization.id },
    data: { name: input.name },
    include: { domains: { orderBy: [{ createdAt: "asc" }, { id: "asc" }] } },
  });

  await writeAudit(tx, request, who, {
    action: "organization.updated",
    resourceType: "organization",
    resourceId: updated.id,
    metadata: {
      fields: ["name"],
      previousName: organization.name,
      name: updated.name,
    },
  });

  return serializeOrganization(updated, {
    includeVerificationTxt: true,
    domainVerificationSecret: options.domainVerificationSecret,
  });
}

/**
 * Dodaje niezweryfikowaną domenę (`PENDING`, `DNS_TXT`, `isPrimary = false`) do firmy:
 * - odrzuca darmowe skrzynki i ich subdomeny (`422 EMAIL_DOMAIN_NOT_ALLOWED`),
 * - odrzuca domenę już zweryfikowaną (`VERIFIED`) przez dowolną firmę albo już dodaną w tej firmie
 *   (`409 CONFLICT` bez ujawniania właściciela, ADR-0019),
 * - zgodnie z zasadą „wygrywa weryfikacja” pozwala dodać domenę, która ma jedynie niezweryfikowane
 *   roszczenie w innej firmie,
 * - pilnuje limitu 20 domen w firmie (`409 CONFLICT`).
 */
export async function addOrganizationDomain(
  tx: Tx,
  request: FastifyRequest,
  who: AuthzSubject & AuditActorAccount,
  input: CreateOrganizationDomain,
  now: Date,
  options: DomainServiceOptions,
): Promise<OrganizationDomain> {
  const snapshot = await loadPermissionSnapshot(tx, who);
  assertCorePermission(snapshot, CORE_PERMISSIONS.keys["organization.manage"], {});

  if (isFreeEmailDomain(input.domain)) {
    throw new DomainError(422, "EMAIL_DOMAIN_NOT_ALLOWED", "Darmowe domeny pocztowe nie mogą należeć do firmy", [
      { field: "domain", message: "Darmowe domeny pocztowe (np. Gmail, WP, Onet) nie mogą być domeną firmy" },
    ]);
  }

  const secret = options.domainVerificationSecret?.trim();
  if (!secret) {
    throw new Error("Brak zmiennej środowiskowej CORE_DOMAIN_VERIFICATION_SECRET");
  }

  await lockDomainVerification(tx, input.domain);
  await lockOrganizationDomains(tx, who.organizationId);

  const [verifiedOwner, existingInOrg] = await Promise.all([
    domainOwner(tx, input.domain),
    tx.organizationDomain.findFirst({
      where: { organizationId: who.organizationId, domain: input.domain },
      select: { id: true },
    }),
  ]);
  if (verifiedOwner || existingInOrg) {
    throw new DomainError(409, "CONFLICT", "Ta domena jest już przypisana do firmy");
  }

  const domainCount = await tx.organizationDomain.count({ where: { organizationId: who.organizationId } });
  if (domainCount >= MAX_ORGANIZATION_DOMAINS) {
    throw new DomainError(409, "CONFLICT", `Firma może mieć co najwyżej ${MAX_ORGANIZATION_DOMAINS} domen`);
  }

  const txtValue = domainTxtValue(secret, who.organizationId, input.domain);
  const verificationTokenHash = hashToken(txtValue);

  let created: SerializableOrganizationDomainRow;
  try {
    created = await tx.organizationDomain.create({
      data: {
        id: uuidv7(now.getTime()),
        organizationId: who.organizationId,
        domain: input.domain,
        status: "PENDING",
        verificationMethod: "DNS_TXT",
        verificationTokenHash,
        verifiedAt: null,
        lastCheckedAt: null,
        isPrimary: false,
      },
    });
  } catch (error) {
    if (isUniqueViolation(error)) {
      throw new DomainError(409, "CONFLICT", "Ta domena jest już przypisana do firmy");
    }
    throw error;
  }

  await writeAudit(tx, request, who, {
    action: "organization.domain.added",
    resourceType: "organization_domain",
    resourceId: created.id,
    metadata: { domain: created.domain },
  });

  return serializeOrganizationDomain(created, {
    organizationId: who.organizationId,
    includeVerificationTxt: true,
    domainVerificationSecret: secret,
  });
}

/**
 * Etap 1 weryfikacji domeny — poza długą transakcją i blokadami bazy:
 * 1. Wyszukuje domenę (`404 NOT_FOUND` przed sprawdzeniem uprawnień) i weryfikuje `core.organization.manage`.
 * 2. Pilnuje flagi `trustLocally` (`403`, gdy `devTrustDomains !== true`), statusu `REVOKED` (`409`)
 *    oraz tego, czy inna firma nie zdążyła już zweryfikować tej domeny (`409`).
 * 3. Dla niezweryfikowanej domeny wykonuje zapytanie DNS TXT (timeout 5 s) poza transakcją, akceptując
 *    zarówno zapisany `verificationTokenHash`, jak i skrót wyliczony z bieżącego sekretu; gdy rekord
 *    nie pasuje, utrwala `lastCheckedAt = now` w osobnej krótkiej transakcji i rzuca `422 VALIDATION_FAILED`.
 */
export async function prepareVerifyOrganizationDomain(
  db: PrismaClient,
  who: AuthzSubject,
  domainId: string,
  input: VerifyOrganizationDomain,
  now: Date,
  options: DomainServiceOptions,
): Promise<PreparedDomainVerification> {
  const { domain, verifiedByOther } = await withOrganization(db, who.organizationId, async (tx) => {
    const found = await tx.organizationDomain.findUnique({ where: { id: domainId } });
    if (!found) {
      throw new DomainError(404, "NOT_FOUND", "Nie znaleziono domeny firmy");
    }
    const snapshot = await loadPermissionSnapshot(tx, who);
    assertCorePermission(snapshot, CORE_PERMISSIONS.keys["organization.manage"], {});

    let verifiedByOther = false;
    if (found.status !== "VERIFIED" && found.status !== "REVOKED") {
      const owner = await domainOwner(tx, found.domain);
      verifiedByOther = owner !== null && owner.organizationId !== who.organizationId;
    }

    return { domain: found, verifiedByOther };
  });

  const trustLocally = input.trustLocally ?? false;

  if (trustLocally && !options.devTrustDomains) {
    throw new DomainError(403, "PERMISSION_DENIED", "Potwierdzenie bez DNS działa tylko lokalnie");
  }

  if (domain.status === "REVOKED") {
    throw new DomainError(409, "CONFLICT", "Nie można zweryfikować cofniętej domeny");
  }

  if (domain.status === "VERIFIED") {
    return { domainId: domain.id, domain: domain.domain, alreadyVerified: true, trustLocally };
  }

  if (verifiedByOther) {
    throw new DomainError(409, "CONFLICT", "Ta domena została już zweryfikowana przez inną firmę");
  }

  if (!trustLocally) {
    const expectedHashes = expectedDomainTokenHashes({
      storedHash: domain.verificationTokenHash,
      currentSecret: options.domainVerificationSecret,
      organizationId: who.organizationId,
      domain: domain.domain,
    });

    let matched = false;
    if (expectedHashes.length > 0) {
      const resolver = options.resolveTxt ?? dnsResolveTxt;
      try {
        const records = await resolveTxtWithTimeout(resolver, domainVerificationHost(domain.domain));
        matched = records.some((parts) => matchesAnyDomainTokenHash(parts.join(""), expectedHashes));
      } catch {
        matched = false;
      }
    }

    if (!matched) {
      await withOrganization(db, who.organizationId, async (tx) => {
        await tx.organizationDomain.updateMany({
          where: { id: domain.id, status: { not: "VERIFIED" } },
          data: { lastCheckedAt: now },
        });
      });
      throw new DomainError(422, "VALIDATION_FAILED", "Nie znaleziono oczekiwanego rekordu TXT w DNS");
    }
  }

  return { domainId: domain.id, domain: domain.domain, alreadyVerified: false, trustLocally };
}

/**
 * Etap 2 weryfikacji domeny — wewnątrz transakcji `withOrganization` (i ewentualnego `Idempotency-Key`):
 * pod blokadami `domain_verify` i `org_domains` ustawia `VERIFIED`, usuwa konkurencyjne niezweryfikowane
 * niegłówne roszczenia innych firm („wygrywa weryfikacja”), zapisuje wpis audytu `organization.domain.verified`,
 * a gdy to domena główna — przenosi firmę z `PENDING_VERIFICATION` do `ACTIVE` (także w gałęzi
 * idempotentnej „już zweryfikowana”).
 */
export async function commitVerifyOrganizationDomain(
  tx: Tx,
  request: FastifyRequest,
  who: AuthzSubject & AuditActorAccount,
  prepared: PreparedDomainVerification,
  now: Date,
  options: DomainServiceOptions,
): Promise<OrganizationDomain> {
  await lockDomainVerification(tx, prepared.domain);
  await lockOrganizationDomains(tx, who.organizationId);

  const domain = await tx.organizationDomain.findUnique({ where: { id: prepared.domainId } });
  if (!domain) {
    const owner = await domainOwner(tx, prepared.domain);
    if (owner && owner.organizationId !== who.organizationId) {
      throw new DomainError(409, "CONFLICT", "Ta domena została już zweryfikowana przez inną firmę");
    }
    throw new DomainError(404, "NOT_FOUND", "Nie znaleziono domeny firmy");
  }
  if (domain.status === "REVOKED") {
    throw new DomainError(409, "CONFLICT", "Nie można zweryfikować cofniętej domeny");
  }
  if (domain.status === "VERIFIED") {
    if (domain.isPrimary) {
      await activateOrganizationIfPending(tx, request, who, domain);
    }
    return serializeOrganizationDomain(domain, {
      organizationId: who.organizationId,
      includeVerificationTxt: true,
      domainVerificationSecret: options.domainVerificationSecret,
    });
  }

  const existingOwner = await domainOwner(tx, domain.domain);
  if (existingOwner && existingOwner.organizationId !== who.organizationId) {
    throw new DomainError(409, "CONFLICT", "Ta domena została już zweryfikowana przez inną firmę");
  }

  let updated: SerializableOrganizationDomainRow;
  try {
    updated = await tx.organizationDomain.update({
      where: { id: domain.id },
      data: {
        status: "VERIFIED",
        verifiedAt: now,
        lastCheckedAt: now,
      },
    });
  } catch (error) {
    if (isUniqueViolation(error)) {
      throw new DomainError(409, "CONFLICT", "Ta domena została już zweryfikowana przez inną firmę");
    }
    throw error;
  }

  await releaseCompetingDomainClaims(tx, updated.domain);

  await writeAudit(tx, request, who, {
    action: "organization.domain.verified",
    resourceType: "organization_domain",
    resourceId: updated.id,
    metadata: {
      domain: updated.domain,
      method: prepared.trustLocally ? "DEV_TRUST" : "DNS_TXT",
    },
  });

  if (updated.isPrimary) {
    await activateOrganizationIfPending(tx, request, who, updated);
  }

  return serializeOrganizationDomain(updated, {
    organizationId: who.organizationId,
    includeVerificationTxt: true,
    domainVerificationSecret: options.domainVerificationSecret,
  });
}

/**
 * Usuwa niegłówną, nieużywaną domenę firmy (`204`):
 * 1. Najpierw `404` (przed `403`).
 * 2. Blokuje usunięcie domeny głównej (`isPrimary`) oraz ostatniej zweryfikowanej domeny (`409`).
 * 3. Blokuje usunięcie domeny używanej przez konto (`Account.normalizedEmail`), oczekujące zaproszenie
 *    (`Invitation.status = PENDING`) albo pracownika (`Employee.workEmail`) w firmie (`409`, ADR-0019).
 * 4. Trwale usuwa wiersz (zwalniając domenę) i zapisuje audyt `organization.domain.removed`.
 */
export async function deleteOrganizationDomain(
  tx: Tx,
  request: FastifyRequest,
  who: AuthzSubject & AuditActorAccount,
  domainId: string,
): Promise<void> {
  const initial = await tx.organizationDomain.findUnique({ where: { id: domainId }, select: { id: true } });
  if (!initial) {
    throw new DomainError(404, "NOT_FOUND", "Nie znaleziono domeny firmy");
  }

  const snapshot = await loadPermissionSnapshot(tx, who);
  assertCorePermission(snapshot, CORE_PERMISSIONS.keys["organization.manage"], {});

  await lockOrganizationDomains(tx, who.organizationId);

  const domain = await tx.organizationDomain.findUnique({ where: { id: domainId } });
  if (!domain) {
    throw new DomainError(404, "NOT_FOUND", "Nie znaleziono domeny firmy");
  }

  if (domain.isPrimary) {
    throw new DomainError(409, "CONFLICT", "Nie można usunąć głównej domeny firmy");
  }

  if (domain.status === "VERIFIED") {
    const verifiedCount = await tx.organizationDomain.count({
      where: { organizationId: who.organizationId, status: "VERIFIED" },
    });
    if (verifiedCount <= 1) {
      throw new DomainError(409, "CONFLICT", "Nie można usunąć ostatniej zweryfikowanej domeny firmy");
    }
  }

  const emailSuffix = `@${domain.domain.toLowerCase()}`;
  const [usedByAccount, usedByInvitation, usedByEmployee] = await Promise.all([
    tx.account.findFirst({
      where: {
        organizationId: who.organizationId,
        normalizedEmail: { endsWith: emailSuffix, mode: "insensitive" },
      },
      select: { id: true },
    }),
    tx.invitation.findFirst({
      where: {
        organizationId: who.organizationId,
        status: "PENDING",
        normalizedEmail: { endsWith: emailSuffix, mode: "insensitive" },
      },
      select: { id: true },
    }),
    tx.employee.findFirst({
      where: {
        organizationId: who.organizationId,
        workEmail: { endsWith: emailSuffix, mode: "insensitive" },
      },
      select: { id: true },
    }),
  ]);

  if (usedByAccount || usedByInvitation || usedByEmployee) {
    throw new DomainError(
      409,
      "CONFLICT",
      "Nie można usunąć domeny, ponieważ jest używana przez konta, pracowników lub oczekujące zaproszenia w firmie",
    );
  }

  await tx.organizationDomain.delete({ where: { id: domain.id } });

  await writeAudit(tx, request, who, {
    action: "organization.domain.removed",
    resourceType: "organization_domain",
    resourceId: domain.id,
    metadata: { domain: domain.domain },
  });
}

/**
 * Ustawia wskazaną zweryfikowaną domenę jako główną domenę firmy w jednej transakcji (atomowa zamiana
 * `isPrimary`, zgodna z częściowym indeksem unikalnym) i aktywuje firmę, jeśli wciąż była w stanie
 * `PENDING_VERIFICATION`. Powtórzenie na bieżącej domenie głównej jest idempotentne (bez duplikatu audytu).
 */
export async function setPrimaryOrganizationDomain(
  tx: Tx,
  request: FastifyRequest,
  who: AuthzSubject & AuditActorAccount,
  domainId: string,
  options: DomainServiceOptions,
): Promise<Organization> {
  const initial = await tx.organizationDomain.findUnique({ where: { id: domainId }, select: { id: true } });
  if (!initial) {
    throw new DomainError(404, "NOT_FOUND", "Nie znaleziono domeny firmy");
  }

  const snapshot = await loadPermissionSnapshot(tx, who);
  assertCorePermission(snapshot, CORE_PERMISSIONS.keys["organization.manage"], {});

  await lockOrganizationDomains(tx, who.organizationId);

  const domain = await tx.organizationDomain.findUnique({ where: { id: domainId } });
  if (!domain) {
    throw new DomainError(404, "NOT_FOUND", "Nie znaleziono domeny firmy");
  }

  if (domain.status !== "VERIFIED") {
    throw new DomainError(409, "CONFLICT", "Główną domeną firmy może być wyłącznie zweryfikowana domena");
  }

  if (!domain.isPrimary) {
    const previousPrimary = await tx.organizationDomain.findFirst({
      where: { organizationId: who.organizationId, isPrimary: true },
      select: { id: true, domain: true },
    });

    await tx.organizationDomain.updateMany({
      where: { organizationId: who.organizationId, isPrimary: true },
      data: { isPrimary: false },
    });

    await tx.organizationDomain.update({
      where: { id: domain.id },
      data: { isPrimary: true },
    });

    await writeAudit(tx, request, who, {
      action: "organization.domain.primary_changed",
      resourceType: "organization",
      resourceId: who.organizationId,
      metadata: {
        domainId: domain.id,
        fromDomain: previousPrimary?.domain ?? null,
        toDomain: domain.domain,
      },
    });
  }

  await activateOrganizationIfPending(tx, request, who, domain);

  const organization = await tx.organization.findUniqueOrThrow({
    where: { id: who.organizationId },
    include: { domains: { orderBy: [{ createdAt: "asc" }, { id: "asc" }] } },
  });

  return serializeOrganization(organization, {
    includeVerificationTxt: true,
    domainVerificationSecret: options.domainVerificationSecret,
  });
}
