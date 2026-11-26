import {
  CORE_PERMISSIONS,
  domainVerificationHost,
  IDEMPOTENCY_KEY_HEADER,
  IDEMPOTENCY_REPLAYED_HEADER,
  MAX_ORGANIZATION_DOMAINS,
  type AccountStatus,
  type DomainStatus,
  type InvitationStatus,
  type OrganizationStatus,
} from "@core/contracts";
import {
  domainTxtValue,
  expectedDomainTokenHashes,
  hashToken,
  isDevTrustDomainsEnabled,
  matchesAnyDomainTokenHash,
  matchesDomainTokenHash,
  MIN_DOMAIN_VERIFICATION_SECRET_LENGTH,
  resolveDomainVerificationSecret,
  type PrismaClient,
} from "@core/db";
import { describe, expect, it } from "vitest";
import { resolveTxtWithTimeout, type ResolveTxtFn } from "../src/domains.js";
import { buildServer } from "../src/server.js";

const SECRET = "test-domain-verification-secret-0123456789";
const ROTATED_SECRET = "rotated-domain-verification-secret-9876543210";

const ORG_ACME = "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6a01";
const ORG_GLOBEX = "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6a02";
const ORG_SIGNUP = "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6a03";

const OWNER_ACC = "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6a11";
const OWNER_EMP = "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6a12";
const ADMIN_ACC = "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6a21";
const ADMIN_EMP = "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6a22";
const UNIT_ADMIN_ACC = "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6a31";
const UNIT_ADMIN_EMP = "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6a32";
const REGULAR_ACC = "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6a41";
const REGULAR_EMP = "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6a42";

const GLOBEX_OWNER_ACC = "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6a91";
const GLOBEX_OWNER_EMP = "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6a92";
const SIGNUP_OWNER_ACC = "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6a93";
const SIGNUP_OWNER_EMP = "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6a94";

const UNIT_KRAKOW = "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6a50";
const ACME_PRIMARY_DOM = "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6a61";
const GLOBEX_PRIMARY_DOM = "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6a62";
const SIGNUP_PRIMARY_DOM = "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6a63";

interface MockOrg {
  id: string;
  name: string;
  status: OrganizationStatus;
  ownerAccountId: string;
  createdAt: Date;
}

interface MockDomain {
  id: string;
  organizationId: string;
  domain: string;
  status: DomainStatus;
  verificationMethod: "DNS_TXT" | "OPERATOR";
  verificationTokenHash: string | null;
  verifiedAt: Date | null;
  lastCheckedAt: Date | null;
  isPrimary: boolean;
  createdAt: Date;
}

interface MockAccount {
  id: string;
  organizationId: string;
  employeeId: string;
  email: string;
  normalizedEmail: string;
  status: AccountStatus;
  authzRevision: number;
}

interface MockEmployee {
  id: string;
  organizationId: string;
  firstName: string;
  lastName: string;
  workEmail: string | null;
  jobTitle: string | null;
  status: "ACTIVE" | "FORMER" | "ANONYMIZED";
}

interface MockInvitation {
  id: string;
  organizationId: string;
  accountId: string;
  employeeId: string;
  email: string;
  normalizedEmail: string;
  tokenHash: string;
  status: InvitationStatus;
  expiresAt: Date;
  invitedByAccountId: string | null;
  acceptedAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
}

interface MockIdempotencyRow {
  id: string;
  organizationId: string;
  principal: string;
  key: string;
  method: string;
  path: string;
  requestHash: string;
  responseStatus: number;
  responseBody: unknown;
  createdAt: Date;
  expiresAt: Date;
}

interface MockAudit {
  organizationId: string;
  action: string;
  resourceType: string;
  resourceId: string;
  metadata: unknown;
}

function createInMemoryDomainDb() {
  const orgs = new Map<string, MockOrg>([
    [
      ORG_ACME,
      {
        id: ORG_ACME,
        name: "Acme",
        status: "ACTIVE",
        ownerAccountId: OWNER_ACC,
        createdAt: new Date("2026-11-20T00:00:00.000Z"),
      },
    ],
    [
      ORG_GLOBEX,
      {
        id: ORG_GLOBEX,
        name: "Globex",
        status: "ACTIVE",
        ownerAccountId: GLOBEX_OWNER_ACC,
        createdAt: new Date("2026-11-20T00:00:00.000Z"),
      },
    ],
    [
      ORG_SIGNUP,
      {
        id: ORG_SIGNUP,
        name: "SignupCo",
        status: "PENDING_VERIFICATION",
        ownerAccountId: SIGNUP_OWNER_ACC,
        createdAt: new Date("2026-11-20T00:00:00.000Z"),
      },
    ],
  ]);

  const domains = new Map<string, MockDomain>([
    [
      ACME_PRIMARY_DOM,
      {
        id: ACME_PRIMARY_DOM,
        organizationId: ORG_ACME,
        domain: "acme.test",
        status: "VERIFIED",
        verificationMethod: "DNS_TXT",
        verificationTokenHash: hashToken(domainTxtValue(SECRET, ORG_ACME, "acme.test")),
        verifiedAt: new Date("2026-11-20T00:00:00.000Z"),
        lastCheckedAt: new Date("2026-11-20T00:00:00.000Z"),
        isPrimary: true,
        createdAt: new Date("2026-11-20T00:00:00.000Z"),
      },
    ],
    [
      GLOBEX_PRIMARY_DOM,
      {
        id: GLOBEX_PRIMARY_DOM,
        organizationId: ORG_GLOBEX,
        domain: "globex.test",
        status: "VERIFIED",
        verificationMethod: "DNS_TXT",
        verificationTokenHash: hashToken(domainTxtValue(SECRET, ORG_GLOBEX, "globex.test")),
        verifiedAt: new Date("2026-11-20T00:00:00.000Z"),
        lastCheckedAt: new Date("2026-11-20T00:00:00.000Z"),
        isPrimary: true,
        createdAt: new Date("2026-11-20T00:00:00.000Z"),
      },
    ],
    [
      SIGNUP_PRIMARY_DOM,
      {
        id: SIGNUP_PRIMARY_DOM,
        organizationId: ORG_SIGNUP,
        domain: "signup.test",
        status: "PENDING",
        verificationMethod: "DNS_TXT",
        verificationTokenHash: hashToken(domainTxtValue(SECRET, ORG_SIGNUP, "signup.test")),
        verifiedAt: null,
        lastCheckedAt: null,
        isPrimary: true,
        createdAt: new Date("2026-11-20T00:00:00.000Z"),
      },
    ],
  ]);

  const accounts = new Map<string, MockAccount>([
    [
      OWNER_ACC,
      {
        id: OWNER_ACC,
        organizationId: ORG_ACME,
        employeeId: OWNER_EMP,
        email: "anna@acme.test",
        normalizedEmail: "anna@acme.test",
        status: "ACTIVE",
        authzRevision: 0,
      },
    ],
    [
      ADMIN_ACC,
      {
        id: ADMIN_ACC,
        organizationId: ORG_ACME,
        employeeId: ADMIN_EMP,
        email: "marta@acme.test",
        normalizedEmail: "marta@acme.test",
        status: "ACTIVE",
        authzRevision: 0,
      },
    ],
    [
      UNIT_ADMIN_ACC,
      {
        id: UNIT_ADMIN_ACC,
        organizationId: ORG_ACME,
        employeeId: UNIT_ADMIN_EMP,
        email: "tomasz@acme.test",
        normalizedEmail: "tomasz@acme.test",
        status: "ACTIVE",
        authzRevision: 0,
      },
    ],
    [
      REGULAR_ACC,
      {
        id: REGULAR_ACC,
        organizationId: ORG_ACME,
        employeeId: REGULAR_EMP,
        email: "jan@acme.test",
        normalizedEmail: "jan@acme.test",
        status: "ACTIVE",
        authzRevision: 0,
      },
    ],
    [
      GLOBEX_OWNER_ACC,
      {
        id: GLOBEX_OWNER_ACC,
        organizationId: ORG_GLOBEX,
        employeeId: GLOBEX_OWNER_EMP,
        email: "ceo@globex.test",
        normalizedEmail: "ceo@globex.test",
        status: "ACTIVE",
        authzRevision: 0,
      },
    ],
    [
      SIGNUP_OWNER_ACC,
      {
        id: SIGNUP_OWNER_ACC,
        organizationId: ORG_SIGNUP,
        employeeId: SIGNUP_OWNER_EMP,
        email: "founder@signup.test",
        normalizedEmail: "founder@signup.test",
        status: "ACTIVE",
        authzRevision: 0,
      },
    ],
  ]);

  const employees = new Map<string, MockEmployee>([
    [
      OWNER_EMP,
      {
        id: OWNER_EMP,
        organizationId: ORG_ACME,
        firstName: "Anna",
        lastName: "Owner",
        workEmail: "anna@acme.test",
        jobTitle: null,
        status: "ACTIVE",
      },
    ],
    [
      ADMIN_EMP,
      {
        id: ADMIN_EMP,
        organizationId: ORG_ACME,
        firstName: "Marta",
        lastName: "Admin",
        workEmail: "marta@acme.test",
        jobTitle: null,
        status: "ACTIVE",
      },
    ],
    [
      UNIT_ADMIN_EMP,
      {
        id: UNIT_ADMIN_EMP,
        organizationId: ORG_ACME,
        firstName: "Tomasz",
        lastName: "Oddzial",
        workEmail: "tomasz@acme.test",
        jobTitle: null,
        status: "ACTIVE",
      },
    ],
    [
      REGULAR_EMP,
      {
        id: REGULAR_EMP,
        organizationId: ORG_ACME,
        firstName: "Jan",
        lastName: "Zwykly",
        workEmail: "jan@acme.test",
        jobTitle: null,
        status: "ACTIVE",
      },
    ],
    [
      GLOBEX_OWNER_EMP,
      {
        id: GLOBEX_OWNER_EMP,
        organizationId: ORG_GLOBEX,
        firstName: "Ewa",
        lastName: "Globex",
        workEmail: "ceo@globex.test",
        jobTitle: null,
        status: "ACTIVE",
      },
    ],
    [
      SIGNUP_OWNER_EMP,
      {
        id: SIGNUP_OWNER_EMP,
        organizationId: ORG_SIGNUP,
        firstName: "Adam",
        lastName: "Signup",
        workEmail: "founder@signup.test",
        jobTitle: null,
        status: "ACTIVE",
      },
    ],
  ]);

  const authUsers = new Map<string, { id: string; email: string; name: string }>();
  const invitations = new Map<string, MockInvitation>();
  const idempotencyKeys = new Map<string, MockIdempotencyRow>();
  const audits: MockAudit[] = [];
  const executedLocks: string[] = [];

  // Prosta kolejka wzajemnego wykluczania dla pg_advisory_xact_lock w testach współbieżności
  const activeLocks = new Map<string, Promise<void>>();
  async function acquireAdvisoryLock(lockKey: string, heldReleaseFns: (() => void)[]) {
    while (activeLocks.has(lockKey)) {
      await activeLocks.get(lockKey);
    }
    let release!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = () => {
        if (activeLocks.get(lockKey) === gate) activeLocks.delete(lockKey);
        resolve();
      };
    });
    activeLocks.set(lockKey, gate);
    heldReleaseFns.push(release);
  }

  const sortedDomainsForOrg = (orgId: string) =>
    [...domains.values()]
      .filter((d) => d.organizationId === orgId)
      .sort((a, b) => a.createdAt.getTime() - b.createdAt.getTime() || a.id.localeCompare(b.id));

  const idemKey = (orgId: string, principal: string, key: string) => `${orgId}\0${principal}\0${key}`;

  const db = {
    $transaction: async <T>(fn: (tx: unknown) => Promise<T>): Promise<T> => {
      let currentOrgId: string | null = null;
      const heldLocks: (() => void)[] = [];
      const tx = {
        $executeRaw: async (strings: TemplateStringsArray, ...values: unknown[]) => {
          const sql = strings.join(" ");
          if (sql.includes("set_config")) {
            currentOrgId = String(values[0] ?? "");
          } else if (sql.includes("pg_advisory_xact_lock")) {
            let lockKey = String(values[0] ?? "");
            if (sql.includes("'org_domains:'")) lockKey = `org_domains:${String(values[0] ?? "")}`;
            else if (sql.includes("'employee_work_email:'")) lockKey = `employee_work_email:${String(values[0] ?? "")}`;
            executedLocks.push(lockKey);
            await acquireAdvisoryLock(lockKey, heldLocks);
          }
          return 1;
        },
        $queryRaw: async (strings: TemplateStringsArray, ...values: unknown[]) => {
          const sql = strings.join(" ");
          if (sql.includes("domain_owner")) {
            const target = String(values[0] ?? "").toLowerCase();
            // Zasada „wygrywa weryfikacja”: domain_owner zwraca wyłącznie VERIFIED
            const found = [...domains.values()].find(
              (d) => d.domain.toLowerCase() === target && d.status === "VERIFIED",
            );
            return found ? [{ organization_id: found.organizationId, domain_status: found.status }] : [];
          }
          if (sql.includes("organization_domains_release_competing_claims")) {
            const target = String(values[0] ?? "").toLowerCase();
            if (!currentOrgId) throw new Error("Brak kontekstu firmy (app.organization_id)");
            const callerVerified = [...domains.values()].some(
              (d) => d.organizationId === currentOrgId && d.domain.toLowerCase() === target && d.status === "VERIFIED",
            );
            if (!callerVerified) throw new Error(`Bieżąca firma nie ma zweryfikowanej domeny "${target}"`);
            let deleted = 0;
            for (const [id, row] of domains.entries()) {
              if (
                row.domain.toLowerCase() === target &&
                row.organizationId !== currentOrgId &&
                row.status !== "VERIFIED" &&
                !row.isPrimary
              ) {
                domains.delete(id);
                deleted += 1;
              }
            }
            return [{ deleted }];
          }
          return [];
        },
        authUser: {
          findUnique: async ({ where }: { where: { email: string } }) =>
            [...authUsers.values()].find((u) => u.email.toLowerCase() === where.email.toLowerCase()) ?? null,
          findFirst: async ({ where }: { where: { email: { equals: string } } }) =>
            [...authUsers.values()].find((u) => u.email.toLowerCase() === where.email.equals.toLowerCase()) ?? null,
          create: async ({ data }: { data: { id: string; email: string; name: string } }) => {
            authUsers.set(data.id, data);
            return data;
          },
        },
        organization: {
          findUnique: async ({ where }: { where: { id: string } }) => {
            const org = orgs.get(where.id);
            if (!org || org.id !== currentOrgId) return null;
            return { ...org, domains: sortedDomainsForOrg(org.id) };
          },
          findUniqueOrThrow: async ({ where }: { where: { id: string } }) => {
            const org = orgs.get(where.id);
            if (!org || org.id !== currentOrgId) throw new Error("Org not found");
            return { ...org, domains: sortedDomainsForOrg(org.id) };
          },
          update: async ({ where, data }: { where: { id: string }; data: Partial<MockOrg> }) => {
            const org = orgs.get(where.id);
            if (!org || org.id !== currentOrgId) throw new Error("Org not found");
            const next = { ...org, ...data };
            orgs.set(org.id, next);
            return { ...next, domains: sortedDomainsForOrg(org.id) };
          },
          updateMany: async ({
            where,
            data,
          }: {
            where: { id: string; status?: OrganizationStatus };
            data: Partial<MockOrg>;
          }) => {
            const org = orgs.get(where.id);
            if (!org || org.id !== currentOrgId) return { count: 0 };
            if (where.status !== undefined && org.status !== where.status) return { count: 0 };
            orgs.set(org.id, { ...org, ...data });
            return { count: 1 };
          },
        },
        organizationDomain: {
          findUnique: async ({ where }: { where: { id: string } }) => {
            const row = domains.get(where.id);
            if (!row || row.organizationId !== currentOrgId) return null;
            return { ...row };
          },
          findFirst: async ({
            where,
          }: {
            where: { organizationId?: string; isPrimary?: boolean; domain?: string; status?: DomainStatus };
          }) => {
            const orgId = where.organizationId ?? currentOrgId;
            return (
              [...domains.values()].find(
                (d) =>
                  d.organizationId === orgId &&
                  (where.isPrimary === undefined || d.isPrimary === where.isPrimary) &&
                  (where.domain === undefined || d.domain.toLowerCase() === where.domain.toLowerCase()) &&
                  (where.status === undefined || d.status === where.status),
              ) ?? null
            );
          },
          count: async ({ where }: { where: { organizationId?: string; status?: DomainStatus } }) => {
            const orgId = where.organizationId ?? currentOrgId;
            return [...domains.values()].filter(
              (d) => d.organizationId === orgId && (where.status === undefined || d.status === where.status),
            ).length;
          },
          create: async ({ data }: { data: Omit<MockDomain, "createdAt"> & { createdAt?: Date } }) => {
            // UNIQUE("organizationId", domain)
            if (
              [...domains.values()].some(
                (d) => d.organizationId === data.organizationId && d.domain.toLowerCase() === data.domain.toLowerCase(),
              )
            ) {
              throw Object.assign(new Error("organization_domains_organizationId_domain_key"), { code: "P2002" });
            }
            // Partial UNIQUE(domain) WHERE status = 'VERIFIED'
            if (
              data.status === "VERIFIED" &&
              [...domains.values()].some(
                (d) => d.domain.toLowerCase() === data.domain.toLowerCase() && d.status === "VERIFIED",
              )
            ) {
              throw Object.assign(new Error("organization_domains_domain_verified_key"), { code: "P2002" });
            }
            // Partial UNIQUE("organizationId") WHERE isPrimary = true
            if (
              data.isPrimary &&
              [...domains.values()].some((d) => d.organizationId === data.organizationId && d.isPrimary)
            ) {
              throw Object.assign(new Error("organization_domains_organizationId_primary_key"), { code: "P2002" });
            }
            const row: MockDomain = { ...data, createdAt: data.createdAt ?? new Date() };
            domains.set(row.id, row);
            return { ...row };
          },
          update: async ({ where, data }: { where: { id: string }; data: Partial<MockDomain> }) => {
            const prev = domains.get(where.id);
            if (!prev || prev.organizationId !== currentOrgId) throw new Error("Domain not found");
            const next: MockDomain = { ...prev, ...data };
            if (
              next.status === "VERIFIED" &&
              [...domains.values()].some(
                (d) =>
                  d.id !== next.id && d.domain.toLowerCase() === next.domain.toLowerCase() && d.status === "VERIFIED",
              )
            ) {
              throw Object.assign(new Error("organization_domains_domain_verified_key"), { code: "P2002" });
            }
            if (
              next.isPrimary &&
              [...domains.values()].some(
                (d) => d.organizationId === next.organizationId && d.id !== next.id && d.isPrimary,
              )
            ) {
              throw Object.assign(new Error("organization_domains_organizationId_primary_key"), { code: "P2002" });
            }
            domains.set(next.id, next);
            return { ...next };
          },
          updateMany: async ({
            where,
            data,
          }: {
            where: { id?: string; organizationId?: string; isPrimary?: boolean; status?: { not: DomainStatus } };
            data: Partial<MockDomain>;
          }) => {
            let count = 0;
            for (const [id, row] of domains.entries()) {
              if (row.organizationId !== currentOrgId) continue;
              if (where.id !== undefined && row.id !== where.id) continue;
              if (where.organizationId !== undefined && row.organizationId !== where.organizationId) continue;
              if (where.isPrimary !== undefined && row.isPrimary !== where.isPrimary) continue;
              if (where.status?.not !== undefined && row.status === where.status.not) continue;
              domains.set(id, { ...row, ...data });
              count += 1;
            }
            return { count };
          },
          delete: async ({ where }: { where: { id: string } }) => {
            const prev = domains.get(where.id);
            if (!prev || prev.organizationId !== currentOrgId) throw new Error("Domain not found");
            domains.delete(where.id);
            return prev;
          },
        },
        organizationUnit: {
          findMany: async () => [{ id: UNIT_KRAKOW, parentId: null }],
        },
        roleAssignment: {
          findMany: async ({ where }: { where: { accountId: string } }) => {
            if (where.accountId === ADMIN_ACC) {
              return [
                {
                  scopeType: "ORGANIZATION",
                  scopeId: null,
                  validFrom: null,
                  validUntil: null,
                  role: {
                    archivedAt: null,
                    product: null,
                    permissions: [
                      { permission: { key: CORE_PERMISSIONS.keys["organization.manage"], deprecatedAt: null } },
                    ],
                  },
                },
              ];
            }
            if (where.accountId === UNIT_ADMIN_ACC) {
              return [
                {
                  scopeType: "UNIT",
                  scopeId: UNIT_KRAKOW,
                  validFrom: null,
                  validUntil: null,
                  role: {
                    archivedAt: null,
                    product: null,
                    permissions: [
                      { permission: { key: CORE_PERMISSIONS.keys["organization.manage"], deprecatedAt: null } },
                    ],
                  },
                },
              ];
            }
            return [];
          },
        },
        account: {
          findUnique: async ({ where }: { where: { id: string } }) => {
            const acc = accounts.get(where.id);
            if (!acc || acc.organizationId !== currentOrgId) return null;
            const org = orgs.get(acc.organizationId);
            const emp = employees.get(acc.employeeId);
            return {
              ...acc,
              organization: { ownerAccountId: org?.ownerAccountId ?? null },
              employee: emp ? { firstName: emp.firstName, lastName: emp.lastName } : null,
            };
          },
          findFirst: async ({
            where,
          }: {
            where: {
              organizationId?: string;
              normalizedEmail: string | { equals?: string; endsWith?: string; mode?: string };
              employeeId?: { not: string };
            };
          }) => {
            const orgId = where.organizationId ?? currentOrgId;
            return (
              [...accounts.values()].find((a) => {
                if (a.organizationId !== orgId) return false;
                if (where.employeeId?.not !== undefined && a.employeeId === where.employeeId.not) return false;
                if (typeof where.normalizedEmail === "string") {
                  return a.normalizedEmail.toLowerCase() === where.normalizedEmail.toLowerCase();
                }
                if (where.normalizedEmail.equals !== undefined) {
                  return a.normalizedEmail.toLowerCase() === where.normalizedEmail.equals.toLowerCase();
                }
                if (where.normalizedEmail.endsWith !== undefined) {
                  return a.normalizedEmail.toLowerCase().endsWith(where.normalizedEmail.endsWith.toLowerCase());
                }
                return false;
              }) ?? null
            );
          },
          create: async ({ data }: { data: Omit<MockAccount, "authzRevision"> }) => {
            const row: MockAccount = { ...data, authzRevision: 0 };
            accounts.set(row.id, row);
            return row;
          },
        },
        employee: {
          findUnique: async ({ where }: { where: { id: string } }) => {
            const emp = employees.get(where.id);
            if (!emp || emp.organizationId !== currentOrgId) return null;
            return { ...emp, account: null };
          },
          findFirst: async ({
            where,
          }: {
            where: {
              organizationId?: string;
              workEmail: { equals?: string; endsWith?: string; mode?: string };
              id?: { not: string };
            };
          }) => {
            const orgId = where.organizationId ?? currentOrgId;
            return (
              [...employees.values()].find((e) => {
                if (e.organizationId !== orgId || e.workEmail === null) return false;
                if (where.id?.not !== undefined && e.id === where.id.not) return false;
                if (where.workEmail.equals !== undefined) {
                  return e.workEmail.toLowerCase() === where.workEmail.equals.toLowerCase();
                }
                if (where.workEmail.endsWith !== undefined) {
                  return e.workEmail.toLowerCase().endsWith(where.workEmail.endsWith.toLowerCase());
                }
                return false;
              }) ?? null
            );
          },
          create: async ({
            data,
          }: {
            data: {
              id: string;
              organizationId: string;
              firstName: string;
              lastName: string;
              workEmail?: string | null;
              jobTitle?: string | null;
            };
          }) => {
            const row: MockEmployee = {
              id: data.id,
              organizationId: data.organizationId,
              firstName: data.firstName,
              lastName: data.lastName,
              workEmail: data.workEmail ?? null,
              jobTitle: data.jobTitle ?? null,
              status: "ACTIVE",
            };
            employees.set(row.id, row);
            return row;
          },
        },
        invitation: {
          findFirst: async ({
            where,
          }: {
            where: { organizationId?: string; status: InvitationStatus; normalizedEmail: { endsWith: string } };
          }) => {
            const orgId = where.organizationId ?? currentOrgId;
            const suffix = where.normalizedEmail.endsWith.toLowerCase();
            return (
              [...invitations.values()].find(
                (i) =>
                  i.organizationId === orgId &&
                  i.status === where.status &&
                  i.normalizedEmail.toLowerCase().endsWith(suffix),
              ) ?? null
            );
          },
          create: async ({
            data,
          }: {
            data: Omit<MockInvitation, "acceptedAt" | "createdAt" | "updatedAt"> & {
              acceptedAt?: Date | null;
            };
          }) => {
            const now = new Date();
            const acc = accounts.get(data.accountId);
            const row: MockInvitation = {
              ...data,
              employeeId: data.employeeId ?? acc?.employeeId ?? "",
              acceptedAt: data.acceptedAt ?? null,
              createdAt: now,
              updatedAt: now,
            };
            invitations.set(row.id, row);
            return { ...row, account: { employeeId: row.employeeId } };
          },
        },
        idempotencyKey: {
          findUnique: async ({
            where,
          }: {
            where: { organizationId_principal_key: { organizationId: string; principal: string; key: string } };
          }) => {
            const { organizationId, principal, key } = where.organizationId_principal_key;
            if (organizationId !== currentOrgId) return null;
            return idempotencyKeys.get(idemKey(organizationId, principal, key)) ?? null;
          },
          upsert: async ({
            where,
            create,
            update,
          }: {
            where: { organizationId_principal_key: { organizationId: string; principal: string; key: string } };
            create: MockIdempotencyRow;
            update: Partial<MockIdempotencyRow>;
          }) => {
            const { organizationId, principal, key } = where.organizationId_principal_key;
            const k = idemKey(organizationId, principal, key);
            const prev = idempotencyKeys.get(k);
            const next = prev ? { ...prev, ...update } : create;
            idempotencyKeys.set(k, next);
            return next;
          },
        },
        auditLog: {
          create: async ({ data }: { data: MockAudit }) => {
            audits.push({
              organizationId: data.organizationId,
              action: data.action,
              resourceType: data.resourceType,
              resourceId: data.resourceId,
              metadata: data.metadata,
            });
            return data;
          },
        },
      };
      try {
        return await fn(tx);
      } finally {
        for (const release of heldLocks.reverse()) release();
      }
    },
  } as unknown as PrismaClient;

  return { db, orgs, domains, accounts, employees, invitations, audits, executedLocks };
}

function buildTestApp(
  db: PrismaClient,
  options: {
    domainVerificationSecret?: string;
    devTrustDomains?: boolean;
    resolveTxt?: ResolveTxtFn;
    now?: () => Date;
  } = {},
) {
  return buildServer({
    db,
    verifyToken: async (token) => {
      const parts = token.split(":");
      const [orgId, accId, empId] = parts.length === 3 ? parts : [ORG_ACME, parts[0]!, parts[1]!];
      return {
        iss: "http://localhost:3100",
        sub: accId!,
        aud: "http://localhost:3200",
        org_id: orgId!,
        employee_id: empId!,
        amr: ["pwd"],
        authz_rev: 0,
        iat: 1,
        exp: 9_999_999_999,
      };
    },
    verifyMachineToken: async () => {
      throw new Error("Nieoczekiwany token maszynowy");
    },
    domainVerificationSecret: options.domainVerificationSecret ?? SECRET,
    devTrustDomains: options.devTrustDomains ?? false,
    resolveTxt: options.resolveTxt,
    mailer: async () => undefined,
    now: options.now,
  });
}

describe("pomocniki DNS TXT, sekretu i dev trust w @core/db", () => {
  it("wylicza deterministyczny rekord TXT, wspiera dopasowanie do starego i nowego sekretu oraz stały czas porównania", () => {
    const oldTxt = domainTxtValue(SECRET, ORG_ACME, "ACME.EU");
    const newTxt = domainTxtValue(ROTATED_SECRET, ORG_ACME, "acme.eu");
    expect(oldTxt).toBe(domainTxtValue(SECRET, ORG_ACME, "acme.eu"));
    expect(oldTxt).toMatch(/^monorise-verification=[A-Za-z0-9_-]{32}$/);
    expect(oldTxt).not.toBe(newTxt);

    const oldHash = hashToken(oldTxt);
    expect(matchesDomainTokenHash(oldTxt, oldHash)).toBe(true);
    expect(matchesDomainTokenHash(`${oldTxt}x`, oldHash)).toBe(false);
    expect(matchesDomainTokenHash(oldTxt, null)).toBe(false);
    expect(matchesDomainTokenHash(oldTxt, "zbyt-krotki")).toBe(false);

    const both = expectedDomainTokenHashes({
      storedHash: oldHash,
      currentSecret: ROTATED_SECRET,
      organizationId: ORG_ACME,
      domain: "acme.eu",
    });
    expect(both).toHaveLength(2);
    expect(matchesAnyDomainTokenHash(oldTxt, both)).toBe(true);
    expect(matchesAnyDomainTokenHash(newTxt, both)).toBe(true);
    expect(matchesAnyDomainTokenHash("monorise-verification=wrong", both)).toBe(false);

    // Gdy sekret się nie zmienił, lista jest zdeduplikowana do 1 elementu
    const deduped = expectedDomainTokenHashes({
      storedHash: oldHash,
      currentSecret: SECRET,
      organizationId: ORG_ACME,
      domain: "acme.eu",
    });
    expect(deduped).toEqual([oldHash]);
  });

  it("wymaga CORE_DOMAIN_VERIFICATION_SECRET (min. 32 znaki po trim) na produkcji i ogranicza dev trust do development/test", () => {
    expect(MIN_DOMAIN_VERIFICATION_SECRET_LENGTH).toBe(32);

    // Produkcja: brak / spacje / < 32 znaków -> błąd nawet z fallbackiem
    expect(() =>
      resolveDomainVerificationSecret({
        env: { NODE_ENV: "production" },
        fallback: () => SECRET,
      }),
    ).toThrow(/CORE_DOMAIN_VERIFICATION_SECRET/);
    expect(() =>
      resolveDomainVerificationSecret({
        env: { NODE_ENV: "production", CORE_DOMAIN_VERIFICATION_SECRET: "   " },
        fallback: () => SECRET,
      }),
    ).toThrow(/CORE_DOMAIN_VERIFICATION_SECRET/);
    expect(() =>
      resolveDomainVerificationSecret({
        env: { NODE_ENV: "production", CORE_DOMAIN_VERIFICATION_SECRET: `  ${"a".repeat(31)}  ` },
      }),
    ).toThrow(/32/);
    expect(
      resolveDomainVerificationSecret({
        env: { NODE_ENV: "production", CORE_DOMAIN_VERIFICATION_SECRET: `  ${"a".repeat(32)}  ` },
      }),
    ).toBe("a".repeat(32));

    // Poza produkcją: fallback działa, a ustawiony sekret jest przycinany
    expect(
      resolveDomainVerificationSecret({
        env: { NODE_ENV: "development" },
        fallback: () => SECRET,
      }),
    ).toBe(SECRET);
    expect(
      resolveDomainVerificationSecret({
        env: { NODE_ENV: "test", CORE_DOMAIN_VERIFICATION_SECRET: "  local-short-secret  " },
      }),
    ).toBe("local-short-secret");

    // isDevTrustDomainsEnabled: WYŁĄCZNIE NODE_ENV = development | test ORAZ CORE_DEV_TRUST_DOMAINS = "1"
    expect(isDevTrustDomainsEnabled({ NODE_ENV: "development", CORE_DEV_TRUST_DOMAINS: "1" })).toBe(true);
    expect(isDevTrustDomainsEnabled({ NODE_ENV: "test", CORE_DEV_TRUST_DOMAINS: "1" })).toBe(true);
    expect(isDevTrustDomainsEnabled({ NODE_ENV: "production", CORE_DEV_TRUST_DOMAINS: "1" })).toBe(false);
    expect(isDevTrustDomainsEnabled({ NODE_ENV: "staging", CORE_DEV_TRUST_DOMAINS: "1" })).toBe(false);
    expect(isDevTrustDomainsEnabled({ CORE_DEV_TRUST_DOMAINS: "1" })).toBe(false);
    expect(isDevTrustDomainsEnabled({ NODE_ENV: "development", CORE_DEV_TRUST_DOMAINS: "0" })).toBe(false);
    expect(isDevTrustDomainsEnabled({ NODE_ENV: "test" })).toBe(false);
  });

  it("egzekwuje timeout w resolveTxtWithTimeout", async () => {
    const fast = await resolveTxtWithTimeout(async () => [["ok"]], "_monorise-verification.acme.eu", 100);
    expect(fast).toEqual([["ok"]]);

    await expect(
      resolveTxtWithTimeout(() => new Promise(() => undefined), "_monorise-verification.acme.eu", 20),
    ).rejects.toThrow(/limit czasu/i);
  });
});

describe("Firma i zarządzanie domenami (testy jednostkowe HTTP bez bazy)", () => {
  const ownerBearer = `Bearer ${OWNER_ACC}:${OWNER_EMP}`;
  const adminBearer = `Bearer ${ADMIN_ACC}:${ADMIN_EMP}`;
  const unitAdminBearer = `Bearer ${UNIT_ADMIN_ACC}:${UNIT_ADMIN_EMP}`;
  const regularBearer = `Bearer ${REGULAR_ACC}:${REGULAR_EMP}`;
  const globexOwnerBearer = `Bearer ${ORG_GLOBEX}:${GLOBEX_OWNER_ACC}:${GLOBEX_OWNER_EMP}`;
  const signupOwnerBearer = `Bearer ${ORG_SIGNUP}:${SIGNUP_OWNER_ACC}:${SIGNUP_OWNER_EMP}`;

  it("PATCH /core/v1/organization: zmienia nazwę firmy, kontroluje uprawnienia i unika duplikatu audytu przy no-op", async () => {
    const { db, audits } = createInMemoryDomainDb();
    const app = buildTestApp(db);

    try {
      for (const bearer of [regularBearer, unitAdminBearer]) {
        const denied = await app.inject({
          method: "PATCH",
          url: "/core/v1/organization",
          headers: { authorization: bearer },
          payload: { name: "Acme Nowa" },
        });
        expect(denied.statusCode).toBe(403);
        expect(denied.json().error.code).toBe("PERMISSION_DENIED");
      }

      for (const payload of [{ name: "A" }, { name: "   " }, { name: "x".repeat(121) }, { name: "Acme", extra: 1 }]) {
        const bad = await app.inject({
          method: "PATCH",
          url: "/core/v1/organization",
          headers: { authorization: ownerBearer },
          payload,
        });
        expect(bad.statusCode).toBe(422);
        expect(bad.json().error.code).toBe("VALIDATION_FAILED");
      }

      const updated = await app.inject({
        method: "PATCH",
        url: "/core/v1/organization",
        headers: { authorization: ownerBearer },
        payload: { name: "  Acme Europe Sp. z o.o.  " },
      });
      expect(updated.statusCode).toBe(200);
      expect(updated.json().data.name).toBe("Acme Europe Sp. z o.o.");
      expect(audits).toEqual([
        {
          organizationId: ORG_ACME,
          action: "organization.updated",
          resourceType: "organization",
          resourceId: ORG_ACME,
          metadata: { fields: ["name"], previousName: "Acme", name: "Acme Europe Sp. z o.o." },
        },
      ]);

      const noop = await app.inject({
        method: "PATCH",
        url: "/core/v1/organization",
        headers: { authorization: adminBearer },
        payload: { name: "Acme Europe Sp. z o.o." },
      });
      expect(noop.statusCode).toBe(200);
      expect(audits).toHaveLength(1);

      const adminUpdated = await app.inject({
        method: "PATCH",
        url: "/core/v1/organization",
        headers: { authorization: adminBearer },
        payload: { name: "Acme Holding" },
      });
      expect(adminUpdated.statusCode).toBe(200);
      expect(adminUpdated.json().data.name).toBe("Acme Holding");
      expect(audits).toHaveLength(2);
    } finally {
      await app.close();
    }
  });

  it("POST /core/v1/organization/domains i GET /core/v1/organization: dodaje domenę, odrzuca darmowe subdomeny, pokazuje TXT tylko dla PENDING/FAILED i pilnuje limitu", async () => {
    const { db, domains, audits } = createInMemoryDomainDb();
    const app = buildTestApp(db);

    try {
      const forbidden = await app.inject({
        method: "POST",
        url: "/core/v1/organization/domains",
        headers: { authorization: regularBearer },
        payload: { domain: "acme.eu" },
      });
      expect(forbidden.statusCode).toBe(403);

      // Darmowe skrzynki, nowi dostawcy i subdomeny -> 422 EMAIL_DOMAIN_NOT_ALLOWED
      for (const free of ["gmail.com", "WP.PL", "mail.gmail.com", "pm.me", "sub.pm.me", "tuta.com", "tutanota.com"]) {
        const res = await app.inject({
          method: "POST",
          url: "/core/v1/organization/domains",
          headers: { authorization: ownerBearer },
          payload: { domain: free },
        });
        expect(res.statusCode).toBe(422);
        expect(res.json().error.code).toBe("EMAIL_DOMAIN_NOT_ALLOWED");
      }

      const invalid = await app.inject({
        method: "POST",
        url: "/core/v1/organization/domains",
        headers: { authorization: ownerBearer },
        payload: { domain: "nie-domena" },
      });
      expect(invalid.statusCode).toBe(422);
      expect(invalid.json().error.code).toBe("VALIDATION_FAILED");

      // Domena własna oraz zweryfikowana domena innej firmy -> 409 CONFLICT z jednolitym komunikatem
      const dupOwn = await app.inject({
        method: "POST",
        url: "/core/v1/organization/domains",
        headers: { authorization: ownerBearer },
        payload: { domain: "acme.test" },
      });
      const dupOther = await app.inject({
        method: "POST",
        url: "/core/v1/organization/domains",
        headers: { authorization: ownerBearer },
        payload: { domain: "globex.test" },
      });
      expect(dupOwn.statusCode).toBe(409);
      expect(dupOther.statusCode).toBe(409);
      expect(dupOther.json().error.message).toBe(dupOwn.json().error.message);

      // Dodanie z Idempotency-Key -> 201 + replay
      const added = await app.inject({
        method: "POST",
        url: "/core/v1/organization/domains",
        headers: { authorization: ownerBearer, [IDEMPOTENCY_KEY_HEADER]: "add-acme-eu" },
        payload: { domain: "  ACME.EU  " },
      });
      expect(added.statusCode).toBe(201);
      const expectedTxt = domainTxtValue(SECRET, ORG_ACME, "acme.eu");
      expect(added.json().data).toMatchObject({
        domain: "acme.eu",
        status: "PENDING",
        isPrimary: false,
        verificationTxtName: domainVerificationHost("acme.eu"),
        verificationTxtValue: expectedTxt,
      });

      const replay = await app.inject({
        method: "POST",
        url: "/core/v1/organization/domains",
        headers: { authorization: ownerBearer, [IDEMPOTENCY_KEY_HEADER]: "add-acme-eu" },
        payload: { domain: "  ACME.EU  " },
      });
      expect(replay.statusCode).toBe(201);
      expect(replay.headers[IDEMPOTENCY_REPLAYED_HEADER.toLowerCase()]).toBe("true");
      expect(replay.json().data).toEqual(added.json().data);
      expect(audits).toHaveLength(1);

      // Dodaj domenę FAILED oraz REVOKED, żeby sprawdzić widoczność TXT (Nit #7: tylko PENDING i FAILED)
      const failedId = "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6a77";
      const revokedId = "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6a78";
      domains.set(failedId, {
        id: failedId,
        organizationId: ORG_ACME,
        domain: "failed.acme.test",
        status: "FAILED",
        verificationMethod: "DNS_TXT",
        verificationTokenHash: hashToken(domainTxtValue(SECRET, ORG_ACME, "failed.acme.test")),
        verifiedAt: null,
        lastCheckedAt: null,
        isPrimary: false,
        createdAt: new Date("2026-11-21T00:00:00.000Z"),
      });
      domains.set(revokedId, {
        id: revokedId,
        organizationId: ORG_ACME,
        domain: "revoked.acme.test",
        status: "REVOKED",
        verificationMethod: "DNS_TXT",
        verificationTokenHash: hashToken(domainTxtValue(SECRET, ORG_ACME, "revoked.acme.test")),
        verifiedAt: null,
        lastCheckedAt: null,
        isPrimary: false,
        createdAt: new Date("2026-11-22T00:00:00.000Z"),
      });

      const ownerOrg = await app.inject({
        method: "GET",
        url: "/core/v1/organization",
        headers: { authorization: ownerBearer },
      });
      const adminOrg = await app.inject({
        method: "GET",
        url: "/core/v1/organization",
        headers: { authorization: adminBearer },
      });
      const regularOrg = await app.inject({
        method: "GET",
        url: "/core/v1/organization",
        headers: { authorization: regularBearer },
      });
      const unitAdminOrg = await app.inject({
        method: "GET",
        url: "/core/v1/organization",
        headers: { authorization: unitAdminBearer },
      });

      for (const res of [ownerOrg, adminOrg]) {
        const list = res.json().data.domains as {
          domain: string;
          verificationTxtName: string | null;
          verificationTxtValue: string | null;
        }[];
        expect(list.find((d) => d.domain === "acme.test")).toMatchObject({
          verificationTxtName: null,
          verificationTxtValue: null,
        });
        expect(list.find((d) => d.domain === "acme.eu")).toMatchObject({
          verificationTxtName: "_monorise-verification.acme.eu",
          verificationTxtValue: expectedTxt,
        });
        expect(list.find((d) => d.domain === "failed.acme.test")).toMatchObject({
          verificationTxtName: "_monorise-verification.failed.acme.test",
          verificationTxtValue: domainTxtValue(SECRET, ORG_ACME, "failed.acme.test"),
        });
        expect(list.find((d) => d.domain === "revoked.acme.test")).toMatchObject({
          verificationTxtName: null,
          verificationTxtValue: null,
        });
      }

      for (const res of [regularOrg, unitAdminOrg]) {
        const list = res.json().data.domains as {
          domain: string;
          verificationTxtName: string | null;
          verificationTxtValue: string | null;
        }[];
        expect(list.find((d) => d.domain === "acme.eu")).toMatchObject({
          verificationTxtName: null,
          verificationTxtValue: null,
        });
        expect(list.find((d) => d.domain === "failed.acme.test")).toMatchObject({
          verificationTxtName: null,
          verificationTxtValue: null,
        });
      }

      // Weryfikacja domeny REVOKED -> 409 CONFLICT
      const revokedVerify = await app.inject({
        method: "POST",
        url: `/core/v1/organization/domains/${revokedId}/verify`,
        headers: { authorization: ownerBearer },
        payload: {},
      });
      expect(revokedVerify.statusCode).toBe(409);
      expect(revokedVerify.json().error.code).toBe("CONFLICT");

      // Limit 20 domen -> 21. odrzucona kodem 409
      const existingAcmeCount = [...domains.values()].filter((d) => d.organizationId === ORG_ACME).length;
      for (let i = existingAcmeCount; i < MAX_ORGANIZATION_DOMAINS; i++) {
        const res = await app.inject({
          method: "POST",
          url: "/core/v1/organization/domains",
          headers: { authorization: ownerBearer },
          payload: { domain: `extra-${i}.acme.test` },
        });
        expect(res.statusCode).toBe(201);
      }
      const overLimit = await app.inject({
        method: "POST",
        url: "/core/v1/organization/domains",
        headers: { authorization: ownerBearer },
        payload: { domain: "overflow.acme.test" },
      });
      expect(overLimit.statusCode).toBe(409);
    } finally {
      await app.close();
    }
  });

  it("wygrywa weryfikacja: dwie firmy dodają tę samą domenę (równolegle), wygrywa pierwsza zweryfikowana, znikają cudze niegłówne roszczenia, a główna z rejestracji dostaje 409", async () => {
    const { db, domains } = createInMemoryDomainDb();
    const dnsMap = new Map<string, string[][]>();
    let releaseBarrier!: () => void;
    let arrivedAtRaceDns = 0;
    const raceBarrier = new Promise<void>((resolve) => {
      releaseBarrier = resolve;
    });

    const app = buildTestApp(db, {
      resolveTxt: async (hostname) => {
        const records = dnsMap.get(hostname.toLowerCase());
        if (!records) return [];
        if (hostname.toLowerCase().includes("race.test")) {
          arrivedAtRaceDns += 1;
          if (arrivedAtRaceDns === 2) releaseBarrier();
          await raceBarrier;
        }
        return records;
      },
    });

    try {
      // 1) Dwie firmy równolegle dodają tę samą domenę -> obie dostają 201 PENDING
      const [acmeAdd, globexAdd] = await Promise.all([
        app.inject({
          method: "POST",
          url: "/core/v1/organization/domains",
          headers: { authorization: ownerBearer },
          payload: { domain: "shared-claim.test" },
        }),
        app.inject({
          method: "POST",
          url: "/core/v1/organization/domains",
          headers: { authorization: globexOwnerBearer },
          payload: { domain: "shared-claim.test" },
        }),
      ]);
      expect(acmeAdd.statusCode).toBe(201);
      expect(globexAdd.statusCode).toBe(201);
      const acmeSharedId = acmeAdd.json().data.id as string;
      const globexSharedId = globexAdd.json().data.id as string;
      const acmeSharedTxt = acmeAdd.json().data.verificationTxtValue as string;

      // Acme potwierdza DNS TXT -> wygrywa; niegłówne roszczenie Globex znika
      dnsMap.set(domainVerificationHost("shared-claim.test"), [[acmeSharedTxt]]);
      const acmeWin = await app.inject({
        method: "POST",
        url: `/core/v1/organization/domains/${acmeSharedId}/verify`,
        headers: { authorization: ownerBearer },
        payload: {},
      });
      expect(acmeWin.statusCode).toBe(200);
      expect(acmeWin.json().data.status).toBe("VERIFIED");
      expect(domains.has(globexSharedId)).toBe(false);

      // Globex nie może już ponownie dodać ani zweryfikować tej domeny
      const globexReadd = await app.inject({
        method: "POST",
        url: "/core/v1/organization/domains",
        headers: { authorization: globexOwnerBearer },
        payload: { domain: "shared-claim.test" },
      });
      expect(globexReadd.statusCode).toBe(409);

      // 2) Główna niezweryfikowana domena innej firmy (ORG_SIGNUP: signup.test) NIE jest usuwana po cichu,
      //    gdy Acme doda i zweryfikuje signup.test — zamiast tego ORG_SIGNUP dostaje później 409 CONFLICT
      const acmeClaimsSignup = await app.inject({
        method: "POST",
        url: "/core/v1/organization/domains",
        headers: { authorization: ownerBearer },
        payload: { domain: "signup.test" },
      });
      expect(acmeClaimsSignup.statusCode).toBe(201);
      const acmeSignupId = acmeClaimsSignup.json().data.id as string;
      dnsMap.set(domainVerificationHost("signup.test"), [
        [acmeClaimsSignup.json().data.verificationTxtValue as string],
      ]);
      const acmeVerifiesSignup = await app.inject({
        method: "POST",
        url: `/core/v1/organization/domains/${acmeSignupId}/verify`,
        headers: { authorization: ownerBearer },
        payload: {},
      });
      expect(acmeVerifiesSignup.statusCode).toBe(200);
      expect(domains.get(SIGNUP_PRIMARY_DOM)?.status).toBe("PENDING");

      const signupLateVerify = await app.inject({
        method: "POST",
        url: `/core/v1/organization/domains/${SIGNUP_PRIMARY_DOM}/verify`,
        headers: { authorization: signupOwnerBearer },
        payload: {},
      });
      expect(signupLateVerify.statusCode).toBe(409);
      expect(signupLateVerify.json().error.code).toBe("CONFLICT");

      // 3) Równoległa weryfikacja tej samej domeny przez dwie firmy -> [200, 409] i dokładnie jeden właściciel
      const [acmeRaceAdd, globexRaceAdd] = await Promise.all([
        app.inject({
          method: "POST",
          url: "/core/v1/organization/domains",
          headers: { authorization: ownerBearer },
          payload: { domain: "race.test" },
        }),
        app.inject({
          method: "POST",
          url: "/core/v1/organization/domains",
          headers: { authorization: globexOwnerBearer },
          payload: { domain: "race.test" },
        }),
      ]);
      const acmeRaceId = acmeRaceAdd.json().data.id as string;
      const globexRaceId = globexRaceAdd.json().data.id as string;
      // Oba rekordy TXT w DNS, by obie firmy przeszły etap DNS jednocześnie i zderzyły się na commit
      dnsMap.set(domainVerificationHost("race.test"), [
        [acmeRaceAdd.json().data.verificationTxtValue as string],
        [globexRaceAdd.json().data.verificationTxtValue as string],
      ]);

      const [r1, r2] = await Promise.all([
        app.inject({
          method: "POST",
          url: `/core/v1/organization/domains/${acmeRaceId}/verify`,
          headers: { authorization: ownerBearer },
          payload: {},
        }),
        app.inject({
          method: "POST",
          url: `/core/v1/organization/domains/${globexRaceId}/verify`,
          headers: { authorization: globexOwnerBearer },
          payload: {},
        }),
      ]);
      expect([r1.statusCode, r2.statusCode].sort()).toEqual([200, 409]);
      const verifiedRaceRows = [...domains.values()].filter((d) => d.domain === "race.test" && d.status === "VERIFIED");
      expect(verifiedRaceRows).toHaveLength(1);
    } finally {
      await app.close();
    }
  });

  it("Blocker 1: po zmianie CORE_DOMAIN_VERIFICATION_SECRET oczekująca domena weryfikuje się zarówno starym, jak i nowym TXT", async () => {
    const { db, domains } = createInMemoryDomainDb();
    let dnsRecords: string[][] = [];

    const rotatedApp = buildTestApp(db, {
      domainVerificationSecret: ROTATED_SECRET,
      resolveTxt: async () => dnsRecords,
    });

    try {
      const legacyOldId = "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6a71";
      const legacyNewId = "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6a72";
      for (const [id, domain] of [
        [legacyOldId, "legacy-old.test"],
        [legacyNewId, "legacy-new.test"],
      ] as const) {
        domains.set(id, {
          id,
          organizationId: ORG_ACME,
          domain,
          status: "PENDING",
          verificationMethod: "DNS_TXT",
          verificationTokenHash: hashToken(domainTxtValue(SECRET, ORG_ACME, domain)),
          verifiedAt: null,
          lastCheckedAt: null,
          isPrimary: false,
          createdAt: new Date("2026-11-25T00:00:00.000Z"),
        });
      }

      // 1) Wartość opublikowana jeszcze pod STARYM sekretem (pasuje do verificationTokenHash) -> 200
      dnsRecords = [[domainTxtValue(SECRET, ORG_ACME, "legacy-old.test")]];
      const withOld = await rotatedApp.inject({
        method: "POST",
        url: `/core/v1/organization/domains/${legacyOldId}/verify`,
        headers: { authorization: ownerBearer },
        payload: {},
      });
      expect(withOld.statusCode).toBe(200);
      expect(withOld.json().data.status).toBe("VERIFIED");

      // 2) Wartość pokazana teraz w UI pod NOWYM sekretem (pasuje do HMAC z currentSecret) -> 200
      const shownInOrg = await rotatedApp.inject({
        method: "GET",
        url: "/core/v1/organization",
        headers: { authorization: ownerBearer },
      });
      const shownTxt = (shownInOrg.json().data.domains as { id: string; verificationTxtValue: string | null }[]).find(
        (d) => d.id === legacyNewId,
      )?.verificationTxtValue;
      expect(shownTxt).toBe(domainTxtValue(ROTATED_SECRET, ORG_ACME, "legacy-new.test"));

      dnsRecords = [[shownTxt!]];
      const withNew = await rotatedApp.inject({
        method: "POST",
        url: `/core/v1/organization/domains/${legacyNewId}/verify`,
        headers: { authorization: ownerBearer },
        payload: {},
      });
      expect(withNew.statusCode).toBe(200);
      expect(withNew.json().data.status).toBe("VERIFIED");
    } finally {
      await rotatedApp.close();
    }
  });

  it("Blocker 2: weryfikacja domeny głównej (także idempotentna) oraz ustawienie zweryfikowanej jako głównej aktywują firmę z PENDING_VERIFICATION (nigdy SUSPENDED)", async () => {
    const { db, orgs, domains, audits } = createInMemoryDomainDb();
    const app = buildTestApp(db, { devTrustDomains: true });

    try {
      // Scenariusz A: weryfikacja głównej domeny aktywuje ORG_SIGNUP + zapisuje organization.activated
      const verifyPrimary = await app.inject({
        method: "POST",
        url: `/core/v1/organization/domains/${SIGNUP_PRIMARY_DOM}/verify`,
        headers: { authorization: signupOwnerBearer },
        payload: { trustLocally: true },
      });
      expect(verifyPrimary.statusCode).toBe(200);
      expect(orgs.get(ORG_SIGNUP)?.status).toBe("ACTIVE");
      expect(audits.map((a) => a.action)).toEqual(["organization.domain.verified", "organization.activated"]);

      // Scenariusz B: domena główna była już VERIFIED, ale firma nadal PENDING_VERIFICATION -> gałąź idempotentna też aktywuje
      orgs.get(ORG_SIGNUP)!.status = "PENDING_VERIFICATION";
      audits.length = 0;
      const reverifyPrimary = await app.inject({
        method: "POST",
        url: `/core/v1/organization/domains/${SIGNUP_PRIMARY_DOM}/verify`,
        headers: { authorization: signupOwnerBearer },
        payload: {},
      });
      expect(reverifyPrimary.statusCode).toBe(200);
      expect(orgs.get(ORG_SIGNUP)?.status).toBe("ACTIVE");
      expect(audits.map((a) => a.action)).toEqual(["organization.activated"]);

      // Scenariusz C: firma PENDING_VERIFICATION dodaje i weryfikuje drugą domenę, a potem ustawia ją jako główną -> ACTIVE
      orgs.get(ORG_SIGNUP)!.status = "PENDING_VERIFICATION";
      domains.get(SIGNUP_PRIMARY_DOM)!.status = "PENDING";
      audits.length = 0;

      const addedSec = await app.inject({
        method: "POST",
        url: "/core/v1/organization/domains",
        headers: { authorization: signupOwnerBearer },
        payload: { domain: "second.signup.test" },
      });
      const secId = addedSec.json().data.id as string;
      await app.inject({
        method: "POST",
        url: `/core/v1/organization/domains/${secId}/verify`,
        headers: { authorization: signupOwnerBearer },
        payload: { trustLocally: true },
      });
      // Sama weryfikacja niegłównej domeny NIE aktywuje firmy
      expect(orgs.get(ORG_SIGNUP)?.status).toBe("PENDING_VERIFICATION");

      const promoted = await app.inject({
        method: "PUT",
        url: `/core/v1/organization/domains/${secId}/primary`,
        headers: { authorization: signupOwnerBearer },
      });
      expect(promoted.statusCode).toBe(200);
      expect(promoted.json().data.status).toBe("ACTIVE");
      expect(orgs.get(ORG_SIGNUP)?.status).toBe("ACTIVE");
      expect(audits.map((a) => a.action)).toEqual([
        "organization.domain.added",
        "organization.domain.verified",
        "organization.domain.primary_changed",
        "organization.activated",
      ]);

      // Scenariusz D: firma SUSPENDED nigdy nie wraca do ACTIVE po weryfikacji ani zmianie domeny głównej
      orgs.get(ORG_SIGNUP)!.status = "SUSPENDED";
      audits.length = 0;
      await app.inject({
        method: "PUT",
        url: `/core/v1/organization/domains/${secId}/primary`,
        headers: { authorization: signupOwnerBearer },
      });
      expect(orgs.get(ORG_SIGNUP)?.status).toBe("SUSPENDED");
      expect(audits).toHaveLength(0);
    } finally {
      await app.close();
    }
  });

  it("Should-fix #4: POST /employees (workEmail) i POST /invitations biorą blokadę org_domains przed użyciem zweryfikowanej domeny", async () => {
    const { db, executedLocks } = createInMemoryDomainDb();
    const app = buildTestApp(db);

    try {
      const empRes = await app.inject({
        method: "POST",
        url: "/core/v1/employees",
        headers: { authorization: ownerBearer },
        payload: { firstName: "Ewa", lastName: "Nowak", workEmail: "ewa@acme.test" },
      });
      expect(empRes.statusCode).toBe(201);
      expect(executedLocks).toContain(`org_domains:${ORG_ACME}`);

      executedLocks.length = 0;
      const invRes = await app.inject({
        method: "POST",
        url: "/core/v1/invitations",
        headers: { authorization: ownerBearer },
        payload: { email: "kasia@acme.test", firstName: "Kasia", lastName: "Zaproszona" },
      });
      expect(invRes.statusCode).toBe(201);
      expect(executedLocks).toContain(`org_domains:${ORG_ACME}`);
    } finally {
      await app.close();
    }
  });

  it("POST .../verify, PUT .../primary i DELETE .../domains/{domainId}: DNS TXT, lastCheckedAt, Idempotency-Key, zamiana głównej i blokady usuwania", async () => {
    const { db, domains, accounts, employees, invitations, audits } = createInMemoryDomainDb();
    let dnsRecords: string[][] = [];
    let dnsCalls = 0;
    const t1 = new Date("2026-11-26T12:00:00.000Z");
    const t2 = new Date("2026-11-26T12:05:00.000Z");
    let now = t1;

    const app = buildTestApp(db, {
      domainVerificationSecret: SECRET,
      devTrustDomains: false,
      now: () => now,
      resolveTxt: async () => {
        dnsCalls += 1;
        return dnsRecords;
      },
    });

    try {
      // Domena innej firmy -> 404 przed 403
      expect(
        (
          await app.inject({
            method: "POST",
            url: `/core/v1/organization/domains/${GLOBEX_PRIMARY_DOM}/verify`,
            headers: { authorization: regularBearer },
            payload: {},
          })
        ).statusCode,
      ).toBe(404);
      expect(
        (
          await app.inject({
            method: "PUT",
            url: `/core/v1/organization/domains/${GLOBEX_PRIMARY_DOM}/primary`,
            headers: { authorization: regularBearer },
          })
        ).statusCode,
      ).toBe(404);
      expect(
        (
          await app.inject({
            method: "DELETE",
            url: `/core/v1/organization/domains/${GLOBEX_PRIMARY_DOM}`,
            headers: { authorization: regularBearer },
          })
        ).statusCode,
      ).toBe(404);

      const addRes = await app.inject({
        method: "POST",
        url: "/core/v1/organization/domains",
        headers: { authorization: ownerBearer },
        payload: { domain: "acme.eu" },
      });
      const euId = addRes.json().data.id as string;
      const expectedTxt = addRes.json().data.verificationTxtValue as string;

      // Zwykły pracownik -> 403; trustLocally przy devTrustDomains=false -> 403
      expect(
        (
          await app.inject({
            method: "POST",
            url: `/core/v1/organization/domains/${euId}/verify`,
            headers: { authorization: regularBearer },
            payload: {},
          })
        ).statusCode,
      ).toBe(403);
      expect(
        (
          await app.inject({
            method: "POST",
            url: `/core/v1/organization/domains/${euId}/verify`,
            headers: { authorization: ownerBearer },
            payload: { trustLocally: true },
          })
        ).statusCode,
      ).toBe(403);
      expect(dnsCalls).toBe(0);

      // Niezweryfikowana domena nie może zostać główną -> 409
      expect(
        (
          await app.inject({
            method: "PUT",
            url: `/core/v1/organization/domains/${euId}/primary`,
            headers: { authorization: ownerBearer },
          })
        ).statusCode,
      ).toBe(409);

      // Brak rekordu TXT -> 422 + lastCheckedAt + brak zapisu Idempotency-Key
      const failed = await app.inject({
        method: "POST",
        url: `/core/v1/organization/domains/${euId}/verify`,
        headers: { authorization: ownerBearer, [IDEMPOTENCY_KEY_HEADER]: "verify-eu" },
        payload: {},
      });
      expect(failed.statusCode).toBe(422);
      expect(domains.get(euId)?.lastCheckedAt?.toISOString()).toBe(t1.toISOString());

      // Podzielony rekord TXT -> 200 + replay z Idempotency-Key bez DNS
      now = t2;
      dnsRecords = [[expectedTxt.slice(0, 15), expectedTxt.slice(15)]];
      const verified = await app.inject({
        method: "POST",
        url: `/core/v1/organization/domains/${euId}/verify`,
        headers: { authorization: ownerBearer, [IDEMPOTENCY_KEY_HEADER]: "verify-eu" },
        payload: {},
      });
      expect(verified.statusCode).toBe(200);
      expect(verified.json().data).toMatchObject({
        id: euId,
        status: "VERIFIED",
        verifiedAt: t2.toISOString(),
        verificationTxtName: null,
        verificationTxtValue: null,
      });

      const replayed = await app.inject({
        method: "POST",
        url: `/core/v1/organization/domains/${euId}/verify`,
        headers: { authorization: ownerBearer, [IDEMPOTENCY_KEY_HEADER]: "verify-eu" },
        payload: {},
      });
      expect(replayed.statusCode).toBe(200);
      expect(replayed.headers[IDEMPOTENCY_REPLAYED_HEADER.toLowerCase()]).toBe("true");
      expect(dnsCalls).toBe(2);

      // Ustaw acme.eu jako główną -> atomowa zamiana + audyt; powtórka idempotentna
      const swap = await app.inject({
        method: "PUT",
        url: `/core/v1/organization/domains/${euId}/primary`,
        headers: { authorization: adminBearer },
      });
      expect(swap.statusCode).toBe(200);
      const auditsAfterSwap = audits.length;
      const repeatSwap = await app.inject({
        method: "PUT",
        url: `/core/v1/organization/domains/${euId}/primary`,
        headers: { authorization: ownerBearer },
      });
      expect(repeatSwap.statusCode).toBe(200);
      expect(audits).toHaveLength(auditsAfterSwap);

      // Nie można usunąć głównej ani używanej przez konta/pracowników/zaproszenia ani ostatniej VERIFIED -> 409
      expect(
        (
          await app.inject({
            method: "DELETE",
            url: `/core/v1/organization/domains/${euId}`,
            headers: { authorization: ownerBearer },
          })
        ).statusCode,
      ).toBe(409);
      expect(
        (
          await app.inject({
            method: "DELETE",
            url: `/core/v1/organization/domains/${ACME_PRIMARY_DOM}`,
            headers: { authorization: ownerBearer },
          })
        ).statusCode,
      ).toBe(409);

      // Dodaj trzecią domenę i sprawdź blokady + usunięcie 204
      const plAdd = await app.inject({
        method: "POST",
        url: "/core/v1/organization/domains",
        headers: { authorization: ownerBearer },
        payload: { domain: "acme.pl" },
      });
      const plId = plAdd.json().data.id as string;
      dnsRecords = [[plAdd.json().data.verificationTxtValue as string]];
      await app.inject({
        method: "POST",
        url: `/core/v1/organization/domains/${plId}/verify`,
        headers: { authorization: ownerBearer },
        payload: {},
      });

      employees.set("emp-sub", {
        id: "emp-sub",
        organizationId: ORG_ACME,
        firstName: "K",
        lastName: "Sub",
        workEmail: "k@sub.acme.pl",
        jobTitle: null,
        status: "ACTIVE",
      });
      employees.set("emp-pl", {
        id: "emp-pl",
        organizationId: ORG_ACME,
        firstName: "M",
        lastName: "Pl",
        workEmail: "Marek@ACME.PL",
        jobTitle: null,
        status: "ACTIVE",
      });
      expect(
        (
          await app.inject({
            method: "DELETE",
            url: `/core/v1/organization/domains/${plId}`,
            headers: { authorization: ownerBearer },
          })
        ).statusCode,
      ).toBe(409);
      employees.delete("emp-pl");

      invitations.set("inv-pl", {
        id: "inv-pl",
        organizationId: ORG_ACME,
        accountId: "acc-inv",
        employeeId: "emp-inv",
        email: "ewa@acme.pl",
        normalizedEmail: "ewa@acme.pl",
        tokenHash: "hash",
        status: "PENDING",
        expiresAt: new Date("2026-12-10T00:00:00.000Z"),
        invitedByAccountId: OWNER_ACC,
        acceptedAt: null,
        createdAt: t2,
        updatedAt: t2,
      });
      expect(
        (
          await app.inject({
            method: "DELETE",
            url: `/core/v1/organization/domains/${plId}`,
            headers: { authorization: ownerBearer },
          })
        ).statusCode,
      ).toBe(409);
      invitations.delete("inv-pl");

      accounts.set("acc-pl", {
        id: "acc-pl",
        organizationId: ORG_ACME,
        employeeId: "emp-x",
        email: "piotr@acme.pl",
        normalizedEmail: "piotr@acme.pl",
        status: "ACTIVE",
        authzRevision: 0,
      });
      expect(
        (
          await app.inject({
            method: "DELETE",
            url: `/core/v1/organization/domains/${plId}`,
            headers: { authorization: ownerBearer },
          })
        ).statusCode,
      ).toBe(409);
      accounts.delete("acc-pl");

      domains.get(euId)!.status = "PENDING";
      domains.get(ACME_PRIMARY_DOM)!.status = "PENDING";
      expect(
        (
          await app.inject({
            method: "DELETE",
            url: `/core/v1/organization/domains/${plId}`,
            headers: { authorization: ownerBearer },
          })
        ).statusCode,
      ).toBe(409);
      domains.get(euId)!.status = "VERIFIED";
      domains.get(ACME_PRIMARY_DOM)!.status = "VERIFIED";

      const removed = await app.inject({
        method: "DELETE",
        url: `/core/v1/organization/domains/${plId}`,
        headers: { authorization: ownerBearer },
      });
      expect(removed.statusCode).toBe(204);
      expect(removed.body).toBe("");
      expect(domains.has(plId)).toBe(false);
    } finally {
      await app.close();
    }
  });
});
