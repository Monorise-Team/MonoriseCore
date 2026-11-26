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
import { domainTxtValue, hashToken, matchesDomainTokenHash, type PrismaClient } from "@core/db";
import { describe, expect, it } from "vitest";
import { resolveTxtWithTimeout, type ResolveTxtFn } from "../src/domains.js";
import { buildServer } from "../src/server.js";

const SECRET = "test-domain-verification-secret-0123456789";
const ROTATED_SECRET = "rotated-domain-verification-secret-9876543210";

const ORG_ACME = "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6a01";
const ORG_GLOBEX = "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6a02";
const OWNER_ACC = "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6a11";
const OWNER_EMP = "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6a12";
const ADMIN_ACC = "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6a21";
const ADMIN_EMP = "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6a22";
const UNIT_ADMIN_ACC = "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6a31";
const UNIT_ADMIN_EMP = "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6a32";
const REGULAR_ACC = "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6a41";
const REGULAR_EMP = "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6a42";
const UNIT_KRAKOW = "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6a50";
const ACME_PRIMARY_DOM = "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6a61";
const GLOBEX_PRIMARY_DOM = "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6a62";

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
  workEmail: string | null;
}

interface MockInvitation {
  id: string;
  organizationId: string;
  status: InvitationStatus;
  normalizedEmail: string;
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
        ownerAccountId: "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6a99",
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
  ]);

  const employees = new Map<string, MockEmployee>([
    [OWNER_EMP, { id: OWNER_EMP, organizationId: ORG_ACME, workEmail: "anna@acme.test" }],
    [ADMIN_EMP, { id: ADMIN_EMP, organizationId: ORG_ACME, workEmail: "marta@acme.test" }],
    [UNIT_ADMIN_EMP, { id: UNIT_ADMIN_EMP, organizationId: ORG_ACME, workEmail: "tomasz@acme.test" }],
    [REGULAR_EMP, { id: REGULAR_EMP, organizationId: ORG_ACME, workEmail: "jan@acme.test" }],
  ]);

  const invitations = new Map<string, MockInvitation>();
  const idempotencyKeys = new Map<string, MockIdempotencyRow>();
  const audits: MockAudit[] = [];

  const sortedDomainsForOrg = (orgId: string) =>
    [...domains.values()]
      .filter((d) => d.organizationId === orgId)
      .sort((a, b) => a.createdAt.getTime() - b.createdAt.getTime() || a.id.localeCompare(b.id));

  const idemKey = (orgId: string, principal: string, key: string) => `${orgId}\0${principal}\0${key}`;

  const db = {
    $transaction: async <T>(fn: (tx: unknown) => Promise<T>): Promise<T> => {
      let currentOrgId: string | null = null;
      const tx = {
        $executeRaw: async (strings: TemplateStringsArray, ...values: unknown[]) => {
          const sql = strings.join(" ");
          if (sql.includes("set_config")) {
            currentOrgId = String(values[0] ?? "");
          }
          return 1;
        },
        $queryRaw: async (strings: TemplateStringsArray, ...values: unknown[]) => {
          const sql = strings.join(" ");
          if (sql.includes("domain_owner")) {
            const target = String(values[0] ?? "").toLowerCase();
            const found = [...domains.values()].find((d) => d.domain.toLowerCase() === target);
            return found ? [{ organization_id: found.organizationId, domain_status: found.status }] : [];
          }
          return [];
        },
        organization: {
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
        },
        organizationDomain: {
          findUnique: async ({ where }: { where: { id: string } }) => {
            const row = domains.get(where.id);
            if (!row || row.organizationId !== currentOrgId) return null;
            return { ...row };
          },
          findFirst: async ({ where }: { where: { organizationId?: string; isPrimary?: boolean } }) => {
            const orgId = where.organizationId ?? currentOrgId;
            return (
              [...domains.values()].find(
                (d) => d.organizationId === orgId && (where.isPrimary === undefined || d.isPrimary === where.isPrimary),
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
            if ([...domains.values()].some((d) => d.domain.toLowerCase() === data.domain.toLowerCase())) {
              throw Object.assign(new Error("duplicate key value violates unique constraint"), { code: "P2002" });
            }
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
            return { ...acc, organization: { ownerAccountId: org?.ownerAccountId ?? null } };
          },
          findFirst: async ({
            where,
          }: {
            where: { organizationId?: string; normalizedEmail: { endsWith: string; mode?: string } };
          }) => {
            const orgId = where.organizationId ?? currentOrgId;
            const suffix = where.normalizedEmail.endsWith.toLowerCase();
            return (
              [...accounts.values()].find(
                (a) => a.organizationId === orgId && a.normalizedEmail.toLowerCase().endsWith(suffix),
              ) ?? null
            );
          },
        },
        employee: {
          findFirst: async ({
            where,
          }: {
            where: { organizationId?: string; workEmail: { endsWith: string; mode?: string } };
          }) => {
            const orgId = where.organizationId ?? currentOrgId;
            const suffix = where.workEmail.endsWith.toLowerCase();
            return (
              [...employees.values()].find(
                (e) => e.organizationId === orgId && e.workEmail !== null && e.workEmail.toLowerCase().endsWith(suffix),
              ) ?? null
            );
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
              action: data.action,
              resourceType: data.resourceType,
              resourceId: data.resourceId,
              metadata: data.metadata,
            });
            return data;
          },
        },
      };
      return fn(tx);
    },
  } as unknown as PrismaClient;

  return { db, orgs, domains, accounts, employees, invitations, audits };
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
      const [accId, empId] = token.split(":");
      return {
        iss: "http://localhost:3100",
        sub: accId!,
        aud: "http://localhost:3200",
        org_id: ORG_ACME,
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
    now: options.now,
  });
}

describe("pomocniki DNS TXT domen", () => {
  it("wylicza deterministyczny rekord TXT i porównuje skrót w stałym czasie niezależnie od rotacji sekretu", () => {
    const txt = domainTxtValue(SECRET, ORG_ACME, "ACME.EU");
    expect(txt).toBe(domainTxtValue(SECRET, ORG_ACME, "acme.eu"));
    expect(txt).toMatch(/^monorise-verification=[A-Za-z0-9_-]{32}$/);
    expect(txt).not.toBe(domainTxtValue(ROTATED_SECRET, ORG_ACME, "acme.eu"));

    const storedHash = hashToken(txt);
    expect(matchesDomainTokenHash(txt, storedHash)).toBe(true);
    expect(matchesDomainTokenHash(`${txt}x`, storedHash)).toBe(false);
    expect(matchesDomainTokenHash(txt, null)).toBe(false);
    expect(matchesDomainTokenHash(txt, "zbyt-krotki")).toBe(false);
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

  it("PATCH /core/v1/organization: zmienia nazwę firmy, kontroluje uprawnienia i unika duplikatu audytu przy no-op", async () => {
    const { db, audits } = createInMemoryDomainDb();
    const app = buildTestApp(db);

    try {
      // Zwykły pracownik i zakres UNIT -> 403
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

      // Walidacja 422
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

      // Owner zmienia nazwę -> 200 + audyt
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
          action: "organization.updated",
          resourceType: "organization",
          resourceId: ORG_ACME,
          metadata: { fields: ["name"], previousName: "Acme", name: "Acme Europe Sp. z o.o." },
        },
      ]);

      // No-op z tą samą nazwą -> 200 i brak drugiego wpisu audytu
      const noop = await app.inject({
        method: "PATCH",
        url: "/core/v1/organization",
        headers: { authorization: adminBearer },
        payload: { name: "Acme Europe Sp. z o.o." },
      });
      expect(noop.statusCode).toBe(200);
      expect(audits).toHaveLength(1);

      // Administrator z core.organization.manage (ORGANIZATION) -> 200 + audyt
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

  it("POST /core/v1/organization/domains i GET /core/v1/organization: dodaje domenę, ukrywa TXT przed zwykłym pracownikiem, pilnuje limitu i Idempotency-Key", async () => {
    const { db, domains, audits } = createInMemoryDomainDb();
    const app = buildTestApp(db);

    try {
      // Zwykły pracownik -> 403
      const forbidden = await app.inject({
        method: "POST",
        url: "/core/v1/organization/domains",
        headers: { authorization: regularBearer },
        payload: { domain: "acme.eu" },
      });
      expect(forbidden.statusCode).toBe(403);

      // Darmowa domena -> 422 EMAIL_DOMAIN_NOT_ALLOWED
      for (const free of ["gmail.com", "WP.PL"]) {
        const res = await app.inject({
          method: "POST",
          url: "/core/v1/organization/domains",
          headers: { authorization: ownerBearer },
          payload: { domain: free },
        });
        expect(res.statusCode).toBe(422);
        expect(res.json().error.code).toBe("EMAIL_DOMAIN_NOT_ALLOWED");
      }

      // Nieprawidłowa nazwa domeny -> 422 VALIDATION_FAILED
      const invalid = await app.inject({
        method: "POST",
        url: "/core/v1/organization/domains",
        headers: { authorization: ownerBearer },
        payload: { domain: "nie-domena" },
      });
      expect(invalid.statusCode).toBe(422);
      expect(invalid.json().error.code).toBe("VALIDATION_FAILED");

      // Domena własna oraz domena innej firmy -> 409 CONFLICT z jednolitym komunikatem
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
      expect(dupOwn.json().error.code).toBe("CONFLICT");
      expect(dupOther.json().error.code).toBe("CONFLICT");
      expect(dupOther.json().error.message).toBe(dupOwn.json().error.message);

      // Dodanie z Idempotency-Key -> 201 + powtórka z Idempotency-Replayed: true
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
        verifiedAt: null,
        lastCheckedAt: null,
        verificationTxtName: domainVerificationHost("acme.eu"),
        verificationTxtValue: expectedTxt,
      });
      expect(added.json().data).not.toHaveProperty("verificationTokenHash");
      expect(audits).toEqual([
        {
          action: "organization.domain.added",
          resourceType: "organization_domain",
          resourceId: added.json().data.id,
          metadata: { domain: "acme.eu" },
        },
      ]);

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

      const keyConflict = await app.inject({
        method: "POST",
        url: "/core/v1/organization/domains",
        headers: { authorization: ownerBearer, [IDEMPOTENCY_KEY_HEADER]: "add-acme-eu" },
        payload: { domain: "acme.pl" },
      });
      expect(keyConflict.statusCode).toBe(409);

      // GET /core/v1/organization: Owner i admin widzą TXT dla PENDING (i null dla VERIFIED), a zwykły i UNIT-admin widzą null
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
      }

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
      expect(overLimit.json().error.code).toBe("CONFLICT");
    } finally {
      await app.close();
    }
  });

  it("POST /core/v1/organization/domains/{domainId}/verify: DNS TXT, lastCheckedAt przy 422, trustLocally, rotacja sekretu i Idempotency-Key", async () => {
    const { db, domains, audits } = createInMemoryDomainDb();
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
      // Domena z innej firmy daje 404 nawet dla zwykłego pracownika (404 przed 403)
      const foreign = await app.inject({
        method: "POST",
        url: `/core/v1/organization/domains/${GLOBEX_PRIMARY_DOM}/verify`,
        headers: { authorization: regularBearer },
        payload: {},
      });
      expect(foreign.statusCode).toBe(404);
      expect(foreign.json().error.code).toBe("NOT_FOUND");

      // Dodaj domenę do weryfikacji
      const addRes = await app.inject({
        method: "POST",
        url: "/core/v1/organization/domains",
        headers: { authorization: ownerBearer },
        payload: { domain: "acme.eu" },
      });
      const domainId = addRes.json().data.id as string;
      const expectedTxt = addRes.json().data.verificationTxtValue as string;

      // Zwykły pracownik -> 403
      const forbidden = await app.inject({
        method: "POST",
        url: `/core/v1/organization/domains/${domainId}/verify`,
        headers: { authorization: regularBearer },
        payload: {},
      });
      expect(forbidden.statusCode).toBe(403);

      // trustLocally: true gdy devTrustDomains=false -> 403
      const deniedTrust = await app.inject({
        method: "POST",
        url: `/core/v1/organization/domains/${domainId}/verify`,
        headers: { authorization: ownerBearer },
        payload: { trustLocally: true },
      });
      expect(deniedTrust.statusCode).toBe(403);
      expect(deniedTrust.json().error.code).toBe("PERMISSION_DENIED");
      expect(dnsCalls).toBe(0);

      // Brak rekordu TXT -> 422 VALIDATION_FAILED + utrwalony lastCheckedAt + brak zapisu Idempotency-Key
      const failed = await app.inject({
        method: "POST",
        url: `/core/v1/organization/domains/${domainId}/verify`,
        headers: { authorization: ownerBearer, [IDEMPOTENCY_KEY_HEADER]: "verify-eu" },
        payload: {},
      });
      expect(failed.statusCode).toBe(422);
      expect(failed.json().error.code).toBe("VALIDATION_FAILED");
      expect(failed.json().error.message).toBe("Nie znaleziono oczekiwanego rekordu TXT w DNS");
      expect(domains.get(domainId)?.lastCheckedAt?.toISOString()).toBe(t1.toISOString());
      expect(domains.get(domainId)?.status).toBe("PENDING");
      expect(audits).toHaveLength(1); // tylko organization.domain.added
      expect(dnsCalls).toBe(1);

      // Publikacja podzielonego rekordu TXT -> ten sam Idempotency-Key przechodzi (bo 422 nie był zapisany)
      now = t2;
      dnsRecords = [[expectedTxt.slice(0, 15), expectedTxt.slice(15)]];
      const verified = await app.inject({
        method: "POST",
        url: `/core/v1/organization/domains/${domainId}/verify`,
        headers: { authorization: ownerBearer, [IDEMPOTENCY_KEY_HEADER]: "verify-eu" },
        payload: {},
      });
      expect(verified.statusCode).toBe(200);
      expect(verified.json().data).toMatchObject({
        id: domainId,
        domain: "acme.eu",
        status: "VERIFIED",
        verifiedAt: t2.toISOString(),
        lastCheckedAt: t2.toISOString(),
        verificationTxtName: null,
        verificationTxtValue: null,
      });
      expect(dnsCalls).toBe(2);
      expect(audits[1]).toEqual({
        action: "organization.domain.verified",
        resourceType: "organization_domain",
        resourceId: domainId,
        metadata: { domain: "acme.eu", method: "DNS_TXT" },
      });

      // Powtórka z tym samym Idempotency-Key -> replay bez odpytywania DNS
      const replayed = await app.inject({
        method: "POST",
        url: `/core/v1/organization/domains/${domainId}/verify`,
        headers: { authorization: ownerBearer, [IDEMPOTENCY_KEY_HEADER]: "verify-eu" },
        payload: {},
      });
      expect(replayed.statusCode).toBe(200);
      expect(replayed.headers[IDEMPOTENCY_REPLAYED_HEADER.toLowerCase()]).toBe("true");
      expect(dnsCalls).toBe(2);

      // Ten sam Idempotency-Key z inną treścią -> 409 bez DNS
      const idemConflict = await app.inject({
        method: "POST",
        url: `/core/v1/organization/domains/${domainId}/verify`,
        headers: { authorization: ownerBearer, [IDEMPOTENCY_KEY_HEADER]: "verify-eu" },
        payload: { trustLocally: true },
      });
      expect(idemConflict.statusCode).toBe(409);
      expect(dnsCalls).toBe(2);

      // Ponowna weryfikacja już zweryfikowanej domeny (bez klucza) -> 200 idempotentnie, brak nowego audytu i DNS
      const alreadyVerified = await app.inject({
        method: "POST",
        url: `/core/v1/organization/domains/${domainId}/verify`,
        headers: { authorization: ownerBearer },
        payload: {},
      });
      expect(alreadyVerified.statusCode).toBe(200);
      expect(dnsCalls).toBe(2);
      expect(audits).toHaveLength(2);
    } finally {
      await app.close();
    }

    // Sprawdzenie ścieżki lokalnej trustLocally=true oraz weryfikacji po rotacji sekretu
    const rotatedApp = buildTestApp(db, {
      domainVerificationSecret: ROTATED_SECRET,
      devTrustDomains: true,
      resolveTxt: async () => [[domainTxtValue(SECRET, ORG_ACME, "legacy-rotated.test")]],
    });
    try {
      const legacyId = "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6a71";
      domains.set(legacyId, {
        id: legacyId,
        organizationId: ORG_ACME,
        domain: "legacy-rotated.test",
        status: "PENDING",
        verificationMethod: "DNS_TXT",
        verificationTokenHash: hashToken(domainTxtValue(SECRET, ORG_ACME, "legacy-rotated.test")),
        verifiedAt: null,
        lastCheckedAt: null,
        isPrimary: false,
        createdAt: new Date("2026-11-25T00:00:00.000Z"),
      });

      const rotatedVerify = await rotatedApp.inject({
        method: "POST",
        url: `/core/v1/organization/domains/${legacyId}/verify`,
        headers: { authorization: adminBearer },
        payload: {},
      });
      expect(rotatedVerify.statusCode).toBe(200);
      expect(rotatedVerify.json().data.status).toBe("VERIFIED");

      const localAdd = await rotatedApp.inject({
        method: "POST",
        url: "/core/v1/organization/domains",
        headers: { authorization: ownerBearer },
        payload: { domain: "local-dev.test" },
      });
      const localId = localAdd.json().data.id as string;
      const localVerify = await rotatedApp.inject({
        method: "POST",
        url: `/core/v1/organization/domains/${localId}/verify`,
        headers: { authorization: ownerBearer },
        payload: { trustLocally: true },
      });
      expect(localVerify.statusCode).toBe(200);
      expect(localVerify.json().data.status).toBe("VERIFIED");
      expect(audits[audits.length - 1]).toEqual({
        action: "organization.domain.verified",
        resourceType: "organization_domain",
        resourceId: localId,
        metadata: { domain: "local-dev.test", method: "DEV_TRUST" },
      });
    } finally {
      await rotatedApp.close();
    }
  });

  it("PUT .../primary i DELETE .../domains/{domainId}: atomowa zmiana głównej domeny, blokady usuwania i zwolnienie domeny", async () => {
    const { db, domains, accounts, employees, invitations, audits } = createInMemoryDomainDb();
    const app = buildTestApp(db, { devTrustDomains: true });

    try {
      // Dodaj acme.eu (PENDING)
      const added = await app.inject({
        method: "POST",
        url: "/core/v1/organization/domains",
        headers: { authorization: ownerBearer },
        payload: { domain: "acme.eu" },
      });
      const euId = added.json().data.id as string;

      // Niezweryfikowana domena nie może zostać główną -> 409
      const pendingPrimary = await app.inject({
        method: "PUT",
        url: `/core/v1/organization/domains/${euId}/primary`,
        headers: { authorization: ownerBearer },
      });
      expect(pendingPrimary.statusCode).toBe(409);
      expect(pendingPrimary.json().error.code).toBe("CONFLICT");

      // Inna firma -> 404 przed 403
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

      // Zwykły pracownik -> 403
      expect(
        (
          await app.inject({
            method: "PUT",
            url: `/core/v1/organization/domains/${euId}/primary`,
            headers: { authorization: regularBearer },
          })
        ).statusCode,
      ).toBe(403);
      expect(
        (
          await app.inject({
            method: "DELETE",
            url: `/core/v1/organization/domains/${euId}`,
            headers: { authorization: regularBearer },
          })
        ).statusCode,
      ).toBe(403);

      // Zweryfikuj acme.eu
      expect(
        (
          await app.inject({
            method: "POST",
            url: `/core/v1/organization/domains/${euId}/verify`,
            headers: { authorization: ownerBearer },
            payload: { trustLocally: true },
          })
        ).statusCode,
      ).toBe(200);

      // Ustaw acme.eu jako główną -> 200 Organization + audyt
      const swap = await app.inject({
        method: "PUT",
        url: `/core/v1/organization/domains/${euId}/primary`,
        headers: { authorization: adminBearer },
      });
      expect(swap.statusCode).toBe(200);
      const swappedDomains = swap.json().data.domains as { id: string; isPrimary: boolean }[];
      expect(swappedDomains.find((d) => d.id === euId)?.isPrimary).toBe(true);
      expect(swappedDomains.find((d) => d.id === ACME_PRIMARY_DOM)?.isPrimary).toBe(false);
      expect(audits[audits.length - 1]).toEqual({
        action: "organization.domain.primary_changed",
        resourceType: "organization",
        resourceId: ORG_ACME,
        metadata: { domainId: euId, fromDomain: "acme.test", toDomain: "acme.eu" },
      });

      // Powtórzenie PUT na bieżącej głównej -> 200 bez nowego audytu
      const auditCountAfterSwap = audits.length;
      const repeatSwap = await app.inject({
        method: "PUT",
        url: `/core/v1/organization/domains/${euId}/primary`,
        headers: { authorization: ownerBearer },
      });
      expect(repeatSwap.statusCode).toBe(200);
      expect(audits).toHaveLength(auditCountAfterSwap);

      // Nie można usunąć głównej domeny -> 409
      const deletePrimary = await app.inject({
        method: "DELETE",
        url: `/core/v1/organization/domains/${euId}`,
        headers: { authorization: ownerBearer },
      });
      expect(deletePrimary.statusCode).toBe(409);

      // Nie można usunąć starej domeny (acme.test), bo używają jej konta i pracownicy -> 409
      const deleteUsedByAccounts = await app.inject({
        method: "DELETE",
        url: `/core/v1/organization/domains/${ACME_PRIMARY_DOM}`,
        headers: { authorization: ownerBearer },
      });
      expect(deleteUsedByAccounts.statusCode).toBe(409);

      // Dodaj i zweryfikuj trzecią domenę acme.pl i sprawdź blokady dla pracownika, zaproszenia oraz konta
      const addedPl = await app.inject({
        method: "POST",
        url: "/core/v1/organization/domains",
        headers: { authorization: ownerBearer },
        payload: { domain: "acme.pl" },
      });
      const plId = addedPl.json().data.id as string;
      await app.inject({
        method: "POST",
        url: `/core/v1/organization/domains/${plId}/verify`,
        headers: { authorization: ownerBearer },
        payload: { trustLocally: true },
      });

      // 1) Pracownik bez konta z workEmail w @acme.pl blokuje usunięcie (ale sub.acme.pl NIE blokuje)
      employees.set("emp-sub", { id: "emp-sub", organizationId: ORG_ACME, workEmail: "k@sub.acme.pl" });
      employees.set("emp-pl", { id: "emp-pl", organizationId: ORG_ACME, workEmail: "Marek@ACME.PL" });
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

      // 2) Oczekujące zaproszenie w @acme.pl blokuje usunięcie
      invitations.set("inv-pl", {
        id: "inv-pl",
        organizationId: ORG_ACME,
        status: "PENDING",
        normalizedEmail: "ewa@acme.pl",
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

      // 3) Konto w @acme.pl blokuje usunięcie
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

      // 4) Gdy żadna inna domena nie jest VERIFIED (np. główna jest PENDING), usunięcie ostatniej VERIFIED -> 409
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

      // 5) Nieużywana niegłówna domena -> 204, audyt i możliwość ponownego dodania
      const removed = await app.inject({
        method: "DELETE",
        url: `/core/v1/organization/domains/${plId}`,
        headers: { authorization: ownerBearer },
      });
      expect(removed.statusCode).toBe(204);
      expect(removed.body).toBe("");
      expect(domains.has(plId)).toBe(false);
      expect(audits[audits.length - 1]).toEqual({
        action: "organization.domain.removed",
        resourceType: "organization_domain",
        resourceId: plId,
        metadata: { domain: "acme.pl" },
      });

      const readded = await app.inject({
        method: "POST",
        url: "/core/v1/organization/domains",
        headers: { authorization: ownerBearer },
        payload: { domain: "acme.pl" },
      });
      expect(readded.statusCode).toBe(201);
    } finally {
      await app.close();
    }
  });
});
