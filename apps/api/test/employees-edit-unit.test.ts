import { CORE_PERMISSIONS, type AccountStatus, type EmployeeStatus } from "@core/contracts";
import type { PrismaClient } from "@core/db";
import { describe, expect, it } from "vitest";
import { buildServer } from "../src/server.js";

const ORG_ACME = "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6a01";
const ORG_GLOBEX = "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6a02";
const OWNER_ACC = "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6a11";
const OWNER_EMP = "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6a12";
const REGULAR_ACC = "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6a21";
const REGULAR_EMP = "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6a22";
const HR_ACC = "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6a31";
const HR_EMP = "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6a32";
const GLOBEX_EMP = "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6a42";
const ACME_DOMAIN = "acme.test";
const ACME_PENDING_DOMAIN = "pending.acme.test";
const GLOBEX_DOMAIN = "globex.test";

interface MockEmployee {
  id: string;
  organizationId: string;
  firstName: string;
  lastName: string;
  workEmail: string | null;
  jobTitle: string | null;
  status: EmployeeStatus;
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

interface MockDomain {
  id: string;
  organizationId: string;
  domain: string;
  status: "PENDING" | "VERIFIED" | "FAILED" | "REVOKED";
}

interface MockAudit {
  action: string;
  resourceType: string;
  resourceId: string;
  metadata: unknown;
}

/**
 * Lekki mock PrismaClient w pamięci (z symulacją RLS po `organizationId`) do testowania ścieżek HTTP
 * `POST /core/v1/employees` i `PATCH /core/v1/employees/{employeeId}` bez dostępu do PostgreSQL.
 */
function createInMemoryEmployeeDb() {
  const owners = new Map<string, string>([[ORG_ACME, OWNER_ACC]]);
  const domains: MockDomain[] = [
    { id: "dom-1", organizationId: ORG_ACME, domain: ACME_DOMAIN, status: "VERIFIED" },
    { id: "dom-2", organizationId: ORG_ACME, domain: ACME_PENDING_DOMAIN, status: "PENDING" },
    { id: "dom-3", organizationId: ORG_GLOBEX, domain: GLOBEX_DOMAIN, status: "VERIFIED" },
  ];
  const employees = new Map<string, MockEmployee>([
    [
      OWNER_EMP,
      {
        id: OWNER_EMP,
        organizationId: ORG_ACME,
        firstName: "Anna",
        lastName: "Owner",
        workEmail: `anna@${ACME_DOMAIN}`,
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
        lastName: "Kowlski",
        workEmail: null,
        jobTitle: "Magazynier",
        status: "ACTIVE",
      },
    ],
    [
      HR_EMP,
      {
        id: HR_EMP,
        organizationId: ORG_ACME,
        firstName: "Marta",
        lastName: "Kadry",
        workEmail: `marta@${ACME_DOMAIN}`,
        jobTitle: "HR",
        status: "ACTIVE",
      },
    ],
    [
      GLOBEX_EMP,
      {
        id: GLOBEX_EMP,
        organizationId: ORG_GLOBEX,
        firstName: "Obcy",
        lastName: "Pracownik",
        workEmail: `obcy@${GLOBEX_DOMAIN}`,
        jobTitle: null,
        status: "ACTIVE",
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
        email: `anna@${ACME_DOMAIN}`,
        normalizedEmail: `anna@${ACME_DOMAIN}`,
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
        email: `jan@${ACME_DOMAIN}`,
        normalizedEmail: `jan@${ACME_DOMAIN}`,
        status: "ACTIVE",
        authzRevision: 0,
      },
    ],
    [
      HR_ACC,
      {
        id: HR_ACC,
        organizationId: ORG_ACME,
        employeeId: HR_EMP,
        email: `marta@${ACME_DOMAIN}`,
        normalizedEmail: `marta@${ACME_DOMAIN}`,
        status: "ACTIVE",
        authzRevision: 0,
      },
    ],
  ]);
  const authUsers = new Map<string, { id: string; name: string; email: string }>([
    [OWNER_ACC, { id: OWNER_ACC, name: "Anna Owner", email: `anna@${ACME_DOMAIN}` }],
    [REGULAR_ACC, { id: REGULAR_ACC, name: "Jan Kowlski", email: `jan@${ACME_DOMAIN}` }],
    [HR_ACC, { id: HR_ACC, name: "Marta Kadry", email: `marta@${ACME_DOMAIN}` }],
  ]);
  const audits: MockAudit[] = [];

  const accountByEmployeeId = (employeeId: string) =>
    [...accounts.values()].find((acc) => acc.employeeId === employeeId) ?? null;

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
        organizationDomain: {
          findFirst: async ({ where }: { where: { organizationId?: string; domain: string; status: string } }) => {
            const orgId = where.organizationId ?? currentOrgId;
            return (
              domains.find(
                (d) =>
                  d.organizationId === orgId &&
                  d.domain.toLowerCase() === where.domain.toLowerCase() &&
                  d.status === where.status,
              ) ?? null
            );
          },
        },
        organizationUnit: {
          findMany: async () => [],
        },
        roleAssignment: {
          findMany: async ({ where }: { where: { accountId: string } }) => {
            if (where.accountId === HR_ACC) {
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
                      { permission: { key: CORE_PERMISSIONS.keys["employees.manage"], deprecatedAt: null } },
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
            return {
              ...acc,
              organization: { ownerAccountId: owners.get(acc.organizationId) ?? null },
            };
          },
          findFirst: async ({
            where,
          }: {
            where: {
              organizationId?: string;
              normalizedEmail: string | { equals: string; mode?: string };
              employeeId?: { not: string };
            };
          }) => {
            const orgId = where.organizationId ?? currentOrgId;
            const target =
              typeof where.normalizedEmail === "string"
                ? where.normalizedEmail.toLowerCase()
                : where.normalizedEmail.equals.toLowerCase();
            return (
              [...accounts.values()].find(
                (a) =>
                  a.organizationId === orgId &&
                  a.normalizedEmail.toLowerCase() === target &&
                  (where.employeeId?.not === undefined || a.employeeId !== where.employeeId.not),
              ) ?? null
            );
          },
        },
        employee: {
          findUnique: async ({ where }: { where: { id: string } }) => {
            const emp = employees.get(where.id);
            if (!emp || emp.organizationId !== currentOrgId) return null;
            const acc = accountByEmployeeId(emp.id);
            return {
              ...emp,
              account: acc ? { id: acc.id, status: acc.status, normalizedEmail: acc.normalizedEmail } : null,
            };
          },
          findFirst: async ({
            where,
          }: {
            where: {
              organizationId?: string;
              workEmail: { equals: string; mode?: string };
              id?: { not: string };
            };
          }) => {
            const orgId = where.organizationId ?? currentOrgId;
            const target = where.workEmail.equals.toLowerCase();
            return (
              [...employees.values()].find(
                (e) =>
                  e.organizationId === orgId &&
                  e.workEmail !== null &&
                  e.workEmail.toLowerCase() === target &&
                  (where.id?.not === undefined || e.id !== where.id.not),
              ) ?? null
            );
          },
          create: async ({ data }: { data: Omit<MockEmployee, "status"> }) => {
            const row: MockEmployee = { ...data, status: "ACTIVE" };
            employees.set(row.id, row);
            return row;
          },
          update: async ({ where, data }: { where: { id: string }; data: Partial<MockEmployee> }) => {
            const prev = employees.get(where.id);
            if (!prev || prev.organizationId !== currentOrgId) throw new Error("Not found");
            const next: MockEmployee = { ...prev, ...data };
            employees.set(next.id, next);
            const acc = accountByEmployeeId(next.id);
            return {
              ...next,
              account: acc ? { id: acc.id, status: acc.status } : null,
            };
          },
        },
        authUser: {
          update: async ({ where, data }: { where: { id: string }; data: { name: string } }) => {
            const user = authUsers.get(where.id);
            if (!user) throw new Error("AuthUser not found");
            const next = { ...user, name: data.name };
            authUsers.set(where.id, next);
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

  return { db, employees, accounts, authUsers, audits };
}

function buildTestApp(db: PrismaClient) {
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
  });
}

describe("Edycja pracownika i walidacja workEmail (testy jednostkowe HTTP bez bazy)", () => {
  it("aktualizuje imię, nazwisko i stanowisko pracownika z kontem, synchronizuje auth.users.name, wspiera no-op i zapisuje audyt bez PII", async () => {
    const { db, authUsers, audits } = createInMemoryEmployeeDb();
    const app = buildTestApp(db);

    try {
      const ownerBearer = `Bearer ${OWNER_ACC}:${OWNER_EMP}`;

      const res = await app.inject({
        method: "PATCH",
        url: `/core/v1/employees/${REGULAR_EMP}`,
        headers: { authorization: ownerBearer },
        payload: { firstName: " Jan ", lastName: " Kowalski ", jobTitle: " Kierownik " },
      });
      expect(res.statusCode).toBe(200);
      expect(res.json().data).toEqual({
        id: REGULAR_EMP,
        accountId: REGULAR_ACC,
        accountStatus: "ACTIVE",
        firstName: "Jan",
        lastName: "Kowalski",
        workEmail: null,
        jobTitle: "Kierownik",
        status: "ACTIVE",
      });
      expect(authUsers.get(REGULAR_ACC)?.name).toBe("Jan Kowalski");
      expect(audits).toEqual([
        {
          action: "employee.updated",
          resourceType: "employee",
          resourceId: REGULAR_EMP,
          metadata: { fields: ["lastName", "jobTitle"] },
        },
      ]);

      // Uzupełnienie brakującego workEmail zgodnym adresem konta -> 200
      const backfill = await app.inject({
        method: "PATCH",
        url: `/core/v1/employees/${REGULAR_EMP}`,
        headers: { authorization: ownerBearer },
        payload: { workEmail: `JAN@${ACME_DOMAIN.toUpperCase()}` },
      });
      expect(backfill.statusCode).toBe(200);
      expect(backfill.json().data.workEmail).toBe(`jan@${ACME_DOMAIN}`);
      expect(audits).toHaveLength(2);
      expect(audits[1]?.metadata).toEqual({ fields: ["workEmail"] });

      // No-op z niezmienionymi wartościami -> 200 i brak nowego wpisu audytu
      const noop = await app.inject({
        method: "PATCH",
        url: `/core/v1/employees/${REGULAR_EMP}`,
        headers: { authorization: ownerBearer },
        payload: { firstName: "Jan", lastName: "Kowalski", workEmail: `jan@${ACME_DOMAIN}`, jobTitle: "Kierownik" },
      });
      expect(noop.statusCode).toBe(200);
      expect(audits).toHaveLength(2);

      // Próba zmiany lub wyczyszczenia workEmail na koncie -> 409 CONFLICT
      for (const workEmail of [`inny@${ACME_DOMAIN}`, null]) {
        const denied = await app.inject({
          method: "PATCH",
          url: `/core/v1/employees/${REGULAR_EMP}`,
          headers: { authorization: ownerBearer },
          payload: { workEmail },
        });
        expect(denied.statusCode).toBe(409);
        expect(denied.json().error.code).toBe("CONFLICT");
      }
    } finally {
      await app.close();
    }
  });

  it("waliduje workEmail w POST i PATCH pracownika bez konta, sprawdza uprawnienia, RLS 404 i status ANONYMIZED", async () => {
    const { db, employees } = createInMemoryEmployeeDb();
    const app = buildTestApp(db);

    try {
      const ownerBearer = `Bearer ${OWNER_ACC}:${OWNER_EMP}`;
      const regularBearer = `Bearer ${REGULAR_ACC}:${REGULAR_EMP}`;
      const hrBearer = `Bearer ${HR_ACC}:${HR_EMP}`;

      // POST odrzuca darmową i niezweryfikowaną domenę -> 422 EMAIL_DOMAIN_NOT_ALLOWED
      for (const badEmail of ["a@gmail.com", `a@${ACME_PENDING_DOMAIN}`, `a@${GLOBEX_DOMAIN}`]) {
        const res = await app.inject({
          method: "POST",
          url: "/core/v1/employees",
          headers: { authorization: ownerBearer },
          payload: { firstName: "Marek", lastName: "Nowak", workEmail: badEmail },
        });
        expect(res.statusCode).toBe(422);
        expect(res.json().error.code).toBe("EMAIL_DOMAIN_NOT_ALLOWED");
      }

      // POST odrzuca duplikat konta w firmie -> 409
      const dupAcc = await app.inject({
        method: "POST",
        url: "/core/v1/employees",
        headers: { authorization: ownerBearer },
        payload: { firstName: "Marek", lastName: "Nowak", workEmail: `JAN@${ACME_DOMAIN}` },
      });
      expect(dupAcc.statusCode).toBe(409);
      expect(dupAcc.json().error.code).toBe("CONFLICT");

      // POST normalizuje poprawny workEmail w zweryfikowanej domenie -> 201
      const created = await app.inject({
        method: "POST",
        url: "/core/v1/employees",
        headers: { authorization: ownerBearer },
        payload: { firstName: "Marek", lastName: "Nowak", workEmail: `Marek@${ACME_DOMAIN.toUpperCase()}` },
      });
      expect(created.statusCode).toBe(201);
      const marekId = created.json().data.id as string;
      expect(created.json().data.workEmail).toBe(`marek@${ACME_DOMAIN}`);

      // POST odrzuca duplikat workEmail pracownika -> 409
      const dupEmp = await app.inject({
        method: "POST",
        url: "/core/v1/employees",
        headers: { authorization: ownerBearer },
        payload: { firstName: "Drugi", lastName: "Marek", workEmail: `marek@${ACME_DOMAIN}` },
      });
      expect(dupEmp.statusCode).toBe(409);

      // PATCH przez zwykłe konto -> 403; pracownik z innej firmy -> 404 (przed 403)
      const forbidden = await app.inject({
        method: "PATCH",
        url: `/core/v1/employees/${marekId}`,
        headers: { authorization: regularBearer },
        payload: { firstName: "Zmiana" },
      });
      expect(forbidden.statusCode).toBe(403);
      expect(forbidden.json().error.code).toBe("PERMISSION_DENIED");

      const crossTenant = await app.inject({
        method: "PATCH",
        url: `/core/v1/employees/${GLOBEX_EMP}`,
        headers: { authorization: regularBearer },
        payload: { firstName: "Obcy" },
      });
      expect(crossTenant.statusCode).toBe(404);
      expect(crossTenant.json().error.code).toBe("NOT_FOUND");

      // PATCH przez konto z core.employees.manage w ORGANIZATION -> 200; czyszczenie workEmail -> 200
      const hrEdit = await app.inject({
        method: "PATCH",
        url: `/core/v1/employees/${marekId}`,
        headers: { authorization: hrBearer },
        payload: { workEmail: `Marek.Nowy@${ACME_DOMAIN.toUpperCase()}` },
      });
      expect(hrEdit.statusCode).toBe(200);
      expect(hrEdit.json().data.workEmail).toBe(`marek.nowy@${ACME_DOMAIN}`);

      const cleared = await app.inject({
        method: "PATCH",
        url: `/core/v1/employees/${marekId}`,
        headers: { authorization: hrBearer },
        payload: { workEmail: null },
      });
      expect(cleared.statusCode).toBe(200);
      expect(cleared.json().data.workEmail).toBeNull();

      // PATCH odrzuca darmową domenę i duplikat -> 422 / 409
      const freePatch = await app.inject({
        method: "PATCH",
        url: `/core/v1/employees/${marekId}`,
        headers: { authorization: ownerBearer },
        payload: { workEmail: "marek@wp.pl" },
      });
      expect(freePatch.statusCode).toBe(422);
      expect(freePatch.json().error.code).toBe("EMAIL_DOMAIN_NOT_ALLOWED");

      const dupPatch = await app.inject({
        method: "PATCH",
        url: `/core/v1/employees/${marekId}`,
        headers: { authorization: ownerBearer },
        payload: { workEmail: `anna@${ACME_DOMAIN}` },
      });
      expect(dupPatch.statusCode).toBe(409);
      expect(dupPatch.json().error.code).toBe("CONFLICT");

      // ANONYMIZED -> 409
      employees.get(marekId)!.status = "ANONYMIZED";
      const anonRes = await app.inject({
        method: "PATCH",
        url: `/core/v1/employees/${marekId}`,
        headers: { authorization: ownerBearer },
        payload: { firstName: "Proba" },
      });
      expect(anonRes.statusCode).toBe(409);
      expect(anonRes.json().error.code).toBe("CONFLICT");
    } finally {
      await app.close();
    }
  });
});
