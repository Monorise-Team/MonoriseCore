import {
  CORE_PERMISSIONS,
  DIRECTORY_READ_SCOPE,
  type AccountStatus,
  type EmployeeStatus,
  type WorkSchedule,
} from "@core/contracts";
import { Prisma, type PrismaClient } from "@core/db";
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
const UNIT_HR_ACC = "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6a35";
const UNIT_HR_EMP = "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6a36";
const GLOBEX_EMP = "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6a42";
const UNIT_KRAKOW = "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6a50";
const PROD_TIMOTIME = "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6a60";
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
  workSchedule: WorkSchedule | null;
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
  const organizations = new Map<
    string,
    { id: string; name: string; status: "ACTIVE"; timeZone: string; ownerAccountId: string }
  >([
    [ORG_ACME, { id: ORG_ACME, name: "Acme", status: "ACTIVE", timeZone: "Europe/Warsaw", ownerAccountId: OWNER_ACC }],
    [
      ORG_GLOBEX,
      { id: ORG_GLOBEX, name: "Globex", status: "ACTIVE", timeZone: "America/New_York", ownerAccountId: "" },
    ],
  ]);
  const entitlements = new Map<string, boolean>([[`${ORG_ACME}:${PROD_TIMOTIME}`, true]]);
  const unitMemberships = [
    {
      id: "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6a71",
      organizationId: ORG_ACME,
      unitId: UNIT_KRAKOW,
      employeeId: REGULAR_EMP,
      role: "MEMBER" as const,
    },
    {
      id: "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6a72",
      organizationId: ORG_ACME,
      unitId: UNIT_KRAKOW,
      employeeId: OWNER_EMP,
      role: "LEADER" as const,
    },
  ];
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
        workSchedule: null,
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
        workSchedule: null,
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
        workSchedule: null,
        status: "ACTIVE",
      },
    ],
    [
      UNIT_HR_EMP,
      {
        id: UNIT_HR_EMP,
        organizationId: ORG_ACME,
        firstName: "Tomasz",
        lastName: "Oddzial",
        workEmail: `tomasz@${ACME_DOMAIN}`,
        jobTitle: "Kierownik",
        workSchedule: null,
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
        workSchedule: null,
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
    [
      UNIT_HR_ACC,
      {
        id: UNIT_HR_ACC,
        organizationId: ORG_ACME,
        employeeId: UNIT_HR_EMP,
        email: `tomasz@${ACME_DOMAIN}`,
        normalizedEmail: `tomasz@${ACME_DOMAIN}`,
        status: "ACTIVE",
        authzRevision: 0,
      },
    ],
  ]);
  const authUsers = new Map<string, { id: string; name: string; email: string }>([
    [OWNER_ACC, { id: OWNER_ACC, name: "Anna Owner", email: `anna@${ACME_DOMAIN}` }],
    [REGULAR_ACC, { id: REGULAR_ACC, name: "Jan Kowlski", email: `jan@${ACME_DOMAIN}` }],
    [HR_ACC, { id: HR_ACC, name: "Marta Kadry", email: `marta@${ACME_DOMAIN}` }],
    [UNIT_HR_ACC, { id: UNIT_HR_ACC, name: "Tomasz Oddzial", email: `tomasz@${ACME_DOMAIN}` }],
  ]);
  const audits: MockAudit[] = [];

  const accountByEmployeeId = (employeeId: string) =>
    [...accounts.values()].find((acc) => acc.employeeId === employeeId) ?? null;

  const db = {
    product: {
      findUnique: async ({ where }: { where: { key?: string } }) =>
        where.key === "timotime" ? { id: PROD_TIMOTIME, key: "timotime", registrationClientId: "timotime-web" } : null,
    },
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
        organization: {
          findUnique: async ({ where }: { where: { id: string } }) => {
            const org = organizations.get(where.id);
            if (!org || org.id !== currentOrgId) return null;
            return { ...org };
          },
          findUniqueOrThrow: async ({ where }: { where: { id: string } }) => {
            const org = organizations.get(where.id);
            if (!org || org.id !== currentOrgId) throw new Error("Org not found");
            return { ...org };
          },
        },
        entitlement: {
          findFirst: async ({ where }: { where: { productId: string } }) =>
            entitlements.get(`${currentOrgId}:${where.productId}`) ? { id: "ent-1" } : null,
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
          findMany: async () => [{ id: UNIT_KRAKOW, parentId: null }],
        },
        unitMembership: {
          findMany: async ({ where }: { where?: { unitId?: { in: string[] }; id?: { gt: string } } }) => {
            return unitMemberships
              .filter((m) => {
                if (m.organizationId !== currentOrgId) return false;
                if (where?.unitId?.in && !where.unitId.in.includes(m.unitId)) return false;
                if (where?.id?.gt && m.id <= where.id.gt) return false;
                return true;
              })
              .map((m) => {
                const emp = employees.get(m.employeeId)!;
                const acc = accountByEmployeeId(emp.id);
                return {
                  ...m,
                  employee: {
                    workSchedule: emp.workSchedule,
                    account: acc ? { id: acc.id } : null,
                  },
                };
              });
          },
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
            if (where.accountId === UNIT_HR_ACC) {
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
            const org = organizations.get(acc.organizationId);
            return {
              ...acc,
              organization: { ownerAccountId: org?.ownerAccountId ?? null },
            };
          },
          findUniqueOrThrow: async ({ where }: { where: { id: string } }) => {
            const acc = accounts.get(where.id);
            if (!acc || acc.organizationId !== currentOrgId) throw new Error("Account not found");
            const org = organizations.get(acc.organizationId)!;
            const emp = employees.get(acc.employeeId)!;
            return {
              ...acc,
              employee: { ...emp },
              organization: { ...org },
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
          findMany: async ({ where }: { where?: { id?: { in?: string[]; gt?: string } } }) => {
            return [...employees.values()]
              .filter((e) => {
                if (e.organizationId !== currentOrgId) return false;
                if (where?.id?.in && !where.id.in.includes(e.id)) return false;
                if (where?.id?.gt && e.id <= where.id.gt) return false;
                return true;
              })
              .sort((a, b) => a.id.localeCompare(b.id))
              .map((emp) => {
                const acc = accountByEmployeeId(emp.id);
                return {
                  ...emp,
                  account: acc ? { id: acc.id, status: acc.status } : null,
                };
              });
          },
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
          create: async ({ data }: { data: Omit<MockEmployee, "status" | "workSchedule"> }) => {
            const row: MockEmployee = { ...data, workSchedule: null, status: "ACTIVE" };
            employees.set(row.id, row);
            return row;
          },
          update: async ({
            where,
            data,
          }: {
            where: { id: string };
            data: Partial<Omit<MockEmployee, "workSchedule">> & {
              workSchedule?: WorkSchedule | typeof Prisma.DbNull | null;
            };
          }) => {
            const prev = employees.get(where.id);
            if (!prev || prev.organizationId !== currentOrgId) throw new Error("Not found");
            const nextWorkSchedule: WorkSchedule | null =
              data.workSchedule === undefined
                ? prev.workSchedule
                : data.workSchedule === Prisma.DbNull
                  ? null
                  : (data.workSchedule as WorkSchedule | null);
            const next: MockEmployee = { ...prev, ...data, workSchedule: nextWorkSchedule };
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

  return { db, organizations, entitlements, employees, accounts, authUsers, audits };
}

function buildTestApp(db: PrismaClient) {
  return buildServer({
    db,
    verifyToken: async (token) => {
      if (token.startsWith("machine:")) throw new Error("Token maszynowy nie jest tokenem użytkownika");
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
    verifyMachineToken: async (token) => {
      if (!token.startsWith("machine:")) throw new Error("Niepoprawny token maszynowy");
      const [, clientId, ...scopeParts] = token.split(":");
      return {
        iss: "http://localhost:3100",
        aud: "http://localhost:3200",
        client_id: clientId!,
        scope: scopeParts.join(":"),
        iat: 1,
        exp: 9_999_999_999,
      };
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
        workSchedule: null,
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

  it("aktualizuje i czyści workSchedule (z kontrolą uprawnień, no-op i audytem) oraz zwraca workSchedule i timeZone w /me i katalogu produktu", async () => {
    const { db, organizations, entitlements, audits } = createInMemoryEmployeeDb();
    const app = buildTestApp(db);

    try {
      const ownerBearer = `Bearer ${OWNER_ACC}:${OWNER_EMP}`;
      const regularBearer = `Bearer ${REGULAR_ACC}:${REGULAR_EMP}`;
      const hrBearer = `Bearer ${HR_ACC}:${HR_EMP}`;
      const unitHrBearer = `Bearer ${UNIT_HR_ACC}:${UNIT_HR_EMP}`;
      const dirBearer = `Bearer machine:timotime-web:${DIRECTORY_READ_SCOPE}`;
      const wrongScopeBearer = "Bearer machine:timotime-web:core:events.read";
      const wrongClientBearer = `Bearer machine:other-web:${DIRECTORY_READ_SCOPE}`;

      const annaFullTime = { "1": 480, "2": 480, "3": 480, "4": 480, "5": 480 };
      const janPartTime = { "1": 240, "2": 240, "3": 240 };

      // Brak core.employees.manage albo zakres UNIT -> 403 PERMISSION_DENIED
      for (const deniedBearer of [regularBearer, unitHrBearer]) {
        const denied = await app.inject({
          method: "PATCH",
          url: `/core/v1/employees/${REGULAR_EMP}`,
          headers: { authorization: deniedBearer },
          payload: { workSchedule: janPartTime },
        });
        expect(denied.statusCode).toBe(403);
        expect(denied.json().error.code).toBe("PERMISSION_DENIED");
      }

      // Niepoprawne harmonogramy -> 422 VALIDATION_FAILED
      for (const badSchedule of [{ "0": 480 }, { "8": 480 }, { "1": 1441 }, { "1": -1 }, { "1": 480.5 }, [480]]) {
        const bad = await app.inject({
          method: "PATCH",
          url: `/core/v1/employees/${REGULAR_EMP}`,
          headers: { authorization: ownerBearer },
          payload: { workSchedule: badSchedule },
        });
        expect(bad.statusCode).toBe(422);
        expect(bad.json().error.code).toBe("VALIDATION_FAILED");
      }

      // Ustawienie harmonogramu przez Ownera i przez konto z core.employees.manage w ORGANIZATION
      const setAnna = await app.inject({
        method: "PATCH",
        url: `/core/v1/employees/${OWNER_EMP}`,
        headers: { authorization: ownerBearer },
        payload: { workSchedule: annaFullTime },
      });
      expect(setAnna.statusCode).toBe(200);
      expect(setAnna.json().data.workSchedule).toEqual(annaFullTime);

      const setJan = await app.inject({
        method: "PATCH",
        url: `/core/v1/employees/${REGULAR_EMP}`,
        headers: { authorization: hrBearer },
        payload: { workSchedule: janPartTime },
      });
      expect(setJan.statusCode).toBe(200);
      expect(setJan.json().data.workSchedule).toEqual(janPartTime);
      expect(audits).toEqual([
        {
          action: "employee.updated",
          resourceType: "employee",
          resourceId: OWNER_EMP,
          metadata: { fields: ["workSchedule"] },
        },
        {
          action: "employee.updated",
          resourceType: "employee",
          resourceId: REGULAR_EMP,
          metadata: { fields: ["workSchedule"] },
        },
      ]);

      // No-op z tą samą zawartością w innej kolejności kluczy -> 200 i brak kolejnego wpisu audytu
      const noop = await app.inject({
        method: "PATCH",
        url: `/core/v1/employees/${REGULAR_EMP}`,
        headers: { authorization: ownerBearer },
        payload: { workSchedule: { "3": 240, "1": 240, "2": 240 } },
      });
      expect(noop.statusCode).toBe(200);
      expect(audits).toHaveLength(2);

      // GET /core/v1/me zwraca workSchedule pracownika i timeZone firmy
      const meRes = await app.inject({
        method: "GET",
        url: "/core/v1/me",
        headers: { authorization: regularBearer },
      });
      expect(meRes.statusCode).toBe(200);
      expect(meRes.json().data.employee.workSchedule).toEqual(janPartTime);
      expect(meRes.json().data.organization.timeZone).toBe("Europe/Warsaw");

      // Katalog produktu: employees, unit-members i organization
      const dirEmps = await app.inject({
        method: "GET",
        url: `/core/v1/products/timotime/directory/employees?organizationId=${ORG_ACME}`,
        headers: { authorization: dirBearer },
      });
      expect(dirEmps.statusCode).toBe(200);
      expect(dirEmps.json().data).toEqual(
        expect.arrayContaining([
          expect.objectContaining({ id: OWNER_EMP, workSchedule: annaFullTime }),
          expect.objectContaining({ id: REGULAR_EMP, workSchedule: janPartTime }),
          expect.objectContaining({ id: HR_EMP, workSchedule: null }),
        ]),
      );

      const dirMembers = await app.inject({
        method: "GET",
        url: `/core/v1/products/timotime/directory/unit-members?organizationId=${ORG_ACME}`,
        headers: { authorization: dirBearer },
      });
      expect(dirMembers.statusCode).toBe(200);
      expect(dirMembers.json().data).toEqual(
        expect.arrayContaining([
          {
            unitId: UNIT_KRAKOW,
            employeeId: OWNER_EMP,
            accountId: OWNER_ACC,
            role: "LEADER",
            workSchedule: annaFullTime,
          },
          {
            unitId: UNIT_KRAKOW,
            employeeId: REGULAR_EMP,
            accountId: REGULAR_ACC,
            role: "MEMBER",
            workSchedule: janPartTime,
          },
        ]),
      );

      organizations.get(ORG_ACME)!.timeZone = "Europe/London";
      const dirOrg = await app.inject({
        method: "GET",
        url: `/core/v1/products/timotime/directory/organization?organizationId=${ORG_ACME}`,
        headers: { authorization: dirBearer },
      });
      expect(dirOrg.statusCode).toBe(200);
      expect(dirOrg.json().data).toEqual({
        id: ORG_ACME,
        name: "Acme",
        status: "ACTIVE",
        timeZone: "Europe/London",
      });

      // Odmowy na directory/organization: token użytkownika -> 401, zły zakres -> 403, zły klient -> 403, brak Entitlement -> 403, nieznana firma -> 404
      expect(
        (
          await app.inject({
            method: "GET",
            url: `/core/v1/products/timotime/directory/organization?organizationId=${ORG_ACME}`,
            headers: { authorization: ownerBearer },
          })
        ).statusCode,
      ).toBe(401);
      expect(
        (
          await app.inject({
            method: "GET",
            url: `/core/v1/products/timotime/directory/organization?organizationId=${ORG_ACME}`,
            headers: { authorization: wrongScopeBearer },
          })
        ).statusCode,
      ).toBe(403);
      expect(
        (
          await app.inject({
            method: "GET",
            url: `/core/v1/products/timotime/directory/organization?organizationId=${ORG_ACME}`,
            headers: { authorization: wrongClientBearer },
          })
        ).statusCode,
      ).toBe(403);
      expect(
        (
          await app.inject({
            method: "GET",
            url: "/core/v1/products/timotime/directory/organization?organizationId=0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6aff",
            headers: { authorization: dirBearer },
          })
        ).statusCode,
      ).toBe(404);
      entitlements.delete(`${ORG_ACME}:${PROD_TIMOTIME}`);
      expect(
        (
          await app.inject({
            method: "GET",
            url: `/core/v1/products/timotime/directory/organization?organizationId=${ORG_ACME}`,
            headers: { authorization: dirBearer },
          })
        ).statusCode,
      ).toBe(403);

      // Wyczyszczenie harmonogramu przez workSchedule: null -> 200 i wpis audytu; ponowne null -> no-op
      const cleared = await app.inject({
        method: "PATCH",
        url: `/core/v1/employees/${REGULAR_EMP}`,
        headers: { authorization: ownerBearer },
        payload: { workSchedule: null },
      });
      expect(cleared.statusCode).toBe(200);
      expect(cleared.json().data.workSchedule).toBeNull();
      expect(audits).toHaveLength(3);
      expect(audits[2]?.metadata).toEqual({ fields: ["workSchedule"] });

      const clearedAgain = await app.inject({
        method: "PATCH",
        url: `/core/v1/employees/${REGULAR_EMP}`,
        headers: { authorization: ownerBearer },
        payload: { workSchedule: null },
      });
      expect(clearedAgain.statusCode).toBe(200);
      expect(audits).toHaveLength(3);
    } finally {
      await app.close();
    }
  });
});
