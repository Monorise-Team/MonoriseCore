import {
  CORE_PERMISSIONS,
  IDEMPOTENCY_KEY_HEADER,
  IDEMPOTENCY_REPLAYED_HEADER,
  type AccountStatus,
  type EmployeeStatus,
  type InvitationStatus,
} from "@core/contracts";
import type { PrismaClient } from "@core/db";
import { describe, expect, it } from "vitest";
import { AUDIT_ACTION_LABELS, sanitizeAuditMetadata } from "../src/audit.js";
import { buildServer } from "../src/server.js";

const ORG_ACME = "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6a01";
const ORG_GLOBEX = "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6a02";
const OWNER_ACC = "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6a11";
const OWNER_EMP = "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6a12";
const PIOTR_ACC = "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6a21";
const PIOTR_EMP = "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6a22";
const HR_ACC = "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6a31";
const HR_EMP = "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6a32";
const UNIT_HR_ACC = "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6a35";
const UNIT_HR_EMP = "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6a36";
const INVITED_ACC = "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6a41";
const INVITED_EMP = "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6a42";
const NO_ACCOUNT_EMP = "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6a52";
const ANON_ACC = "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6a61";
const ANON_EMP = "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6a62";
const GLOBEX_ACC = "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6a71";
const GLOBEX_EMP = "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6a72";
const UNIT_KRAKOW = "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6a81";

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
  deactivatedAt: Date | null;
}

interface MockSession {
  id: string;
  userId: string;
}

interface MockRefreshToken {
  id: string;
  userId: string;
  rotated: boolean;
}

interface MockAccessToken {
  id: string;
  userId: string;
}

interface MockInvitation {
  id: string;
  organizationId: string;
  accountId: string;
  status: InvitationStatus;
}

interface MockOutboxEvent {
  type: string;
  organizationId: string | null;
  resourceType: string;
  resourceId: string;
  resourceVersion: number;
  payload: unknown;
}

interface MockAudit {
  action: string;
  resourceType: string;
  resourceId: string;
  metadata: unknown;
}

interface MockIdempotencyRow {
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

/**
 * Lekki mock PrismaClient w pamięci (z symulacją RLS po `organizationId`) do testowania
 * `POST /core/v1/employees/{employeeId}/deactivate` i `/reactivate` bez dostępu do PostgreSQL.
 */
function createInMemoryDeactivationDb() {
  const organizations = new Map<string, { id: string; name: string; status: string; ownerAccountId: string }>([
    [ORG_ACME, { id: ORG_ACME, name: "Acme", status: "ACTIVE", ownerAccountId: OWNER_ACC }],
    [ORG_GLOBEX, { id: ORG_GLOBEX, name: "Globex", status: "ACTIVE", ownerAccountId: GLOBEX_ACC }],
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
        jobTitle: "Owner",
        status: "ACTIVE",
      },
    ],
    [
      PIOTR_EMP,
      {
        id: PIOTR_EMP,
        organizationId: ORG_ACME,
        firstName: "Piotr",
        lastName: "Urlopowy",
        workEmail: "piotr@acme.test",
        jobTitle: "Specjalista",
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
        workEmail: "marta@acme.test",
        jobTitle: "HR",
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
        workEmail: "tomasz@acme.test",
        jobTitle: "Kierownik",
        status: "ACTIVE",
      },
    ],
    [
      INVITED_EMP,
      {
        id: INVITED_EMP,
        organizationId: ORG_ACME,
        firstName: "Karol",
        lastName: "Zaproszony",
        workEmail: "karol@acme.test",
        jobTitle: null,
        status: "ACTIVE",
      },
    ],
    [
      NO_ACCOUNT_EMP,
      {
        id: NO_ACCOUNT_EMP,
        organizationId: ORG_ACME,
        firstName: "Marek",
        lastName: "BezKonta",
        workEmail: "marek@acme.test",
        jobTitle: null,
        status: "ACTIVE",
      },
    ],
    [
      ANON_EMP,
      {
        id: ANON_EMP,
        organizationId: ORG_ACME,
        firstName: "Anonim",
        lastName: "Zanonimizowany",
        workEmail: null,
        jobTitle: null,
        status: "ANONYMIZED",
      },
    ],
    [
      GLOBEX_EMP,
      {
        id: GLOBEX_EMP,
        organizationId: ORG_GLOBEX,
        firstName: "Obcy",
        lastName: "Globex",
        workEmail: "obcy@globex.test",
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
        email: "anna@acme.test",
        normalizedEmail: "anna@acme.test",
        status: "ACTIVE",
        authzRevision: 0,
        deactivatedAt: null,
      },
    ],
    [
      PIOTR_ACC,
      {
        id: PIOTR_ACC,
        organizationId: ORG_ACME,
        employeeId: PIOTR_EMP,
        email: "piotr@acme.test",
        normalizedEmail: "piotr@acme.test",
        status: "ACTIVE",
        authzRevision: 2,
        deactivatedAt: null,
      },
    ],
    [
      HR_ACC,
      {
        id: HR_ACC,
        organizationId: ORG_ACME,
        employeeId: HR_EMP,
        email: "marta@acme.test",
        normalizedEmail: "marta@acme.test",
        status: "ACTIVE",
        authzRevision: 0,
        deactivatedAt: null,
      },
    ],
    [
      UNIT_HR_ACC,
      {
        id: UNIT_HR_ACC,
        organizationId: ORG_ACME,
        employeeId: UNIT_HR_EMP,
        email: "tomasz@acme.test",
        normalizedEmail: "tomasz@acme.test",
        status: "ACTIVE",
        authzRevision: 0,
        deactivatedAt: null,
      },
    ],
    [
      INVITED_ACC,
      {
        id: INVITED_ACC,
        organizationId: ORG_ACME,
        employeeId: INVITED_EMP,
        email: "karol@acme.test",
        normalizedEmail: "karol@acme.test",
        status: "INVITED",
        authzRevision: 0,
        deactivatedAt: null,
      },
    ],
    [
      ANON_ACC,
      {
        id: ANON_ACC,
        organizationId: ORG_ACME,
        employeeId: ANON_EMP,
        email: "anon@acme.test",
        normalizedEmail: "anon@acme.test",
        status: "ACTIVE",
        authzRevision: 0,
        deactivatedAt: null,
      },
    ],
    [
      GLOBEX_ACC,
      {
        id: GLOBEX_ACC,
        organizationId: ORG_GLOBEX,
        employeeId: GLOBEX_EMP,
        email: "obcy@globex.test",
        normalizedEmail: "obcy@globex.test",
        status: "ACTIVE",
        authzRevision: 0,
        deactivatedAt: null,
      },
    ],
  ]);

  let sessions: MockSession[] = [
    { id: "sess-piotr-1", userId: PIOTR_ACC },
    { id: "sess-piotr-2", userId: PIOTR_ACC },
    { id: "sess-owner-1", userId: OWNER_ACC },
  ];
  let refreshTokens: MockRefreshToken[] = [
    { id: "rt-piotr-active", userId: PIOTR_ACC, rotated: false },
    { id: "rt-piotr-rotated-replay", userId: PIOTR_ACC, rotated: true },
    { id: "rt-owner-active", userId: OWNER_ACC, rotated: false },
  ];
  let accessTokens: MockAccessToken[] = [
    { id: "at-piotr-1", userId: PIOTR_ACC },
    { id: "at-owner-1", userId: OWNER_ACC },
  ];
  const invitations: MockInvitation[] = [
    { id: "inv-stray-piotr", organizationId: ORG_ACME, accountId: PIOTR_ACC, status: "PENDING" },
    { id: "inv-karol", organizationId: ORG_ACME, accountId: INVITED_ACC, status: "PENDING" },
  ];
  const outboxEvents: MockOutboxEvent[] = [];
  const audits: MockAudit[] = [];
  const idempotencyKeys = new Map<string, MockIdempotencyRow>();
  const locks: string[] = [];

  const accountByEmployeeId = (employeeId: string) =>
    [...accounts.values()].find((acc) => acc.employeeId === employeeId) ?? null;

  const idemCompositeKey = (orgId: string, principal: string, key: string) => `${orgId}\0${principal}\0${key}`;

  const db = {
    $transaction: async <T>(fn: (tx: unknown) => Promise<T>): Promise<T> => {
      let currentOrgId: string | null = null;
      const tx = {
        $executeRaw: async (strings: TemplateStringsArray, ...values: unknown[]) => {
          const sql = strings.join(" ");
          if (sql.includes("set_config")) {
            currentOrgId = String(values[0] ?? "");
          } else if (sql.includes("pg_advisory_xact_lock")) {
            locks.push(`${sql}:${values.map(String).join(",")}`);
          }
          return 1;
        },
        organization: {
          findUniqueOrThrow: async ({ where }: { where: { id: string } }) => {
            const org = organizations.get(where.id);
            if (!org || org.id !== currentOrgId) throw new Error("Organization not found");
            return org;
          },
        },
        organizationUnit: {
          findMany: async () => [{ id: UNIT_KRAKOW, parentId: null }],
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
            const org = organizations.get(acc.organizationId)!;
            return { ...acc, organization: { ownerAccountId: org.ownerAccountId } };
          },
          findUniqueOrThrow: async ({ where }: { where: { id: string } }) => {
            const acc = accounts.get(where.id);
            if (!acc || acc.organizationId !== currentOrgId) throw new Error("Account not found");
            const emp = employees.get(acc.employeeId)!;
            const org = organizations.get(acc.organizationId)!;
            return { ...acc, employee: emp, organization: org };
          },
          update: async ({
            where,
            data,
          }: {
            where: { id: string };
            data: { status?: AccountStatus; deactivatedAt?: Date | null };
          }) => {
            const acc = accounts.get(where.id);
            if (!acc || acc.organizationId !== currentOrgId) throw new Error("Account not found");
            const next: MockAccount = {
              ...acc,
              ...(data.status !== undefined ? { status: data.status } : {}),
              ...(data.deactivatedAt !== undefined ? { deactivatedAt: data.deactivatedAt } : {}),
            };
            accounts.set(acc.id, next);
            return next;
          },
          updateManyAndReturn: async ({
            where,
            data,
          }: {
            where: { id?: string };
            data: { authzRevision?: { increment: number } };
          }) => {
            const updated: { id: string; authzRevision: number }[] = [];
            for (const acc of accounts.values()) {
              if (acc.organizationId !== currentOrgId) continue;
              if (where.id !== undefined && acc.id !== where.id) continue;
              if (data.authzRevision?.increment) {
                acc.authzRevision += data.authzRevision.increment;
              }
              updated.push({ id: acc.id, authzRevision: acc.authzRevision });
            }
            return updated;
          },
        },
        employee: {
          findUnique: async ({ where }: { where: { id: string } }) => {
            const emp = employees.get(where.id);
            if (!emp || emp.organizationId !== currentOrgId) return null;
            const acc = accountByEmployeeId(emp.id);
            return { ...emp, account: acc ? { id: acc.id, status: acc.status } : null };
          },
        },
        authSession: {
          deleteMany: async ({ where }: { where: { userId: string } }) => {
            const before = sessions.length;
            sessions = sessions.filter((s) => s.userId !== where.userId);
            return { count: before - sessions.length };
          },
        },
        authOAuthRefreshToken: {
          deleteMany: async ({ where }: { where: { userId: string } }) => {
            const before = refreshTokens.length;
            refreshTokens = refreshTokens.filter((t) => t.userId !== where.userId);
            return { count: before - refreshTokens.length };
          },
        },
        authOAuthAccessToken: {
          deleteMany: async ({ where }: { where: { userId: string } }) => {
            const before = accessTokens.length;
            accessTokens = accessTokens.filter((t) => t.userId !== where.userId);
            return { count: before - accessTokens.length };
          },
        },
        invitation: {
          updateMany: async ({
            where,
            data,
          }: {
            where: { accountId: string; status: InvitationStatus };
            data: { status: InvitationStatus };
          }) => {
            let count = 0;
            for (const inv of invitations) {
              if (inv.organizationId !== currentOrgId) continue;
              if (inv.accountId === where.accountId && inv.status === where.status) {
                inv.status = data.status;
                count += 1;
              }
            }
            return { count };
          },
        },
        outboxEvent: {
          create: async ({ data }: { data: MockOutboxEvent }) => {
            outboxEvents.push({
              type: data.type,
              organizationId: data.organizationId ?? null,
              resourceType: data.resourceType,
              resourceId: data.resourceId,
              resourceVersion: data.resourceVersion,
              payload: data.payload,
            });
            return data;
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
        idempotencyKey: {
          findUnique: async ({
            where,
          }: {
            where: { organizationId_principal_key: { organizationId: string; principal: string; key: string } };
          }) => {
            const k = where.organizationId_principal_key;
            if (k.organizationId !== currentOrgId) return null;
            return idempotencyKeys.get(idemCompositeKey(k.organizationId, k.principal, k.key)) ?? null;
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
            const k = where.organizationId_principal_key;
            const composite = idemCompositeKey(k.organizationId, k.principal, k.key);
            const prev = idempotencyKeys.get(composite);
            const next = prev ? { ...prev, ...update } : create;
            idempotencyKeys.set(composite, next);
            return next;
          },
        },
      };
      return fn(tx);
    },
  } as unknown as PrismaClient;

  return {
    db,
    employees,
    accounts,
    getSessions: () => sessions,
    getRefreshTokens: () => refreshTokens,
    getAccessTokens: () => accessTokens,
    invitations,
    outboxEvents,
    audits,
    locks,
  };
}

function buildTestApp(db: PrismaClient, getNow: () => Date) {
  return buildServer({
    db,
    now: getNow,
    verifyToken: async (token) => {
      const [orgId, accId, empId] = token.split(":");
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
  });
}

describe("Wyłączanie i przywracanie konta pracownika (testy jednostkowe HTTP bez bazy)", () => {
  it("wyłącza konto, usuwa sesje i tokeny OAuth (zostawiając cudze), cofa stray PENDING zaproszenie, emituje 1 zdarzenie, blokuje GET /me i pozwala na idempotentne powtórki oraz przywrócenie", async () => {
    let now = new Date("2026-11-26T10:00:00.000Z");
    const state = createInMemoryDeactivationDb();
    const app = buildTestApp(state.db, () => now);

    try {
      const ownerBearer = `Bearer ${ORG_ACME}:${OWNER_ACC}:${OWNER_EMP}`;
      const piotrBearer = `Bearer ${ORG_ACME}:${PIOTR_ACC}:${PIOTR_EMP}`;

      // 1. Wyłączenie konta Piotra z Idempotency-Key
      const deactivateRes = await app.inject({
        method: "POST",
        url: `/core/v1/employees/${PIOTR_EMP}/deactivate`,
        headers: {
          authorization: ownerBearer,
          [IDEMPOTENCY_KEY_HEADER]: "deact-piotr-1",
        },
      });
      expect(deactivateRes.statusCode).toBe(200);
      expect(deactivateRes.headers[IDEMPOTENCY_REPLAYED_HEADER.toLowerCase()]).toBeUndefined();
      expect(deactivateRes.json()).toMatchObject({
        data: {
          id: PIOTR_EMP,
          accountId: PIOTR_ACC,
          accountStatus: "DEACTIVATED",
          firstName: "Piotr",
          lastName: "Urlopowy",
          status: "ACTIVE",
        },
        error: null,
      });

      // Stan konta i pracownika (Employee.status bez zmian!)
      const piotrAfterDeactivate = state.accounts.get(PIOTR_ACC)!;
      expect(piotrAfterDeactivate.status).toBe("DEACTIVATED");
      expect(piotrAfterDeactivate.deactivatedAt).toEqual(now);
      expect(piotrAfterDeactivate.authzRevision).toBe(3);
      expect(state.employees.get(PIOTR_EMP)?.status).toBe("ACTIVE");

      // Usunięte sesje i tokeny OAuth Piotra (włącznie z obróconym), tokeny Ownera nietknięte
      expect(state.getSessions()).toEqual([{ id: "sess-owner-1", userId: OWNER_ACC }]);
      expect(state.getRefreshTokens()).toEqual([{ id: "rt-owner-active", userId: OWNER_ACC, rotated: false }]);
      expect(state.getAccessTokens()).toEqual([{ id: "at-owner-1", userId: OWNER_ACC }]);

      // Stray PENDING zaproszenie Piotra cofnięte, zaproszenie Karola nietknięte
      expect(state.invitations.find((i) => i.id === "inv-stray-piotr")?.status).toBe("REVOKED");
      expect(state.invitations.find((i) => i.id === "inv-karol")?.status).toBe("PENDING");

      // Jedno zdarzenie outbox organization.permissions.changed z nową rewizją
      expect(state.outboxEvents).toHaveLength(1);
      expect(state.outboxEvents[0]).toMatchObject({
        type: "organization.permissions.changed",
        organizationId: ORG_ACME,
        resourceType: "account",
        resourceId: PIOTR_ACC,
        resourceVersion: 3,
      });

      // Jeden wpis audytu account.deactivated bez PII i z metadanymi nieusuwanymi przez sanitizeAuditMetadata
      expect(state.audits).toHaveLength(1);
      expect(state.audits[0]).toEqual({
        action: "account.deactivated",
        resourceType: "account",
        resourceId: PIOTR_ACC,
        metadata: {
          employeeId: PIOTR_EMP,
          revokedSessions: 2,
          revokedOAuthRefreshes: 2,
          revokedOAuthAccesses: 1,
        },
      });
      expect(AUDIT_ACTION_LABELS["account.deactivated"]).toBe("Wyłączono konto pracownika");
      expect(sanitizeAuditMetadata(state.audits[0]?.metadata)).toEqual(state.audits[0]?.metadata);
      expect(JSON.stringify(state.audits[0]?.metadata)).not.toContain("Piotr");
      expect(JSON.stringify(state.audits[0]?.metadata)).not.toContain("piotr@acme.test");

      // Niewygasły token JWT Piotra natychmiast dostaje 401 ACCOUNT_DEACTIVATED
      const piotrMeBlocked = await app.inject({
        method: "GET",
        url: "/core/v1/me",
        headers: { authorization: piotrBearer },
      });
      expect(piotrMeBlocked.statusCode).toBe(401);
      expect(piotrMeBlocked.json().error.code).toBe("ACCOUNT_DEACTIVATED");

      // 2. Powtórka z tym samym Idempotency-Key -> 200 + Idempotency-Replayed: true, brak drugiego zdarzenia
      const replayRes = await app.inject({
        method: "POST",
        url: `/core/v1/employees/${PIOTR_EMP}/deactivate`,
        headers: {
          authorization: ownerBearer,
          [IDEMPOTENCY_KEY_HEADER]: "deact-piotr-1",
        },
      });
      expect(replayRes.statusCode).toBe(200);
      expect(replayRes.headers[IDEMPOTENCY_REPLAYED_HEADER.toLowerCase()]).toBe("true");
      expect(replayRes.json().data).toEqual(deactivateRes.json().data);
      expect(state.accounts.get(PIOTR_ACC)?.authzRevision).toBe(3);
      expect(state.outboxEvents).toHaveLength(1);
      expect(state.audits).toHaveLength(1);

      // 3. Idempotentne powtórzenie bez Idempotency-Key (później w czasie) -> 200 z bieżącym stanem, bez zdarzenia/audytu/zmiany deactivatedAt
      const firstDeactivatedAt = state.accounts.get(PIOTR_ACC)?.deactivatedAt;
      now = new Date("2026-11-26T10:05:00.000Z");
      const idempotentDeactivate = await app.inject({
        method: "POST",
        url: `/core/v1/employees/${PIOTR_EMP}/deactivate`,
        headers: { authorization: ownerBearer },
      });
      expect(idempotentDeactivate.statusCode).toBe(200);
      expect(idempotentDeactivate.headers[IDEMPOTENCY_REPLAYED_HEADER.toLowerCase()]).toBeUndefined();
      expect(idempotentDeactivate.json().data.accountStatus).toBe("DEACTIVATED");
      expect(state.accounts.get(PIOTR_ACC)?.deactivatedAt).toEqual(firstDeactivatedAt);
      expect(state.accounts.get(PIOTR_ACC)?.authzRevision).toBe(3);
      expect(state.outboxEvents).toHaveLength(1);
      expect(state.audits).toHaveLength(1);

      // 4. Przywrócenie konta Piotra przez konto HR z core.employees.manage (ORGANIZATION)
      const hrBearer = `Bearer ${ORG_ACME}:${HR_ACC}:${HR_EMP}`;
      const reactivateRes = await app.inject({
        method: "POST",
        url: `/core/v1/employees/${PIOTR_EMP}/reactivate`,
        headers: {
          authorization: hrBearer,
          [IDEMPOTENCY_KEY_HEADER]: "react-piotr-1",
        },
      });
      expect(reactivateRes.statusCode).toBe(200);
      expect(reactivateRes.json().data).toMatchObject({
        id: PIOTR_EMP,
        accountId: PIOTR_ACC,
        accountStatus: "ACTIVE",
        status: "ACTIVE",
      });
      const piotrAfterReactivate = state.accounts.get(PIOTR_ACC)!;
      expect(piotrAfterReactivate.status).toBe("ACTIVE");
      expect(piotrAfterReactivate.deactivatedAt).toBeNull();
      expect(piotrAfterReactivate.authzRevision).toBe(4);
      expect(state.outboxEvents).toHaveLength(2);
      expect(state.outboxEvents[1]).toMatchObject({
        type: "organization.permissions.changed",
        resourceId: PIOTR_ACC,
        resourceVersion: 4,
      });
      expect(state.audits).toHaveLength(2);
      expect(state.audits[1]).toEqual({
        action: "account.reactivated",
        resourceType: "account",
        resourceId: PIOTR_ACC,
        metadata: { employeeId: PIOTR_EMP },
      });
      expect(AUDIT_ACTION_LABELS["account.reactivated"]).toBe("Przywrócono konto pracownika");

      // Idempotentne powtórzenie /reactivate na aktywnym koncie -> 200 bez zdarzenia i podbicia rewizji
      const idempotentReactivate = await app.inject({
        method: "POST",
        url: `/core/v1/employees/${PIOTR_EMP}/reactivate`,
        headers: { authorization: ownerBearer },
      });
      expect(idempotentReactivate.statusCode).toBe(200);
      expect(idempotentReactivate.json().data.accountStatus).toBe("ACTIVE");
      expect(state.accounts.get(PIOTR_ACC)?.authzRevision).toBe(4);
      expect(state.outboxEvents).toHaveLength(2);
      expect(state.audits).toHaveLength(2);

      // Po przywróceniu GET /me Piotra znowu działa
      const piotrMeRestored = await app.inject({
        method: "GET",
        url: "/core/v1/me",
        headers: { authorization: piotrBearer },
      });
      expect(piotrMeRestored.statusCode).toBe(200);
      expect(piotrMeRestored.json().data.account.status).toBe("ACTIVE");
    } finally {
      await app.close();
    }
  });

  it("egzekwuje uprawnienia (403), izolację firm (404 przed 403), walidację UUID (422) i reguły 409 (Owner, self, brak konta, INVITED, ANONYMIZED) na obu endpointach", async () => {
    const state = createInMemoryDeactivationDb();
    const app = buildTestApp(state.db, () => new Date("2026-11-26T10:00:00.000Z"));

    try {
      const ownerBearer = `Bearer ${ORG_ACME}:${OWNER_ACC}:${OWNER_EMP}`;
      const hrBearer = `Bearer ${ORG_ACME}:${HR_ACC}:${HR_EMP}`;
      const unitHrBearer = `Bearer ${ORG_ACME}:${UNIT_HR_ACC}:${UNIT_HR_EMP}`;
      const piotrBearer = `Bearer ${ORG_ACME}:${PIOTR_ACC}:${PIOTR_EMP}`;

      for (const action of ["deactivate", "reactivate"] as const) {
        // Brak uprawnienia albo zakres UNIT -> 403 PERMISSION_DENIED
        for (const deniedBearer of [piotrBearer, unitHrBearer]) {
          const denied = await app.inject({
            method: "POST",
            url: `/core/v1/employees/${PIOTR_EMP}/${action}`,
            headers: { authorization: deniedBearer },
          });
          expect(denied.statusCode).toBe(403);
          expect(denied.json().error.code).toBe("PERMISSION_DENIED");
        }

        // Pracownik innej firmy (nawet bez uprawnień) lub nieznany UUID -> 404 NOT_FOUND
        for (const [bearer, empId] of [
          [piotrBearer, GLOBEX_EMP],
          [ownerBearer, GLOBEX_EMP],
          [ownerBearer, "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6aff"],
        ] as const) {
          const missing = await app.inject({
            method: "POST",
            url: `/core/v1/employees/${empId}/${action}`,
            headers: { authorization: bearer },
          });
          expect(missing.statusCode).toBe(404);
          expect(missing.json().error.code).toBe("NOT_FOUND");
        }

        // Niepoprawny UUID -> 422 VALIDATION_FAILED
        const badUuid = await app.inject({
          method: "POST",
          url: `/core/v1/employees/not-a-uuid/${action}`,
          headers: { authorization: ownerBearer },
        });
        expect(badUuid.statusCode).toBe(422);
        expect(badUuid.json().error.code).toBe("VALIDATION_FAILED");

        // Owner (przez Ownera i przez HR), własne konto HR, brak konta, INVITED, ANONYMIZED -> 409 CONFLICT
        for (const [bearer, empId] of [
          [ownerBearer, OWNER_EMP],
          [hrBearer, OWNER_EMP],
          [hrBearer, HR_EMP],
          [ownerBearer, NO_ACCOUNT_EMP],
          [ownerBearer, INVITED_EMP],
          [ownerBearer, ANON_EMP],
        ] as const) {
          const conflict = await app.inject({
            method: "POST",
            url: `/core/v1/employees/${empId}/${action}`,
            headers: { authorization: bearer },
          });
          expect(conflict.statusCode).toBe(409);
          expect(conflict.json().error.code).toBe("CONFLICT");
          expect(typeof conflict.json().error.message).toBe("string");
          expect(conflict.json().error.message.length).toBeGreaterThan(0);
        }
      }

      // Żaden z odrzuconych ruchów nie wyemitował zdarzeń ani audytu
      expect(state.outboxEvents).toHaveLength(0);
      expect(state.audits).toHaveLength(0);
    } finally {
      await app.close();
    }
  });
});
