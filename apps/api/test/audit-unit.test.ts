import { AUDIT_LOG_RETENTION_DAYS, CORE_PERMISSIONS, type AuditActorType } from "@core/contracts";
import type { PrismaClient } from "@core/db";
import { describe, expect, it } from "vitest";
import {
  AUDIT_ACTION_LABELS,
  AuditCursorError,
  decodeAuditCursor,
  encodeAuditCursor,
  getAuditActionLabel,
  sanitizeAuditMetadata,
} from "../src/audit.js";
import { buildServer } from "../src/server.js";

const ORG_ID = "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6a01";
const OTHER_ORG_ID = "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6a02";
const OWNER_ACC_ID = "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6a11";
const OWNER_EMP_ID = "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6a12";
const ADMIN_ACC_ID = "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6a21";
const ADMIN_EMP_ID = "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6a22";
const UNIT_AUDITOR_ACC_ID = "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6a31";
const UNIT_AUDITOR_EMP_ID = "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6a32";
const REGULAR_ACC_ID = "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6a41";
const REGULAR_EMP_ID = "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6a42";
const UNIT_ID = "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6a51";
const SUPPORT_GRANT_ID = "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6a61";
const OPERATOR_ID = "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6a71";

interface StoredAuditRow {
  id: string;
  organizationId: string | null;
  actorType: AuditActorType;
  actorAccountId: string | null;
  actorOperatorId: string | null;
  product: { key: string } | null;
  action: string;
  resourceType: string;
  resourceId: string;
  metadata: unknown;
  ipAddress: string | null;
  userAgent: string | null;
  requestId: string | null;
  supportAccessGrantId: string | null;
  createdAt: Date;
}

interface StoredAccount {
  id: string;
  organizationId: string;
  employeeId: string;
  firstName: string;
  lastName: string;
  assignments: {
    scopeType: "ORGANIZATION" | "UNIT" | "RESOURCE";
    scopeId: string | null;
    permissions: string[];
  }[];
}

function matchesAuditWhere(row: StoredAuditRow, where: Record<string, unknown> | undefined): boolean {
  if (!where) return true;
  if (Array.isArray(where.AND)) {
    return (where.AND as Record<string, unknown>[]).every((clause) => matchesAuditWhere(row, clause));
  }
  if (Array.isArray(where.OR)) {
    return (where.OR as Record<string, unknown>[]).some((clause) => matchesAuditWhere(row, clause));
  }
  if ("organizationId" in where && row.organizationId !== where.organizationId) return false;
  if ("actorAccountId" in where && row.actorAccountId !== where.actorAccountId) return false;
  if ("actorType" in where && row.actorType !== where.actorType) return false;
  if ("action" in where && row.action !== where.action) return false;
  if ("resourceType" in where && row.resourceType !== where.resourceType) return false;
  if ("resourceId" in where && row.resourceId !== where.resourceId) return false;
  if ("id" in where) {
    const idCond = where.id;
    if (typeof idCond === "string" && row.id !== idCond) return false;
    if (idCond && typeof idCond === "object" && "lt" in idCond) {
      if (!(row.id < String((idCond as { lt: string }).lt))) return false;
    }
  }
  if ("createdAt" in where) {
    const cond = where.createdAt;
    if (cond instanceof Date && row.createdAt.getTime() !== cond.getTime()) return false;
    if (cond && typeof cond === "object" && !(cond instanceof Date)) {
      const range = cond as { gte?: Date; lte?: Date; lt?: Date };
      if (range.gte && row.createdAt.getTime() < range.gte.getTime()) return false;
      if (range.lte && row.createdAt.getTime() > range.lte.getTime()) return false;
      if (range.lt && row.createdAt.getTime() >= range.lt.getTime()) return false;
    }
  }
  return true;
}

function createInMemoryAuditServer(rows: StoredAuditRow[], now: Date) {
  const accounts = new Map<string, StoredAccount>([
    [
      OWNER_ACC_ID,
      {
        id: OWNER_ACC_ID,
        organizationId: ORG_ID,
        employeeId: OWNER_EMP_ID,
        firstName: "Anna",
        lastName: "Kowalska",
        assignments: [],
      },
    ],
    [
      ADMIN_ACC_ID,
      {
        id: ADMIN_ACC_ID,
        organizationId: ORG_ID,
        employeeId: ADMIN_EMP_ID,
        firstName: "Jan",
        lastName: "Admin",
        assignments: [
          {
            scopeType: "ORGANIZATION",
            scopeId: null,
            permissions: [CORE_PERMISSIONS.keys["audit.read"]],
          },
        ],
      },
    ],
    [
      UNIT_AUDITOR_ACC_ID,
      {
        id: UNIT_AUDITOR_ACC_ID,
        organizationId: ORG_ID,
        employeeId: UNIT_AUDITOR_EMP_ID,
        firstName: "Ewa",
        lastName: "Działowa",
        assignments: [
          {
            scopeType: "UNIT",
            scopeId: UNIT_ID,
            permissions: [CORE_PERMISSIONS.keys["audit.read"]],
          },
        ],
      },
    ],
    [
      REGULAR_ACC_ID,
      {
        id: REGULAR_ACC_ID,
        organizationId: ORG_ID,
        employeeId: REGULAR_EMP_ID,
        firstName: "Marek",
        lastName: "Pracownik",
        assignments: [],
      },
    ],
  ]);

  const db = {
    $transaction: async <T>(fn: (tx: unknown) => Promise<T>): Promise<T> => {
      let currentOrgId: string | null = null;
      const tx = {
        $executeRaw: async (_strings: TemplateStringsArray, ...values: unknown[]) => {
          currentOrgId = String(values[0] ?? "");
          return 1;
        },
        account: {
          findUnique: async ({ where }: { where: { id: string } }) => {
            const acc = accounts.get(where.id);
            if (!acc || acc.organizationId !== currentOrgId) return null;
            return {
              status: "ACTIVE",
              employeeId: acc.employeeId,
              authzRevision: 0,
              organization: { ownerAccountId: OWNER_ACC_ID },
            };
          },
          findMany: async ({ where }: { where: { id: { in: string[] } } }) =>
            where.id.in
              .map((id) => accounts.get(id))
              .filter((acc): acc is StoredAccount => acc !== undefined && acc.organizationId === currentOrgId)
              .map((acc) => ({
                id: acc.id,
                employee: { firstName: acc.firstName, lastName: acc.lastName },
              })),
        },
        organizationUnit: {
          findMany: async () => [{ id: UNIT_ID, parentId: null }],
        },
        roleAssignment: {
          findMany: async ({ where }: { where: { accountId: string } }) => {
            const acc = accounts.get(where.accountId);
            if (!acc || acc.organizationId !== currentOrgId) return [];
            return acc.assignments.map((a) => ({
              scopeType: a.scopeType,
              scopeId: a.scopeId,
              validFrom: null,
              validUntil: null,
              role: {
                archivedAt: null,
                product: null,
                permissions: a.permissions.map((key) => ({ permission: { key, deprecatedAt: null } })),
              },
            }));
          },
        },
        auditLog: {
          findMany: async ({
            where,
            select,
            take,
          }: {
            where?: Record<string, unknown>;
            select?: Record<string, unknown>;
            take?: number;
          }) => {
            // Symulacja RLS na audit_log (organizationId IS NOT DISTINCT FROM current_organization_id())
            const rlsRows = rows.filter((row) => row.organizationId === currentOrgId);
            const filtered = rlsRows
              .filter((row) => matchesAuditWhere(row, where))
              .sort((a, b) => {
                const diff = b.createdAt.getTime() - a.createdAt.getTime();
                if (diff !== 0) return diff;
                return b.id.localeCompare(a.id);
              });
            const sliced = take !== undefined ? filtered.slice(0, take) : filtered;
            return sliced.map((row) => {
              if (!select) return row;
              const projected: Record<string, unknown> = {};
              for (const key of Object.keys(select)) {
                projected[key] = row[key as keyof StoredAuditRow];
              }
              return projected;
            });
          },
        },
      };
      return fn(tx);
    },
  } as unknown as PrismaClient;

  return buildServer({
    db,
    now: () => now,
    verifyToken: async (token) => {
      const acc = accounts.get(token);
      if (!acc) throw new Error("invalid token");
      return {
        iss: "http://localhost:3100",
        sub: acc.id,
        aud: "http://localhost:3200",
        org_id: acc.organizationId,
        employee_id: acc.employeeId,
        amr: ["pwd"],
        authz_rev: 0,
        iat: 1,
        exp: 9999999999,
      };
    },
    verifyMachineToken: async () => {
      throw new Error("not used");
    },
  });
}

describe("dziennik zdarzeń — testy jednostkowe bez bazy", () => {
  it("usuwa rekurencyjnie wrażliwe klucze z metadata, zachowując bezpieczne pola", () => {
    const cleaned = sanitizeAuditMetadata({
      accountId: ADMIN_ACC_ID,
      product: "timotime",
      tokenHash: "abc123",
      verificationTokenHash: "def456",
      clientSecret: "super-secret",
      PASSWORD: "hidden",
      Authorization: "Bearer xyz",
      setCookie: "session=1",
      nested: {
        safe: true,
        refreshToken: "rt_123",
        deep: {
          passwordHash: "bcrypt$...",
          roleId: "role-1",
        },
      },
      items: [{ name: "ok", access_token: "nope" }, { secretKey: "nope", count: 2 }, "primitive"],
    });

    expect(cleaned).toEqual({
      accountId: ADMIN_ACC_ID,
      product: "timotime",
      nested: {
        safe: true,
        deep: {
          roleId: "role-1",
        },
      },
      items: [{ name: "ok" }, { count: 2 }, "primitive"],
    });

    expect(sanitizeAuditMetadata(null)).toEqual({});
    expect(sanitizeAuditMetadata(["not", "object"])).toEqual({});
    expect(sanitizeAuditMetadata("string")).toEqual({});
  });

  it("mapuje znane akcje Core na polskie etykiety i bezpiecznie zwraca surową akcję dla nieznanych", () => {
    expect(getAuditActionLabel("app_access.revoked")).toBe("Wyłączono dostęp do aplikacji");
    expect(getAuditActionLabel("organization.owner.transferred")).toBe("Przekazano rolę Ownera firmy");
    expect(getAuditActionLabel("unit.member.set")).toBe("Zapisano członkostwo w jednostce organizacyjnej");
    expect(getAuditActionLabel("timotime.entry.approved")).toBe("timotime.entry.approved");
    expect(getAuditActionLabel("toString")).toBe("toString");
    expect(getAuditActionLabel("constructor")).toBe("constructor");
    expect(Object.keys(AUDIT_ACTION_LABELS).length).toBeGreaterThan(15);
  });

  it("koduje i kanonicznie dekoduje złożony kursor (createdAt, id)", () => {
    const t = new Date("2026-11-26T14:05:00.123Z");
    const encoded = encodeAuditCursor(t, OWNER_ACC_ID);
    expect(decodeAuditCursor(encoded)).toEqual({ t, id: OWNER_ACC_ID });

    expect(() => decodeAuditCursor("not!base64")).toThrow(AuditCursorError);
    expect(() => decodeAuditCursor(Buffer.from("not-json").toString("base64url"))).toThrow(AuditCursorError);
    expect(() =>
      decodeAuditCursor(Buffer.from(JSON.stringify({ t: t.toISOString(), id: "bad" })).toString("base64url")),
    ).toThrow(AuditCursorError);
    expect(() =>
      decodeAuditCursor(
        Buffer.from(JSON.stringify({ t: "2026-11-26T14:05:00.123+00:00", id: OWNER_ACC_ID })).toString("base64url"),
      ),
    ).toThrow(AuditCursorError);
    expect(() =>
      decodeAuditCursor(
        Buffer.from(JSON.stringify({ t: t.toISOString(), id: OWNER_ACC_ID, extra: 1 })).toString("base64url"),
      ),
    ).toThrow(AuditCursorError);
  });

  it("obsługuje uprawnienia, filtry, stronicowanie z remisem czasu, 730-dniowe okno retencji i redakcję na ścieżce HTTP", async () => {
    const now = new Date("2026-11-26T15:00:00.000Z");
    const tiedTime = new Date("2026-11-26T14:05:00.000Z");
    const olderTime = new Date("2026-11-25T10:00:00.000Z");
    const withinRetention = new Date(now.getTime() - (AUDIT_LOG_RETENTION_DAYS - 1) * 24 * 60 * 60 * 1000);
    const expiredRetention = new Date(now.getTime() - (AUDIT_LOG_RETENTION_DAYS + 1) * 24 * 60 * 60 * 1000);

    const rows: StoredAuditRow[] = [
      {
        id: "0193a5b2-7c3d-7e4f-8a1b-000000000005",
        organizationId: ORG_ID,
        actorType: "ACCOUNT",
        actorAccountId: ADMIN_ACC_ID,
        actorOperatorId: null,
        product: { key: "timotime" },
        action: "app_access.revoked",
        resourceType: "app_access",
        resourceId: "0193a5b2-7c3d-7e4f-8a1b-111111111111",
        metadata: { product: "timotime", tokenHash: "secret-hash", clientSecret: "top-secret" },
        ipAddress: "127.0.0.1",
        userAgent: "Portal/1.0",
        requestId: "req_005",
        supportAccessGrantId: null,
        createdAt: tiedTime,
      },
      {
        id: "0193a5b2-7c3d-7e4f-8a1b-000000000004",
        organizationId: ORG_ID,
        actorType: "OPERATOR",
        actorAccountId: null,
        actorOperatorId: OPERATOR_ID,
        product: null,
        action: "organization.updated",
        resourceType: "organization",
        resourceId: ORG_ID,
        metadata: { field: "name" },
        ipAddress: null,
        userAgent: null,
        requestId: "req_004",
        supportAccessGrantId: SUPPORT_GRANT_ID,
        createdAt: tiedTime,
      },
      {
        id: "0193a5b2-7c3d-7e4f-8a1b-000000000003",
        organizationId: ORG_ID,
        actorType: "PRODUCT",
        actorAccountId: null,
        actorOperatorId: null,
        product: { key: "timotime" },
        action: "timotime.entry.approved",
        resourceType: "time_entry",
        resourceId: "entry-42",
        metadata: { hours: 8 },
        ipAddress: null,
        userAgent: null,
        requestId: "req_003",
        supportAccessGrantId: null,
        createdAt: olderTime,
      },
      {
        id: "0193a5b2-7c3d-7e4f-8a1b-000000000002",
        organizationId: ORG_ID,
        actorType: "SYSTEM",
        actorAccountId: null,
        actorOperatorId: null,
        product: null,
        action: "entitlement.granted",
        resourceType: "entitlement",
        resourceId: "ent-1",
        metadata: { source: "cli" },
        ipAddress: null,
        userAgent: null,
        requestId: null,
        supportAccessGrantId: null,
        createdAt: withinRetention,
      },
      {
        id: "0193a5b2-7c3d-7e4f-8a1b-000000000001",
        organizationId: ORG_ID,
        actorType: "ACCOUNT",
        actorAccountId: OWNER_ACC_ID,
        actorOperatorId: null,
        product: null,
        action: "unit.created",
        resourceType: "unit",
        resourceId: UNIT_ID,
        metadata: {},
        ipAddress: null,
        userAgent: null,
        requestId: null,
        supportAccessGrantId: null,
        createdAt: expiredRetention,
      },
      {
        id: "0193a5b2-7c3d-7e4f-8a1b-000000000099",
        organizationId: OTHER_ORG_ID,
        actorType: "ACCOUNT",
        actorAccountId: OWNER_ACC_ID,
        actorOperatorId: null,
        product: null,
        action: "unit.created",
        resourceType: "unit",
        resourceId: "other-unit",
        metadata: {},
        ipAddress: null,
        userAgent: null,
        requestId: null,
        supportAccessGrantId: null,
        createdAt: tiedTime,
      },
      {
        id: "0193a5b2-7c3d-7e4f-8a1b-000000000098",
        organizationId: null,
        actorType: "SYSTEM",
        actorAccountId: null,
        actorOperatorId: null,
        product: null,
        action: "role_templates.registered",
        resourceType: "product",
        resourceId: "core",
        metadata: {},
        ipAddress: null,
        userAgent: null,
        requestId: null,
        supportAccessGrantId: null,
        createdAt: tiedTime,
      },
    ];

    const app = createInMemoryAuditServer(rows, now);
    try {
      // Brak uprawnień i zakres UNIT -> 403
      const regularRes = await app.inject({
        method: "GET",
        url: "/core/v1/audit-log",
        headers: { authorization: `Bearer ${REGULAR_ACC_ID}` },
      });
      expect(regularRes.statusCode).toBe(403);
      expect(regularRes.json().error.code).toBe("PERMISSION_DENIED");

      const unitScopedRes = await app.inject({
        method: "GET",
        url: "/core/v1/audit-log",
        headers: { authorization: `Bearer ${UNIT_AUDITOR_ACC_ID}` },
      });
      expect(unitScopedRes.statusCode).toBe(403);
      expect(unitScopedRes.json().error.code).toBe("PERMISSION_DENIED");

      // Nawet z zakresem spoza retencji osoba bez uprawnień dostaje 403
      const regularOldRange = await app.inject({
        method: "GET",
        url: "/core/v1/audit-log?to=2020-01-01T00:00:00.000Z",
        headers: { authorization: `Bearer ${REGULAR_ACC_ID}` },
      });
      expect(regularOldRange.statusCode).toBe(403);

      // Admin z core.audit.read (ORGANIZATION) -> 200
      const adminRes = await app.inject({
        method: "GET",
        url: "/core/v1/audit-log",
        headers: { authorization: `Bearer ${ADMIN_ACC_ID}` },
      });
      expect(adminRes.statusCode).toBe(200);
      expect(adminRes.json().data).toHaveLength(4);

      // Owner: kolejność od najnowszych, brak wpisu > 730 dni, brak innej firmy i platformy, redakcja i brak actorOperatorId
      const ownerRes = await app.inject({
        method: "GET",
        url: "/core/v1/audit-log",
        headers: { authorization: `Bearer ${OWNER_ACC_ID}` },
      });
      expect(ownerRes.statusCode).toBe(200);
      const entries = ownerRes.json().data as Record<string, unknown>[];
      expect(entries.map((e) => e.id)).toEqual([
        "0193a5b2-7c3d-7e4f-8a1b-000000000005",
        "0193a5b2-7c3d-7e4f-8a1b-000000000004",
        "0193a5b2-7c3d-7e4f-8a1b-000000000003",
        "0193a5b2-7c3d-7e4f-8a1b-000000000002",
      ]);
      expect(entries[0]).toMatchObject({
        actorType: "ACCOUNT",
        actorAccountId: ADMIN_ACC_ID,
        actorDisplayName: "Jan Admin",
        product: "timotime",
        action: "app_access.revoked",
        actionLabel: "Wyłączono dostęp do aplikacji",
        metadata: { product: "timotime" },
      });
      expect(entries[1]).toMatchObject({
        actorType: "OPERATOR",
        actorAccountId: null,
        actorDisplayName: null,
        supportAccessGrantId: SUPPORT_GRANT_ID,
      });
      expect(entries[2]).toMatchObject({
        actorType: "PRODUCT",
        actorDisplayName: null,
        action: "timotime.entry.approved",
        actionLabel: "timotime.entry.approved",
      });
      expect(entries[3]).toMatchObject({
        actorType: "SYSTEM",
        actorDisplayName: null,
      });
      for (const entry of entries) {
        expect("actorOperatorId" in entry).toBe(false);
      }

      // Stronicowanie po 1 elemencie przez identyczne znaczniki czasu (tiedTime) bez duplikatów i pominięć
      const collectedIds: string[] = [];
      let nextCursor: string | null = null;
      do {
        const url = nextCursor
          ? `/core/v1/audit-log?limit=1&cursor=${encodeURIComponent(nextCursor)}`
          : "/core/v1/audit-log?limit=1";
        const pageRes = await app.inject({
          method: "GET",
          url,
          headers: { authorization: `Bearer ${OWNER_ACC_ID}` },
        });
        expect(pageRes.statusCode).toBe(200);
        const body = pageRes.json() as { data: { id: string }[]; meta: { nextCursor: string | null } };
        collectedIds.push(...body.data.map((d) => d.id));
        nextCursor = body.meta.nextCursor;
      } while (nextCursor !== null);
      expect(collectedIds).toEqual(entries.map((e) => e.id));

      // Filtry
      const byActor = await app.inject({
        method: "GET",
        url: `/core/v1/audit-log?actorAccountId=${ADMIN_ACC_ID}`,
        headers: { authorization: `Bearer ${OWNER_ACC_ID}` },
      });
      expect(byActor.json().data.map((e: { id: string }) => e.id)).toEqual(["0193a5b2-7c3d-7e4f-8a1b-000000000005"]);

      const byActorType = await app.inject({
        method: "GET",
        url: "/core/v1/audit-log?actorType=PRODUCT",
        headers: { authorization: `Bearer ${OWNER_ACC_ID}` },
      });
      expect(byActorType.json().data.map((e: { id: string }) => e.id)).toEqual([
        "0193a5b2-7c3d-7e4f-8a1b-000000000003",
      ]);

      const byResource = await app.inject({
        method: "GET",
        url: "/core/v1/audit-log?resourceType=time_entry&resourceId=entry-42&action=timotime.entry.approved",
        headers: { authorization: `Bearer ${OWNER_ACC_ID}` },
      });
      expect(byResource.json().data.map((e: { id: string }) => e.id)).toEqual(["0193a5b2-7c3d-7e4f-8a1b-000000000003"]);

      // Zakres dat: from starsze niż 730 dni jest przycinane do 730 dni
      const clampedFrom = await app.inject({
        method: "GET",
        url: "/core/v1/audit-log?from=2020-01-01T00:00:00.000Z",
        headers: { authorization: `Bearer ${OWNER_ACC_ID}` },
      });
      expect(clampedFrom.json().data).toHaveLength(4);

      // Zakres dat zawężony do olderTime..olderTime
      const narrowRange = await app.inject({
        method: "GET",
        url: `/core/v1/audit-log?from=${encodeURIComponent(olderTime.toISOString())}&to=${encodeURIComponent(olderTime.toISOString())}`,
        headers: { authorization: `Bearer ${OWNER_ACC_ID}` },
      });
      expect(narrowRange.json().data.map((e: { id: string }) => e.id)).toEqual([
        "0193a5b2-7c3d-7e4f-8a1b-000000000003",
      ]);

      // Walidacje 422: from > to, limit > 100, zły kursor
      const badRange = await app.inject({
        method: "GET",
        url: "/core/v1/audit-log?from=2026-11-26T15:00:00.000Z&to=2026-11-26T14:00:00.000Z",
        headers: { authorization: `Bearer ${OWNER_ACC_ID}` },
      });
      expect(badRange.statusCode).toBe(422);
      expect(badRange.json().error.code).toBe("VALIDATION_FAILED");

      const badLimit = await app.inject({
        method: "GET",
        url: "/core/v1/audit-log?limit=101",
        headers: { authorization: `Bearer ${OWNER_ACC_ID}` },
      });
      expect(badLimit.statusCode).toBe(422);

      const badCursor = await app.inject({
        method: "GET",
        url: "/core/v1/audit-log?cursor=niepoprawny",
        headers: { authorization: `Bearer ${OWNER_ACC_ID}` },
      });
      expect(badCursor.statusCode).toBe(422);
      expect(badCursor.json().error.details).toEqual([
        { field: "cursor", message: "Nieprawidłowy kursor stronicowania" },
      ]);
    } finally {
      await app.close();
    }
  });
});
