import { IDEMPOTENCY_KEY_HEADER, IDEMPOTENCY_KEY_TTL_MS, IDEMPOTENCY_REPLAYED_HEADER } from "@core/contracts";
import type { PrismaClient } from "@core/db";
import { describe, expect, it, vi } from "vitest";
import {
  canonicalJson,
  cleanupAllExpiredIdempotencyKeys,
  computeRequestHash,
  IdempotencyError,
  parseIdempotencyKeyHeader,
  startIdempotencyCleanup,
} from "../src/idempotency.js";
import { buildServer } from "../src/server.js";

const ORG_ID = "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6a71";
const EMP_ID = "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6a72";
const ACC_ID = "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6a73";

interface StoredKeyRow {
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

/** Minimalny mock PrismaClient w pamięci do testów mechanizmu HTTP bez połączenia z bazą. */
function createInMemoryIdempotencyDb() {
  const keys = new Map<string, StoredKeyRow>();
  const employees: { id: string; firstName: string; lastName: string }[] = [];

  const compositeKey = (k: { organizationId: string; principal: string; key: string }) =>
    `${k.organizationId}|${k.principal}|${k.key}`;

  const db = {
    $transaction: async <T>(fn: (tx: unknown) => Promise<T>): Promise<T> => {
      const stagedKeys = new Map(keys);
      const stagedEmployees = [...employees];

      const tx = {
        $executeRaw: async () => 1,
        account: {
          findUnique: async () => ({
            status: "ACTIVE",
            employeeId: EMP_ID,
            authzRevision: 0,
            organization: { ownerAccountId: ACC_ID },
          }),
        },
        organizationUnit: {
          findMany: async () => [],
        },
        roleAssignment: {
          findMany: async () => [],
        },
        employee: {
          create: async ({ data }: { data: { id: string; firstName: string; lastName: string } }) => {
            const row = {
              id: data.id,
              firstName: data.firstName,
              lastName: data.lastName,
              workEmail: null,
              jobTitle: null,
              status: "ACTIVE" as const,
            };
            stagedEmployees.push({ id: row.id, firstName: row.firstName, lastName: row.lastName });
            return row;
          },
        },
        auditLog: {
          create: async () => ({}),
        },
        idempotencyKey: {
          findUnique: async ({
            where,
          }: {
            where: { organizationId_principal_key: { organizationId: string; principal: string; key: string } };
          }) => stagedKeys.get(compositeKey(where.organizationId_principal_key)) ?? null,
          upsert: async ({
            where,
            create,
            update,
          }: {
            where: { organizationId_principal_key: { organizationId: string; principal: string; key: string } };
            create: StoredKeyRow;
            update: Omit<StoredKeyRow, "id" | "organizationId" | "principal" | "key">;
          }) => {
            const mapKey = compositeKey(where.organizationId_principal_key);
            const prev = stagedKeys.get(mapKey);
            const next: StoredKeyRow = prev ? { ...prev, ...update } : create;
            stagedKeys.set(mapKey, next);
            return next;
          },
        },
      };

      const result = await fn(tx);
      keys.clear();
      for (const [k, v] of stagedKeys) keys.set(k, v);
      employees.length = 0;
      employees.push(...stagedEmployees);
      return result;
    },
  } as unknown as PrismaClient;

  return { db, keys, employees };
}

describe("Idempotency-Key — testy jednostkowe bez bazy", () => {
  it("waliduje nagłówek Idempotency-Key (brak -> null, poprawne -> wartość, błędne -> 400 VALIDATION_FAILED)", () => {
    expect(parseIdempotencyKeyHeader(undefined)).toBeNull();
    expect(parseIdempotencyKeyHeader("a")).toBe("a");
    expect(parseIdempotencyKeyHeader("0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6a7b")).toBe(
      "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6a7b",
    );
    expect(parseIdempotencyKeyHeader("req_1:retry/2+ok=")).toBe("req_1:retry/2+ok=");
    expect(parseIdempotencyKeyHeader("key with space")).toBe("key with space");
    expect(parseIdempotencyKeyHeader("k".repeat(255))).toBe("k".repeat(255));

    const invalidInputs: (string | string[])[] = [
      "",
      "   ",
      " leading",
      "trailing ",
      "k".repeat(256),
      "bad\tkey",
      "bad\nkey",
      "bad\rkey",
      "bad\x00key",
      "bad\x1fkey",
      "bad\x7fkey",
      "klucz-ą",
      "klucz-🔑",
      ["key-1", "key-2"],
    ];

    for (const input of invalidInputs) {
      let caught: unknown;
      try {
        parseIdempotencyKeyHeader(input);
      } catch (error) {
        caught = error;
      }
      expect(caught, `Oczekiwano błędu dla: ${JSON.stringify(input)}`).toBeInstanceOf(IdempotencyError);
      expect(caught).toMatchObject({
        status: 400,
        code: "VALIDATION_FAILED",
        details: [{ field: IDEMPOTENCY_KEY_HEADER }],
      });
    }
  });

  it("serializuje JSON kanonicznie z sortowaniem kluczy i liczy deterministyczny skrót SHA-256", () => {
    expect(canonicalJson(undefined)).toBe("");
    expect(canonicalJson(null)).toBe("null");
    expect(canonicalJson({})).toBe("{}");
    expect(canonicalJson([])).toBe("[]");
    expect(canonicalJson({ b: 1, a: 2 })).toBe('{"a":2,"b":1}');
    expect(canonicalJson({ b: { z: true, a: [2, { y: 1, x: 0 }, undefined] }, a: undefined })).toBe(
      '{"b":{"a":[2,{"x":0,"y":1},null],"z":true}}',
    );
    expect(canonicalJson([2, 1])).not.toBe(canonicalJson([1, 2]));

    const h1 = computeRequestHash("POST", "/core/v1/employees", { lastName: "Nowak", firstName: "Anna" });
    const h2 = computeRequestHash("post", "/core/v1/employees", { firstName: "Anna", lastName: "Nowak" }, {});
    expect(h1).toBe(h2);
    expect(h1).toMatch(/^[0-9a-f]{64}$/);

    // Zmiana ścieżki, metody, parametrów ścieżki albo treści daje inny skrót
    expect(h1).not.toBe(computeRequestHash("POST", "/core/v1/units", { firstName: "Anna", lastName: "Nowak" }));
    expect(h1).not.toBe(computeRequestHash("PUT", "/core/v1/employees", { firstName: "Anna", lastName: "Nowak" }));
    expect(h1).not.toBe(computeRequestHash("POST", "/core/v1/employees", { firstName: "Jan", lastName: "Nowak" }));

    const r1 = computeRequestHash("POST", "/core/v1/invitations/{invitationId}/resend", undefined, {
      invitationId: "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6a71",
    });
    const r2 = computeRequestHash("POST", "/core/v1/invitations/{invitationId}/resend", undefined, {
      invitationId: "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6a72",
    });
    expect(r1).not.toBe(r2);
  });

  it("obsługuje pełny cykl HTTP (400, 201, powtórka z Idempotency-Replayed, 409, wygasanie i brak zapisu błędu)", async () => {
    const { db, employees } = createInMemoryIdempotencyDb();
    let currentNow = new Date("2026-11-25T12:00:00.000Z");

    const app = buildServer({
      db,
      verifyToken: async () => ({
        iss: "http://localhost:3100",
        sub: ACC_ID,
        aud: "http://localhost:3200",
        org_id: ORG_ID,
        employee_id: EMP_ID,
        amr: ["pwd"],
        authz_rev: 0,
        iat: 1,
        exp: 9_999_999_999,
      }),
      verifyMachineToken: async () => {
        throw new Error("Nieoczekiwany token maszynowy");
      },
      now: () => currentNow,
    });

    try {
      // Nieprawidłowy nagłówek -> 400 VALIDATION_FAILED w kopercie błędu
      const invalidRes = await app.inject({
        method: "POST",
        url: "/core/v1/employees",
        headers: { authorization: "Bearer stub", [IDEMPOTENCY_KEY_HEADER]: "" },
        payload: { firstName: "Jan", lastName: "Nowak" },
      });
      expect(invalidRes.statusCode).toBe(400);
      expect(invalidRes.json()).toMatchObject({
        data: null,
        meta: { requestId: expect.any(String) },
        error: { code: "VALIDATION_FAILED", details: [{ field: IDEMPOTENCY_KEY_HEADER }] },
      });
      expect(employees).toHaveLength(0);

      // Błąd 422 nie zapisuje klucza -> ponowienie z tym samym kluczem i poprawną treścią udaje się
      const badBodyRes = await app.inject({
        method: "POST",
        url: "/core/v1/employees",
        headers: { authorization: "Bearer stub", [IDEMPOTENCY_KEY_HEADER]: "retry-after-422" },
        payload: { firstName: "   ", lastName: "Nowak" },
      });
      expect(badBodyRes.statusCode).toBe(422);
      expect(employees).toHaveLength(0);

      const firstOk = await app.inject({
        method: "POST",
        url: "/core/v1/employees",
        headers: { authorization: "Bearer stub", [IDEMPOTENCY_KEY_HEADER]: "retry-after-422" },
        payload: { firstName: "Jan", lastName: "Nowak" },
      });
      expect(firstOk.statusCode).toBe(201);
      expect(firstOk.headers[IDEMPOTENCY_REPLAYED_HEADER.toLowerCase()]).toBeUndefined();
      expect(employees).toHaveLength(1);

      // Powtórzenie z tym samym kluczem i inną kolejnością pól JSON -> ta sama odpowiedź + Idempotency-Replayed: true
      const replayed = await app.inject({
        method: "POST",
        url: "/core/v1/employees",
        headers: { authorization: "Bearer stub", [IDEMPOTENCY_KEY_HEADER]: "retry-after-422" },
        payload: { lastName: "Nowak", firstName: "Jan" },
      });
      expect(replayed.statusCode).toBe(201);
      expect(replayed.headers[IDEMPOTENCY_REPLAYED_HEADER.toLowerCase()]).toBe("true");
      expect(replayed.json()).toEqual(firstOk.json());
      expect(employees).toHaveLength(1);

      // Ten sam klucz z inną treścią -> 409 CONFLICT
      const conflict = await app.inject({
        method: "POST",
        url: "/core/v1/employees",
        headers: { authorization: "Bearer stub", [IDEMPOTENCY_KEY_HEADER]: "retry-after-422" },
        payload: { firstName: "Ewa", lastName: "Kowalska" },
      });
      expect(conflict.statusCode).toBe(409);
      expect(conflict.json()).toMatchObject({
        data: null,
        error: { code: "CONFLICT" },
      });
      expect(employees).toHaveLength(1);

      // Po wygaśnięciu (24h) klucz może zostać użyty ponownie z nową treścią
      currentNow = new Date(currentNow.getTime() + IDEMPOTENCY_KEY_TTL_MS);
      const afterExpiry = await app.inject({
        method: "POST",
        url: "/core/v1/employees",
        headers: { authorization: "Bearer stub", [IDEMPOTENCY_KEY_HEADER]: "retry-after-422" },
        payload: { firstName: "Ewa", lastName: "Kowalska" },
      });
      expect(afterExpiry.statusCode).toBe(201);
      expect(afterExpiry.headers[IDEMPOTENCY_REPLAYED_HEADER.toLowerCase()]).toBeUndefined();
      expect(afterExpiry.json().data.id).not.toBe(firstOk.json().data.id);
      expect(employees).toHaveLength(2);
    } finally {
      await app.close();
    }
  });

  it("okresowe sprzątanie wygasłych kluczy działa w pętli, przeżywa błędy i zatrzymuje się na żądanie", async () => {
    vi.useFakeTimers();
    try {
      let calls = 0;
      const errors: unknown[] = [];
      const stop = startIdempotencyCleanup({
        db: {} as PrismaClient,
        intervalMs: 1000,
        cleanup: async () => {
          calls += 1;
          if (calls === 1) throw new Error("chwilowy brak bazy");
          return 3;
        },
        onError: (err) => errors.push(err),
      });

      await vi.advanceTimersByTimeAsync(0);
      expect(calls).toBe(1);
      expect(errors).toHaveLength(1);

      await vi.advanceTimersByTimeAsync(1000);
      expect(calls).toBe(2);

      stop();
      await vi.advanceTimersByTimeAsync(5000);
      expect(calls).toBe(2);
    } finally {
      vi.useRealTimers();
    }

    // cleanupAllExpiredIdempotencyKeys pobiera kolejne porcje aż do niepełnej
    let batch = 0;
    const fakeDb = {
      $queryRaw: async () => {
        batch += 1;
        return [{ deleted: batch === 1 ? 2 : 1 }];
      },
    } as unknown as PrismaClient;
    expect(await cleanupAllExpiredIdempotencyKeys(fakeDb, 2)).toBe(3);
    expect(batch).toBe(2);
  });
});
