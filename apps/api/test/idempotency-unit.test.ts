import { IDEMPOTENCY_KEY_HEADER, IDEMPOTENCY_KEY_TTL_MS, IDEMPOTENCY_REPLAYED_HEADER } from "@core/contracts";
import type { PrismaClient } from "@core/db";
import { describe, expect, it, vi } from "vitest";
import {
  accountPrincipal,
  canonicalJson,
  cleanupAllExpiredIdempotencyKeys,
  clientPrincipal,
  computeRequestHash,
  DEFAULT_IDEMPOTENCY_CLEANUP_INTERVAL_MS,
  executeWithIdempotency,
  extractIdempotencyKeyHeader,
  IdempotencyError,
  MAX_IDEMPOTENCY_CLEANUP_INTERVAL_MS,
  parseIdempotencyCleanupIntervalMs,
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

function deferred<T = void>() {
  let resolve!: (value: T | PromiseLike<T>) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

/**
 * Mock PrismaClient w pamięci z transakcyjną kolejką blokad `pg_advisory_xact_lock`,
 * pozwalający deterministycznie testować współbieżność, wycofanie i ścieżkę HTTP bez bazy.
 */
function createInMemoryIdempotencyDb(options?: { onUpsert?: () => void }) {
  const keys = new Map<string, StoredKeyRow>();
  const employees: { id: string; firstName: string; lastName: string }[] = [];
  const lockQueues = new Map<string, Promise<void>>();

  const compositeKey = (k: { organizationId: string; principal: string; key: string }) =>
    `${k.organizationId}|${k.principal}|${k.key}`;

  const acquireAdvisoryLock = async (lockName: string): Promise<() => void> => {
    const previous = lockQueues.get(lockName) ?? Promise.resolve();
    let release!: () => void;
    const next = new Promise<void>((resolve) => {
      release = resolve;
    });
    const tail = previous.then(() => next);
    lockQueues.set(lockName, tail);
    await previous;
    return () => {
      release();
      if (lockQueues.get(lockName) === tail) {
        lockQueues.delete(lockName);
      }
    };
  };

  const db = {
    $transaction: async <T>(fn: (tx: unknown) => Promise<T>): Promise<T> => {
      const releaseLocks: (() => void)[] = [];
      const stagedDeletes = new Set<string>();
      const stagedUpserts = new Map<string, StoredKeyRow>();
      const stagedEmployees: { id: string; firstName: string; lastName: string }[] = [];

      const tx = {
        $executeRaw: async (strings: TemplateStringsArray, ...values: unknown[]) => {
          const sql = strings.join(" ");
          if (sql.includes("pg_advisory_xact_lock")) {
            const lockName = String(values[0] ?? "");
            releaseLocks.push(await acquireAdvisoryLock(lockName));
          }
          return 1;
        },
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
          }) => {
            const mapKey = compositeKey(where.organizationId_principal_key);
            if (stagedUpserts.has(mapKey)) return stagedUpserts.get(mapKey) ?? null;
            if (stagedDeletes.has(mapKey)) return null;
            // Odczyt pod READ COMMITTED: zawsze widzi aktualny zatwierdzony stan po zwolnieniu blokady.
            return keys.get(mapKey) ?? null;
          },
          upsert: async ({
            where,
            create,
            update,
          }: {
            where: { organizationId_principal_key: { organizationId: string; principal: string; key: string } };
            create: StoredKeyRow;
            update: Omit<StoredKeyRow, "id" | "organizationId" | "principal" | "key">;
          }) => {
            options?.onUpsert?.();
            const mapKey = compositeKey(where.organizationId_principal_key);
            const prev = stagedUpserts.get(mapKey) ?? keys.get(mapKey);
            const next: StoredKeyRow = prev ? { ...prev, ...update } : create;
            stagedUpserts.set(mapKey, next);
            return next;
          },
        },
      };

      try {
        const result = await fn(tx);
        for (const [k, v] of stagedUpserts) keys.set(k, v);
        employees.push(...stagedEmployees);
        return result;
      } finally {
        for (const release of releaseLocks) release();
      }
    },
  } as unknown as PrismaClient;

  return { db, keys, employees };
}

describe("Idempotency-Key — testy jednostkowe bez bazy", () => {
  it("formatuje przestrzeń nazw principal oraz waliduje CORE_IDEMPOTENCY_CLEANUP_INTERVAL_MS", () => {
    expect(accountPrincipal(ACC_ID)).toBe(`account:${ACC_ID}`);
    expect(clientPrincipal("timotime-web")).toBe("client:timotime-web");

    expect(parseIdempotencyCleanupIntervalMs(undefined)).toBe(DEFAULT_IDEMPOTENCY_CLEANUP_INTERVAL_MS);
    expect(parseIdempotencyCleanupIntervalMs("0")).toBe(0);
    expect(parseIdempotencyCleanupIntervalMs(" 60000 ")).toBe(60_000);
    expect(parseIdempotencyCleanupIntervalMs(String(MAX_IDEMPOTENCY_CLEANUP_INTERVAL_MS))).toBe(
      MAX_IDEMPOTENCY_CLEANUP_INTERVAL_MS,
    );

    for (const bad of ["", "   ", "-1", "1.5", "01", "abc", "NaN", "Infinity", "2147483648", "99999999999999999"]) {
      expect(() => parseIdempotencyCleanupIntervalMs(bad), `Wartość: ${JSON.stringify(bad)}`).toThrow(
        /CORE_IDEMPOTENCY_CLEANUP_INTERVAL_MS/,
      );
    }
  });

  it("odczytuje nagłówek z headersDistinct (rozpakowuje 1 element, zachowuje duplikaty) z fallbackiem do headers", () => {
    expect(
      extractIdempotencyKeyHeader({
        headers: { "idempotency-key": "k1, k2" },
        raw: { headersDistinct: { "idempotency-key": ["k1", "k2"] } },
      }),
    ).toEqual(["k1", "k2"]);

    expect(
      extractIdempotencyKeyHeader({
        headers: { "idempotency-key": "k1" },
        raw: { headersDistinct: { "idempotency-key": ["k1"] } },
      }),
    ).toBe("k1");

    expect(
      extractIdempotencyKeyHeader({
        headers: {},
        raw: { headersDistinct: { "idempotency-key": [] } },
      }),
    ).toBeUndefined();

    expect(extractIdempotencyKeyHeader({ headers: { "idempotency-key": "fallback-key" } })).toBe("fallback-key");
  });

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

  it("wycofuje zapis klucza przy błędzie w run, zapisuje klucz przy sukcesie i nie wywołuje run przy powtórce", async () => {
    const events: string[] = [];
    const { db, keys } = createInMemoryIdempotencyDb({ onUpsert: () => events.push("upsert") });
    const now = new Date("2026-11-25T12:00:00.000Z");

    // 1. Błąd w run wycofuje całą transakcję -> brak zapisanego klucza
    await expect(
      executeWithIdempotency({
        db,
        organizationId: ORG_ID,
        principal: accountPrincipal(ACC_ID),
        key: "run-rollback",
        method: "POST",
        pathTemplate: "/core/v1/invitations",
        body: { email: "jan@acme.test" },
        getNow: () => now,
        run: async () => {
          events.push("run-fail");
          throw new Error("błąd zapisu w transakcji");
        },
      }),
    ).rejects.toThrow("błąd zapisu w transakcji");
    expect(events).toEqual(["run-fail"]);
    expect(keys.size).toBe(0);

    // 2. Ponowienie z tym samym kluczem uruchamia run i zapisuje klucz
    events.length = 0;
    const ok = await executeWithIdempotency({
      db,
      organizationId: ORG_ID,
      principal: accountPrincipal(ACC_ID),
      key: "run-rollback",
      method: "POST",
      pathTemplate: "/core/v1/invitations",
      body: { email: "jan@acme.test" },
      getNow: () => now,
      run: async () => {
        events.push("run-ok");
        return { status: 201, body: { data: { id: "inv-2" } } };
      },
    });
    expect(ok).toEqual({ replayed: false, status: 201, body: { data: { id: "inv-2" } } });
    expect(events).toEqual(["run-ok", "upsert"]);

    // 3. Powtórka zwraca zapisany wynik i nie wywołuje run
    events.length = 0;
    const replay = await executeWithIdempotency({
      db,
      organizationId: ORG_ID,
      principal: accountPrincipal(ACC_ID),
      key: "run-rollback",
      method: "POST",
      pathTemplate: "/core/v1/invitations",
      body: { email: "jan@acme.test" },
      getNow: () => now,
      run: async () => {
        events.push("should-not-run");
        return { status: 201, body: { data: { id: "inv-3" } } };
      },
    });
    expect(replay).toEqual({ replayed: true, status: 201, body: { data: { id: "inv-2" } } });
    expect(events).toEqual([]);
  });

  it("deterministyczna współbieżność z barierą: commit-while-waiting (handler raz) i rollback-while-waiting (drugi przejmuje)", async () => {
    const { db } = createInMemoryIdempotencyDb();
    let currentNow = new Date("2026-11-25T12:00:00.000Z");

    // 1. Commit-while-waiting: drugie żądanie czeka na blokadzie, pierwsze zatwierdza -> drugie dostaje powtórkę
    const enteredCommit = deferred();
    const releaseCommit = deferred();
    let commitRunCount = 0;

    const firstCommit = executeWithIdempotency({
      db,
      organizationId: ORG_ID,
      principal: accountPrincipal(ACC_ID),
      key: "barrier-commit",
      method: "POST",
      pathTemplate: "/core/v1/employees",
      body: { firstName: "Anna" },
      getNow: () => currentNow,
      run: async () => {
        commitRunCount += 1;
        enteredCommit.resolve();
        await releaseCommit.promise;
        return { status: 201, body: { data: { id: "emp-committed" } } };
      },
    });

    await enteredCommit.promise;
    // Przesuwamy zegar przed zwolnieniem blokady, żeby sprawdzić, że drugie żądanie pobiera czas po przejęciu blokady
    const secondCommit = executeWithIdempotency({
      db,
      organizationId: ORG_ID,
      principal: accountPrincipal(ACC_ID),
      key: "barrier-commit",
      method: "POST",
      pathTemplate: "/core/v1/employees",
      body: { firstName: "Anna" },
      getNow: () => currentNow,
      run: async () => {
        commitRunCount += 1;
        return { status: 201, body: { data: { id: "emp-should-not-run" } } };
      },
    });

    currentNow = new Date(currentNow.getTime() + 1000);
    releaseCommit.resolve();

    const [c1, c2] = await Promise.all([firstCommit, secondCommit]);
    expect(commitRunCount).toBe(1);
    expect(c1).toEqual({ replayed: false, status: 201, body: { data: { id: "emp-committed" } } });
    expect(c2).toEqual({ replayed: true, status: 201, body: { data: { id: "emp-committed" } } });

    // 2. Rollback-while-waiting: pierwsze rzuca błąd i wycofuje -> czekające drugie uruchamia handler i kończy się sukcesem
    const enteredRollback = deferred();
    const releaseRollback = deferred();
    let rollbackRunCount = 0;

    const firstRollback = executeWithIdempotency({
      db,
      organizationId: ORG_ID,
      principal: accountPrincipal(ACC_ID),
      key: "barrier-rollback",
      method: "POST",
      pathTemplate: "/core/v1/employees",
      body: { firstName: "Jan" },
      getNow: () => currentNow,
      run: async () => {
        rollbackRunCount += 1;
        enteredRollback.resolve();
        await releaseRollback.promise;
        throw new Error("błąd w pierwszej transakcji");
      },
    });

    await enteredRollback.promise;
    const secondRollback = executeWithIdempotency({
      db,
      organizationId: ORG_ID,
      principal: accountPrincipal(ACC_ID),
      key: "barrier-rollback",
      method: "POST",
      pathTemplate: "/core/v1/employees",
      body: { firstName: "Jan" },
      getNow: () => currentNow,
      run: async () => {
        rollbackRunCount += 1;
        return { status: 201, body: { data: { id: "emp-after-rollback" } } };
      },
    });

    releaseRollback.resolve();

    await expect(firstRollback).rejects.toThrow("błąd w pierwszej transakcji");
    const r2 = await secondRollback;
    expect(rollbackRunCount).toBe(2);
    expect(r2).toEqual({ replayed: false, status: 201, body: { data: { id: "emp-after-rollback" } } });
  });

  it("obsługuje pełny cykl HTTP (400 przy błędnym lub powtórzonym nagłówku, 201, powtórka, 409, wygasanie, brak zapisu błędu)", async () => {
    const { db, keys, employees } = createInMemoryIdempotencyDb();
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

      // Dwa nagłówki Idempotency-Key w jednym żądaniu HTTP -> 400 VALIDATION_FAILED
      const duplicateHeaderRes = await app.inject({
        method: "POST",
        url: "/core/v1/employees",
        headers: { authorization: "Bearer stub", [IDEMPOTENCY_KEY_HEADER]: ["dup-1", "dup-2"] },
        payload: { firstName: "Jan", lastName: "Nowak" },
      });
      expect(duplicateHeaderRes.statusCode).toBe(400);
      expect(duplicateHeaderRes.json()).toMatchObject({
        data: null,
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
      // Principal zapisany z prefiksem account:
      expect([...keys.values()][0]?.principal).toBe(`account:${ACC_ID}`);

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

  it("okresowe sprzątanie wygasłych kluczy działa w pętli, przeżywa błędy, przerywa między porcjami i czeka na bieżący przebieg", async () => {
    vi.useFakeTimers();
    try {
      let calls = 0;
      const errors: unknown[] = [];
      const inFlightStarted = deferred();
      const releaseInFlight = deferred();
      let inFlightFinished = false;

      const stop = startIdempotencyCleanup({
        db: {} as PrismaClient,
        intervalMs: 1000,
        cleanup: async () => {
          calls += 1;
          if (calls === 1) throw new Error("chwilowy brak bazy");
          inFlightStarted.resolve();
          await releaseInFlight.promise;
          inFlightFinished = true;
          return 3;
        },
        onError: (err) => errors.push(err),
      });

      await vi.advanceTimersByTimeAsync(0);
      expect(calls).toBe(1);
      expect(errors).toHaveLength(1);

      await vi.advanceTimersByTimeAsync(1000);
      await inFlightStarted.promise;
      expect(calls).toBe(2);

      // stop() czeka na zakończenie trwającego przebiegu
      let stopResolved = false;
      const stopPromise = stop().then(() => {
        stopResolved = true;
      });
      await Promise.resolve();
      expect(stopResolved).toBe(false);

      releaseInFlight.resolve();
      await stopPromise;
      expect(inFlightFinished).toBe(true);
      expect(stopResolved).toBe(true);

      await vi.advanceTimersByTimeAsync(5000);
      expect(calls).toBe(2);
    } finally {
      vi.useRealTimers();
    }

    // cleanupAllExpiredIdempotencyKeys przerywa między porcjami, gdy shouldStop() zwróci true
    let batch = 0;
    let shouldStop = false;
    const fakeDb = {
      $queryRaw: async () => {
        batch += 1;
        if (batch === 1) shouldStop = true;
        return [{ deleted: 2 }];
      },
    } as unknown as PrismaClient;
    expect(await cleanupAllExpiredIdempotencyKeys(fakeDb, 2, () => shouldStop)).toBe(2);
    expect(batch).toBe(1);
  });
});
