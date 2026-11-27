import { IDEMPOTENCY_KEY_HEADER, IDEMPOTENCY_REPLAYED_HEADER } from "@core/contracts";
import type { PrismaClient } from "@core/db";
import { describe, expect, it, vi } from "vitest";
import { MAIL_SEND_DEADLINE_MS, sendMailWithDeadline, SMTP_TIMEOUTS } from "../src/mail.js";
import {
  cleanupOldMailJobs,
  computeMailBackoffMs,
  DEFAULT_MAIL_OUTBOX_INTERVAL_MS,
  deliverPendingMail,
  formatMailError,
  MAIL_BACKOFF_BASE_MS,
  MAIL_BACKOFF_MAX_MS,
  MAIL_CLEANUP_MIN_INTERVAL_MS,
  MAIL_LAST_ERROR_MAX_LENGTH,
  MAIL_LEASE_MS,
  MAIL_MAX_BATCHES_PER_TICK,
  MAX_MAIL_OUTBOX_INTERVAL_MS,
  parseMailOutboxIntervalMs,
  startMailOutboxWorker,
  type DeliverPendingMailSummary,
} from "../src/mail-outbox.js";
import { buildServer } from "../src/server.js";

const ORG_ID = "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6a71";
const EMP_ID = "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6a72";
const ACC_ID = "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6a73";
const INV_ID = "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6a74";

function deferred<T = void>() {
  let resolve!: (value: T | PromiseLike<T>) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

function emptySummary(claimed = 0, overrides: Partial<DeliverPendingMailSummary> = {}): DeliverPendingMailSummary {
  return { claimed, sent: claimed, retried: 0, failed: 0, cancelled: 0, skipped: 0, ...overrides };
}

describe("Kolejka poczty mail_outbox — testy jednostkowe bez bazy", () => {
  it("wylicza wykładniczy backoff 30 s × 2^(attempts-1) z limitem 1 godziny", () => {
    expect(computeMailBackoffMs(1)).toBe(30_000);
    expect(computeMailBackoffMs(2)).toBe(60_000);
    expect(computeMailBackoffMs(3)).toBe(120_000);
    expect(computeMailBackoffMs(4)).toBe(240_000);
    expect(computeMailBackoffMs(5)).toBe(480_000);
    expect(computeMailBackoffMs(6)).toBe(960_000);
    expect(computeMailBackoffMs(7)).toBe(1_920_000);
    expect(computeMailBackoffMs(8)).toBe(MAIL_BACKOFF_MAX_MS);
    expect(computeMailBackoffMs(9)).toBe(MAIL_BACKOFF_MAX_MS);

    // Wartości brzegowe i bardzo duże próby nie zwracają NaN ani Infinity
    expect(computeMailBackoffMs(0)).toBe(MAIL_BACKOFF_BASE_MS);
    expect(computeMailBackoffMs(-5)).toBe(MAIL_BACKOFF_BASE_MS);
    expect(computeMailBackoffMs(10_000)).toBe(MAIL_BACKOFF_MAX_MS);
  });

  it("waliduje CORE_MAIL_OUTBOX_INTERVAL_MS (domyślnie 1000 ms, 0 wyłącza, błędne wartości przerywają start)", () => {
    expect(parseMailOutboxIntervalMs(undefined)).toBe(DEFAULT_MAIL_OUTBOX_INTERVAL_MS);
    expect(parseMailOutboxIntervalMs("0")).toBe(0);
    expect(parseMailOutboxIntervalMs(" 2500 ")).toBe(2500);
    expect(parseMailOutboxIntervalMs(String(MAX_MAIL_OUTBOX_INTERVAL_MS))).toBe(MAX_MAIL_OUTBOX_INTERVAL_MS);

    for (const bad of ["", "   ", "-1", "1.5", "01", "abc", "NaN", "Infinity", "2147483648", "99999999999999999"]) {
      expect(() => parseMailOutboxIntervalMs(bad), `Wartość: ${JSON.stringify(bad)}`).toThrow(
        /CORE_MAIL_OUTBOX_INTERVAL_MS/,
      );
    }
  });

  it("cenzuruje dane uwierzytelniające w URL i parametry token= przed przycięciem lastError do 500 znaków", () => {
    expect(formatMailError(new Error("  451 Temporary failure \0  "))).toBe("451 Temporary failure");
    expect(formatMailError("timeout")).toBe("timeout");
    expect(formatMailError(new Error(""))).toBe("Error");
    expect(formatMailError("   ")).toBe("Nieznany błąd wysyłki poczty");

    // Redakcja userinfo (://user:pass@), token= oraz ścieżki wypisania z powiadomień bez ruszania zwykłego adresu e-mail
    const withSecrets = formatMailError(
      new Error(
        "Nie udało się wysłać do anna@acme.com przez smtps://mailer:s3cr3t!@smtp.acme.com:465 " +
          "(link https://auth.monorise.studio/invite?token=raw_secret_123&lang=pl, TOKEN=InnySekret, " +
          "unsub <https://api.monorise.studio/core/v1/notifications/unsubscribe/eyJwb3IifQ.sig_secret_987>)",
      ),
    );
    expect(withSecrets).toContain("anna@acme.com");
    expect(withSecrets).toContain("smtps://[redacted]@smtp.acme.com:465");
    expect(withSecrets).toContain("https://auth.monorise.studio/invite?token=[redacted]&lang=pl");
    expect(withSecrets).toContain("TOKEN=[redacted]");
    expect(withSecrets).toContain("https://api.monorise.studio/core/v1/notifications/unsubscribe/[redacted]");
    expect(withSecrets).not.toContain("s3cr3t");
    expect(withSecrets).not.toContain("raw_secret_123");
    expect(withSecrets).not.toContain("InnySekret");
    expect(withSecrets).not.toContain("eyJwb3IifQ");
    expect(withSecrets).not.toContain("sig_secret_987");

    // Redakcja działa PRZED przycięciem, więc sekret na granicy 500 znaków nie może przeciec
    const secretAtBoundary = `${"e".repeat(485)}://u:tajnehaslo@h?token=sekretnytoken123456`;
    const formattedBoundary = formatMailError(secretAtBoundary);
    expect(formattedBoundary.length).toBeLessThanOrEqual(MAIL_LAST_ERROR_MAX_LENGTH);
    expect(formattedBoundary).not.toContain("tajnehaslo");
    expect(formattedBoundary).not.toContain("sekretnytoken");

    const unsubAtBoundary = `${"e".repeat(460)}/core/v1/notifications/unsubscribe/tajny_token_wypisania.podpis123`;
    const formattedUnsubBoundary = formatMailError(unsubAtBoundary);
    expect(formattedUnsubBoundary.length).toBeLessThanOrEqual(MAIL_LAST_ERROR_MAX_LENGTH);
    expect(formattedUnsubBoundary).not.toContain("tajny_token_wypisania");
    expect(formattedUnsubBoundary).not.toContain("podpis123");

    const longAscii = "E".repeat(MAIL_LAST_ERROR_MAX_LENGTH + 250);
    const truncatedAscii = formatMailError(new Error(longAscii));
    expect(truncatedAscii).toHaveLength(MAIL_LAST_ERROR_MAX_LENGTH);

    // Znak spoza BMP (para surogatów UTF-16) dokładnie na granicy 500 punktów kodowych
    const withSurrogateAtBoundary = `${"a".repeat(499)}🚀tail`;
    const truncatedUnicode = formatMailError(withSurrogateAtBoundary);
    expect(Array.from(truncatedUnicode)).toHaveLength(MAIL_LAST_ERROR_MAX_LENGTH);
    expect(truncatedUnicode.endsWith("🚀")).toBe(true);
  });

  it("deliverPendingMail wywołuje funkcję zegara now osobno dla każdego zadania i liczy skipped", async () => {
    const job1 = {
      id: "job-1",
      organizationId: ORG_ID,
      kind: "INVITATION" as const,
      invitationId: INV_ID,
      notificationId: null,
      attempts: 1,
    };
    const job2 = {
      id: "job-2",
      organizationId: ORG_ID,
      kind: "INVITATION" as const,
      invitationId: INV_ID,
      notificationId: null,
      attempts: 1,
    };
    const observedNowMs: number[] = [];
    let tickMs = Date.parse("2026-11-26T10:00:00.000Z");

    const fakeDb = {
      $queryRaw: async () => [job1, job2],
      $transaction: async <T>(fn: (tx: unknown) => Promise<T>): Promise<T> => {
        const tx = {
          $executeRaw: async (strings: TemplateStringsArray, ...values: unknown[]) => {
            if (strings.join(" ").includes("UPDATE")) {
              const dateArg = values.find((value): value is Date => value instanceof Date);
              if (dateArg) observedNowMs.push(dateArg.getTime());
            }
            return 1;
          },
          mailOutbox: {
            findUnique: async ({ where }: { where: { id: string } }) =>
              // job-2 ma już wyższy numer próby -> powinien zostać pominięty (SKIPPED)
              where.id === "job-2" ? { status: "PENDING", attempts: 2 } : { status: "PENDING", attempts: 1 },
          },
          invitation: {
            findUnique: async () => ({
              id: INV_ID,
              email: "jan@acme.test",
              status: "PENDING",
              expiresAt: new Date("2026-12-03T10:00:00.000Z"),
              invitedByAccountId: null,
              account: { status: "INVITED" },
              organization: { name: "Acme" },
            }),
            update: async () => ({}),
          },
        };
        return fn(tx);
      },
    } as unknown as PrismaClient;

    const nowCalls: number[] = [];
    const summary = await deliverPendingMail(fakeDb, {
      mailer: async () => undefined,
      now: () => {
        tickMs += 1_000;
        nowCalls.push(tickMs);
        return new Date(tickMs);
      },
    });

    expect(summary).toEqual({ claimed: 2, sent: 1, retried: 0, failed: 0, cancelled: 0, skipped: 1 });
    // Funkcja zegara wywołana osobno dla job-1 i job-2 (nie raz na całą porcję)
    expect(nowCalls).toHaveLength(2);
    expect(nowCalls[1]).toBe(nowCalls[0]! + 1_000);
    expect(observedNowMs.every((ts) => ts === nowCalls[0])).toBe(true);
  });

  it("cleanupOldMailJobs usuwa porcjami aż do niepełnej porcji i przerywa przy shouldStop()", async () => {
    let calls = 0;
    const fakeDb = {
      $queryRaw: async () => {
        calls += 1;
        return [{ deleted: calls < 3 ? 2 : 1 }];
      },
    } as unknown as PrismaClient;
    expect(await cleanupOldMailJobs(fakeDb, 2)).toBe(5);
    expect(calls).toBe(3);

    let stopCalls = 0;
    let shouldStop = false;
    const stoppableDb = {
      $queryRaw: async () => {
        stopCalls += 1;
        if (stopCalls === 1) shouldStop = true;
        return [{ deleted: 2 }];
      },
    } as unknown as PrismaClient;
    expect(await cleanupOldMailJobs(stoppableDb, 2, () => shouldStop)).toBe(2);
    expect(stopCalls).toBe(1);
  });

  it("worker opróżnia porcje z postępem, obsługuje wake() także w trakcie przebiegu, sprząta raz na godzinę i kończy się czysto", async () => {
    vi.useFakeTimers();
    try {
      let currentNow = new Date("2026-11-26T10:00:00.000Z");
      let deliverCalls = 0;
      let cleanupCalls = 0;
      const errors: unknown[] = [];

      const inFlightStarted = deferred();
      const releaseInFlight = deferred();
      let blockNextDeliver = false;

      const worker = startMailOutboxWorker({
        db: {} as PrismaClient,
        intervalMs: 10_000,
        batchSize: 2,
        now: () => currentNow,
        onError: (err) => errors.push(err),
        deliver: async () => {
          deliverCalls += 1;
          if (deliverCalls === 1) {
            return emptySummary(2);
          }
          if (deliverCalls === 2) {
            return emptySummary(0);
          }
          if (deliverCalls === 3) {
            throw new Error("chwilowy błąd bazy");
          }
          if (blockNextDeliver) {
            blockNextDeliver = false;
            inFlightStarted.resolve();
            await releaseInFlight.promise;
            return emptySummary(0);
          }
          return emptySummary(0);
        },
        cleanup: async () => {
          cleanupCalls += 1;
          return 1;
        },
      });

      // Przebieg początkowy (t = 0): 2 wywołania deliver (drenaż pełnej porcji) + 1 cleanup
      await vi.advanceTimersByTimeAsync(0);
      expect(deliverCalls).toBe(2);
      expect(cleanupCalls).toBe(1);

      // wake() wybudza natychmiast bez czekania 10 s; błąd trafia do onError, cleanup nie uruchamia się przed upływem godziny
      currentNow = new Date(currentNow.getTime() + 500);
      worker.wake();
      await vi.advanceTimersByTimeAsync(0);
      expect(deliverCalls).toBe(3);
      expect(errors).toHaveLength(1);
      expect(cleanupCalls).toBe(1);

      // wake() w trakcie trwającego przebiegu nie nakłada przebiegów, tylko natychmiast planuje kolejny w .finally()
      blockNextDeliver = true;
      worker.wake();
      await vi.advanceTimersByTimeAsync(0);
      await inFlightStarted.promise;
      expect(deliverCalls).toBe(4);

      worker.wake();
      await vi.advanceTimersByTimeAsync(0);
      expect(deliverCalls).toBe(4);

      releaseInFlight.resolve();
      await vi.advanceTimersByTimeAsync(0);
      expect(deliverCalls).toBe(5);
      expect(cleanupCalls).toBe(1);

      // Po upływie godziny kolejny przebieg uruchamia cleanup ponownie
      currentNow = new Date(currentNow.getTime() + MAIL_CLEANUP_MIN_INTERVAL_MS);
      await vi.advanceTimersByTimeAsync(10_000);
      expect(deliverCalls).toBe(6);
      expect(cleanupCalls).toBe(2);

      // stop() czeka na zakończenie trwającego przebiegu i nie uruchamia kolejnych
      const stopStarted = deferred();
      const releaseStop = deferred();
      let stopDeliverDone = false;
      const stopWorker = startMailOutboxWorker({
        db: {} as PrismaClient,
        intervalMs: 1000,
        deliver: async () => {
          stopStarted.resolve();
          await releaseStop.promise;
          stopDeliverDone = true;
          return emptySummary(0);
        },
        cleanup: async () => 0,
      });

      await vi.advanceTimersByTimeAsync(0);
      await stopStarted.promise;

      let stopped = false;
      const stopPromise = stopWorker.stop().then(() => {
        stopped = true;
      });
      await Promise.resolve();
      expect(stopped).toBe(false);

      releaseStop.resolve();
      await stopPromise;
      expect(stopDeliverDone).toBe(true);
      expect(stopped).toBe(true);

      await worker.stop();
      const callsBeforeAdvance = deliverCalls;
      await vi.advanceTimersByTimeAsync(60_000);
      expect(deliverCalls).toBe(callsBeforeAdvance);
    } finally {
      vi.useRealTimers();
    }
  });

  it("przerywa pętlę drenażu przy braku postępu (sent + cancelled === 0) i po limicie 10 porcji na przebieg", async () => {
    vi.useFakeTimers();
    try {
      // 1. Pełna porcja samych błędów (sent = 0, cancelled = 0) przerywa drenaż po 1 porcji i oddaje głos sprzątaniu
      let failingDeliverCalls = 0;
      let failingCleanupCalls = 0;
      const failingWorker = startMailOutboxWorker({
        db: {} as PrismaClient,
        intervalMs: 5_000,
        batchSize: 2,
        deliver: async () => {
          failingDeliverCalls += 1;
          return emptySummary(2, { sent: 0, retried: 2 });
        },
        cleanup: async () => {
          failingCleanupCalls += 1;
          return 0;
        },
      });

      await vi.advanceTimersByTimeAsync(0);
      expect(failingDeliverCalls).toBe(1);
      expect(failingCleanupCalls).toBe(1);
      await failingWorker.stop();

      // 2. Ciągły strumień pełnych porcji z postępem zatrzymuje się po MAIL_MAX_BATCHES_PER_TICK (10) na jeden przebieg
      let busyDeliverCalls = 0;
      let busyCleanupCalls = 0;
      const busyWorker = startMailOutboxWorker({
        db: {} as PrismaClient,
        intervalMs: 5_000,
        batchSize: 2,
        deliver: async () => {
          busyDeliverCalls += 1;
          return emptySummary(2);
        },
        cleanup: async () => {
          busyCleanupCalls += 1;
          return 0;
        },
      });

      await vi.advanceTimersByTimeAsync(0);
      expect(busyDeliverCalls).toBe(MAIL_MAX_BATCHES_PER_TICK);
      expect(busyCleanupCalls).toBe(1);

      // Następne 10 porcji dopiero po intervalMs
      await vi.advanceTimersByTimeAsync(5_000);
      expect(busyDeliverCalls).toBe(MAIL_MAX_BATCHES_PER_TICK * 2);
      await busyWorker.stop();
    } finally {
      vi.useRealTimers();
    }
  });

  it("nie gubi wake() wywołanego w mikro-zadaniu między końcem tick() a wykonaniem .finally()", async () => {
    vi.useFakeTimers();
    try {
      let deliverCalls = 0;
      const releaseCleanup = deferred();

      const worker = startMailOutboxWorker({
        db: {} as PrismaClient,
        intervalMs: 60_000,
        batchSize: 2,
        deliver: async () => {
          deliverCalls += 1;
          return emptySummary(0);
        },
        cleanup: async () => {
          await releaseCleanup.promise;
          return 0;
        },
      });

      await vi.advanceTimersByTimeAsync(0);
      expect(deliverCalls).toBe(1);

      // Rozwiązujemy ostatni krok tick() i w tym samym kolejkowaniu mikro-zadań (przed .finally()) wywołujemy wake()
      releaseCleanup.resolve();
      queueMicrotask(() => {
        worker.wake();
      });

      // Przesuwamy zegar o 0 ms (nie 60 s!): wake() nie zostało zgubione i uruchomiło drugi przebieg natychmiast
      await vi.advanceTimersByTimeAsync(0);
      expect(deliverCalls).toBe(2);

      await worker.stop();
    } finally {
      vi.useRealTimers();
    }
  });

  it("serwer wywołuje mailOutboxWorker.wake() po COMMIT tworzenia i ponowienia zaproszenia, nigdy przy błędzie ani powtórce Idempotency-Key", async () => {
    const events: string[] = [];
    const now = new Date("2026-11-26T10:00:00.000Z");
    const idempotencyStore = new Map<
      string,
      { requestHash: string; responseStatus: number; responseBody: unknown; expiresAt: Date }
    >();
    let failCreate = false;

    const db = {
      $transaction: async <T>(fn: (tx: unknown) => Promise<T>): Promise<T> => {
        const tx = {
          $executeRaw: async () => 1,
          organization: {
            findUnique: async () => ({ id: ORG_ID, name: "Acme", ownerAccountId: ACC_ID }),
          },
          organizationDomain: {
            findFirst: async () => ({ id: "dom-1" }),
          },
          organizationUnit: { findMany: async () => [] },
          roleAssignment: { findMany: async () => [] },
          authUser: {
            findFirst: async () => null,
            create: async () => ({}),
          },
          employee: {
            create: async () => ({}),
          },
          account: {
            findUnique: async () => ({
              status: "ACTIVE",
              employeeId: EMP_ID,
              authzRevision: 0,
              organization: { ownerAccountId: ACC_ID },
            }),
            findFirst: async () => null,
            create: async () => ({}),
          },
          invitation: {
            create: async ({ data }: { data: { id: string; accountId: string; email: string; expiresAt: Date } }) => {
              if (failCreate) throw new Error("błąd bazy");
              events.push("invitation.create");
              return {
                ...data,
                status: "PENDING",
                invitedByAccountId: ACC_ID,
                acceptedAt: null,
                createdAt: now,
                updatedAt: now,
                account: { employeeId: EMP_ID },
              };
            },
            findUnique: async () => ({
              id: INV_ID,
              accountId: ACC_ID,
              email: "jan@acme.test",
              status: "PENDING",
              expiresAt: new Date(now.getTime() + 60_000),
              invitedByAccountId: ACC_ID,
              acceptedAt: null,
              createdAt: now,
              updatedAt: now,
              account: { id: ACC_ID, employeeId: EMP_ID, status: "INVITED" },
            }),
            update: async ({ data }: { data: { expiresAt: Date } }) => {
              events.push("invitation.update");
              return {
                id: INV_ID,
                accountId: ACC_ID,
                email: "jan@acme.test",
                status: "PENDING",
                expiresAt: data.expiresAt,
                invitedByAccountId: ACC_ID,
                acceptedAt: null,
                createdAt: now,
                updatedAt: now,
                account: { employeeId: EMP_ID },
              };
            },
          },
          mailOutbox: {
            create: async ({ data }: { data: { id: string } }) => {
              events.push("mailOutbox.create");
              return { id: data.id, status: "PENDING", attempts: 0, lastAttemptAt: null, sentAt: null };
            },
            updateMany: async () => ({ count: 1 }),
            findFirst: async () => null,
          },
          auditLog: {
            create: async () => ({}),
          },
          idempotencyKey: {
            findUnique: async ({ where }: { where: { organizationId_principal_key: { key: string } } }) =>
              idempotencyStore.get(where.organizationId_principal_key.key) ?? null,
            upsert: async ({
              where,
              create,
            }: {
              where: { organizationId_principal_key: { key: string } };
              create: { requestHash: string; responseStatus: number; responseBody: unknown; expiresAt: Date };
            }) => {
              idempotencyStore.set(where.organizationId_principal_key.key, create);
              return create;
            },
          },
        };
        const result = await fn(tx);
        events.push("tx.commit");
        return result;
      },
    } as unknown as PrismaClient;

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
      mailOutboxWorker: {
        wake: () => {
          events.push("worker.wake");
        },
      },
      now: () => now,
    });

    try {
      // 1. Błąd transakcji -> brak wake()
      failCreate = true;
      const failed = await app.inject({
        method: "POST",
        url: "/core/v1/invitations",
        headers: { authorization: "Bearer stub", [IDEMPOTENCY_KEY_HEADER]: "k-wake-1" },
        payload: { email: "jan@acme.test", firstName: "Jan", lastName: "Kowalski" },
      });
      expect(failed.statusCode).toBe(500);
      expect(events).not.toContain("worker.wake");

      // 2. Sukces tworzenia -> wake() wywołane po tx.commit
      failCreate = false;
      events.length = 0;
      const created = await app.inject({
        method: "POST",
        url: "/core/v1/invitations",
        headers: { authorization: "Bearer stub", [IDEMPOTENCY_KEY_HEADER]: "k-wake-1" },
        payload: { email: "jan@acme.test", firstName: "Jan", lastName: "Kowalski" },
      });
      expect(created.statusCode).toBe(201);
      expect(events.indexOf("tx.commit")).toBeLessThan(events.indexOf("worker.wake"));
      expect(events.filter((e) => e === "worker.wake")).toHaveLength(1);

      // 3. Powtórka z Idempotency-Key -> brak kolejnego wake()
      events.length = 0;
      const replayed = await app.inject({
        method: "POST",
        url: "/core/v1/invitations",
        headers: { authorization: "Bearer stub", [IDEMPOTENCY_KEY_HEADER]: "k-wake-1" },
        payload: { email: "jan@acme.test", firstName: "Jan", lastName: "Kowalski" },
      });
      expect(replayed.statusCode).toBe(201);
      expect(replayed.headers[IDEMPOTENCY_REPLAYED_HEADER.toLowerCase()]).toBe("true");
      expect(events).not.toContain("worker.wake");

      // 4. Ponowienie zaproszenia -> wake() po tx.commit, powtórka bez wake()
      events.length = 0;
      const resent = await app.inject({
        method: "POST",
        url: `/core/v1/invitations/${INV_ID}/resend`,
        headers: { authorization: "Bearer stub", [IDEMPOTENCY_KEY_HEADER]: "k-resend-1" },
      });
      expect(resent.statusCode).toBe(200);
      expect(events.indexOf("tx.commit")).toBeLessThan(events.indexOf("worker.wake"));
      expect(events.filter((e) => e === "worker.wake")).toHaveLength(1);

      events.length = 0;
      const replayedResend = await app.inject({
        method: "POST",
        url: `/core/v1/invitations/${INV_ID}/resend`,
        headers: { authorization: "Bearer stub", [IDEMPOTENCY_KEY_HEADER]: "k-resend-1" },
      });
      expect(replayedResend.statusCode).toBe(200);
      expect(replayedResend.headers[IDEMPOTENCY_REPLAYED_HEADER.toLowerCase()]).toBe("true");
      expect(events).not.toContain("worker.wake");
    } finally {
      await app.close();
    }
  });
});

describe("limity czasu SMTP", () => {
  it("twardy limit sendMail (30 s) i limity gniazda są krótsze niż dzierżawa zadania (90 s >= 2× limit)", () => {
    const worstCaseSocket =
      SMTP_TIMEOUTS.connectionTimeout + SMTP_TIMEOUTS.greetingTimeout + SMTP_TIMEOUTS.socketTimeout;
    expect(MAIL_SEND_DEADLINE_MS).toBeLessThan(MAIL_LEASE_MS);
    expect(MAIL_LEASE_MS).toBeGreaterThanOrEqual(2 * MAIL_SEND_DEADLINE_MS);
    expect(worstCaseSocket).toBeLessThan(MAIL_LEASE_MS);
  });

  it("sendMailWithDeadline zamyka transport przy sukcesie oraz przerywa i zamyka transport po przekroczeniu terminu", async () => {
    vi.useFakeTimers();
    try {
      const sample = {
        from: "Monorise <no-reply@monorise.studio>",
        to: "jan@acme.test",
        subject: "Test",
        text: "Treść",
        html: "<p>Treść</p>",
      };

      // Sukces przed terminem -> zwraca wynik i zamyka transport
      let closedOk = 0;
      await sendMailWithDeadline(
        {
          sendMail: async () => undefined,
          close: () => {
            closedOk += 1;
          },
        },
        sample,
        5_000,
      );
      expect(closedOk).toBe(1);

      // Zawieszony serwer -> po deadlineMs odrzuca z błędem limitu czasu i zamyka transport
      let closedHung = 0;
      const hungPromise = sendMailWithDeadline(
        {
          sendMail: () => new Promise(() => undefined),
          close: () => {
            closedHung += 1;
          },
        },
        sample,
        1_000,
      );
      const assertion = expect(hungPromise).rejects.toThrow(/limit czasu wysyłki SMTP/i);
      await vi.advanceTimersByTimeAsync(1_000);
      await assertion;
      expect(closedHung).toBeGreaterThanOrEqual(1);
    } finally {
      vi.useRealTimers();
    }
  });
});
