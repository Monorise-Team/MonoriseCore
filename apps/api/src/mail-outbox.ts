import {
  claimMailOutboxJobs,
  cleanupMailOutbox,
  hashToken,
  withOrganization,
  type ClaimedMailOutboxJob,
  type MailStatus,
  type PrismaClient,
} from "@core/db";
import {
  buildInviteUrl,
  effectiveInvitationStatus,
  generateInvitationToken,
  lockInvitation,
  resolveInviterName,
} from "./invitations.js";
import { invitationMail, sendMail, type MailSender } from "./mail.js";

/** Domyślny odstęp pętli workera kolejki poczty (1 s). */
export const DEFAULT_MAIL_OUTBOX_INTERVAL_MS = 1000;

/** Maksymalny bezpieczny odstęp dla `setTimeout` w Node.js (2^31 - 1 ms, ok. 24,8 dnia). */
export const MAX_MAIL_OUTBOX_INTERVAL_MS = 2_147_483_647;

/** Ile zadań pobieramy w jednej porcji z `public.mail_outbox_claim`. */
export const MAIL_CLAIM_BATCH_SIZE = 20;

/** Czas dzierżawy (lease) zadania podczas wysyłki SMTP (1 minuta). */
export const MAIL_LEASE_MS = 60_000;

/** Maksymalna liczba prób wysyłki; po osiągnięciu zadanie otrzymuje status `FAILED`. */
export const MAIL_MAX_ATTEMPTS = 8;

/** Bazowe opóźnienie ponowienia po pierwszej nieudanej próbie (30 s). */
export const MAIL_BACKOFF_BASE_MS = 30_000;

/** Maksymalne opóźnienie między kolejnymi próbami (1 godzina). */
export const MAIL_BACKOFF_MAX_MS = 60 * 60 * 1000;

/** Maksymalna długość wewnętrznego komunikatu błędu zapisywanego w `mail_outbox.lastError`. */
export const MAIL_LAST_ERROR_MAX_LENGTH = 500;

/** Czas przechowywania zakończonych wierszy `SENT` i `CANCELLED` przed sprzątaniem (30 dni). */
export const MAIL_CLEANUP_RETENTION_DAYS = 30;
export const MAIL_CLEANUP_RETENTION_MS = MAIL_CLEANUP_RETENTION_DAYS * 24 * 60 * 60 * 1000;

/** Minimalny odstęp między przebiegami sprzątania `public.mail_outbox_cleanup` (1 godzina). */
export const MAIL_CLEANUP_MIN_INTERVAL_MS = 60 * 60 * 1000;

export type ClaimedMailJob = ClaimedMailOutboxJob;

export interface ClaimMailJobsOptions {
  limit?: number | undefined;
  leaseMs?: number | undefined;
  now?: Date | undefined;
}

export interface DeliverMailJobOptions {
  authUrl?: string | undefined;
  mailer?: MailSender | undefined;
  now?: Date | undefined;
}

export interface DeliverMailJobResult {
  status: MailStatus;
  inviteUrl?: string | undefined;
}

export interface DeliverPendingMailOptions extends ClaimMailJobsOptions, DeliverMailJobOptions {
  onError?: ((error: unknown) => void) | undefined;
}

export interface DeliverPendingMailSummary {
  claimed: number;
  sent: number;
  retried: number;
  failed: number;
  cancelled: number;
}

export interface MailOutboxWorker {
  /** Zatrzymuje harmonogram i czeka na zakończenie trwającego przebiegu. */
  stop: () => Promise<void>;
  /** Natychmiast wybudza worker (np. po zapisaniu nowego zaproszenia), bez nakładania przebiegów. */
  wake: () => void;
}

export interface MailOutboxWorkerOptions {
  db: PrismaClient;
  /** Odstęp między przebiegami (ms). */
  intervalMs: number;
  authUrl?: string | undefined;
  mailer?: MailSender | undefined;
  batchSize?: number | undefined;
  leaseMs?: number | undefined;
  retentionMs?: number | undefined;
  cleanupIntervalMs?: number | undefined;
  now?: (() => Date) | undefined;
  onError?: ((error: unknown) => void) | undefined;
  /** Nadpisanie kroku wysyłki porcji (do testów jednostkowych). */
  deliver?: ((db: PrismaClient) => Promise<DeliverPendingMailSummary>) | undefined;
  /** Nadpisanie kroku sprzątania (do testów jednostkowych). */
  cleanup?: ((db: PrismaClient, before: Date) => Promise<number>) | undefined;
}

/**
 * Waliduje zmienną `CORE_MAIL_OUTBOX_INTERVAL_MS` przy starcie procesu.
 * Brak zmiennej oznacza wartość domyślną (1 s), `0` wyłącza worker, a błędna wartość przerywa start.
 */
export function parseMailOutboxIntervalMs(raw: string | undefined): number {
  if (raw === undefined) return DEFAULT_MAIL_OUTBOX_INTERVAL_MS;
  const trimmed = raw.trim();
  if (!/^(0|[1-9][0-9]*)$/.test(trimmed)) {
    throw new Error(
      `Nieprawidłowa wartość CORE_MAIL_OUTBOX_INTERVAL_MS="${raw}": wymagana liczba całkowita z zakresu 0..${MAX_MAIL_OUTBOX_INTERVAL_MS}`,
    );
  }
  const value = Number(trimmed);
  if (!Number.isSafeInteger(value) || value > MAX_MAIL_OUTBOX_INTERVAL_MS) {
    throw new Error(
      `Nieprawidłowa wartość CORE_MAIL_OUTBOX_INTERVAL_MS="${raw}": wymagana liczba całkowita z zakresu 0..${MAX_MAIL_OUTBOX_INTERVAL_MS}`,
    );
  }
  return value;
}

/**
 * Wylicza opóźnienie przed kolejną próbą wysyłki: `30 s × 2^(attempts − 1)`, maksymalnie 1 godzina.
 */
export function computeMailBackoffMs(attempts: number): number {
  const exponent = Math.min(Math.max(0, Math.floor(attempts) - 1), 20);
  return Math.min(MAIL_BACKOFF_MAX_MS, MAIL_BACKOFF_BASE_MS * 2 ** exponent);
}

/** Formatuje wewnętrzny komunikat błędu dla `mail_outbox.lastError` (przycięty do 500 znaków, bez znaków NUL). */
export function formatMailError(error: unknown, maxLength = MAIL_LAST_ERROR_MAX_LENGTH): string {
  const raw = error instanceof Error ? error.message || error.name : String(error);
  const cleaned = raw.replaceAll("\0", "").trim() || "Nieznany błąd wysyłki poczty";
  if (cleaned.length <= maxLength) return cleaned;
  // Przycinamy po punktach kodowych Unicode, żeby nie rozciąć pary surogatów (UTF-8 w PostgreSQL).
  return Array.from(cleaned).slice(0, maxLength).join("");
}

/**
 * Atomowo pobiera porcję gotowych zadań z kolejki `public.mail_outbox` (`mail_outbox_claim`, `FOR UPDATE SKIP LOCKED`),
 * ustawiając dzierżawę `lockedUntil` oraz podbijając `attempts` i `lastAttemptAt`.
 */
export async function claimMailJobs(db: PrismaClient, options: ClaimMailJobsOptions = {}): Promise<ClaimedMailJob[]> {
  return claimMailOutboxJobs(db, {
    limit: options.limit ?? MAIL_CLAIM_BATCH_SIZE,
    leaseMs: options.leaseMs ?? MAIL_LEASE_MS,
    now: options.now,
  });
}

/**
 * Atomowo rezerwuje konkretne zadanie `PENDING` w kontekście firmy (używane przez CLI `pnpm invitation:create`,
 * żeby nie dublować wysyłki przy równocześnie działającym workerze Core API).
 */
export async function claimMailJobById(
  db: PrismaClient,
  organizationId: string,
  jobId: string,
  options: { leaseMs?: number | undefined; now?: Date | undefined } = {},
): Promise<ClaimedMailJob | null> {
  const leaseMs = options.leaseMs ?? MAIL_LEASE_MS;
  const now = options.now ?? new Date();
  const lockedUntil = new Date(now.getTime() + leaseMs);

  return withOrganization(db, organizationId, async (tx) => {
    const rows = await tx.$queryRaw<ClaimedMailJob[]>`
      UPDATE "public"."mail_outbox"
      SET "lockedUntil" = ${lockedUntil}::timestamptz,
          "attempts" = "attempts" + 1,
          "lastAttemptAt" = ${now}::timestamptz,
          "updatedAt" = ${now}::timestamptz
      WHERE "id" = ${jobId}::uuid
        AND "organizationId" = ${organizationId}::uuid
        AND "status" = 'PENDING'
        AND ("lockedUntil" IS NULL OR "lockedUntil" < ${now}::timestamptz)
      RETURNING "id", "organizationId", "kind", "invitationId", "attempts"
    `;
    return rows[0] ?? null;
  });
}

type PreparedDelivery =
  | { action: "skip"; status: MailStatus }
  | { action: "cancelled" }
  | {
      action: "send";
      to: string;
      organizationName: string;
      inviterName: string | null;
      inviteUrl: string;
    };

/**
 * Dostarcza pojedyncze zarezerwowane zadanie z `mail_outbox`:
 * 1. W krótkiej transakcji `withOrganization` z blokadą `lockInvitation` sprawdza, czy zadanie i zaproszenie
 *    są wciąż aktualne (`PENDING`, niewygasłe, konto `INVITED`); jeśli nie — oznacza zadanie jako `CANCELLED`.
 *    W przeciwnym razie generuje świeży token aktywacyjny, zapisuje jego skrót SHA-256 (bez zmiany `expiresAt`)
 *    i zamyka transakcję przed rozmową z serwerem SMTP.
 * 2. Poza jakąkolwiek transakcją bazy wysyła wiadomość e-mail przez `mailer`.
 * 3. W nowej krótkiej transakcji oznacza zadanie jako `SENT`, albo przy błędzie planuje ponowienie z backoffem
 *    (`PENDING`) bądź oznacza jako `FAILED` po `MAIL_MAX_ATTEMPTS` (8) próbach.
 */
export async function deliverMailJob(
  db: PrismaClient,
  job: ClaimedMailJob,
  options: DeliverMailJobOptions = {},
): Promise<DeliverMailJobResult> {
  const prepareNow = options.now ?? new Date();

  const prepared: PreparedDelivery = await withOrganization(db, job.organizationId, async (tx) => {
    await lockInvitation(tx, job.invitationId);

    const currentJob = await tx.mailOutbox.findUnique({
      where: { id: job.id },
      select: { status: true },
    });
    if (!currentJob || currentJob.status !== "PENDING") {
      return { action: "skip", status: currentJob?.status ?? "CANCELLED" };
    }

    switch (job.kind) {
      case "INVITATION": {
        const invitation = await tx.invitation.findUnique({
          where: { id: job.invitationId },
          select: {
            id: true,
            email: true,
            status: true,
            expiresAt: true,
            invitedByAccountId: true,
            account: { select: { status: true } },
            organization: { select: { name: true } },
          },
        });

        if (
          !invitation ||
          effectiveInvitationStatus(invitation.status, invitation.expiresAt, prepareNow) !== "PENDING" ||
          invitation.account.status !== "INVITED"
        ) {
          await tx.mailOutbox.update({
            where: { id: job.id },
            data: {
              status: "CANCELLED",
              lockedUntil: null,
              updatedAt: prepareNow,
            },
          });
          return { action: "cancelled" };
        }

        const token = generateInvitationToken();
        const tokenHash = hashToken(token);
        await tx.invitation.update({
          where: { id: invitation.id },
          data: { tokenHash },
        });
        const inviterName = await resolveInviterName(tx, invitation.invitedByAccountId);
        return {
          action: "send",
          to: invitation.email,
          organizationName: invitation.organization.name,
          inviterName,
          inviteUrl: buildInviteUrl(token, options.authUrl),
        };
      }
    }
  });

  if (prepared.action === "skip") {
    return { status: prepared.status };
  }
  if (prepared.action === "cancelled") {
    return { status: "CANCELLED" };
  }

  const mailer = options.mailer ?? sendMail;
  try {
    await mailer(
      invitationMail({
        to: prepared.to,
        organizationName: prepared.organizationName,
        inviterName: prepared.inviterName,
        inviteUrl: prepared.inviteUrl,
      }),
    );
  } catch (error) {
    const lastError = formatMailError(error);
    const reachedMax = job.attempts >= MAIL_MAX_ATTEMPTS;
    const failureNow = options.now ?? new Date();
    const nextAttemptAt = reachedMax ? undefined : new Date(failureNow.getTime() + computeMailBackoffMs(job.attempts));

    const updated = await withOrganization(db, job.organizationId, (tx) =>
      tx.mailOutbox.updateMany({
        where: { id: job.id, status: "PENDING" },
        data: reachedMax
          ? {
              status: "FAILED",
              failedAt: failureNow,
              lockedUntil: null,
              lastError,
              updatedAt: failureNow,
            }
          : {
              status: "PENDING",
              nextAttemptAt,
              lockedUntil: null,
              lastError,
              updatedAt: failureNow,
            },
      }),
    );
    if (updated.count === 0) {
      return { status: "CANCELLED" };
    }
    return { status: reachedMax ? "FAILED" : "PENDING" };
  }

  // Semantyka dostarczania co najmniej raz (at-least-once): jeśli serwer SMTP przyjął wiadomość,
  // ale poniższy zapis statusu SENT nie powiedzie się (np. chwilowy brak połączenia z bazą),
  // dzierżawa lockedUntil wygaśnie i kolejna próba wygeneruje nowy token oraz wyśle nowy link —
  // poprzedni link przestanie działać z chwilą nadpisania tokenHash.
  const sentAt = options.now ?? new Date();
  const updated = await withOrganization(db, job.organizationId, (tx) =>
    tx.mailOutbox.updateMany({
      where: { id: job.id, status: "PENDING" },
      data: {
        status: "SENT",
        sentAt,
        lockedUntil: null,
        lastError: null,
        updatedAt: sentAt,
      },
    }),
  );
  if (updated.count === 0) {
    return { status: "CANCELLED" };
  }

  return { status: "SENT", inviteUrl: prepared.inviteUrl };
}

/**
 * Wykonuje jedno przejście pobrania i wysyłki gotowych zadań z kolejki `mail_outbox` (używane przez worker i testy).
 */
export async function deliverPendingMail(
  db: PrismaClient,
  options: DeliverPendingMailOptions = {},
): Promise<DeliverPendingMailSummary> {
  const jobs = await claimMailJobs(db, {
    limit: options.limit,
    leaseMs: options.leaseMs,
    now: options.now,
  });

  const summary: DeliverPendingMailSummary = {
    claimed: jobs.length,
    sent: 0,
    retried: 0,
    failed: 0,
    cancelled: 0,
  };

  for (const job of jobs) {
    try {
      const outcome = await deliverMailJob(db, job, {
        authUrl: options.authUrl,
        mailer: options.mailer,
        now: options.now,
      });
      switch (outcome.status) {
        case "SENT":
          summary.sent += 1;
          break;
        case "PENDING":
          summary.retried += 1;
          break;
        case "FAILED":
          summary.failed += 1;
          break;
        case "CANCELLED":
          summary.cancelled += 1;
          break;
      }
    } catch (error) {
      if (options.onError) {
        options.onError(error);
      } else {
        throw error;
      }
    }
  }

  return summary;
}

/** Usuwa wysłane (`SENT`) i anulowane (`CANCELLED`) zadania starsze niż `before` (`public.mail_outbox_cleanup`). */
export async function cleanupOldMailJobs(db: PrismaClient, before: Date): Promise<number> {
  return cleanupMailOutbox(db, before);
}

/**
 * Proces wysyłki poczty w Core API (wzorowany na `startOutboxPublisher`): co `intervalMs` opróżnia gotowe
 * zadania z `mail_outbox`, pozwala na natychmiastowe wybudzenie przez `wake()`, a co najwyżej raz na godzinę
 * usuwa stare wiersze `SENT`/`CANCELLED` sprzed 30 dni. Przebiegi nie nakładają się, timer używa `unref()`,
 * a `stop()` czeka na zakończenie bieżącego przebiegu.
 */
export function startMailOutboxWorker({
  db,
  intervalMs,
  authUrl,
  mailer,
  batchSize = MAIL_CLAIM_BATCH_SIZE,
  leaseMs = MAIL_LEASE_MS,
  retentionMs = MAIL_CLEANUP_RETENTION_MS,
  cleanupIntervalMs = MAIL_CLEANUP_MIN_INTERVAL_MS,
  now: getNow,
  onError,
  deliver,
  cleanup = cleanupOldMailJobs,
}: MailOutboxWorkerOptions): MailOutboxWorker {
  let stopped = false;
  let timer: ReturnType<typeof setTimeout> | undefined;
  let inFlight: Promise<void> | null = null;
  let wakePending = false;
  let lastCleanupAt: number | null = null;

  const deliverBatch =
    deliver ??
    ((client: PrismaClient) =>
      deliverPendingMail(client, {
        limit: batchSize,
        leaseMs,
        authUrl,
        mailer,
        now: getNow?.(),
        onError,
      }));

  const schedule = (delayMs: number) => {
    if (stopped) return;
    if (timer) {
      clearTimeout(timer);
    }
    timer = setTimeout(() => {
      timer = undefined;
      inFlight = tick().finally(() => {
        inFlight = null;
      });
    }, delayMs);
    timer.unref?.();
  };

  const tick = async () => {
    wakePending = false;
    try {
      while (!stopped) {
        const summary = await deliverBatch(db);
        if (summary.claimed < batchSize) break;
      }
    } catch (error) {
      onError?.(error);
    }

    if (!stopped) {
      const nowMs = (getNow ? getNow() : new Date()).getTime();
      if (lastCleanupAt === null || nowMs - lastCleanupAt >= cleanupIntervalMs) {
        lastCleanupAt = nowMs;
        try {
          await cleanup(db, new Date(nowMs - retentionMs));
        } catch (error) {
          onError?.(error);
        }
      }
    }

    if (!stopped) {
      if (wakePending) {
        wakePending = false;
        schedule(0);
      } else {
        schedule(intervalMs);
      }
    }
  };

  schedule(0);

  return {
    wake: () => {
      if (stopped) return;
      if (inFlight) {
        wakePending = true;
        return;
      }
      schedule(0);
    },
    stop: async () => {
      stopped = true;
      wakePending = false;
      if (timer) {
        clearTimeout(timer);
        timer = undefined;
      }
      if (inFlight) {
        await inFlight;
      }
    },
  };
}
