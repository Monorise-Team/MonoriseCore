import {
  claimMailOutboxJobs,
  cleanupMailOutbox,
  hashToken,
  withOrganization,
  type ClaimedMailOutboxJob,
  type MailStatus,
  type PrismaClient,
  type Tx,
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

/**
 * Czas dzierżawy (lease) zadania podczas wysyłki SMTP (90 s — 3× twardy limit `MAIL_SEND_DEADLINE_MS`).
 * Dodatkowo odnawiany na starcie wysyłki pojedynczego zadania, więc późniejsze zadania w porcji dostają pełny czas.
 */
export const MAIL_LEASE_MS = 90_000;

/** Maksymalna liczba porcji w pojedynczym przebiegu workera (chroni sprzątanie i odstęp `intervalMs` przed zagłodzeniem). */
export const MAIL_MAX_BATCHES_PER_TICK = 10;

/** Maksymalna liczba prób wysyłki; po osiągnięciu zadanie otrzymuje status `FAILED`. */
export const MAIL_MAX_ATTEMPTS = 8;

/** Bazowe opóźnienie ponowienia po pierwszej nieudanej próbie (30 s). */
export const MAIL_BACKOFF_BASE_MS = 30_000;

/** Maksymalne opóźnienie między kolejnymi próbami (1 godzina). */
export const MAIL_BACKOFF_MAX_MS = 60 * 60 * 1000;

/** Maksymalna długość wewnętrznego komunikatu błędu zapisywanego w `mail_outbox.lastError`. */
export const MAIL_LAST_ERROR_MAX_LENGTH = 500;

/** Czas przechowywania zakończonych wierszy `SENT`/`CANCELLED` i zastąpionych `FAILED` (30 dni, wymuszane w SQL). */
export const MAIL_CLEANUP_RETENTION_DAYS = 30;
export const MAIL_CLEANUP_RETENTION_MS = MAIL_CLEANUP_RETENTION_DAYS * 24 * 60 * 60 * 1000;

/** Ile starych wierszy usuwa jedno wywołanie `public.mail_outbox_cleanup`. */
export const MAIL_CLEANUP_BATCH_SIZE = 1000;

/** Minimalny odstęp między przebiegami sprzątania `public.mail_outbox_cleanup` (1 godzina). */
export const MAIL_CLEANUP_MIN_INTERVAL_MS = 60 * 60 * 1000;

const URL_USERINFO_RE = /(:\/\/)[^/?#\s@]+@/g;
const TOKEN_PARAM_RE = /(\btoken=)[^&#\s"'<>]+/gi;

export type ClaimedMailJob = ClaimedMailOutboxJob;

export interface ClaimMailJobsOptions {
  limit?: number | undefined;
  leaseMs?: number | undefined;
}

export interface DeliverMailJobOptions {
  authUrl?: string | undefined;
  mailer?: MailSender | undefined;
  leaseMs?: number | undefined;
  /** Opcjonalny zegar (wyłącznie do testów — produkcja zawsze używa `now()` z PostgreSQL). */
  now?: Date | undefined;
}

export interface DeliverMailJobResult {
  status: MailStatus | "SKIPPED";
  inviteUrl?: string | undefined;
}

export interface DeliverPendingMailOptions extends ClaimMailJobsOptions {
  authUrl?: string | undefined;
  mailer?: MailSender | undefined;
  /** Opcjonalny zegar (wyłącznie do testów — nigdy nie trafia do `mail_outbox_claim`). */
  now?: Date | (() => Date) | undefined;
  onError?: ((error: unknown) => void) | undefined;
}

export interface DeliverPendingMailSummary {
  claimed: number;
  sent: number;
  retried: number;
  failed: number;
  cancelled: number;
  skipped: number;
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
  maxBatchesPerTick?: number | undefined;
  leaseMs?: number | undefined;
  cleanupBatchSize?: number | undefined;
  cleanupIntervalMs?: number | undefined;
  now?: (() => Date) | undefined;
  onError?: ((error: unknown) => void) | undefined;
  /** Nadpisanie kroku wysyłki porcji (do testów jednostkowych). */
  deliver?: ((db: PrismaClient) => Promise<DeliverPendingMailSummary>) | undefined;
  /** Nadpisanie kroku sprzątania (do testów jednostkowych). */
  cleanup?: ((db: PrismaClient, shouldStop: () => boolean) => Promise<number>) | undefined;
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

/**
 * Formatuje wewnętrzny komunikat błędu dla `mail_outbox.lastError`: przed przycięciem do 500 znaków
 * usuwa znaki NUL oraz cenzuruje dane uwierzytelniające z adresów URL (`://user:pass@`) i wartości `token=`.
 */
export function formatMailError(error: unknown, maxLength = MAIL_LAST_ERROR_MAX_LENGTH): string {
  const raw = error instanceof Error ? error.message || error.name : String(error);
  const redacted = raw
    .replaceAll("\0", "")
    .replace(URL_USERINFO_RE, "$1[redacted]@")
    .replace(TOKEN_PARAM_RE, "$1[redacted]")
    .trim();
  const cleaned = redacted || "Nieznany błąd wysyłki poczty";
  if (cleaned.length <= maxLength) return cleaned;
  // Przycinamy po punktach kodowych Unicode, żeby nie rozciąć pary surogatów (UTF-8 w PostgreSQL).
  return Array.from(cleaned).slice(0, maxLength).join("");
}

async function readDbNow(tx: Tx): Promise<Date> {
  const rows = await tx.$queryRaw<{ now: Date }[]>`SELECT now() AS now`;
  return rows[0]?.now ?? new Date();
}

/**
 * Atomowo pobiera porcję gotowych zadań z kolejki `public.mail_outbox` (`mail_outbox_claim`, `FOR UPDATE SKIP LOCKED`),
 * zawsze według zegara bazy `now()`, ustawiając dzierżawę `lockedUntil` oraz podbijając `attempts` i `lastAttemptAt`.
 */
export async function claimMailJobs(db: PrismaClient, options: ClaimMailJobsOptions = {}): Promise<ClaimedMailJob[]> {
  return claimMailOutboxJobs(db, {
    limit: options.limit ?? MAIL_CLAIM_BATCH_SIZE,
    leaseMs: options.leaseMs ?? MAIL_LEASE_MS,
  });
}

/**
 * Atomowo rezerwuje konkretne zadanie `PENDING` w kontekście firmy (używane przez CLI `pnpm invitation:create`,
 * żeby nie dublować wysyłki przy równocześnie działającym workerze Core API). Bez jawnego `now` używa `now()` z bazy.
 */
export async function claimMailJobById(
  db: PrismaClient,
  organizationId: string,
  jobId: string,
  options: { leaseMs?: number | undefined; now?: Date | undefined } = {},
): Promise<ClaimedMailJob | null> {
  const leaseMs = options.leaseMs ?? MAIL_LEASE_MS;
  const explicitNow = options.now;

  return withOrganization(db, organizationId, async (tx) => {
    const rows =
      explicitNow !== undefined
        ? await tx.$queryRaw<ClaimedMailJob[]>`
            UPDATE "public"."mail_outbox"
            SET "lockedUntil" = ${explicitNow}::timestamptz + (${leaseMs}::integer * interval '1 millisecond'),
                "attempts" = "attempts" + 1,
                "lastAttemptAt" = ${explicitNow}::timestamptz,
                "updatedAt" = ${explicitNow}::timestamptz
            WHERE "id" = ${jobId}::uuid
              AND "organizationId" = ${organizationId}::uuid
              AND "status" = 'PENDING'
              AND ("lockedUntil" IS NULL OR "lockedUntil" < ${explicitNow}::timestamptz)
            RETURNING "id", "organizationId", "kind", "invitationId", "attempts"`
        : await tx.$queryRaw<ClaimedMailJob[]>`
            UPDATE "public"."mail_outbox"
            SET "lockedUntil" = now() + (${leaseMs}::integer * interval '1 millisecond'),
                "attempts" = "attempts" + 1,
                "lastAttemptAt" = now(),
                "updatedAt" = now()
            WHERE "id" = ${jobId}::uuid
              AND "organizationId" = ${organizationId}::uuid
              AND "status" = 'PENDING'
              AND ("lockedUntil" IS NULL OR "lockedUntil" < now())
            RETURNING "id", "organizationId", "kind", "invitationId", "attempts"`;
    return rows[0] ?? null;
  });
}

type PreparedDelivery =
  | { action: "skip" }
  | { action: "cancelled" }
  | {
      action: "send";
      to: string;
      organizationName: string;
      inviterName: string | null;
      inviteUrl: string;
    };

/**
 * Dostarcza pojedyncze zarezerwowane zadanie z `mail_outbox` z ogrodzeniem (fencing) po numerze próby `job.attempts`:
 * 1. W krótkiej transakcji `withOrganization` z blokadą `lockInvitation` sprawdza, czy zadanie nadal ma
 *    `status = PENDING` i `attempts = job.attempts`. Jeśli nie — pomija bez modyfikacji (`SKIPPED`).
 *    Gdy zaproszenie jest nieaktualne (nie-`PENDING`, wygasłe lub konto nie-`INVITED`), oznacza zadanie `CANCELLED`
 *    (również z warunkiem `status = PENDING AND attempts = job.attempts`). W przeciwnym razie odnawia dzierżawę
 *    (`lockedUntil = now() + leaseMs`, ogrodzone tym samym warunkiem), generuje świeży token aktywacyjny,
 *    zapisuje jego skrót SHA-256 (bez zmiany `expiresAt`) i zamyka transakcję przed rozmową z serwerem SMTP.
 * 2. Poza jakąkolwiek transakcją bazy wysyła wiadomość e-mail przez `mailer`.
 * 3. W nowej krótkiej transakcji (zawsze z warunkiem `status = PENDING AND attempts = job.attempts`) oznacza zadanie
 *    jako `SENT`, albo przy błędzie planuje ponowienie z backoffem (`PENDING`) bądź oznacza jako `FAILED`
 *    po `MAIL_MAX_ATTEMPTS` (8) próbach. Spóźniony worker po wygaśnięciu dzierżawy nigdy nie nadpisze nowszej próby.
 */
export async function deliverMailJob(
  db: PrismaClient,
  job: ClaimedMailJob,
  options: DeliverMailJobOptions = {},
): Promise<DeliverMailJobResult> {
  const leaseMs = options.leaseMs ?? MAIL_LEASE_MS;
  const explicitNow = options.now;

  const prepared: PreparedDelivery = await withOrganization(db, job.organizationId, async (tx) => {
    await lockInvitation(tx, job.invitationId);

    const currentJob = await tx.mailOutbox.findUnique({
      where: { id: job.id },
      select: { status: true, attempts: true },
    });
    if (!currentJob || currentJob.status !== "PENDING" || currentJob.attempts !== job.attempts) {
      return { action: "skip" };
    }

    const effectiveNow = explicitNow ?? (await readDbNow(tx));

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
          effectiveInvitationStatus(invitation.status, invitation.expiresAt, effectiveNow) !== "PENDING" ||
          invitation.account.status !== "INVITED"
        ) {
          const cancelled =
            explicitNow !== undefined
              ? await tx.$executeRaw`
                  UPDATE "public"."mail_outbox"
                  SET "status" = 'CANCELLED', "lockedUntil" = NULL, "updatedAt" = ${explicitNow}::timestamptz
                  WHERE "id" = ${job.id}::uuid
                    AND "organizationId" = ${job.organizationId}::uuid
                    AND "status" = 'PENDING'
                    AND "attempts" = ${job.attempts}::integer`
              : await tx.$executeRaw`
                  UPDATE "public"."mail_outbox"
                  SET "status" = 'CANCELLED', "lockedUntil" = NULL, "updatedAt" = now()
                  WHERE "id" = ${job.id}::uuid
                    AND "organizationId" = ${job.organizationId}::uuid
                    AND "status" = 'PENDING'
                    AND "attempts" = ${job.attempts}::integer`;
          return cancelled === 0 ? { action: "skip" } : { action: "cancelled" };
        }

        // Odnawiamy dzierżawę z ogrodzeniem po numerze próby, żeby zadanie czekające w porcji dostało pełny czas.
        const renewed =
          explicitNow !== undefined
            ? await tx.$executeRaw`
                UPDATE "public"."mail_outbox"
                SET "lockedUntil" = ${explicitNow}::timestamptz + (${leaseMs}::integer * interval '1 millisecond'),
                    "updatedAt" = ${explicitNow}::timestamptz
                WHERE "id" = ${job.id}::uuid
                  AND "organizationId" = ${job.organizationId}::uuid
                  AND "status" = 'PENDING'
                  AND "attempts" = ${job.attempts}::integer`
            : await tx.$executeRaw`
                UPDATE "public"."mail_outbox"
                SET "lockedUntil" = now() + (${leaseMs}::integer * interval '1 millisecond'),
                    "updatedAt" = now()
                WHERE "id" = ${job.id}::uuid
                  AND "organizationId" = ${job.organizationId}::uuid
                  AND "status" = 'PENDING'
                  AND "attempts" = ${job.attempts}::integer`;
        if (renewed === 0) {
          return { action: "skip" };
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
    return { status: "SKIPPED" };
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
    const backoffMs = computeMailBackoffMs(job.attempts);

    const failureStatus = await withOrganization(db, job.organizationId, async (tx) => {
      const invitation = await tx.invitation.findUnique({
        where: { id: job.invitationId },
        select: {
          status: true,
          expiresAt: true,
          account: { select: { status: true } },
        },
      });
      const effectiveNow = explicitNow ?? (await readDbNow(tx));
      if (
        !invitation ||
        effectiveInvitationStatus(invitation.status, invitation.expiresAt, effectiveNow) !== "PENDING" ||
        invitation.account.status !== "INVITED"
      ) {
        const cancelled =
          explicitNow !== undefined
            ? await tx.$executeRaw`
                UPDATE "public"."mail_outbox"
                SET "status" = 'CANCELLED', "lockedUntil" = NULL, "updatedAt" = ${explicitNow}::timestamptz
                WHERE "id" = ${job.id}::uuid
                  AND "organizationId" = ${job.organizationId}::uuid
                  AND "status" = 'PENDING'
                  AND "attempts" = ${job.attempts}::integer`
            : await tx.$executeRaw`
                UPDATE "public"."mail_outbox"
                SET "status" = 'CANCELLED', "lockedUntil" = NULL, "updatedAt" = now()
                WHERE "id" = ${job.id}::uuid
                  AND "organizationId" = ${job.organizationId}::uuid
                  AND "status" = 'PENDING'
                  AND "attempts" = ${job.attempts}::integer`;
        return cancelled === 0 ? ("SKIPPED" as const) : ("CANCELLED" as const);
      }

      if (reachedMax) {
        const affected =
          explicitNow !== undefined
            ? await tx.$executeRaw`
                UPDATE "public"."mail_outbox"
                SET "status" = 'FAILED',
                    "failedAt" = ${explicitNow}::timestamptz,
                    "lockedUntil" = NULL,
                    "lastError" = ${lastError}::text,
                    "updatedAt" = ${explicitNow}::timestamptz
                WHERE "id" = ${job.id}::uuid
                  AND "organizationId" = ${job.organizationId}::uuid
                  AND "status" = 'PENDING'
                  AND "attempts" = ${job.attempts}::integer`
            : await tx.$executeRaw`
                UPDATE "public"."mail_outbox"
                SET "status" = 'FAILED',
                    "failedAt" = now(),
                    "lockedUntil" = NULL,
                    "lastError" = ${lastError}::text,
                    "updatedAt" = now()
                WHERE "id" = ${job.id}::uuid
                  AND "organizationId" = ${job.organizationId}::uuid
                  AND "status" = 'PENDING'
                  AND "attempts" = ${job.attempts}::integer`;
        return affected === 0 ? ("SKIPPED" as const) : ("FAILED" as const);
      }

      const affected =
        explicitNow !== undefined
          ? await tx.$executeRaw`
              UPDATE "public"."mail_outbox"
              SET "status" = 'PENDING',
                  "nextAttemptAt" = ${explicitNow}::timestamptz + (${backoffMs}::integer * interval '1 millisecond'),
                  "lockedUntil" = NULL,
                  "lastError" = ${lastError}::text,
                  "updatedAt" = ${explicitNow}::timestamptz
              WHERE "id" = ${job.id}::uuid
                AND "organizationId" = ${job.organizationId}::uuid
                AND "status" = 'PENDING'
                AND "attempts" = ${job.attempts}::integer`
          : await tx.$executeRaw`
              UPDATE "public"."mail_outbox"
              SET "status" = 'PENDING',
                  "nextAttemptAt" = now() + (${backoffMs}::integer * interval '1 millisecond'),
                  "lockedUntil" = NULL,
                  "lastError" = ${lastError}::text,
                  "updatedAt" = now()
              WHERE "id" = ${job.id}::uuid
                AND "organizationId" = ${job.organizationId}::uuid
                AND "status" = 'PENDING'
                AND "attempts" = ${job.attempts}::integer`;
      return affected === 0 ? ("SKIPPED" as const) : ("PENDING" as const);
    });

    return { status: failureStatus };
  }

  // Semantyka dostarczania co najmniej raz (at-least-once): jeśli serwer SMTP przyjął wiadomość,
  // ale poniższy zapis statusu SENT nie powiedzie się (np. chwilowy brak połączenia z bazą),
  // dzierżawa lockedUntil wygaśnie i kolejna próba wygeneruje nowy token oraz wyśle nowy link —
  // poprzedni link przestanie działać z chwilą nadpisania tokenHash, a spóźniony worker zostanie
  // pominięty dzięki ogrodzeniu po numerze próby (attempts = job.attempts).
  const markedSent = await withOrganization(db, job.organizationId, (tx) =>
    explicitNow !== undefined
      ? tx.$executeRaw`
          UPDATE "public"."mail_outbox"
          SET "status" = 'SENT',
              "sentAt" = ${explicitNow}::timestamptz,
              "lockedUntil" = NULL,
              "lastError" = NULL,
              "updatedAt" = ${explicitNow}::timestamptz
          WHERE "id" = ${job.id}::uuid
            AND "organizationId" = ${job.organizationId}::uuid
            AND "status" = 'PENDING'
            AND "attempts" = ${job.attempts}::integer`
      : tx.$executeRaw`
          UPDATE "public"."mail_outbox"
          SET "status" = 'SENT',
              "sentAt" = now(),
              "lockedUntil" = NULL,
              "lastError" = NULL,
              "updatedAt" = now()
          WHERE "id" = ${job.id}::uuid
            AND "organizationId" = ${job.organizationId}::uuid
            AND "status" = 'PENDING'
            AND "attempts" = ${job.attempts}::integer`,
  );
  if (markedSent === 0) {
    return { status: "SKIPPED" };
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
  });

  const resolveNow =
    typeof options.now === "function" ? options.now : options.now !== undefined ? () => options.now as Date : undefined;

  const summary: DeliverPendingMailSummary = {
    claimed: jobs.length,
    sent: 0,
    retried: 0,
    failed: 0,
    cancelled: 0,
    skipped: 0,
  };

  for (const job of jobs) {
    try {
      const outcome = await deliverMailJob(db, job, {
        authUrl: options.authUrl,
        mailer: options.mailer,
        leaseMs: options.leaseMs,
        now: resolveNow?.(),
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
        case "SKIPPED":
          summary.skipped += 1;
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

/**
 * Usuwa wysłane (`SENT`), anulowane (`CANCELLED`) oraz zastąpione nieudane (`FAILED`) zadania starsze
 * niż 30 dni w kolejnych porcjach (`public.mail_outbox_cleanup`), przerywając między porcjami przy `shouldStop`.
 */
export async function cleanupOldMailJobs(
  db: PrismaClient,
  batchSize = MAIL_CLEANUP_BATCH_SIZE,
  shouldStop?: () => boolean,
): Promise<number> {
  let total = 0;
  for (;;) {
    if (shouldStop?.()) return total;
    const deleted = await cleanupMailOutbox(db, batchSize);
    total += deleted;
    if (deleted < batchSize) return total;
  }
}

/**
 * Proces wysyłki poczty w Core API (wzorowany na `startOutboxPublisher`): co `intervalMs` opróżnia gotowe
 * zadania z `mail_outbox` (maksymalnie `maxBatchesPerTick` porcji z postępem), pozwala na natychmiastowe
 * wybudzenie przez `wake()`, a co najwyżej raz na godzinę porcjowo usuwa stare wiersze sprzed 30 dni.
 * Przebiegi nie nakładają się, timer używa `unref()`, planowanie kolejnego kroku odbywa się po wyzerowaniu
 * `inFlight` (bez wyścigu z `wake()`), a `stop()` czeka na zakończenie bieżącego przebiegu.
 */
export function startMailOutboxWorker({
  db,
  intervalMs,
  authUrl,
  mailer,
  batchSize = MAIL_CLAIM_BATCH_SIZE,
  maxBatchesPerTick = MAIL_MAX_BATCHES_PER_TICK,
  leaseMs = MAIL_LEASE_MS,
  cleanupBatchSize = MAIL_CLEANUP_BATCH_SIZE,
  cleanupIntervalMs = MAIL_CLEANUP_MIN_INTERVAL_MS,
  now: getNow,
  onError,
  deliver,
  cleanup = (client, shouldStop) => cleanupOldMailJobs(client, cleanupBatchSize, shouldStop),
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
        now: getNow,
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
        if (!stopped) {
          if (wakePending) {
            wakePending = false;
            schedule(0);
          } else {
            schedule(intervalMs);
          }
        }
      });
    }, delayMs);
    timer.unref?.();
  };

  const tick = async () => {
    wakePending = false;
    try {
      for (let batch = 0; batch < maxBatchesPerTick && !stopped; batch += 1) {
        const summary = await deliverBatch(db);
        if (summary.claimed < batchSize || summary.sent + summary.cancelled === 0) {
          break;
        }
      }
    } catch (error) {
      onError?.(error);
    }

    if (!stopped) {
      const nowMs = (getNow ? getNow() : new Date()).getTime();
      if (lastCleanupAt === null || nowMs - lastCleanupAt >= cleanupIntervalMs) {
        lastCleanupAt = nowMs;
        try {
          await cleanup(db, () => stopped);
        } catch (error) {
          onError?.(error);
        }
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
