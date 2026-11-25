import { createHash } from "node:crypto";
import {
  IDEMPOTENCY_KEY_HEADER,
  IDEMPOTENCY_KEY_TTL_MS,
  IdempotencyKeyHeader,
  type ApiErrorBody,
  type ErrorCode,
} from "@core/contracts";
import { cleanupExpiredIdempotencyKeys, Prisma, uuidv7, withOrganization, type PrismaClient, type Tx } from "@core/db";

/** Domyślny odstęp okresowego sprzątania wygasłych kluczy powtórzeń (1 godzina). */
export const DEFAULT_IDEMPOTENCY_CLEANUP_INTERVAL_MS = 60 * 60 * 1000;

/** Ile wygasłych kluczy usuwamy w jednej transakcji (`idempotency_keys_cleanup_expired`). */
export const IDEMPOTENCY_CLEANUP_BATCH_SIZE = 1000;

export class IdempotencyError extends Error {
  constructor(
    readonly status: 400 | 409,
    readonly code: ErrorCode,
    message: string,
    readonly details: ApiErrorBody["details"] = [],
  ) {
    super(message);
  }
}

/**
 * Waliduje wartość nagłówka `Idempotency-Key`.
 * Brak nagłówka zwraca `null` (operacja działa bez mechanizmu powtórzeń).
 * Pusty, za długi (> 255), zawierający niedrukowalne znaki lub powtórzony nagłówek rzuca `400 VALIDATION_FAILED`.
 */
export function parseIdempotencyKeyHeader(raw: string | string[] | undefined): string | null {
  if (raw === undefined) return null;
  if (Array.isArray(raw)) {
    throw new IdempotencyError(400, "VALIDATION_FAILED", "Nieprawidłowy nagłówek Idempotency-Key", [
      { field: IDEMPOTENCY_KEY_HEADER, message: "Nagłówek Idempotency-Key może zostać przekazany tylko raz" },
    ]);
  }
  const parsed = IdempotencyKeyHeader.safeParse(raw);
  if (!parsed.success) {
    const message = parsed.error.issues[0]?.message ?? "Nieprawidłowa wartość nagłówka Idempotency-Key";
    throw new IdempotencyError(400, "VALIDATION_FAILED", "Nieprawidłowy nagłówek Idempotency-Key", [
      { field: IDEMPOTENCY_KEY_HEADER, message },
    ]);
  }
  return parsed.data;
}

/**
 * Kanoniczna serializacja JSON z deterministycznie posortowanymi kluczami obiektów (rekurencyjnie).
 * Zachowuje kolejność elementów tablic i pomija właściwości o wartości `undefined`, jak `JSON.stringify`.
 */
export function canonicalJson(value: unknown): string {
  if (value === undefined) return "";
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) {
    return `[${value.map((item) => (item === undefined ? "null" : canonicalJson(item))).join(",")}]`;
  }
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record)
    .filter((key) => record[key] !== undefined)
    .sort();
  const entries = keys.map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`);
  return `{${entries.join(",")}}`;
}

/**
 * Skrót SHA-256 (hex) identyfikujący treść żądania: metoda + szablon ścieżki + (opcjonalne parametry ścieżki)
 * + kanoniczny JSON treści żądania.
 */
export function computeRequestHash(
  method: string,
  pathTemplate: string,
  body: unknown,
  params?: Record<string, unknown>,
): string {
  const normalizedMethod = method.toUpperCase();
  const hasParams =
    params !== undefined && typeof params === "object" && Object.values(params).some((value) => value !== undefined);
  const payload = hasParams
    ? `${normalizedMethod}\n${pathTemplate}\n${canonicalJson(params)}\n${canonicalJson(body)}`
    : `${normalizedMethod}\n${pathTemplate}\n${canonicalJson(body)}`;
  return createHash("sha256").update(payload).digest("hex");
}

/** Serializuje równoległe żądania z tą samą trójką `(organizationId, principal, key)` do końca transakcji. */
async function lockIdempotencyKey(tx: Tx, organizationId: string, principal: string, key: string): Promise<void> {
  const lockKey = `idempotency:${organizationId}:${principal.length}:${principal}:${key}`;
  await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtextextended(${lockKey}::text, 0))`;
}

export interface IdempotentExecutionResult {
  status: number;
  body: unknown;
}

export interface ExecuteWithIdempotencyInput {
  db: PrismaClient;
  organizationId: string;
  /** Identyfikator wywołującego: UUID konta (token użytkownika) albo `client_id` (token maszynowy). */
  principal: string;
  key: string;
  method: string;
  /** Szablon ścieżki z katalogu tras (np. `/core/v1/employees`), nie surowy URL. */
  pathTemplate: string;
  body: unknown;
  params?: Record<string, unknown> | undefined;
  now: Date;
  run: (tx: Tx) => Promise<IdempotentExecutionResult>;
}

export interface ExecuteWithIdempotencyOutcome {
  replayed: boolean;
  status: number;
  body: unknown;
}

/**
 * Wykonuje operację zapisu w pojedynczej transakcji `withOrganization` pod blokadą doradczą na
 * `(organizationId, principal, key)`:
 * - jeśli klucz istnieje, nie wygasł i ma ten sam `requestHash` -> zwraca zapisaną odpowiedź (`replayed: true`),
 * - jeśli klucz istnieje, nie wygasł i ma inny `requestHash` -> rzuca `409 CONFLICT`,
 * - jeśli klucz nie istnieje albo wygasł -> uruchamia `run(tx)` i zapisuje odpowiedź 2xx w tej samej transakcji.
 * Błąd w `run(tx)` wycofuje całą transakcję, więc klucz nie jest zapisywany i klient może ponowić żądanie.
 */
export async function executeWithIdempotency({
  db,
  organizationId,
  principal,
  key,
  method,
  pathTemplate,
  body,
  params,
  now,
  run,
}: ExecuteWithIdempotencyInput): Promise<ExecuteWithIdempotencyOutcome> {
  const normalizedMethod = method.toUpperCase();
  const requestHash = computeRequestHash(normalizedMethod, pathTemplate, body, params);

  return withOrganization(db, organizationId, async (tx) => {
    await lockIdempotencyKey(tx, organizationId, principal, key);

    const existing = await tx.idempotencyKey.findUnique({
      where: {
        organizationId_principal_key: { organizationId, principal, key },
      },
    });

    if (existing && existing.expiresAt.getTime() > now.getTime()) {
      if (existing.requestHash !== requestHash) {
        throw new IdempotencyError(409, "CONFLICT", "Ten klucz Idempotency-Key był już użyty z inną treścią żądania.");
      }
      return {
        replayed: true,
        status: existing.responseStatus,
        body: existing.responseBody,
      };
    }

    const result = await run(tx);

    if (result.status >= 200 && result.status < 300) {
      const expiresAt = new Date(now.getTime() + IDEMPOTENCY_KEY_TTL_MS);
      const responseBody =
        result.body === undefined || result.body === null ? Prisma.JsonNull : (result.body as Prisma.InputJsonValue);
      const recordData = {
        method: normalizedMethod,
        path: pathTemplate,
        requestHash,
        responseStatus: result.status,
        responseBody,
        createdAt: now,
        expiresAt,
      };
      await tx.idempotencyKey.upsert({
        where: {
          organizationId_principal_key: { organizationId, principal, key },
        },
        create: {
          id: uuidv7(now.getTime()),
          organizationId,
          principal,
          key,
          ...recordData,
        },
        update: recordData,
      });
    }

    return {
      replayed: false,
      status: result.status,
      body: result.body,
    };
  });
}

/** Usuwa wszystkie wygasłe klucze powtórzeń w kolejnych porcjach (`idempotency_keys_cleanup_expired`). */
export async function cleanupAllExpiredIdempotencyKeys(
  db: PrismaClient,
  batchSize = IDEMPOTENCY_CLEANUP_BATCH_SIZE,
): Promise<number> {
  let total = 0;
  for (;;) {
    const deleted = await cleanupExpiredIdempotencyKeys(db, batchSize);
    total += deleted;
    if (deleted < batchSize) return total;
  }
}

export interface IdempotencyCleanupOptions {
  db: PrismaClient;
  /** Odstęp między przebiegami (ms). */
  intervalMs: number;
  onError?: (error: unknown) => void;
  /** Nadpisanie funkcji sprzątającej (do testów jednostkowych). */
  cleanup?: (db: PrismaClient) => Promise<number>;
}

/**
 * Okresowe sprzątanie wygasłych kluczy `Idempotency-Key` w procesie Core API.
 * Przebiegi nie nakładają się, a błąd bazy nie zatrzymuje pętli. Zwraca funkcję zatrzymującą.
 */
export function startIdempotencyCleanup({
  db,
  intervalMs,
  onError,
  cleanup = cleanupAllExpiredIdempotencyKeys,
}: IdempotencyCleanupOptions): () => void {
  let stopped = false;
  let timer: ReturnType<typeof setTimeout> | undefined;
  const tick = async () => {
    try {
      await cleanup(db);
    } catch (error) {
      onError?.(error);
    }
    if (!stopped) timer = setTimeout(() => void tick(), intervalMs);
  };
  timer = setTimeout(() => void tick(), 0);
  return () => {
    stopped = true;
    if (timer) clearTimeout(timer);
  };
}
