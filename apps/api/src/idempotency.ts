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

/** Maksymalny bezpieczny odstęp dla `setTimeout` w Node.js (2^31 - 1 ms, ok. 24,8 dnia). */
export const MAX_IDEMPOTENCY_CLEANUP_INTERVAL_MS = 2_147_483_647;

/** Ile wygasłych kluczy usuwamy w jednej transakcji (`idempotency_keys_cleanup_expired`). */
export const IDEMPOTENCY_CLEANUP_BATCH_SIZE = 1000;

/** Rejestruje krok wykonywany w tej samej transakcji po zapisaniu klucza `Idempotency-Key` (nigdy przy powtórce). */
export type DeferFn = (fn: () => Promise<void>) => void;

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

/** Identyfikator wywołującego dla tokenu użytkownika (przestrzeń nazw `account:<uuid>`). */
export function accountPrincipal(accountId: string): string {
  return `account:${accountId}`;
}

/** Identyfikator wywołującego dla tokenu maszynowego OAuth (przestrzeń nazw `client:<clientId>`). */
export function clientPrincipal(clientId: string): string {
  return `client:${clientId}`;
}

/**
 * Waliduje zmienną `CORE_IDEMPOTENCY_CLEANUP_INTERVAL_MS` przy starcie procesu.
 * Brak zmiennej oznacza wartość domyślną (1 h), `0` wyłącza sprzątanie, a błędna wartość przerywa start.
 */
export function parseIdempotencyCleanupIntervalMs(raw: string | undefined): number {
  if (raw === undefined) return DEFAULT_IDEMPOTENCY_CLEANUP_INTERVAL_MS;
  const trimmed = raw.trim();
  if (!/^(0|[1-9][0-9]*)$/.test(trimmed)) {
    throw new Error(
      `Nieprawidłowa wartość CORE_IDEMPOTENCY_CLEANUP_INTERVAL_MS="${raw}": wymagana liczba całkowita z zakresu 0..${MAX_IDEMPOTENCY_CLEANUP_INTERVAL_MS}`,
    );
  }
  const value = Number(trimmed);
  if (!Number.isSafeInteger(value) || value > MAX_IDEMPOTENCY_CLEANUP_INTERVAL_MS) {
    throw new Error(
      `Nieprawidłowa wartość CORE_IDEMPOTENCY_CLEANUP_INTERVAL_MS="${raw}": wymagana liczba całkowita z zakresu 0..${MAX_IDEMPOTENCY_CLEANUP_INTERVAL_MS}`,
    );
  }
  return value;
}

/**
 * Odczytuje nagłówek `Idempotency-Key` z żądania HTTP z wykrywaniem duplikatów:
 * najpierw sprawdza `request.raw.headersDistinct["idempotency-key"]` (Node.js nie scala tam powtórzonych
 * nagłówków), następnie `request.raw.rawHeaders` (np. w `app.inject` / `light-my-request`), rozpakowując
 * jedno wystąpienie i zostawiając dłuższą tablicę do odrzucenia kodem 400; w przeciwnym razie wraca do
 * `request.headers["idempotency-key"]`.
 */
export function extractIdempotencyKeyHeader(request: {
  headers: Record<string, string | string[] | undefined>;
  raw?:
    | {
        headersDistinct?: Record<string, string[] | undefined> | undefined;
        rawHeaders?: string[] | undefined;
      }
    | undefined;
}): string | string[] | undefined {
  const distinct = request.raw?.headersDistinct?.["idempotency-key"];
  if (distinct !== undefined) {
    if (distinct.length === 0) return undefined;
    return distinct.length === 1 ? distinct[0] : distinct;
  }
  const rawHeaders = request.raw?.rawHeaders;
  if (Array.isArray(rawHeaders)) {
    const values: string[] = [];
    for (let i = 0; i + 1 < rawHeaders.length; i += 2) {
      if (rawHeaders[i]?.toLowerCase() === "idempotency-key") {
        values.push(rawHeaders[i + 1] ?? "");
      }
    }
    if (values.length > 0) {
      return values.length === 1 ? values[0] : values;
    }
  }
  return request.headers["idempotency-key"];
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
  /** Identyfikator wywołującego w przestrzeni nazw: `account:<uuid>` albo `client:<clientId>`. */
  principal: string;
  key: string;
  method: string;
  /** Szablon ścieżki z katalogu tras (np. `/core/v1/employees`), nie surowy URL. */
  pathTemplate: string;
  body: unknown;
  params?: Record<string, unknown> | undefined;
  /** Zegar wywoływany po przejęciu blokady doradczej (do deterministycznych testów wygasania). */
  getNow?: (() => Date) | undefined;
  run: (tx: Tx, defer: DeferFn, now: Date) => Promise<IdempotentExecutionResult>;
}

export interface ExecuteWithIdempotencyOutcome {
  replayed: boolean;
  status: number;
  body: unknown;
}

/**
 * Wykonuje operację zapisu w pojedynczej transakcji `withOrganization` pod blokadą doradczą na
 * `(organizationId, principal, key)`:
 * - po przejęciu blokady pobiera bieżący czas (`getNow`),
 * - jeśli klucz istnieje, nie wygasł i ma ten sam `requestHash` -> zwraca zapisaną odpowiedź (`replayed: true`)
 *   bez wywoływania `run` ani kroków odłożonych przez `defer`,
 * - jeśli klucz istnieje, nie wygasł i ma inny `requestHash` -> rzuca `409 CONFLICT`,
 * - jeśli klucz nie istnieje albo wygasł -> uruchamia `run(tx, defer, now)`, zapisuje odpowiedź 2xx w tej samej
 *   transakcji, a na końcu (przed `COMMIT`) uruchamia kolejno funkcje zarejestrowane przez `defer`.
 * Błąd w `run` lub w funkcji z `defer` wycofuje całą transakcję, więc klucz nie jest zapisywany i klient może ponowić żądanie.
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
  getNow = () => new Date(),
  run,
}: ExecuteWithIdempotencyInput): Promise<ExecuteWithIdempotencyOutcome> {
  const normalizedMethod = method.toUpperCase();
  const requestHash = computeRequestHash(normalizedMethod, pathTemplate, body, params);

  return withOrganization(db, organizationId, async (tx) => {
    await lockIdempotencyKey(tx, organizationId, principal, key);
    const now = getNow();

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

    const deferred: (() => Promise<void>)[] = [];
    const defer: DeferFn = (fn) => {
      deferred.push(fn);
    };

    const result = await run(tx, defer, now);

    if (result.status >= 200 && result.status < 300) {
      const expiresAt = new Date(now.getTime() + IDEMPOTENCY_KEY_TTL_MS);
      const responseBody =
        result.status === 204 || result.body === undefined || result.body === null
          ? Prisma.JsonNull
          : (result.body as Prisma.InputJsonValue);
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

    for (const fn of deferred) {
      await fn();
    }

    return {
      replayed: false,
      status: result.status,
      body: result.body,
    };
  });
}

/**
 * Usuwa wygasłe klucze powtórzeń w kolejnych porcjach (`idempotency_keys_cleanup_expired`).
 * Jeśli przekazano `shouldStop`, przerywa między porcjami przy zamykaniu serwera.
 */
export async function cleanupAllExpiredIdempotencyKeys(
  db: PrismaClient,
  batchSize = IDEMPOTENCY_CLEANUP_BATCH_SIZE,
  shouldStop?: () => boolean,
): Promise<number> {
  let total = 0;
  for (;;) {
    if (shouldStop?.()) return total;
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
  cleanup?: (db: PrismaClient, shouldStop: () => boolean) => Promise<number>;
}

/**
 * Okresowe sprzątanie wygasłych kluczy `Idempotency-Key` w procesie Core API.
 * Przebiegi nie nakładają się, timer używa `unref()`, błąd bazy nie zatrzymuje pętli,
 * a zwracana funkcja zatrzymująca przerywa między porcjami i czeka na bieżący przebieg.
 */
export function startIdempotencyCleanup({
  db,
  intervalMs,
  onError,
  cleanup = (client, shouldStop) =>
    cleanupAllExpiredIdempotencyKeys(client, IDEMPOTENCY_CLEANUP_BATCH_SIZE, shouldStop),
}: IdempotencyCleanupOptions): () => Promise<void> {
  let stopped = false;
  let timer: ReturnType<typeof setTimeout> | undefined;
  let inFlight: Promise<void> | null = null;

  const schedule = (delayMs: number) => {
    if (stopped) return;
    timer = setTimeout(() => {
      timer = undefined;
      inFlight = tick().finally(() => {
        inFlight = null;
      });
    }, delayMs);
    timer.unref?.();
  };

  const tick = async () => {
    try {
      await cleanup(db, () => stopped);
    } catch (error) {
      onError?.(error);
    }
    schedule(intervalMs);
  };

  schedule(0);

  return async () => {
    stopped = true;
    if (timer) {
      clearTimeout(timer);
      timer = undefined;
    }
    if (inFlight) {
      await inFlight;
    }
  };
}
