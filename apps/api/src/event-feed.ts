import type { PrismaClient } from "@core/db";
import type { ProductEvent } from "@core/contracts";

/** Ile zdarzeń wysyłamy w jednej transakcji (`outbox_publish_pending`). */
export const PUBLISH_BATCH_SIZE = 100;

/**
 * Wysyła porcję niewysłanych zdarzeń z `outbox_events` do kanału produktów: nadaje im kolejne numery
 * `sequence` i `publishedAt`. Numery nadaje jeden wysyłający naraz (blokada w funkcji bazy). Zwraca liczbę zdarzeń.
 */
export async function publishPendingEvents(db: PrismaClient, limit = PUBLISH_BATCH_SIZE): Promise<number> {
  const rows = await db.$queryRaw<{ published: number }[]>`
    SELECT "public"."outbox_publish_pending"(${limit}::integer) AS published`;
  return rows[0]?.published ?? 0;
}

/** Wysyła wszystko, co czeka (kolejne porcje, aż porcja nie będzie pełna). */
export async function publishAllPendingEvents(db: PrismaClient): Promise<number> {
  let total = 0;
  for (;;) {
    const published = await publishPendingEvents(db);
    total += published;
    if (published < PUBLISH_BATCH_SIZE) return total;
  }
}

export interface OutboxPublisherOptions {
  db: PrismaClient;
  /** Odstęp między przebiegami (ms). */
  intervalMs: number;
  onError?: (error: unknown) => void;
}

/**
 * Proces wysyłki w Core API: co `intervalMs` wysyła oczekujące zdarzenia. Przebiegi nie nakładają się,
 * a błąd (np. chwilowy brak bazy) nie zatrzymuje pętli. Zwraca funkcję zatrzymującą.
 */
export function startOutboxPublisher({ db, intervalMs, onError }: OutboxPublisherOptions): () => void {
  let stopped = false;
  let timer: ReturnType<typeof setTimeout> | undefined;
  const tick = async () => {
    try {
      await publishAllPendingEvents(db);
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

interface FeedRow {
  sequence: bigint;
  id: string;
  organizationId: string;
  type: string;
  version: number;
  resourceType: string;
  resourceId: string;
  resourceVersion: number;
  payload: unknown;
  occurredAt: Date;
}

/** Strona kanału produktu: zdarzenia firm z aktywnym dostępem do produktu, po numerze `after` (wyłącznie). */
export async function readProductEventFeed(
  db: PrismaClient,
  productId: string,
  after: bigint,
  limit: number,
): Promise<ProductEvent[]> {
  const rows = await db.$queryRaw<FeedRow[]>`
    SELECT * FROM "public"."product_event_feed"(${productId}::uuid, ${after}::bigint, ${limit}::integer)`;
  return rows.map((row) => ({
    sequence: row.sequence.toString(),
    id: row.id,
    type: row.type,
    version: row.version,
    source: "core",
    organizationId: row.organizationId,
    resourceType: row.resourceType,
    resourceId: row.resourceId,
    resourceVersion: row.resourceVersion,
    occurredAt: row.occurredAt.toISOString(),
    data: (row.payload ?? {}) as Record<string, unknown>,
  }));
}
