import { AUDIT_LOG_RETENTION_MS, IsoDatetime, type AuditLogEntry, type ListAuditLogQuery } from "@core/contracts";
import { uuidv7, type Prisma, type Tx } from "@core/db";
import type { FastifyRequest } from "fastify";
import { z } from "zod";

export interface AuditActorAccount {
  accountId: string;
  organizationId: string;
}

export interface AuditEntryInput {
  action: string;
  resourceType: string;
  resourceId: string;
  metadata?: Prisma.InputJsonValue;
}

export interface AuditLogCursor {
  t: Date;
  id: string;
}

export interface ListAuditLogOptions {
  organizationId: string;
  query: ListAuditLogQuery;
  cursor?: AuditLogCursor;
  now: Date;
}

export class AuditCursorError extends Error {
  constructor(message = "Nieprawidłowy kursor stronicowania") {
    super(message);
  }
}

/** Czytelne polskie etykiety znanych akcji platformy Core; dla nieznanych akcji (np. z produktów) zwracamy surową nazwę. */
export const AUDIT_ACTION_LABELS: Readonly<Record<string, string>> = {
  "organization.owner.transferred": "Przekazano rolę Ownera firmy",
  "organization.activated": "Aktywowano firmę",
  "organization.updated": "Zaktualizowano dane firmy",
  "organization.domain.added": "Dodano domenę firmy",
  "organization.domain.verified": "Zweryfikowano domenę firmy",
  "organization.domain.removed": "Usunięto domenę firmy",
  "organization.domain.primary_changed": "Zmieniono główną domenę firmy",
  "employee.created": "Dodano pracownika",
  "employee.updated": "Zaktualizowano dane pracownika",
  "account.deactivated": "Wyłączono konto pracownika",
  "account.reactivated": "Przywrócono konto pracownika",
  "invitation.created": "Wysłano zaproszenie pracownika",
  "invitation.resent": "Ponownie wysłano zaproszenie pracownika",
  "invitation.revoked": "Cofnięto zaproszenie pracownika",
  "invitation.accepted": "Zaakceptowano zaproszenie pracownika",
  "unit.created": "Utworzono jednostkę organizacyjną",
  "unit.updated": "Zaktualizowano jednostkę organizacyjną",
  "unit.deleted": "Usunięto jednostkę organizacyjną",
  "unit.member.set": "Zapisano członkostwo w jednostce organizacyjnej",
  "unit.member.removed": "Usunięto pracownika z jednostki organizacyjnej",
  "role.created": "Utworzono rolę",
  "role.updated": "Zaktualizowano rolę",
  "role.archived": "Zarchiwizowano rolę",
  "role.deleted": "Usunięto rolę",
  "role.assigned": "Nadano rolę",
  "role.revoked": "Odebrano rolę",
  "app_access.granted": "Włączono dostęp do aplikacji",
  "app_access.revoked": "Wyłączono dostęp do aplikacji",
  "entitlement.granted": "Przyznano firmie dostęp do produktu",
  "entitlement.ended": "Zakończono dostęp firmy do produktu",
};

const SENSITIVE_METADATA_KEY_RE = /token|secret|password|hash|authorization|cookie/i;
const BASE64URL_RE = /^[A-Za-z0-9_-]+$/;

const AuditCursorPayload = z
  .object({
    t: IsoDatetime,
    id: z.uuid(),
  })
  .strict();

export function getAuditActionLabel(action: string): string {
  return Object.hasOwn(AUDIT_ACTION_LABELS, action) ? AUDIT_ACTION_LABELS[action]! : action;
}

function sanitizeAuditValue(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map((item) => sanitizeAuditValue(item));
  }
  if (value !== null && typeof value === "object") {
    const clean: Record<string, unknown> = {};
    for (const [key, entry] of Object.entries(value as Record<string, unknown>)) {
      if (SENSITIVE_METADATA_KEY_RE.test(key)) continue;
      clean[key] = sanitizeAuditValue(entry);
    }
    return clean;
  }
  return value;
}

/**
 * Usuwa rekurencyjnie wrażliwe klucze (tokeny, sekrety, hasła, skróty, nagłówki autoryzacji i ciasteczka)
 * z pola `metadata` przed zwrotem wpisu dziennika w API (obrona w głąb, ADR-0039).
 */
export function sanitizeAuditMetadata(raw: unknown): Record<string, unknown> {
  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) {
    return {};
  }
  return sanitizeAuditValue(raw) as Record<string, unknown>;
}

/** Koduje kursor stronicowania `(createdAt, id)` jako nieprzezroczysty base64url JSON. */
export function encodeAuditCursor(createdAt: Date, id: string): string {
  return Buffer.from(JSON.stringify({ t: createdAt.toISOString(), id }), "utf8").toString("base64url");
}

/** Dekoduje i kanonicznie waliduje kursor stronicowania dziennika zdarzeń. */
export function decodeAuditCursor(cursor: string): AuditLogCursor {
  if (!BASE64URL_RE.test(cursor)) {
    throw new AuditCursorError();
  }
  let parsedJson: unknown;
  try {
    parsedJson = JSON.parse(Buffer.from(cursor, "base64url").toString("utf8"));
  } catch {
    throw new AuditCursorError();
  }
  const parsed = AuditCursorPayload.safeParse(parsedJson);
  if (!parsed.success) {
    throw new AuditCursorError();
  }
  const t = new Date(parsed.data.t);
  if (Number.isNaN(t.getTime()) || encodeAuditCursor(t, parsed.data.id) !== cursor) {
    throw new AuditCursorError();
  }
  return { t, id: parsed.data.id };
}

/**
 * Odczytuje stronę wpisów dziennika zdarzeń bieżącej firmy (w transakcji `withOrganization`)
 * od najnowszych (`createdAt DESC, id DESC`), pilnując 730-dniowego okna retencji, uzupełniając nazwy
 * aktorów w jednym zapytaniu i usuwając wrażliwe pola z `metadata`.
 */
export async function listAuditLogEntries(
  tx: Tx,
  options: ListAuditLogOptions,
): Promise<{ items: AuditLogEntry[]; nextCursor: string | null }> {
  const { organizationId, query, cursor, now } = options;
  const retentionFloor = new Date(now.getTime() - AUDIT_LOG_RETENTION_MS);
  const fromDate = query.from ? new Date(query.from) : undefined;
  const toDate = query.to ? new Date(query.to) : undefined;
  const effectiveFrom = fromDate && fromDate > retentionFloor ? fromDate : retentionFloor;

  if (toDate && toDate < effectiveFrom) {
    return { items: [], nextCursor: null };
  }

  const effectiveTo = cursor ? (toDate && toDate < cursor.t ? toDate : cursor.t) : toDate;
  if (effectiveTo && effectiveTo < effectiveFrom) {
    return { items: [], nextCursor: null };
  }

  const filters: Prisma.AuditLogWhereInput[] = [
    { organizationId },
    {
      createdAt: {
        gte: effectiveFrom,
        ...(effectiveTo ? { lte: effectiveTo } : {}),
      },
    },
  ];

  if (query.actorAccountId !== undefined) {
    filters.push({ actorAccountId: query.actorAccountId });
  }
  if (query.actorType !== undefined) {
    filters.push({ actorType: query.actorType });
  }
  if (query.action !== undefined) {
    filters.push({ action: query.action });
  }
  if (query.resourceType !== undefined) {
    filters.push({ resourceType: query.resourceType });
  }
  if (query.resourceId !== undefined) {
    filters.push({ resourceId: query.resourceId });
  }
  if (cursor) {
    filters.push({
      OR: [{ createdAt: { lt: cursor.t } }, { AND: [{ createdAt: cursor.t }, { id: { lt: cursor.id } }] }],
    });
  }

  const rows = await tx.auditLog.findMany({
    where: { AND: filters },
    select: {
      id: true,
      actorType: true,
      actorAccountId: true,
      product: { select: { key: true } },
      action: true,
      resourceType: true,
      resourceId: true,
      metadata: true,
      ipAddress: true,
      userAgent: true,
      requestId: true,
      supportAccessGrantId: true,
      createdAt: true,
    },
    orderBy: [{ createdAt: "desc" }, { id: "desc" }],
    take: query.limit + 1,
  });

  const hasMore = rows.length > query.limit;
  const pageRows = hasMore ? rows.slice(0, query.limit) : rows;
  const last = pageRows[pageRows.length - 1];
  const nextCursor = hasMore && last ? encodeAuditCursor(last.createdAt, last.id) : null;

  const actorAccountIds = [
    ...new Set(pageRows.map((row) => row.actorAccountId).filter((id): id is string => id !== null)),
  ];

  const displayNameByAccountId = new Map<string, string>();
  if (actorAccountIds.length > 0) {
    const accounts = await tx.account.findMany({
      where: { id: { in: actorAccountIds } },
      select: {
        id: true,
        employee: { select: { firstName: true, lastName: true } },
      },
    });
    for (const account of accounts) {
      const fullName = `${account.employee.firstName} ${account.employee.lastName}`.trim();
      if (fullName.length > 0) {
        displayNameByAccountId.set(account.id, fullName);
      }
    }
  }

  const items: AuditLogEntry[] = pageRows.map((row) => ({
    id: row.id,
    actorType: row.actorType,
    actorAccountId: row.actorAccountId,
    actorDisplayName: row.actorAccountId !== null ? (displayNameByAccountId.get(row.actorAccountId) ?? null) : null,
    product: row.product?.key ?? null,
    action: row.action,
    actionLabel: getAuditActionLabel(row.action),
    resourceType: row.resourceType,
    resourceId: row.resourceId,
    metadata: sanitizeAuditMetadata(row.metadata),
    ipAddress: row.ipAddress,
    userAgent: row.userAgent,
    requestId: row.requestId,
    supportAccessGrantId: row.supportAccessGrantId,
    createdAt: row.createdAt.toISOString(),
  }));

  return { items, nextCursor };
}

function extractUserAgent(request: FastifyRequest): string | null {
  const header = request.headers["user-agent"];
  return typeof header === "string" && header.length > 0 ? header : null;
}

/**
 * Zapisuje wpis w centralnym dzienniku zdarzeń firmy w tej samej transakcji co zmiana (`withOrganization`).
 * W polu `metadata` nie zapisujemy danych osobowych poza identyfikatorami (ADR-0039).
 */
export async function writeAudit(
  tx: Tx,
  request: FastifyRequest,
  who: AuditActorAccount,
  entry: AuditEntryInput,
): Promise<void> {
  await tx.auditLog.create({
    data: {
      id: uuidv7(),
      organizationId: who.organizationId,
      actorType: "ACCOUNT",
      actorAccountId: who.accountId,
      action: entry.action,
      resourceType: entry.resourceType,
      resourceId: entry.resourceId,
      metadata: entry.metadata ?? {},
      ipAddress: request.ip || null,
      userAgent: extractUserAgent(request),
      requestId: request.id,
    },
  });
}
