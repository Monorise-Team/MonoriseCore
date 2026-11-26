import { createHmac, timingSafeEqual } from "node:crypto";
import {
  API_PREFIX,
  getNotificationCategory,
  NOTIFICATION_CATEGORIES,
  NotificationCategoryKey,
  type ApiErrorBody,
  type ErrorCode,
  type NotificationPreference,
  type NotificationResult,
  type UnsubscribeNotificationResult,
} from "@core/contracts";
import { uuidv7, withOrganization, type PrismaClient, type Tx } from "@core/db";
import { z } from "zod";

export const MIN_NOTIFICATIONS_UNSUBSCRIBE_SECRET_LENGTH = 32;

const BASE64URL_RE = /^[A-Za-z0-9_-]+$/;
const UNSUBSCRIBE_TOKEN_MAX_LENGTH = 1024;
const UNSUBSCRIBE_SECRET_DOMAIN = "monorise:core:notifications:unsubscribe:v1";

const UnsubscribeTokenPayloadSchema = z
  .object({
    organizationId: z.uuid(),
    accountId: z.uuid(),
    category: NotificationCategoryKey,
  })
  .strict();

export type UnsubscribeTokenPayload = z.infer<typeof UnsubscribeTokenPayloadSchema>;

export class NotificationError extends Error {
  constructor(
    readonly status: number,
    readonly code: ErrorCode,
    message: string,
    readonly details: ApiErrorBody["details"] = [],
  ) {
    super(message);
  }
}

export interface NotificationAuditMeta {
  ipAddress: string | null;
  userAgent: string | null;
  requestId: string | null;
}

export interface CreateNotificationInput {
  organizationId: string;
  productId: string;
  productKey: string;
  category: NotificationCategoryKey;
  recipientAccountId: string;
  title: string;
  body: string;
  actionUrl: string | null;
  /** Jawny zegar wyłącznie do testów; `undefined` używa zegara PostgreSQL `now()` dla `mail_outbox`. */
  now?: Date | undefined;
}

export interface CreateNotificationOutcome {
  result: NotificationResult;
  queued: boolean;
  mailJobId?: string | undefined;
}

function deriveDevUnsubscribeSecret(baseSecret: string): string {
  return createHmac("sha256", baseSecret).update(UNSUBSCRIBE_SECRET_DOMAIN).digest("hex");
}

/**
 * Wyznacza sekret HMAC-SHA256 dla tokenów jednoklikowego wypisania z powiadomień (RFC 8058):
 * - na produkcji (`NODE_ENV === "production"`) zawsze wymagany w `CORE_NOTIFICATIONS_UNSUBSCRIBE_SECRET`
 *   (po przycięciu spacji co najmniej 32 znaki, bez fallbacku),
 * - w `development` i `test` wraca do wartości wyprowadzonej z sekretu deweloperskiego Core
 *   (`CORE_DOMAIN_VERIFICATION_SECRET`, z separacją domenową przez HMAC-SHA256).
 */
export function resolveNotificationsUnsubscribeSecret(
  options: {
    env?: {
      NODE_ENV?: string | undefined;
      CORE_NOTIFICATIONS_UNSUBSCRIBE_SECRET?: string | undefined;
      CORE_DOMAIN_VERIFICATION_SECRET?: string | undefined;
    };
    fallbackSecret?: string | undefined;
  } = {},
): string {
  const env = options.env ?? process.env;
  const trimmed = env.CORE_NOTIFICATIONS_UNSUBSCRIBE_SECRET?.trim() ?? "";
  const isProd = env.NODE_ENV === "production";

  if (isProd) {
    if (trimmed.length < MIN_NOTIFICATIONS_UNSUBSCRIBE_SECRET_LENGTH) {
      throw new Error(
        `Zmienna środowiskowa CORE_NOTIFICATIONS_UNSUBSCRIBE_SECRET jest wymagana na produkcji i musi mieć co najmniej ${MIN_NOTIFICATIONS_UNSUBSCRIBE_SECRET_LENGTH} znaki`,
      );
    }
    return trimmed;
  }

  if (trimmed.length > 0) {
    return trimmed;
  }

  const base = options.fallbackSecret?.trim() || env.CORE_DOMAIN_VERIFICATION_SECRET?.trim() || "";
  if (base.length > 0) {
    return deriveDevUnsubscribeSecret(base);
  }

  if (env.NODE_ENV === "test") {
    return deriveDevUnsubscribeSecret("monorise-core-test-unsubscribe-secret");
  }

  throw new Error("Brak zmiennej środowiskowej CORE_NOTIFICATIONS_UNSUBSCRIBE_SECRET (lokalnie: pnpm setup:env)");
}

/** Wyznacza publiczny bazowy adres Core API do linków wypisania z powiadomień. */
export function resolveApiUrl(
  apiUrl?: string,
  env: { CORE_API_URL?: string | undefined; CORE_API_AUDIENCE?: string | undefined } = process.env,
): string {
  const raw = apiUrl?.trim() || env.CORE_API_URL?.trim() || env.CORE_API_AUDIENCE?.trim() || "http://localhost:3200";
  return raw.replace(/\/+$/, "");
}

/**
 * Tworzy podpisany token wypisania z powiadomień (RFC 8058):
 * `base64url(JSON({ organizationId, accountId, category })) + "." + base64url(HMAC-SHA256)`.
 */
export function createUnsubscribeToken(payload: UnsubscribeTokenPayload, secret: string): string {
  if (!secret) {
    throw new Error("Brak sekretu podpisywania tokenu wypisania z powiadomień");
  }
  const encodedPayload = Buffer.from(
    JSON.stringify({
      organizationId: payload.organizationId,
      accountId: payload.accountId,
      category: payload.category,
    }),
    "utf8",
  ).toString("base64url");
  const signature = createHmac("sha256", secret).update(encodedPayload).digest("base64url");
  return `${encodedPayload}.${signature}`;
}

/**
 * Weryfikuje podpis HMAC-SHA256 tokenu wypisania w stałym czasie (`timingSafeEqual`) i waliduje ładunek.
 * Zwraca `null` dla każdego nieprawidłowego, zmanipulowanego lub nieopcjonalnego tokenu.
 */
export function verifyUnsubscribeToken(token: string, secret: string): UnsubscribeTokenPayload | null {
  if (!token || !secret || token.length > UNSUBSCRIBE_TOKEN_MAX_LENGTH) {
    return null;
  }
  const parts = token.split(".");
  if (parts.length !== 2) {
    return null;
  }
  const [encodedPayload, providedSignature] = parts;
  if (
    !encodedPayload ||
    !providedSignature ||
    !BASE64URL_RE.test(encodedPayload) ||
    !BASE64URL_RE.test(providedSignature)
  ) {
    return null;
  }

  const expectedSig = createHmac("sha256", secret).update(encodedPayload).digest();
  const actualSig = Buffer.from(providedSignature, "base64url");
  if (
    actualSig.length !== expectedSig.length ||
    actualSig.toString("base64url") !== providedSignature ||
    !timingSafeEqual(actualSig, expectedSig)
  ) {
    return null;
  }

  let parsedJson: unknown;
  try {
    parsedJson = JSON.parse(Buffer.from(encodedPayload, "base64url").toString("utf8"));
  } catch {
    return null;
  }

  const parsed = UnsubscribeTokenPayloadSchema.safeParse(parsedJson);
  if (!parsed.success) {
    return null;
  }

  const categoryDef = getNotificationCategory(parsed.data.category);
  if (!categoryDef || !categoryDef.optional) {
    return null;
  }

  return parsed.data;
}

export function buildUnsubscribeUrl(token: string, apiUrl?: string): string {
  const base = resolveApiUrl(apiUrl);
  return `${base}${API_PREFIX}/notifications/unsubscribe/${encodeURIComponent(token)}`;
}

/**
 * Pilnuje, żeby `actionUrl` w powiadomieniu produktu wskazywał wyłącznie ten sam origin (schemat, host, port)
 * co zarejestrowane pole `uri` klienta OAuth tego produktu, bez danych uwierzytelniających w URL.
 */
export function validateActionUrlOrigin(actionUrl: string, clientUri: string | null): void {
  if (!clientUri) {
    throw new NotificationError(422, "VALIDATION_FAILED", "Klient produktu nie ma skonfigurowanego adresu aplikacji", [
      { field: "actionUrl", message: "Nie można zweryfikować originu actionUrl dla tego produktu" },
    ]);
  }

  let allowedUrl: URL;
  try {
    allowedUrl = new URL(clientUri);
  } catch {
    throw new NotificationError(422, "VALIDATION_FAILED", "Klient produktu ma nieprawidłowy adres aplikacji", [
      { field: "actionUrl", message: "Nie można zweryfikować originu actionUrl dla tego produktu" },
    ]);
  }
  if ((allowedUrl.protocol !== "http:" && allowedUrl.protocol !== "https:") || allowedUrl.origin === "null") {
    throw new NotificationError(422, "VALIDATION_FAILED", "Klient produktu ma nieprawidłowy adres aplikacji", [
      { field: "actionUrl", message: "Nie można zweryfikować originu actionUrl dla tego produktu" },
    ]);
  }

  let parsedAction: URL;
  try {
    parsedAction = new URL(actionUrl);
  } catch {
    throw new NotificationError(422, "VALIDATION_FAILED", "Błędne dane wejściowe", [
      { field: "actionUrl", message: "Podaj poprawny adres URL" },
    ]);
  }

  if (
    (parsedAction.protocol !== "http:" && parsedAction.protocol !== "https:") ||
    parsedAction.origin === "null" ||
    parsedAction.username !== "" ||
    parsedAction.password !== "" ||
    parsedAction.origin !== allowedUrl.origin
  ) {
    throw new NotificationError(
      422,
      "VALIDATION_FAILED",
      "Adres actionUrl musi należeć do originu aplikacji produktu",
      [{ field: "actionUrl", message: "Adres actionUrl musi mieć ten sam origin co adres produktu" }],
    );
  }
}

/** Serializuje operacje na pojedynczym powiadomieniu (np. wysyłka w workerze) do końca transakcji. */
export async function lockNotification(tx: Tx, notificationId: string): Promise<void> {
  await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtextextended('notification:' || ${notificationId}::uuid::text, 0))`;
}

/**
 * Sprawdza, czy odbiorca jest aktywnym pracownikiem bieżącej firmy (pod RLS) z aktywnym kontem
 * oraz dostępem do wskazanego produktu (Owner firmy albo aktywny wpis `AppAccess`).
 */
export async function checkRecipientProductAccess(
  tx: Tx,
  accountId: string,
  productId: string,
): Promise<{ hasAccess: boolean; email: string | null }> {
  const account = await tx.account.findUnique({
    where: { id: accountId },
    select: {
      id: true,
      email: true,
      status: true,
      employee: { select: { status: true } },
      organization: { select: { ownerAccountId: true } },
    },
  });

  if (!account || account.status !== "ACTIVE" || account.employee.status !== "ACTIVE") {
    return { hasAccess: false, email: null };
  }

  if (account.organization.ownerAccountId === account.id) {
    return { hasAccess: true, email: account.email };
  }

  const activeAccess = await tx.appAccess.findFirst({
    where: {
      accountId: account.id,
      productId,
      status: "ACTIVE",
    },
    select: { id: true },
  });

  return { hasAccess: activeAccess !== null, email: activeAccess !== null ? account.email : null };
}

/** Zwraca, czy odbiorca ma włączoną kategorię na kanale `EMAIL` (brak wiersza oznacza włączoną). */
export async function isEmailPreferenceEnabled(
  tx: Tx,
  organizationId: string,
  accountId: string,
  category: string,
): Promise<boolean> {
  const pref = await tx.notificationPreference.findUnique({
    where: {
      organizationId_accountId_category_channel: {
        organizationId,
        accountId,
        category,
        channel: "EMAIL",
      },
    },
    select: { enabled: true },
  });
  return pref ? pref.enabled : true;
}

/**
 * Zleca powiadomienie w transakcji `withOrganization`:
 * 1. Sprawdza istnienie firmy (`404`) oraz aktywny `Entitlement` firmy na produkt (`403`).
 * 2. Sprawdza, czy odbiorca to aktywny pracownik firmy z aktywnym kontem i dostępem do produktu
 *    (inaczej zapisuje `SKIPPED` / `NO_ACCESS` i zwraca `202` bez zdradzania szczegółów).
 * 3. Sprawdza preferencję e-mail odbiorcy dla kategorii (wyłączona -> zapisuje `SKIPPED` / `PREFERENCE_OFF`).
 * 4. W przeciwnym razie zapisuje `notifications` (`QUEUED`) oraz wpis w `mail_outbox` (`NOTIFICATION`, `PENDING`)
 *    w jednej transakcji.
 */
export async function createNotification(tx: Tx, input: CreateNotificationInput): Promise<CreateNotificationOutcome> {
  const explicitNow = input.now;
  const now = explicitNow ?? new Date();

  const organization = await tx.organization.findUnique({
    where: { id: input.organizationId },
    select: { id: true },
  });
  if (!organization) {
    throw new NotificationError(404, "NOT_FOUND", "Nie znaleziono firmy");
  }

  const activeEntitlement = await tx.entitlement.findFirst({
    where: {
      productId: input.productId,
      status: "ACTIVE",
      startsAt: { lte: now },
      OR: [{ endsAt: null }, { endsAt: { gt: now } }],
    },
    select: { id: true },
  });
  if (!activeEntitlement) {
    throw new NotificationError(403, "PERMISSION_DENIED", "Firma nie ma aktywnego dostępu do tego produktu");
  }

  const notificationId = uuidv7(now.getTime());
  const access = await checkRecipientProductAccess(tx, input.recipientAccountId, input.productId);
  if (!access.hasAccess) {
    await tx.notification.create({
      data: {
        id: notificationId,
        organizationId: input.organizationId,
        product: input.productKey,
        category: input.category,
        recipientAccountId: input.recipientAccountId,
        title: input.title,
        body: input.body,
        actionUrl: input.actionUrl,
        status: "SKIPPED",
        skipReason: "NO_ACCESS",
        ...(explicitNow !== undefined ? { createdAt: explicitNow } : {}),
      },
    });
    return {
      result: { id: notificationId, status: "SKIPPED", skipReason: "NO_ACCESS" },
      queued: false,
    };
  }

  const enabled = await isEmailPreferenceEnabled(tx, input.organizationId, input.recipientAccountId, input.category);
  if (!enabled) {
    await tx.notification.create({
      data: {
        id: notificationId,
        organizationId: input.organizationId,
        product: input.productKey,
        category: input.category,
        recipientAccountId: input.recipientAccountId,
        title: input.title,
        body: input.body,
        actionUrl: input.actionUrl,
        status: "SKIPPED",
        skipReason: "PREFERENCE_OFF",
        ...(explicitNow !== undefined ? { createdAt: explicitNow } : {}),
      },
    });
    return {
      result: { id: notificationId, status: "SKIPPED", skipReason: "PREFERENCE_OFF" },
      queued: false,
    };
  }

  await tx.notification.create({
    data: {
      id: notificationId,
      organizationId: input.organizationId,
      product: input.productKey,
      category: input.category,
      recipientAccountId: input.recipientAccountId,
      title: input.title,
      body: input.body,
      actionUrl: input.actionUrl,
      status: "QUEUED",
      skipReason: null,
      ...(explicitNow !== undefined ? { createdAt: explicitNow } : {}),
    },
  });

  const mailJob = await tx.mailOutbox.create({
    data: {
      id: uuidv7(now.getTime()),
      organizationId: input.organizationId,
      kind: "NOTIFICATION",
      notificationId,
      status: "PENDING",
      attempts: 0,
      ...(explicitNow !== undefined
        ? { nextAttemptAt: explicitNow, createdAt: explicitNow, updatedAt: explicitNow }
        : {}),
    },
    select: { id: true },
  });

  return {
    result: { id: notificationId, status: "QUEUED", skipReason: null },
    queued: true,
    mailJobId: mailJob.id,
  };
}

/**
 * Zwraca listę kategorii powiadomień dla zalogowanego konta w bieżącej firmie:
 * kategorie kanału `login` (zawsze włączone, nieopcjonalne) oraz kategorie produktów,
 * do których firma ma aktywny `Entitlement` (domyślnie włączone przy braku wiersza).
 */
export async function listNotificationPreferencesForAccount(
  tx: Tx,
  input: { organizationId: string; accountId: string; now: Date },
): Promise<NotificationPreference[]> {
  const [activeEntitlements, preferences] = await Promise.all([
    tx.entitlement.findMany({
      where: {
        status: "ACTIVE",
        startsAt: { lte: input.now },
        OR: [{ endsAt: null }, { endsAt: { gt: input.now } }],
      },
      select: { product: { select: { key: true } } },
    }),
    tx.notificationPreference.findMany({
      where: {
        organizationId: input.organizationId,
        accountId: input.accountId,
        channel: "EMAIL",
      },
      select: { category: true, enabled: true },
    }),
  ]);

  const activeProducts = new Set(activeEntitlements.map((entitlement) => entitlement.product.key));
  const enabledByCategory = new Map(preferences.map((pref) => [pref.category, pref.enabled]));

  const items: NotificationPreference[] = [];
  for (const category of NOTIFICATION_CATEGORIES) {
    if (category.product === null) {
      items.push({
        category: category.key,
        product: null,
        channel: category.channel,
        optional: category.optional,
        name: category.name,
        description: category.description,
        enabled: true,
      });
    } else if (activeProducts.has(category.product)) {
      items.push({
        category: category.key,
        product: category.product,
        channel: category.channel,
        optional: category.optional,
        name: category.name,
        description: category.description,
        enabled: enabledByCategory.get(category.key) ?? true,
      });
    }
  }
  return items;
}

/**
 * Zapisuje ustawienie kategorii powiadomień dla konta na kanale `EMAIL` i dopisuje wpis
 * `notification.preference_changed` do dziennika zdarzeń firmy w tej samej transakcji.
 */
export async function updateNotificationPreferenceForAccount(
  tx: Tx,
  input: {
    organizationId: string;
    accountId: string;
    category: string;
    enabled: boolean;
    now: Date;
    auditMeta: NotificationAuditMeta;
    source: "api" | "unsubscribe_link";
  },
): Promise<NotificationPreference> {
  const categoryDef = getNotificationCategory(input.category);
  if (!categoryDef) {
    throw new NotificationError(422, "VALIDATION_FAILED", "Nieznana kategoria powiadomień", [
      { field: "category", message: "Nieznana kategoria powiadomień" },
    ]);
  }
  if (!categoryDef.optional) {
    throw new NotificationError(422, "VALIDATION_FAILED", "Tej kategorii powiadomień nie można wyłączyć", [
      { field: "category", message: "Tej kategorii powiadomień nie można zmienić" },
    ]);
  }

  const existing = await tx.notificationPreference.findUnique({
    where: {
      organizationId_accountId_category_channel: {
        organizationId: input.organizationId,
        accountId: input.accountId,
        category: categoryDef.key,
        channel: "EMAIL",
      },
    },
    select: { id: true, enabled: true },
  });
  const previousEnabled = existing ? existing.enabled : true;

  const saved = await tx.notificationPreference.upsert({
    where: {
      organizationId_accountId_category_channel: {
        organizationId: input.organizationId,
        accountId: input.accountId,
        category: categoryDef.key,
        channel: "EMAIL",
      },
    },
    create: {
      id: uuidv7(input.now.getTime()),
      organizationId: input.organizationId,
      accountId: input.accountId,
      category: categoryDef.key,
      channel: "EMAIL",
      enabled: input.enabled,
    },
    update: {
      enabled: input.enabled,
    },
    select: { id: true, enabled: true },
  });

  await tx.auditLog.create({
    data: {
      id: uuidv7(input.now.getTime()),
      organizationId: input.organizationId,
      actorType: "ACCOUNT",
      actorAccountId: input.accountId,
      action: "notification.preference_changed",
      resourceType: "notification_preference",
      resourceId: saved.id,
      metadata: {
        accountId: input.accountId,
        category: categoryDef.key,
        channel: "EMAIL",
        previousEnabled,
        enabled: saved.enabled,
        source: input.source,
      },
      ipAddress: input.auditMeta.ipAddress,
      userAgent: input.auditMeta.userAgent,
      requestId: input.auditMeta.requestId,
    },
  });

  return {
    category: categoryDef.key,
    product: categoryDef.product,
    channel: categoryDef.channel,
    optional: categoryDef.optional,
    name: categoryDef.name,
    description: categoryDef.description,
    enabled: saved.enabled,
  };
}

/**
 * Obsługuje jednoklikowe wypisanie z powiadomień (RFC 8058) bez logowania:
 * weryfikuje podpisany token HMAC-SHA256 w stałym czasie, sprawdza konto pod RLS firmy z tokenu,
 * ustawia `enabled = false` dla kanału `EMAIL` i zapisuje wpis audytu `notification.preference_changed`.
 */
export async function unsubscribeNotificationByToken(
  db: PrismaClient,
  input: {
    token: string;
    secret: string;
    now: Date;
    auditMeta: NotificationAuditMeta;
  },
): Promise<UnsubscribeNotificationResult> {
  const payload = verifyUnsubscribeToken(input.token, input.secret);
  if (!payload) {
    throw new NotificationError(404, "NOT_FOUND", "Nieprawidłowy link wypisania z powiadomień");
  }

  await withOrganization(db, payload.organizationId, async (tx) => {
    const account = await tx.account.findUnique({
      where: { id: payload.accountId },
      select: { id: true },
    });
    if (!account) {
      throw new NotificationError(404, "NOT_FOUND", "Nieprawidłowy link wypisania z powiadomień");
    }

    await updateNotificationPreferenceForAccount(tx, {
      organizationId: payload.organizationId,
      accountId: payload.accountId,
      category: payload.category,
      enabled: false,
      now: input.now,
      auditMeta: input.auditMeta,
      source: "unsubscribe_link",
    });
  });

  return {
    category: payload.category,
    enabled: false,
  };
}
