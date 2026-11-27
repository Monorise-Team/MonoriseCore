import { productNameSchema } from "@monorise-team/permissions";
import { z } from "zod";

export const NOTIFICATIONS_SEND_SCOPE = "core:notifications.send";

export const NOTIFICATION_TITLE_MAX_LENGTH = 200;
export const NOTIFICATION_BODY_MAX_LENGTH = 4000;
export const NOTIFICATION_ACTION_URL_MAX_LENGTH = 2048;

export const NOTIFICATION_MAIL_CHANNELS = ["login", "notifications"] as const;
export const NotificationMailChannel = z.enum(NOTIFICATION_MAIL_CHANNELS);
export type NotificationMailChannel = z.infer<typeof NotificationMailChannel>;

export const NOTIFICATION_CHANNELS = ["EMAIL", "PUSH"] as const;
export const NotificationChannel = z.enum(NOTIFICATION_CHANNELS);
export type NotificationChannel = z.infer<typeof NotificationChannel>;

export const NOTIFICATION_STATUSES = ["QUEUED", "SENT", "SKIPPED", "FAILED"] as const;
export const NotificationStatus = z.enum(NOTIFICATION_STATUSES);
export type NotificationStatus = z.infer<typeof NotificationStatus>;

export const NOTIFICATION_SKIP_REASONS = ["PREFERENCE_OFF", "NO_ACCESS"] as const;
export const NotificationSkipReason = z.enum(NOTIFICATION_SKIP_REASONS);
export type NotificationSkipReason = z.infer<typeof NotificationSkipReason>;

/**
 * Stały katalog kategorii powiadomień platformy Monorise (ADR-0048).
 * Kategorie kanału `login` (`security`, `account`) są obowiązkowe (nie można ich wyłączyć)
 * i produkty nie mogą ich zlecać. Kategorie produktów korzystają z kanału `notifications`
 * i są domyślnie włączone (brak wiersza w `notification_preferences` oznacza `enabled = true`).
 */
export const NOTIFICATION_CATEGORIES = [
  {
    key: "security",
    product: null,
    channel: "login",
    optional: false,
    name: "Bezpieczeństwo",
    description: "Wiadomości dotyczące bezpieczeństwa konta, logowania i zmiany hasła.",
  },
  {
    key: "account",
    product: null,
    channel: "login",
    optional: false,
    name: "Konto i firma",
    description: "Zaproszenia do firmy oraz ważne informacje o stanie konta.",
  },
  {
    key: "timotime.reminders",
    product: "timotime",
    channel: "notifications",
    optional: true,
    name: "Przypomnienia TimoTime",
    description: "Przypomnienia o uzupełnianiu i zatwierdzaniu czasu pracy w TimoTime.",
  },
  {
    key: "kivotasks.assignments",
    product: "kivotasks",
    channel: "notifications",
    optional: true,
    name: "Przypisane zadania KivoTasks",
    description: "Powiadomienia o przypisaniu do zadań w KivoTasks.",
  },
] as const;

export type NotificationCategoryDefinition = (typeof NOTIFICATION_CATEGORIES)[number];
export type NotificationCategoryKey = NotificationCategoryDefinition["key"];

export const NOTIFICATION_CATEGORY_KEYS = [
  "security",
  "account",
  "timotime.reminders",
  "kivotasks.assignments",
] as const satisfies readonly NotificationCategoryKey[];

export const NotificationCategoryKey = z.enum(NOTIFICATION_CATEGORY_KEYS);

const NOTIFICATION_CATEGORY_BY_KEY = new Map<string, NotificationCategoryDefinition>(
  NOTIFICATION_CATEGORIES.map((category) => [category.key, category]),
);

/** Zwraca definicję kategorii powiadomień po kluczu albo `undefined`, gdy kategoria nie istnieje. */
export function getNotificationCategory(key: string): NotificationCategoryDefinition | undefined {
  return NOTIFICATION_CATEGORY_BY_KEY.get(key);
}

/** Zwraca `true`, gdy surowy URL zawiera białe znaki, znaki sterujące (w tym NUL) lub ukośnik odwrotny (`\`). */
export function hasUnsafeUrlChars(value: string): boolean {
  for (let i = 0; i < value.length; i += 1) {
    const code = value.charCodeAt(i);
    if (code <= 0x1f || code === 0x7f || code === 0x5c || /\s/.test(value[i]!)) {
      return true;
    }
  }
  return false;
}

const RawUrlFormat = z.url("Podaj poprawny adres URL");

/** Żądanie zlecenia powiadomienia e-mail przez serwer produktu (`POST /core/v1/organizations/{organizationId}/notifications`). */
export const CreateNotification = z
  .object({
    recipientAccountId: z.uuid(),
    category: NotificationCategoryKey,
    title: z
      .string()
      .trim()
      .min(1, "Tytuł powiadomienia nie może być pusty")
      .max(
        NOTIFICATION_TITLE_MAX_LENGTH,
        `Tytuł powiadomienia może mieć co najwyżej ${NOTIFICATION_TITLE_MAX_LENGTH} znaków`,
      )
      .regex(/^[^\r\n]+$/, "Tytuł powiadomienia nie może zawierać znaków nowej linii"),
    body: z
      .string()
      .trim()
      .min(1, "Treść powiadomienia nie może być pusta")
      .max(
        NOTIFICATION_BODY_MAX_LENGTH,
        `Treść powiadomienia może mieć co najwyżej ${NOTIFICATION_BODY_MAX_LENGTH} znaków`,
      ),
    actionUrl: z
      .string()
      .max(
        NOTIFICATION_ACTION_URL_MAX_LENGTH,
        `Adres actionUrl może mieć co najwyżej ${NOTIFICATION_ACTION_URL_MAX_LENGTH} znaków`,
      )
      .refine((value) => !hasUnsafeUrlChars(value), {
        message: "Adres actionUrl nie może zawierać białych znaków, znaków sterujących ani ukośników odwrotnych",
      })
      .refine((value) => RawUrlFormat.safeParse(value).success, {
        message: "Podaj poprawny adres URL",
      })
      .meta({ format: "uri" })
      .nullable()
      .optional(),
  })
  .strict();
export type CreateNotification = z.infer<typeof CreateNotification>;

/** Odpowiedź na zlecenie powiadomienia (`202 Accepted`): zakolejkowane (`QUEUED`) albo pominięte (`SKIPPED`). */
export const NotificationResult = z.object({
  id: z.uuid(),
  status: NotificationStatus,
  skipReason: NotificationSkipReason.nullable(),
});
export type NotificationResult = z.infer<typeof NotificationResult>;

/** Pozycja listy ustawień powiadomień zalogowanego konta (`GET /core/v1/me/notification-preferences`). */
export const NotificationPreference = z.object({
  category: NotificationCategoryKey,
  product: productNameSchema.nullable(),
  channel: NotificationMailChannel,
  optional: z.boolean(),
  name: z.string(),
  description: z.string(),
  enabled: z.boolean(),
});
export type NotificationPreference = z.infer<typeof NotificationPreference>;

/** Zmiana ustawienia wybranej kategorii powiadomień (`PUT /core/v1/me/notification-preferences/{category}`). */
export const UpdateNotificationPreference = z
  .object({
    enabled: z.boolean(),
  })
  .strict();
export type UpdateNotificationPreference = z.infer<typeof UpdateNotificationPreference>;

/** Wynik jednoklikowego wypisania z powiadomień (RFC 8058, `POST /core/v1/notifications/unsubscribe/{token}`). */
export const UnsubscribeNotificationResult = z.object({
  category: NotificationCategoryKey,
  enabled: z.literal(false),
});
export type UnsubscribeNotificationResult = z.infer<typeof UnsubscribeNotificationResult>;
