import nodemailer from "nodemailer";

export interface OutgoingMail {
  to: string;
  subject: string;
  text: string;
  html: string;
  headers?: Record<string, string> | undefined;
}

export interface SentNotificationMail extends OutgoingMail {
  from: string;
}

export interface MailChannelConfig {
  smtpUrl: string;
  from: string;
}

export type MailSender = (mail: OutgoingMail) => Promise<void>;

const memory: OutgoingMail[] = [];
const notificationMemory: SentNotificationMail[] = [];

/** Wiadomości kanału logowania wysłane przy CORE_SMTP_URL=memory (testy). */
export function sentMails(): readonly OutgoingMail[] {
  return memory;
}

/** Czyści bufor wiadomości kanału logowania w pamięci (do izolacji przypadków testowych). */
export function clearSentMails(): void {
  memory.length = 0;
}

/** Wiadomości kanału powiadomień wysłane przy trybie memory (testy). */
export function sentNotificationMails(): readonly SentNotificationMail[] {
  return notificationMemory;
}

/** Czyści bufor wiadomości kanału powiadomień w pamięci (do izolacji przypadków testowych). */
export function clearSentNotificationMails(): void {
  notificationMemory.length = 0;
}

export function currentSmtpUrl(): string {
  return process.env.CORE_SMTP_URL ?? "memory";
}

export function currentMailFrom(): string {
  return process.env.CORE_MAIL_FROM ?? "Monorise <no-reply@monorise.studio>";
}

/**
 * Konfiguracja osobnego kanału poczty powiadomień (ADR-0048):
 * - na produkcji (`NODE_ENV === "production"`) wymaga obu zmiennych `CORE_NOTIFICATIONS_SMTP_URL`
 *   oraz `CORE_NOTIFICATIONS_FROM` (błąd przy starcie procesu, żeby problemy z powiadomieniami
 *   nigdy nie dzieliły transportu z e-mailami logowania),
 * - poza produkcją (development, test) domyślnie wraca do ustawień kanału logowania (`CORE_SMTP_URL`,
 *   `CORE_MAIL_FROM`, lokalnie Mailpit albo `memory`).
 */
export function resolveNotificationsMailConfig(
  env: {
    NODE_ENV?: string | undefined;
    CORE_NOTIFICATIONS_SMTP_URL?: string | undefined;
    CORE_NOTIFICATIONS_FROM?: string | undefined;
    CORE_SMTP_URL?: string | undefined;
    CORE_MAIL_FROM?: string | undefined;
  } = process.env,
): MailChannelConfig {
  const isProd = env.NODE_ENV === "production";
  const smtpUrl = env.CORE_NOTIFICATIONS_SMTP_URL?.trim() ?? "";
  const from = env.CORE_NOTIFICATIONS_FROM?.trim() ?? "";

  if (isProd) {
    if (!smtpUrl) {
      throw new Error("Zmienna środowiskowa CORE_NOTIFICATIONS_SMTP_URL jest wymagana na produkcji");
    }
    if (!from) {
      throw new Error("Zmienna środowiskowa CORE_NOTIFICATIONS_FROM jest wymagana na produkcji");
    }
    return { smtpUrl, from };
  }

  return {
    smtpUrl: smtpUrl || env.CORE_SMTP_URL?.trim() || "memory",
    from: from || env.CORE_MAIL_FROM?.trim() || "Monorise <no-reply@monorise.studio>",
  };
}

/**
 * Zwraca `true` wyłącznie wtedy, gdy poczta trafia do bufora w pamięci (`memory`) albo na lokalny
 * serwer SMTP (`localhost` / pętla zwrotna) — tylko wtedy CLI może wypisać link aktywacyjny na ekran.
 */
export function isLocalMailSink(smtpUrl: string = currentSmtpUrl()): boolean {
  const trimmed = smtpUrl.trim();
  if (!trimmed || trimmed === "memory") return true;
  try {
    const parsed = new URL(trimmed);
    const host = parsed.hostname.toLowerCase();
    return host === "localhost" || host === "127.0.0.1" || host === "::1" || host === "[::1]";
  } catch {
    return false;
  }
}

/**
 * Twardy limit całkowitego czasu pojedynczej wysyłki `sendMail()` (ms), niezależny od bezczynności gniazda.
 * Razem z odnowieniem dzierżawy na starcie zadania pozostaje wielokrotnie krótszy niż `MAIL_LEASE_MS` (90 s),
 * więc nawet powolny serwer SMTP (tarpit) nie przekroczy dzierżawy.
 */
export const MAIL_SEND_DEADLINE_MS = 30_000;

/**
 * Limity czasu gniazda w `nodemailer` (domyślnie sięgają minut). Uzupełniają twardy limit
 * `MAIL_SEND_DEADLINE_MS`, przerywając szybciej zerwane połączenia i bezczynne gniazda.
 */
export const SMTP_TIMEOUTS = {
  connectionTimeout: 10_000,
  greetingTimeout: 10_000,
  socketTimeout: 20_000,
} as const;

export interface ClosableMailTransport {
  sendMail: (options: { from: string } & OutgoingMail) => Promise<unknown>;
  close: () => void;
}

/**
 * Wysyła wiadomość przez transport SMTP z twardym limitem czasu całkowitego (`MAIL_SEND_DEADLINE_MS`).
 * Po przekroczeniu terminu zamyka transport i odrzuca obietnicę bez wycieku timera ani gniazda.
 */
export async function sendMailWithDeadline(
  transport: ClosableMailTransport,
  mail: { from: string } & OutgoingMail,
  deadlineMs = MAIL_SEND_DEADLINE_MS,
): Promise<void> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    const sendPromise = transport.sendMail(mail);
    // Tłumimy ewentualne późne odrzucenie po zamknięciu transportu przy przekroczeniu terminu.
    void sendPromise.catch(() => undefined);

    const timeoutPromise = new Promise<never>((_, reject) => {
      timer = setTimeout(() => {
        try {
          transport.close();
        } catch {
          // Ignorujemy błąd zamykania transportu przy przekroczeniu terminu.
        }
        reject(new Error(`Przekroczono limit czasu wysyłki SMTP (${deadlineMs} ms)`));
      }, deadlineMs);
      timer.unref?.();
    });

    await Promise.race([sendPromise, timeoutPromise]);
  } finally {
    if (timer) clearTimeout(timer);
    try {
      transport.close();
    } catch {
      // Transport mógł zostać już zamknięty.
    }
  }
}

export async function sendMail(mail: OutgoingMail): Promise<void> {
  const smtpUrl = currentSmtpUrl();
  if (smtpUrl === "memory") {
    memory.push(mail);
    return;
  }
  const transport = nodemailer.createTransport({ url: smtpUrl, ...SMTP_TIMEOUTS });
  await sendMailWithDeadline(transport, { from: currentMailFrom(), ...mail });
}

/** Wysyła wiadomość kanałem powiadomień (`CORE_NOTIFICATIONS_SMTP_URL`, `CORE_NOTIFICATIONS_FROM`). */
export async function sendNotificationMail(mail: OutgoingMail): Promise<void> {
  const config = resolveNotificationsMailConfig(process.env);
  if (config.smtpUrl === "memory") {
    notificationMemory.push({ from: config.from, ...mail });
    return;
  }
  const transport = nodemailer.createTransport({ url: config.smtpUrl, ...SMTP_TIMEOUTS });
  await sendMailWithDeadline(transport, { from: config.from, ...mail });
}

export function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function sanitizeHeaderLine(value: string): string {
  return value.replace(/[\r\n]+/g, " ").trim();
}

/** Prosta wiadomość z jednym przyciskiem: tekst i HTML z tym samym linkiem. */
export function linkMail(to: string, subject: string, intro: string, action: string, url: string): OutgoingMail {
  return {
    to,
    subject,
    text: `${intro}\n\n${action}: ${url}\n\nJeśli to nie Ty, zignoruj tę wiadomość.\n\nMonorise`,
    html: `<p>${escapeHtml(intro)}</p><p><a href="${escapeHtml(url)}">${escapeHtml(action)}</a></p><p>Jeśli to nie Ty, zignoruj tę wiadomość.</p><p>Monorise</p>`,
  };
}

export interface InvitationMailParams {
  to: string;
  organizationName: string;
  inviterName: string | null;
  inviteUrl: string;
}

/** Wiadomość z zaproszeniem pracownika do aktywacji konta Monorise (link ważny 7 dni). */
export function invitationMail({ to, organizationName, inviterName, inviteUrl }: InvitationMailParams): OutgoingMail {
  const subject = `Zaproszenie do Monorise od firmy ${organizationName}`;
  const intro = inviterName
    ? `${inviterName} zaprasza Cię do firmy ${organizationName} w Monorise. Otwórz link poniżej i ustaw hasło, żeby aktywować konto. Link jest ważny przez 7 dni.`
    : `Firma ${organizationName} zaprasza Cię do Monorise. Otwórz link poniżej i ustaw hasło, żeby aktywować konto. Link jest ważny przez 7 dni.`;
  return linkMail(to, subject, intro, "Aktywuj konto", inviteUrl);
}

export interface NotificationMailParams {
  to: string;
  productName: string;
  organizationName: string;
  categoryName: string;
  title: string;
  body: string;
  actionUrl: string | null;
  unsubscribeUrl: string;
}

/**
 * Wspólny układ wiadomości e-mail powiadomień produktów (ADR-0048):
 * tekst i prosty HTML (nazwa produktu, tytuł, treść, opcjonalny przycisk do `actionUrl`, stopka z powodem
 * otrzymania i linkiem wypisania) oraz nagłówki RFC 8058 (`List-Unsubscribe`, `List-Unsubscribe-Post`).
 * Cały tekst przekazany przez produkt jest kodowany w HTML (`escapeHtml`).
 */
export function notificationMail({
  to,
  productName,
  organizationName,
  categoryName,
  title,
  body,
  actionUrl,
  unsubscribeUrl,
}: NotificationMailParams): OutgoingMail {
  const safeProduct = sanitizeHeaderLine(productName);
  const safeTitle = sanitizeHeaderLine(title);
  const subject = `[${safeProduct}] ${safeTitle}`;
  const footerReason = `Otrzymujesz tę wiadomość, ponieważ masz włączone powiadomienia „${categoryName}” dla ${productName} w firmie ${organizationName}.`;

  const textParts = [`${productName} (${organizationName})`, "", title, "", body];
  if (actionUrl) {
    textParts.push("", `Otwórz w ${productName}: ${actionUrl}`);
  }
  textParts.push("", "---", footerReason, `Wyłącz powiadomienia z tej kategorii: ${unsubscribeUrl}`, "", "Monorise");

  const escapedProduct = escapeHtml(productName);
  const escapedOrg = escapeHtml(organizationName);
  const escapedTitle = escapeHtml(title);
  const escapedBody = escapeHtml(body).replace(/\r?\n/g, "<br>");
  const escapedReason = escapeHtml(footerReason);
  const escapedUnsubscribeUrl = escapeHtml(unsubscribeUrl);

  const actionBlock = actionUrl
    ? `<p style="margin:24px 0"><a href="${escapeHtml(actionUrl)}" style="display:inline-block;padding:10px 18px;background:#111827;color:#ffffff;text-decoration:none;border-radius:6px;font-weight:600">Otwórz w ${escapedProduct}</a></p>`
    : "";

  const html = [
    `<div style="font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;max-width:600px;margin:0 auto;color:#111827;line-height:1.5">`,
    `<p style="margin:0 0 8px;font-size:13px;font-weight:600;color:#4b5563">${escapedProduct} · ${escapedOrg}</p>`,
    `<h2 style="margin:0 0 16px;font-size:20px;line-height:1.3">${escapedTitle}</h2>`,
    `<div style="margin:0 0 16px;font-size:15px">${escapedBody}</div>`,
    actionBlock,
    `<hr style="border:none;border-top:1px solid #e5e7eb;margin:24px 0 16px">`,
    `<p style="margin:0 0 8px;font-size:12px;color:#6b7280">${escapedReason}</p>`,
    `<p style="margin:0;font-size:12px;color:#6b7280"><a href="${escapedUnsubscribeUrl}" style="color:#4b5563">Wyłącz powiadomienia z tej kategorii</a></p>`,
    `</div>`,
  ].join("");

  return {
    to,
    subject,
    text: textParts.join("\n"),
    html,
    headers: {
      "List-Unsubscribe": `<${unsubscribeUrl}>`,
      "List-Unsubscribe-Post": "List-Unsubscribe=One-Click",
    },
  };
}
