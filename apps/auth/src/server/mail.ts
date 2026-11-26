import "server-only";
import nodemailer from "nodemailer";
import { config } from "./config";

export interface OutgoingMail {
  to: string;
  subject: string;
  text: string;
  html: string;
}

export type MailSender = (mail: OutgoingMail) => Promise<void>;

const memory: OutgoingMail[] = [];

/** Wiadomości wysłane przy CORE_SMTP_URL=memory (testy). */
export function sentMails(): readonly OutgoingMail[] {
  return memory;
}

/** Czyści bufor wiadomości w pamięci (do izolacji przypadków testowych). */
export function clearSentMails(): void {
  memory.length = 0;
}

/** Twardy limit całkowitego czasu pojedynczej próby wysyłki SMTP (ms). */
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

/** Opóźnienia kolejnych prób dla maili logowania (natychmiast, +2 s, +5 s — łącznie 3 próby). */
export const MAIL_RETRY_DELAYS_MS = [0, 2_000, 5_000] as const;

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
  if (config.smtpUrl === "memory") {
    memory.push(mail);
    return;
  }
  const transport = nodemailer.createTransport({ url: config.smtpUrl, ...SMTP_TIMEOUTS });
  await sendMailWithDeadline(transport, { from: config.mailFrom, ...mail });
}

function defaultSleep(ms: number): Promise<void> {
  return new Promise((resolve) => {
    const timer = setTimeout(resolve, ms);
    timer.unref?.();
  });
}

export interface SendMailWithRetryOptions {
  delaysMs?: readonly number[] | undefined;
  sender?: MailSender | undefined;
  sleep?: ((ms: number) => Promise<void>) | undefined;
  onAttemptError?: ((attempt: number, error: unknown) => void) | undefined;
}

/**
 * Wysyła wiadomość e-mail z krótkimi ponowieniami (domyślnie 3 próby: od razu, po 2 s i po 5 s).
 * Używane do maili logowania (potwierdzenie adresu i reset hasła), poza kolejką `mail_outbox`.
 */
export async function sendMailWithRetry(mail: OutgoingMail, options: SendMailWithRetryOptions = {}): Promise<void> {
  const delays = options.delaysMs ?? MAIL_RETRY_DELAYS_MS;
  if (delays.length === 0) {
    throw new Error("Lista opóźnień wysyłki nie może być pusta");
  }
  const sender = options.sender ?? sendMail;
  const sleep = options.sleep ?? defaultSleep;

  let lastError: unknown;
  for (let attempt = 0; attempt < delays.length; attempt++) {
    const delayMs = delays[attempt] ?? 0;
    if (delayMs > 0) {
      await sleep(delayMs);
    }
    try {
      await sender(mail);
      return;
    } catch (error) {
      lastError = error;
      options.onAttemptError?.(attempt + 1, error);
    }
  }
  throw lastError;
}

/** Usuwa z komunikatu błędu ewentualne dane logowania SMTP i parametry `token=`, zanim trafi do logów. */
export function sanitizeMailError(error: unknown): string {
  const raw = error instanceof Error ? `${error.name}: ${error.message}` : String(error);
  return raw
    .replace(/(smtps?:\/\/)([^/\s@]+)@/gi, "$1***@")
    .replace(/([?&]token=)[^&\s]+/gi, "$1***")
    .slice(0, 500);
}

/**
 * Uruchamia wysyłkę wiadomości w tle bez blokowania odpowiedzi HTTP (eliminuje wyrocznię czasową).
 * Błędy po wyczerpaniu prób trafiają wyłącznie do logów (bez tokenów i haseł).
 */
export function sendMailInBackground(
  mail: OutgoingMail,
  kind: string,
  options: SendMailWithRetryOptions & { logger?: (message: string) => void } = {},
): Promise<void> {
  const logError = options.logger ?? ((message: string) => console.error(message));
  return sendMailWithRetry(mail, options).catch((error) => {
    logError(`[auth:mail:${kind}] Nie udało się wysłać wiadomości po wszystkich próbach: ${sanitizeMailError(error)}`);
  });
}

const escape = (value: string) =>
  value.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;");

/** Prosta wiadomość z jednym przyciskiem: tekst i HTML z tym samym linkiem. */
export function linkMail(to: string, subject: string, intro: string, action: string, url: string): OutgoingMail {
  return {
    to,
    subject,
    text: `${intro}\n\n${action}: ${url}\n\nJeśli to nie Ty, zignoruj tę wiadomość.\n\nMonorise`,
    html: `<p>${escape(intro)}</p><p><a href="${escape(url)}">${escape(action)}</a></p><p>Jeśli to nie Ty, zignoruj tę wiadomość.</p><p>Monorise</p>`,
  };
}

/** Wiadomość z jednorazowym linkiem do zmiany hasła (ważnym 30 minut). */
export function passwordResetMail(to: string, resetUrl: string): OutgoingMail {
  return linkMail(
    to,
    "Zmiana hasła w Monorise",
    "Otwórz link poniżej, żeby ustawić nowe hasło do konta Monorise. Link jest ważny przez 30 minut.",
    "Zmień hasło",
    resetUrl,
  );
}
