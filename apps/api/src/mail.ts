import nodemailer from "nodemailer";

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

export function currentSmtpUrl(): string {
  return process.env.CORE_SMTP_URL ?? "memory";
}

export function currentMailFrom(): string {
  return process.env.CORE_MAIL_FROM ?? "Monorise <no-reply@monorise.studio>";
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

const escapeHtml = (value: string) =>
  value.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;");

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
