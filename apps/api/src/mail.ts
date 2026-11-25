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

export async function sendMail(mail: OutgoingMail): Promise<void> {
  const smtpUrl = currentSmtpUrl();
  if (smtpUrl === "memory") {
    memory.push(mail);
    return;
  }
  const transport = nodemailer.createTransport(smtpUrl);
  await transport.sendMail({ from: currentMailFrom(), ...mail });
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
