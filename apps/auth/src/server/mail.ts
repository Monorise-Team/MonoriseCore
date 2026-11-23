import "server-only";
import nodemailer from "nodemailer";
import { config } from "./config";

export interface OutgoingMail {
  to: string;
  subject: string;
  text: string;
  html: string;
}

const memory: OutgoingMail[] = [];

/** Wiadomości wysłane przy CORE_SMTP_URL=memory (testy). */
export function sentMails(): readonly OutgoingMail[] {
  return memory;
}

export async function sendMail(mail: OutgoingMail): Promise<void> {
  if (config.smtpUrl === "memory") {
    memory.push(mail);
    return;
  }
  const transport = nodemailer.createTransport(config.smtpUrl);
  await transport.sendMail({ from: config.mailFrom, ...mail });
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
