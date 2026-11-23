import { ConsentForm } from "./ConsentForm";

export const metadata = { title: "Zgoda na dostęp — Monorise" };

/** Zgoda na dostęp aplikacji spoza Monorise. Aplikacje Monorise (AvenMail, TimoTime) jej nie wymagają. */
export default function ConsentPage() {
  return <ConsentForm />;
}
