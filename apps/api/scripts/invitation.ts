/**
 * Narzędzie CLI do tworzenia zaproszeń pracowników (pilotaż i lokalne testy, ADR-0021).
 *
 *   pnpm invitation:create -- --organization <uuid|domena> --email <e-mail> --first-name <imię> --last-name <nazwisko>
 *   pnpm invitation:create -- --organization <uuid|domena> --email <e-mail> --employee-id <uuid>
 */
import { parseArgs } from "node:util";
import { createDb } from "@core/db";
import { createInvitationByOrganization } from "../src/invitations.js";
import { isLocalMailSink } from "../src/mail.js";
import { claimMailJobById, deliverMailJob } from "../src/mail-outbox.js";

function usage(): never {
  console.error(
    "Użycie:\n" +
      "  pnpm invitation:create -- --organization <uuid|domena> --email <e-mail> --first-name <imię> --last-name <nazwisko>\n" +
      "  pnpm invitation:create -- --organization <uuid|domena> --email <e-mail> --employee-id <uuid>",
  );
  process.exit(1);
}

const command = process.argv[2];
if (command !== "create") {
  usage();
}

const rawArgs = process.argv.slice(3);
const normalizedArgs = rawArgs[0] === "--" ? rawArgs.slice(1) : rawArgs;

const { values } = parseArgs({
  args: normalizedArgs,
  options: {
    organization: { type: "string" },
    email: { type: "string" },
    "first-name": { type: "string" },
    "last-name": { type: "string" },
    "employee-id": { type: "string" },
  },
  strict: true,
});

if (!values.organization || !values.email) {
  usage();
}
if (!values["employee-id"] && (!values["first-name"] || !values["last-name"])) {
  usage();
}

const databaseUrl = process.env.CORE_DATABASE_URL;
if (!databaseUrl) {
  console.error("Brak zmiennej środowiskowej CORE_DATABASE_URL (lokalnie: pnpm setup:env)");
  process.exit(1);
}

const db = createDb(databaseUrl);

try {
  const result = await createInvitationByOrganization(db, {
    organization: values.organization,
    email: values.email,
    firstName: values["first-name"],
    lastName: values["last-name"],
    employeeId: values["employee-id"],
  });
  console.log(
    `Utworzono zaproszenie dla ${result.invitation.email} w firmie ${result.organizationId} ` +
      `(id=${result.invitation.id}, accountId=${result.invitation.accountId}, ` +
      `employeeId=${result.invitation.employeeId}, ważne do=${result.invitation.expiresAt}).`,
  );

  const claimed = await claimMailJobById(db, result.organizationId, result.mailJobId);
  if (!claimed) {
    console.log("Wiadomość zaproszenia została już podjęta do wysyłki przez worker Core API.");
  } else {
    const delivery = await deliverMailJob(db, claimed, {
      authUrl: process.env.CORE_AUTH_URL?.trim() || process.env.CORE_AUTH_ISSUER?.trim() || undefined,
    });
    if (delivery.status === "SENT") {
      if (delivery.inviteUrl && isLocalMailSink()) {
        console.log(`Link aktywacyjny (tylko lokalnie): ${delivery.inviteUrl}`);
      }
    } else if (delivery.status === "SKIPPED") {
      console.log("Zadanie wysyłki zostało już przejęte lub zmienione przez inny proces.");
    } else {
      console.error(
        `Zaproszenie zostało zapisane, ale bezpośrednia wysyłka wiadomości nie powiodła się (status: ${delivery.status}). ` +
          "Kolejka poczty Core API ponowi wysyłkę automatycznie.",
      );
    }
  }
} finally {
  await db.$disconnect();
}
