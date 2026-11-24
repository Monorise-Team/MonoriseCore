/**
 * Narzędzie CLI do przyznawania i kończenia dostępu firm do produktów (Entitlement, ADR-0051, ADR-0052).
 *
 *   pnpm entitlement:grant -- --organization <uuid|domena> --product <klucz> [--ends-at <ISO>]
 *   pnpm entitlement:end   -- --organization <uuid|domena> --product <klucz>
 */
import { parseArgs } from "node:util";
import { createDb } from "@core/db";
import { endEntitlement, grantEntitlement } from "../src/entitlements.js";

function usage(): never {
  console.error(
    "Użycie:\n" +
      "  pnpm entitlement:grant -- --organization <uuid|domena> --product <klucz> [--ends-at <ISO>]\n" +
      "  pnpm entitlement:end -- --organization <uuid|domena> --product <klucz>",
  );
  process.exit(1);
}

const command = process.argv[2];
if (command !== "grant" && command !== "end") {
  usage();
}

const rawArgs = process.argv.slice(3);
const normalizedArgs = rawArgs[0] === "--" ? rawArgs.slice(1) : rawArgs;

const { values } = parseArgs({
  args: normalizedArgs,
  options: {
    organization: { type: "string" },
    product: { type: "string" },
    "ends-at": { type: "string" },
  },
  strict: true,
});

if (!values.organization || !values.product) {
  usage();
}

const databaseUrl = process.env.CORE_DATABASE_URL;
if (!databaseUrl) {
  console.error("Brak zmiennej środowiskowej CORE_DATABASE_URL (lokalnie: pnpm setup:env)");
  process.exit(1);
}

const db = createDb(databaseUrl);

try {
  if (command === "grant") {
    let endsAt: Date | null = null;
    if (values["ends-at"] !== undefined) {
      endsAt = new Date(values["ends-at"]);
      if (Number.isNaN(endsAt.getTime())) {
        console.error(`Nieprawidłowa data --ends-at: "${values["ends-at"]}" (oczekiwany format ISO 8601)`);
        process.exit(1);
      }
    }
    const result = await grantEntitlement(db, {
      organization: values.organization,
      product: values.product,
      endsAt,
    });
    console.log(
      `${result.updated ? "Zaktualizowano" : "Przyznano"} dostęp do produktu "${result.productKey}" ` +
        `dla firmy ${result.organizationId} (id=${result.entitlementId}, ` +
        `endsAt=${result.endsAt ? result.endsAt.toISOString() : "bezterminowo"}, ` +
        `zaktualizowane konta=${result.affectedAccounts}).`,
    );
  } else {
    const result = await endEntitlement(db, {
      organization: values.organization,
      product: values.product,
    });
    console.log(
      `Zakończono dostęp do produktu "${result.productKey}" dla firmy ${result.organizationId} ` +
        `(id=${result.entitlementId}, zaktualizowane konta=${result.affectedAccounts}).`,
    );
  }
} finally {
  await db.$disconnect();
}
