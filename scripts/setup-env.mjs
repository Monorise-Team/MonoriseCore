#!/usr/bin/env node
/**
 * Tworzy pliki .env.local aplikacji do pracy lokalnej: losowy sekret logowania, adresy lokalnej bazy
 * (docker compose) i poczty (Mailpit) oraz zgodę na pominięcie weryfikacji domeny rekordem DNS TXT.
 * Istniejących plików nie nadpisuje.
 */
import { randomBytes } from "node:crypto";
import { existsSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const root = join(import.meta.dirname, "..");
const appUrl = "postgresql://core_app:core_app@localhost:5433/monorise_core";
const files = {
  "packages/db/.env": [`DATABASE_URL=postgresql://core_owner:core_owner@localhost:5433/monorise_core`],
  "apps/auth/.env.local": [
    `BETTER_AUTH_SECRET=${randomBytes(32).toString("base64")}`,
    "BETTER_AUTH_URL=http://localhost:3100",
    `CORE_DATABASE_URL=${appUrl}`,
    "CORE_SMTP_URL=smtp://localhost:1125",
    "CORE_MAIL_FROM=Monorise <no-reply@monorise.studio>",
    "CORE_TOKEN_AUDIENCE=http://localhost:3200",
    "CORE_DEV_TRUST_DOMAINS=1",
  ],
  "apps/api/.env.local": [
    `CORE_DATABASE_URL=${appUrl}`,
    "CORE_AUTH_ISSUER=http://localhost:3100",
    "CORE_AUTH_JWKS_URL=http://localhost:3100/api/auth/jwks",
    "CORE_AUTH_URL=http://localhost:3100",
    "CORE_API_AUDIENCE=http://localhost:3200",
    "CORE_SMTP_URL=smtp://localhost:1125",
    "CORE_MAIL_FROM=Monorise <no-reply@monorise.studio>",
  ],
};
for (const [rel, lines] of Object.entries(files)) {
  const file = join(root, rel);
  if (existsSync(file)) {
    console.log(`${rel} już istnieje, zostawiam bez zmian.`);
    continue;
  }
  writeFileSync(file, ["# Tylko lokalnie. Nigdy nie commituj tego pliku.", ...lines, ""].join("\n"), { mode: 0o600 });
  console.log(`Zapisano ${rel}.`);
}
