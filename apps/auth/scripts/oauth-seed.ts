/**
 * Rejestruje aplikacje Monorise jako klientów OAuth Core, a ich API jako zasoby (odbiorców tokenów).
 * Działa wielokrotnie; sekrety nowych klientów poufnych zapisuje w apps/auth/.data/oauth-clients.json
 * (tylko lokalnie, plik poza repozytorium), bo w bazie zostaje wyłącznie ich skrót.
 *
 *   pnpm oauth:seed
 *
 * Adresy produktów można zmienić zmiennymi środowiskowymi (domyślnie lokalne *.localhost).
 */
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { db } from "../src/server/db";
import { ensureFirstPartyClients, PRODUCT_MACHINE_SCOPES, PRODUCT_SCOPES } from "../src/server/oauth-clients";

const env = (name: string, fallback: string) => process.env[name] ?? fallback;
const AVEN_API = env("CORE_AVENMAIL_API_URL", "http://aven.localhost:3000");
const AVEN_WEB = env("CORE_AVENMAIL_WEB_URL", "http://aven-mail.localhost:3000");
const TIME_API = env("CORE_TIMOTIME_API_URL", "http://time.localhost:3300");
const TIME_WEB = env("CORE_TIMOTIME_WEB_URL", "http://timo-time.localhost:3300");
const CORE_API = env("CORE_API_URL", "http://localhost:3200");
const PORTAL_WEB = env("CORE_PORTAL_WEB_URL", "http://portal.localhost:3400");
// Expo Go podczas pracy lokalnej wraca adresem exp:// serwera Metro (`expo start --localhost`)
const EXPO_GO = env("CORE_EXPO_GO_REDIRECT", "exp://127.0.0.1:8081/--/oauth/callback");

const secrets = await ensureFirstPartyClients({
  resources: [
    { identifier: AVEN_API, name: "AvenMail API" },
    { identifier: TIME_API, name: "TimoTime API" },
    { identifier: CORE_API, name: "Core API", allowedScopes: [...PRODUCT_SCOPES, ...PRODUCT_MACHINE_SCOPES] },
  ],
  clients: [
    {
      clientId: "avenmail-web",
      name: "AvenMail",
      redirectUris: [`${AVEN_WEB}/api/auth/callback`],
      confidential: true,
      resources: [AVEN_API, CORE_API],
      clientCredentialsScopes: [...PRODUCT_MACHINE_SCOPES],
    },
    {
      clientId: "avenmail-desktop",
      name: "AvenMail na komputer",
      // RFC 8252: aplikacja na komputer odbiera powrót na 127.0.0.1; port wybiera przy każdym logowaniu
      redirectUris: ["http://127.0.0.1/oauth/callback"],
      confidential: false,
      resources: [AVEN_API, CORE_API],
    },
    {
      clientId: "avenmail-mobile",
      name: "AvenMail na telefon",
      redirectUris: ["avenmail://oauth/callback", EXPO_GO],
      confidential: false,
      resources: [AVEN_API, CORE_API],
    },
    {
      clientId: "timotime-web",
      name: "TimoTime",
      redirectUris: [`${TIME_WEB}/api/auth/callback`],
      confidential: true,
      resources: [TIME_API, CORE_API],
      clientCredentialsScopes: [...PRODUCT_MACHINE_SCOPES],
    },
    {
      clientId: "timotime-mobile",
      name: "TimoTime na telefon",
      redirectUris: ["timotime://oauth/callback", EXPO_GO],
      confidential: false,
      resources: [TIME_API, CORE_API],
    },
    {
      // Panel klienta (BFF bez własnej bazy): tylko Core API, bez tokenów serwerowych i bez wpisu w products
      clientId: "monorise-portal",
      name: "MonorisePortal",
      redirectUris: [`${PORTAL_WEB}/api/auth/callback`],
      confidential: true,
      resources: [CORE_API],
    },
  ],
  products: [
    { key: "avenmail", name: "AvenMail", registrationClientId: "avenmail-web" },
    { key: "timotime", name: "TimoTime", registrationClientId: "timotime-web" },
  ],
});

const dir = new URL("../.data/", import.meta.url);
const file = new URL("oauth-clients.json", dir);
mkdirSync(dir, { recursive: true });
const previous = existsSync(file) ? (JSON.parse(readFileSync(file, "utf8")) as Record<string, string>) : {};
writeFileSync(file, `${JSON.stringify({ ...previous, ...secrets }, null, 2)}\n`, { mode: 0o600 });
const created = Object.keys(secrets);
console.log(
  created.length
    ? `Nowi klienci z sekretami: ${created.join(", ")} (zapisane w apps/auth/.data/oauth-clients.json).`
    : "Klienci OAuth są aktualni.",
);
await db.$disconnect();
