import { createDb, isDevTrustDomainsEnabled, resolveDomainVerificationSecret } from "@core/db";
import { startOutboxPublisher } from "./event-feed.js";
import { parseIdempotencyCleanupIntervalMs, startIdempotencyCleanup } from "./idempotency.js";
import { resolveNotificationsMailConfig } from "./mail.js";
import { parseMailOutboxIntervalMs, startMailOutboxWorker, type MailOutboxWorker } from "./mail-outbox.js";
import { resolveApiUrl, resolveNotificationsUnsubscribeSecret } from "./notifications.js";
import { registerCorePermissions } from "./permissions-registry.js";
import { registerCoreRoleTemplates } from "./role-templates-registry.js";
import { buildServer } from "./server.js";
import { createMachineTokenVerifier, createTokenVerifier, remoteKeys } from "./tokens.js";

function required(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`Brak zmiennej środowiskowej ${name} (lokalnie: pnpm setup:env)`);
  return value;
}

const db = createDb(required("CORE_DATABASE_URL"));
const authIssuer = required("CORE_AUTH_ISSUER");
const authUrl = process.env.CORE_AUTH_URL?.trim() || authIssuer;
const apiAudience = required("CORE_API_AUDIENCE");
const apiUrl = resolveApiUrl(process.env.CORE_API_URL, {
  NODE_ENV: process.env.NODE_ENV,
  CORE_API_URL: process.env.CORE_API_URL,
  CORE_API_AUDIENCE: apiAudience,
});
const tokenOptions = {
  keys: remoteKeys(required("CORE_AUTH_JWKS_URL")),
  issuer: authIssuer,
  audience: apiAudience,
};

const domainVerificationSecret = resolveDomainVerificationSecret({ env: process.env });
const notificationsUnsubscribeSecret = resolveNotificationsUnsubscribeSecret({
  env: process.env,
  fallbackSecret: domainVerificationSecret,
});
// Walidacja konfiguracji kanału powiadomień przy starcie (na produkcji wymagane CORE_NOTIFICATIONS_SMTP_URL i CORE_NOTIFICATIONS_FROM)
resolveNotificationsMailConfig(process.env);

const mailOutboxIntervalMs = parseMailOutboxIntervalMs(process.env.CORE_MAIL_OUTBOX_INTERVAL_MS);
const idempotencyCleanupIntervalMs = parseIdempotencyCleanupIntervalMs(
  process.env.CORE_IDEMPOTENCY_CLEANUP_INTERVAL_MS,
);

let mailOutboxWorker: MailOutboxWorker | undefined;

const app = buildServer({
  db,
  verifyToken: createTokenVerifier(tokenOptions),
  verifyMachineToken: createMachineTokenVerifier(tokenOptions),
  domainVerificationSecret,
  notificationsUnsubscribeSecret,
  devTrustDomains: isDevTrustDomainsEnabled(process.env),
  mailOutboxWorker: { wake: () => mailOutboxWorker?.wake() },
  logger: true,
});

const summary = await registerCorePermissions(db);
app.log.info({ summary }, "zarejestrowano uprawnienia platformy Core");

const templatesSummary = await registerCoreRoleTemplates(db);
app.log.info({ summary: templatesSummary }, "zarejestrowano gotowe role platformy Core");

// Wysyłka zdarzeń z outboxa do kanału produktów (MonoriseCore#53); 0 wyłącza (np. gdy wysyła inna instancja)
const publishIntervalMs = Number(process.env.CORE_OUTBOX_PUBLISH_INTERVAL_MS ?? 1000);
if (publishIntervalMs > 0) {
  const stopPublisher = startOutboxPublisher({
    db,
    intervalMs: publishIntervalMs,
    onError: (error) => app.log.error({ err: error }, "wysyłka zdarzeń z outboxa nie powiodła się"),
  });
  app.addHook("onClose", async () => stopPublisher());
}

// Transakcyjna kolejka wysyłki poczty (MonoriseCore#60, MonoriseCore#86); 0 wyłącza (np. gdy wysyła inna instancja)
if (mailOutboxIntervalMs > 0) {
  mailOutboxWorker = startMailOutboxWorker({
    db,
    intervalMs: mailOutboxIntervalMs,
    authUrl,
    apiUrl,
    notificationsUnsubscribeSecret,
    onError: (error) => app.log.error({ err: error }, "wysyłka poczty z kolejki outbox nie powiodła się"),
  });
  app.addHook("onClose", async () => {
    await mailOutboxWorker?.stop();
  });
}

// Sprzątanie wygasłych kluczy powtórzeń Idempotency-Key (MonoriseCore#30); 0 wyłącza
if (idempotencyCleanupIntervalMs > 0) {
  const stopIdempotencyCleanup = startIdempotencyCleanup({
    db,
    intervalMs: idempotencyCleanupIntervalMs,
    onError: (error) => app.log.error({ err: error }, "sprzątanie wygasłych kluczy Idempotency-Key nie powiodło się"),
  });
  app.addHook("onClose", async () => {
    await stopIdempotencyCleanup();
  });
}

await app.listen({ host: process.env.HOST ?? "127.0.0.1", port: Number(process.env.PORT ?? 3200) });
