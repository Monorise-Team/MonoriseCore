import { createDb } from "@core/db";
import { startOutboxPublisher } from "./event-feed.js";
import { parseIdempotencyCleanupIntervalMs, startIdempotencyCleanup } from "./idempotency.js";
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
const tokenOptions = {
  keys: remoteKeys(required("CORE_AUTH_JWKS_URL")),
  issuer: required("CORE_AUTH_ISSUER"),
  audience: required("CORE_API_AUDIENCE"),
};

const app = buildServer({
  db,
  verifyToken: createTokenVerifier(tokenOptions),
  verifyMachineToken: createMachineTokenVerifier(tokenOptions),
  authUrl: process.env.CORE_AUTH_URL ?? process.env.CORE_AUTH_ISSUER,
  domainVerificationSecret: required("CORE_DOMAIN_VERIFICATION_SECRET"),
  devTrustDomains: process.env.CORE_DEV_TRUST_DOMAINS === "1" && process.env.NODE_ENV !== "production",
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

// Sprzątanie wygasłych kluczy powtórzeń Idempotency-Key (MonoriseCore#30); 0 wyłącza
const idempotencyCleanupIntervalMs = parseIdempotencyCleanupIntervalMs(
  process.env.CORE_IDEMPOTENCY_CLEANUP_INTERVAL_MS,
);
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
