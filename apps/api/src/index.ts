import { createDb } from "@core/db";
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
  logger: true,
});

const summary = await registerCorePermissions(db);
app.log.info({ summary }, "zarejestrowano uprawnienia platformy Core");

const templatesSummary = await registerCoreRoleTemplates(db);
app.log.info({ summary: templatesSummary }, "zarejestrowano gotowe role platformy Core");

await app.listen({ host: process.env.HOST ?? "127.0.0.1", port: Number(process.env.PORT ?? 3200) });
