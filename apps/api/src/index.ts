import { createDb } from "@core/db";
import { buildServer } from "./server.js";
import { createTokenVerifier, remoteKeys } from "./tokens.js";

function required(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`Brak zmiennej środowiskowej ${name} (lokalnie: pnpm setup:env)`);
  return value;
}

const app = buildServer({
  db: createDb(required("CORE_DATABASE_URL")),
  verifyToken: createTokenVerifier({
    keys: remoteKeys(required("CORE_AUTH_JWKS_URL")),
    issuer: required("CORE_AUTH_ISSUER"),
    audience: required("CORE_API_AUDIENCE"),
  }),
  logger: true,
});

await app.listen({ host: process.env.HOST ?? "127.0.0.1", port: Number(process.env.PORT ?? 3200) });
