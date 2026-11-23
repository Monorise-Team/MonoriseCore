import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

export default defineConfig({
  resolve: {
    alias: {
      "@": fileURLToPath(new URL("./src", import.meta.url)),
      // Moduły tylko dla serwera: w testach nie ma podziału na klienta i serwer
      "server-only": fileURLToPath(new URL("./test/server-only.ts", import.meta.url)),
    },
  },
  test: {
    environment: "node",
    testTimeout: 30_000,
    hookTimeout: 30_000,
    fileParallelism: false,
    env: {
      // Prawdziwy PostgreSQL z rolą aplikacji (lokalnie docker compose, w CI usługa)
      CORE_DATABASE_URL:
        process.env.CORE_TEST_APP_DATABASE_URL ?? "postgresql://core_app:core_app@localhost:5433/monorise_core_test",
      BETTER_AUTH_SECRET: "test-secret-test-secret-test-secret-0123456789",
      BETTER_AUTH_URL: "http://localhost:3100",
      CORE_TOKEN_AUDIENCE: "http://localhost:3200",
      CORE_SMTP_URL: "memory",
      CORE_DEV_TRUST_DOMAINS: "1",
    },
  },
});
