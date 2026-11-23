import "server-only";
import { createDb } from "@core/db";
import type { PrismaClient } from "@core/db";
import { config } from "./config";

const globalForDb = globalThis as unknown as { coreDb?: PrismaClient };

/** Jedno połączenie na proces (także po przeładowaniu modułów w trybie deweloperskim). Rola core_app. */
export const db: PrismaClient = (globalForDb.coreDb ??= createDb(config.databaseUrl));
