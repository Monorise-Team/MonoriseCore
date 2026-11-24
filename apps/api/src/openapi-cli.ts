import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { serializeOpenApiDocument } from "./openapi.js";

const OUTPUT_PATH = resolve(import.meta.dirname, "../../../openapi/core-api.json");
const checkOnly = process.argv.includes("--check");
const expected = serializeOpenApiDocument();

if (checkOnly) {
  const actual = existsSync(OUTPUT_PATH) ? readFileSync(OUTPUT_PATH, "utf8") : null;
  if (actual !== expected) {
    console.error("Plik openapi/core-api.json jest nieaktualny lub brakuje go. Uruchom: pnpm openapi");
    process.exit(1);
  }
  console.log("openapi/core-api.json jest aktualny.");
} else {
  mkdirSync(dirname(OUTPUT_PATH), { recursive: true });
  writeFileSync(OUTPUT_PATH, expected, "utf8");
  console.log("Zapisano openapi/core-api.json.");
}
