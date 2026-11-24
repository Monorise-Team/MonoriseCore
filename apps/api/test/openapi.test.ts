import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import type { PrismaClient } from "@core/db";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { buildOpenApiDocument, serializeOpenApiDocument, type OpenApiSpec } from "../src/openapi.js";
import { ROUTE_LIST } from "../src/routes.js";
import { buildServer } from "../src/server.js";

const COMMITTED_OPENAPI_PATH = resolve(import.meta.dirname, "../../../openapi/core-api.json");

const registeredRoutes: { method: string; path: string }[] = [];
let app: ReturnType<typeof buildServer>;
let document: OpenApiSpec;

beforeAll(() => {
  document = buildOpenApiDocument();
  app = buildServer({
    db: {} as PrismaClient,
    verifyToken: async () => {
      throw new Error("Stub verifyToken nie powinien być wywołany w testach OpenAPI");
    },
    onRoute: (route) => {
      const methods = Array.isArray(route.method) ? route.method : [route.method];
      for (const method of methods) {
        const upper = method.toUpperCase();
        if (upper === "HEAD" || upper === "OPTIONS") continue;
        registeredRoutes.push({ method: upper, path: route.url });
      }
    },
  });
});

afterAll(async () => {
  await app?.close();
});

describe("OpenAPI Core API", () => {
  it("pokrywa dokładnie wszystkie ścieżki zarejestrowane w Fastify (1:1)", () => {
    const fastifySet = new Set(registeredRoutes.map((route) => `${route.method} ${route.path}`));
    const openApiSet = new Set<string>();
    for (const [path, methods] of Object.entries(document.paths)) {
      for (const method of Object.keys(methods)) {
        openApiSet.add(`${method.toUpperCase()} ${path}`);
      }
    }

    expect([...fastifySet].sort()).toEqual([...openApiSet].sort());
  });

  it("wymaga bearerAuth wyłącznie w chronionych operacjach", () => {
    expect("security" in document).toBe(false);

    for (const route of ROUTE_LIST) {
      const operation = document.paths[route.path]?.[route.method.toLowerCase()];
      expect(operation, `Brak operacji ${route.method} ${route.path}`).toBeDefined();

      if (route.auth) {
        expect(operation?.security).toEqual([{ bearerAuth: [] }]);
        expect(operation?.responses["401"]).toBeDefined();
      } else {
        expect(operation?.security).toBeUndefined();
        expect(operation?.responses["401"]).toBeUndefined();
      }
    }
  });

  it("jest zgodny z zakomitowanym plikiem openapi/core-api.json i deterministyczny", () => {
    const rawCommitted = readFileSync(COMMITTED_OPENAPI_PATH, "utf8");
    expect(JSON.parse(rawCommitted)).toEqual(document);
    expect(rawCommitted).toBe(serializeOpenApiDocument(document));
    expect(serializeOpenApiDocument(buildOpenApiDocument())).toBe(rawCommitted);
  });

  it("udostępnia GET /core/v1/openapi.json bez tokenu jako czysty dokument OpenAPI z Cache-Control: no-store", async () => {
    const response = await app.inject({ method: "GET", url: "/core/v1/openapi.json" });

    expect(response.statusCode).toBe(200);
    expect(response.headers["cache-control"]).toBe("no-store");
    expect(response.headers["content-type"]).toContain("application/json");
    expect(response.json()).toEqual(document);
    expect(response.json()).not.toHaveProperty("data");
    expect(response.json()).not.toHaveProperty("error");
  });
});
