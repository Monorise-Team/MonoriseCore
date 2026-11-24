import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import type { PrismaClient } from "@core/db";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { buildOpenApiDocument, serializeOpenApiDocument, type OpenApiSpec } from "../src/openapi.js";
import { ROUTE_LIST, toOpenApiPath } from "../src/routes.js";
import { buildServer } from "../src/server.js";

const COMMITTED_OPENAPI_PATH = resolve(import.meta.dirname, "../../../openapi/core-api.json");

const registeredRoutes: { method: string; path: string }[] = [];
let app: ReturnType<typeof buildServer>;
let document: OpenApiSpec;

function collectSchemaRefs(value: unknown, refs: Set<string>): void {
  if (!value || typeof value !== "object") return;
  if (Array.isArray(value)) {
    for (const item of value) collectSchemaRefs(item, refs);
    return;
  }
  for (const [key, entry] of Object.entries(value)) {
    if (key === "$ref" && typeof entry === "string") {
      refs.add(entry);
    } else {
      collectSchemaRefs(entry, refs);
    }
  }
}

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
        registeredRoutes.push({ method: upper, path: toOpenApiPath(route.url) });
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

  it("opisuje parametry ścieżek, treści żądań, kody 201/204 i ma poprawne referencje bez nieużywanych schematów", () => {
    const schemaNames = new Set(Object.keys(document.components.schemas));
    const usedRefs = new Set<string>();
    collectSchemaRefs(document.paths, usedRefs);
    collectSchemaRefs(document.components.schemas, usedRefs);

    for (const ref of usedRefs) {
      expect(ref.startsWith("#/components/schemas/")).toBe(true);
      const name = ref.slice("#/components/schemas/".length);
      expect(schemaNames.has(name), `Brakujący schemat ${name}`).toBe(true);
    }

    for (const name of schemaNames) {
      expect(usedRefs.has(`#/components/schemas/${name}`), `Nieużywany schemat ${name}`).toBe(true);
    }

    for (const [path, methods] of Object.entries(document.paths)) {
      const pathParams = [...path.matchAll(/\{([^}]+)\}/g)].map((match) => match[1]!);
      for (const [method, operation] of Object.entries(methods)) {
        for (const paramName of pathParams) {
          const declared = operation.parameters?.find((p) => p.in === "path" && p.name === paramName);
          expect(declared, `Brak parametru ścieżki ${paramName} w ${method.toUpperCase()} ${path}`).toBeDefined();
          expect(declared?.required).toBe(true);
        }
        if (operation.responses["204"]) {
          expect(operation.responses["204"].content).toBeUndefined();
        }
      }
    }

    for (const paginatedRoute of ROUTE_LIST.filter((route) => route.paginated)) {
      const operation = document.paths[paginatedRoute.path]?.[paginatedRoute.method.toLowerCase()];
      expect(operation?.parameters?.find((p) => p.in === "query" && p.name === "limit")).toBeDefined();
      expect(operation?.parameters?.find((p) => p.in === "query" && p.name === "cursor")).toBeDefined();
      const responseSchema = paginatedRoute.responseSchemaName
        ? document.components.schemas[paginatedRoute.responseSchemaName]
        : undefined;
      expect((responseSchema?.properties as Record<string, unknown> | undefined)?.meta).toEqual({
        $ref: "#/components/schemas/ApiListMeta",
      });
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
