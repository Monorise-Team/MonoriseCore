import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { IDEMPOTENCY_KEY_HEADER, IDEMPOTENCY_REPLAYED_HEADER } from "@core/contracts";
import type { PrismaClient } from "@core/db";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { buildOpenApiDocument, serializeOpenApiDocument, type OpenApiSpec } from "../src/openapi.js";
import { ROUTE_LIST, supportsIdempotencyKey, toOpenApiPath } from "../src/routes.js";
import { buildServer } from "../src/server.js";

const COMMITTED_OPENAPI_PATH = resolve(import.meta.dirname, "../../../openapi/core-api.json");

const registeredRoutes: { method: string; path: string; idempotent: boolean }[] = [];
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
    verifyMachineToken: async () => {
      throw new Error("Stub verifyMachineToken nie powinien być wywołany w testach OpenAPI");
    },
    onRoute: (route) => {
      const methods = Array.isArray(route.method) ? route.method : [route.method];
      for (const method of methods) {
        const upper = method.toUpperCase();
        if (upper === "HEAD" || upper === "OPTIONS") continue;
        const idempotent = Boolean((route.config as { idempotent?: boolean } | undefined)?.idempotent);
        registeredRoutes.push({ method: upper, path: toOpenApiPath(route.url), idempotent });
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

  it("wymaga właściwego schematu bezpieczeństwa wyłącznie w chronionych operacjach", () => {
    expect("security" in document).toBe(false);

    for (const route of ROUTE_LIST) {
      const operation = document.paths[route.path]?.[route.method.toLowerCase()];
      expect(operation, `Brak operacji ${route.method} ${route.path}`).toBeDefined();

      if (route.auth === false) {
        expect(operation?.security).toBeUndefined();
        expect(operation?.responses["401"]).toBeUndefined();
      } else if (route.auth === "bearer") {
        expect(operation?.security).toEqual([{ bearerAuth: [] }]);
        expect(operation?.responses["401"]).toBeDefined();
      } else {
        expect(operation?.security).toEqual([{ [route.auth.scheme]: [...route.auth.scopes] }]);
        expect(operation?.responses["401"]).toBeDefined();
        expect(operation?.responses["403"]).toBeDefined();
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

  it("rejestruje każdą trasę POST z tokenem użytkownika przez registerPostRoute i dokumentuje Idempotency-Key dokładnie dla nich", () => {
    const idempotentRoutes = ROUTE_LIST.filter(supportsIdempotencyKey);
    expect(idempotentRoutes.length).toBeGreaterThan(0);

    const registeredByKey = new Map(registeredRoutes.map((route) => [`${route.method} ${route.path}`, route]));

    for (const route of ROUTE_LIST) {
      const expectedIdempotent = supportsIdempotencyKey(route);
      const registered = registeredByKey.get(`${route.method} ${route.path}`);
      expect(registered, `Brak zarejestrowanej trasy ${route.method} ${route.path}`).toBeDefined();
      expect(
        registered?.idempotent,
        `Trasa ${route.method} ${route.path} powinna mieć idempotent=${String(expectedIdempotent)}`,
      ).toBe(expectedIdempotent);

      const operation = document.paths[route.path]?.[route.method.toLowerCase()];
      expect(operation).toBeDefined();
      const idemParam = operation?.parameters?.find((p) => p.in === "header" && p.name === IDEMPOTENCY_KEY_HEADER);
      const successResponse = operation?.responses[String(route.successStatus)];

      if (expectedIdempotent) {
        expect(idemParam, `Brak nagłówka ${IDEMPOTENCY_KEY_HEADER} w ${route.method} ${route.path}`).toBeDefined();
        expect(idemParam?.required).toBe(false);
        expect(idemParam?.schema).toMatchObject({ type: "string", minLength: 1, maxLength: 255 });
        expect(operation?.responses["400"]).toBeDefined();
        expect(operation?.responses["409"]).toBeDefined();
        expect(successResponse?.headers?.[IDEMPOTENCY_REPLAYED_HEADER]).toMatchObject({
          required: false,
          schema: { type: "string", enum: ["true"] },
        });
      } else {
        expect(idemParam).toBeUndefined();
        expect(successResponse?.headers?.[IDEMPOTENCY_REPLAYED_HEADER]).toBeUndefined();
      }
    }
  });

  it("dokumentuje GET /core/v1/audit-log w tagu Audit wraz z filtrami i schematami AuditLogEntry*", () => {
    expect(document.tags.some((tag) => tag.name === "Audit")).toBe(true);

    const operation = document.paths["/core/v1/audit-log"]?.get;
    expect(operation).toBeDefined();
    expect(operation?.operationId).toBe("listAuditLog");
    expect(operation?.tags).toEqual(["Audit"]);
    expect(operation?.security).toEqual([{ bearerAuth: [] }]);
    expect(operation?.responses["200"]?.content?.["application/json"]?.schema).toEqual({
      $ref: "#/components/schemas/AuditLogEntryListResponse",
    });
    expect(operation?.responses["403"]).toBeDefined();
    expect(operation?.responses["422"]).toBeDefined();

    const queryParamNames = (operation?.parameters ?? [])
      .filter((param) => param.in === "query")
      .map((param) => param.name)
      .sort();
    expect(queryParamNames).toEqual(
      ["action", "actorAccountId", "actorType", "cursor", "from", "limit", "resourceId", "resourceType", "to"].sort(),
    );

    expect(document.components.schemas.AuditActorType).toBeDefined();
    expect(document.components.schemas.AuditLogEntry).toBeDefined();
    expect(document.components.schemas.AuditLogEntryList).toBeDefined();
    expect(document.components.schemas.AuditLogEntryListResponse).toBeDefined();

    const entryProps = (document.components.schemas.AuditLogEntry?.properties ?? {}) as Record<string, unknown>;
    expect("actorOperatorId" in entryProps).toBe(false);
    expect("actorDisplayName" in entryProps).toBe(true);
    expect("actionLabel" in entryProps).toBe(true);
  });

  it("dokumentuje edycję firmy i zarządzanie domenami w tagu Organization bez ujawniania verificationTokenHash", () => {
    expect(document.paths["/core/v1/organization"]?.patch?.operationId).toBe("updateOrganization");
    expect(document.paths["/core/v1/organization/domains"]?.post?.operationId).toBe("addOrganizationDomain");
    expect(document.paths["/core/v1/organization/domains/{domainId}/verify"]?.post?.operationId).toBe(
      "verifyOrganizationDomain",
    );
    expect(document.paths["/core/v1/organization/domains/{domainId}"]?.delete?.operationId).toBe(
      "deleteOrganizationDomain",
    );
    expect(document.paths["/core/v1/organization/domains/{domainId}/primary"]?.put?.operationId).toBe(
      "setPrimaryOrganizationDomain",
    );

    expect(
      document.paths["/core/v1/organization/domains/{domainId}"]?.delete?.responses["204"]?.content,
    ).toBeUndefined();
    expect(document.components.schemas.DomainName).toBeDefined();
    expect(document.components.schemas.UpdateOrganization).toBeDefined();
    expect(document.components.schemas.CreateOrganizationDomain).toBeDefined();
    expect(document.components.schemas.VerifyOrganizationDomain).toBeDefined();
    expect(document.components.schemas.OrganizationDomainResponse).toBeDefined();

    const domainProps = (document.components.schemas.OrganizationDomain?.properties ?? {}) as Record<string, unknown>;
    expect(Object.keys(domainProps).sort()).toEqual([
      "domain",
      "id",
      "isPrimary",
      "lastCheckedAt",
      "status",
      "verificationTxtName",
      "verificationTxtValue",
      "verifiedAt",
    ]);
    expect("verificationTokenHash" in domainProps).toBe(false);
  });

  it("dokumentuje POST /core/v1/employees/{employeeId}/deactivate i /reactivate z Idempotency-Key i EmployeeResponse", () => {
    for (const [path, operationId] of [
      ["/core/v1/employees/{employeeId}/deactivate", "deactivateEmployee"],
      ["/core/v1/employees/{employeeId}/reactivate", "reactivateEmployee"],
    ] as const) {
      const operation = document.paths[path]?.post;
      expect(operation, `Brak operacji POST ${path}`).toBeDefined();
      expect(operation?.operationId).toBe(operationId);
      expect(operation?.tags).toEqual(["People"]);
      expect(operation?.security).toEqual([{ bearerAuth: [] }]);
      expect(operation?.requestBody).toBeUndefined();
      expect(operation?.responses["200"]?.content?.["application/json"]?.schema).toEqual({
        $ref: "#/components/schemas/EmployeeResponse",
      });
      expect(operation?.responses["200"]?.headers?.[IDEMPOTENCY_REPLAYED_HEADER]).toMatchObject({
        required: false,
        schema: { type: "string", enum: ["true"] },
      });
      expect(operation?.parameters?.some((p) => p.in === "path" && p.name === "employeeId" && p.required)).toBe(true);
      expect(operation?.parameters?.some((p) => p.in === "header" && p.name === IDEMPOTENCY_KEY_HEADER)).toBe(true);
      expect(operation?.responses["400"]).toBeDefined();
      expect(operation?.responses["401"]).toBeDefined();
      expect(operation?.responses["403"]).toBeDefined();
      expect(operation?.responses["404"]).toBeDefined();
      expect(operation?.responses["409"]).toBeDefined();
      expect(operation?.responses["422"]).toBeDefined();
      expect(operation?.responses["500"]).toBeDefined();
    }
  });
});
