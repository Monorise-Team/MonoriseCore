import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import {
  ApiErrorBody,
  ApiErrorDetail,
  ApiErrorResponse,
  ApiMeta,
  apiSuccessSchema,
  DomainStatus,
  Employee,
  ErrorCode,
  Health,
  Me,
  Organization,
  OrganizationDomain,
  OrganizationStatus,
} from "@core/contracts";
import { z } from "zod";
import { OpenApiDocument, ROUTE_LIST, TAGS, type ErrorStatus, type RouteDefinition } from "./routes.js";

const ROOT_PACKAGE_JSON_PATH = resolve(import.meta.dirname, "../../../package.json");

const ERROR_STATUS_SUMMARY: Record<ErrorStatus, string> = {
  401: "Brak albo nieważny token dostępu albo wyłączone konto",
  403: "Brak uprawnień",
  404: "Nie znaleziono zasobu",
  409: "Konflikt stanu zasobu",
  422: "Błędne dane wejściowe",
  429: "Przekroczony limit zapytań",
  500: "Wewnętrzny błąd serwera",
};

const METHOD_ORDER = ["get", "post", "put", "patch", "delete"] as const;

export interface OpenApiSpec {
  openapi: "3.1.0";
  info: {
    title: string;
    version: string;
    summary: string;
    description: string;
    license: {
      name: string;
      identifier: string;
    };
  };
  servers: { url: string; description: string }[];
  tags: { name: string; description: string }[];
  paths: Record<string, Record<string, OpenApiOperation>>;
  components: {
    securitySchemes: Record<
      string,
      {
        type: "http";
        scheme: "bearer";
        bearerFormat: string;
        description: string;
      }
    >;
    schemas: Record<string, Record<string, unknown>>;
  };
}

export interface OpenApiResponseObject {
  description: string;
  content: {
    "application/json": {
      schema: { $ref: string };
    };
  };
}

export interface OpenApiOperation {
  tags: string[];
  operationId: string;
  summary: string;
  description?: string;
  security?: { bearerAuth: string[] }[];
  responses: Record<string, OpenApiResponseObject>;
}

function readRootVersion(): string {
  const raw = readFileSync(ROOT_PACKAGE_JSON_PATH, "utf8");
  const parsed = JSON.parse(raw) as { version?: unknown };
  if (typeof parsed.version !== "string" || !parsed.version) {
    throw new Error(`Brak poprawnego pola "version" w ${ROOT_PACKAGE_JSON_PATH}`);
  }
  return parsed.version;
}

function stripSchemaMeta(schema: Record<string, unknown>): Record<string, unknown> {
  const result: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(schema)) {
    if (key === "$schema" || key === "$id") continue;
    result[key] = value;
  }
  return result;
}

function buildComponentSchemas(routes: readonly RouteDefinition[]): Record<string, Record<string, unknown>> {
  const registry = z.registry<{ id: string }>();
  const register = (id: string, schema: z.ZodType) => {
    if (!registry.has(schema)) registry.add(schema, { id });
  };

  register("ErrorCode", ErrorCode);
  register("ApiErrorDetail", ApiErrorDetail);
  register("ApiErrorBody", ApiErrorBody);
  register("ApiMeta", ApiMeta);
  register("ApiErrorResponse", ApiErrorResponse);
  register("Health", Health);
  register("OpenApiDocument", OpenApiDocument);
  register("OrganizationStatus", OrganizationStatus);
  register("DomainStatus", DomainStatus);
  register("OrganizationDomain", OrganizationDomain);
  register("Organization", Organization);
  register("Employee", Employee);
  register("Me", Me);

  for (const route of routes) {
    register(route.dataSchemaName, route.dataSchema);
    if (route.envelope && route.responseSchemaName) {
      register(route.responseSchemaName, apiSuccessSchema(route.dataSchema));
    }
  }

  const generated = z.toJSONSchema(registry, {
    target: "draft-2020-12",
    uri: (id) => `#/components/schemas/${id}`,
  });

  const sorted: Record<string, Record<string, unknown>> = {};
  for (const name of Object.keys(generated.schemas).sort()) {
    const schema = generated.schemas[name];
    if (schema) sorted[name] = stripSchemaMeta(schema as Record<string, unknown>);
  }
  return sorted;
}

function describeError(status: ErrorStatus, codes: readonly string[]): string {
  const base = ERROR_STATUS_SUMMARY[status];
  return codes.length > 0 ? `${base} (${codes.join(", ")}).` : `${base}.`;
}

function buildOperation(route: RouteDefinition): OpenApiOperation {
  const successSchemaName =
    route.envelope && route.responseSchemaName ? route.responseSchemaName : route.dataSchemaName;
  const responses: Record<string, OpenApiResponseObject> = {
    "200": {
      description: route.responseDescription,
      content: {
        "application/json": {
          schema: { $ref: `#/components/schemas/${successSchemaName}` },
        },
      },
    },
  };

  const errorStatuses = Object.keys(route.errors)
    .map(Number)
    .sort((a, b) => a - b) as ErrorStatus[];

  for (const status of errorStatuses) {
    const codes = route.errors[status];
    if (!codes) continue;
    responses[String(status)] = {
      description: describeError(status, codes),
      content: {
        "application/json": {
          schema: { $ref: "#/components/schemas/ApiErrorResponse" },
        },
      },
    };
  }

  const operation: OpenApiOperation = {
    tags: [route.tag],
    operationId: route.operationId,
    summary: route.summary,
    ...(route.description ? { description: route.description } : {}),
    ...(route.auth ? { security: [{ bearerAuth: [] }] } : {}),
    responses,
  };

  return operation;
}

function buildPaths(routes: readonly RouteDefinition[]): Record<string, Record<string, OpenApiOperation>> {
  const grouped = new Map<string, Map<string, OpenApiOperation>>();
  for (const route of routes) {
    const method = route.method.toLowerCase();
    const methods = grouped.get(route.path) ?? new Map<string, OpenApiOperation>();
    methods.set(method, buildOperation(route));
    grouped.set(route.path, methods);
  }

  const paths: Record<string, Record<string, OpenApiOperation>> = {};
  for (const path of [...grouped.keys()].sort()) {
    const methods = grouped.get(path);
    if (!methods) continue;
    const item: Record<string, OpenApiOperation> = {};
    for (const method of METHOD_ORDER) {
      const operation = methods.get(method);
      if (operation) item[method] = operation;
    }
    paths[path] = item;
  }
  return paths;
}

/**
 * Buduje deterministyczny opis OpenAPI 3.1.0 dla Core API na podstawie katalogu ścieżek i schematów Zod.
 * Ten dokument jest jedynym źródłem dla generatora klienta `@monorise-team/sdk`.
 */
export function buildOpenApiDocument(): OpenApiSpec {
  const usedTags = new Set(ROUTE_LIST.map((route) => route.tag));

  return {
    openapi: "3.1.0",
    info: {
      title: "Monorise Core API",
      version: readRootVersion(),
      summary: "Core API platformy Monorise: tożsamość, firma i stan usługi.",
      description:
        "Opis Core API wygenerowany automatycznie z kodu (katalog ścieżek i schematy Zod) i źródło prawdy " +
        "dla generowanego klienta `@monorise-team/sdk`. Wszystkie odpowiedzi ustawiają nagłówek `Cache-Control: no-store` " +
        "i używają koperty `{ data, meta, error }` (ADR-0044), z wyjątkiem `GET /core/v1/openapi.json`, który zwraca " +
        "czysty dokument OpenAPI JSON. Nieznane ścieżki zwracają status `404` z kodem `NOT_FOUND` w kopercie błędu.",
      license: {
        name: "Proprietary, all rights reserved",
        identifier: "LicenseRef-Proprietary",
      },
    },
    servers: [
      { url: "http://localhost:3200", description: "Lokalnie" },
      { url: "https://api.monorise.studio", description: "Produkcja (planowana)" },
    ],
    tags: TAGS.filter((tag) => usedTags.has(tag.name)).map((tag) => ({
      name: tag.name,
      description: tag.description,
    })),
    paths: buildPaths(ROUTE_LIST),
    components: {
      securitySchemes: {
        bearerAuth: {
          type: "http",
          scheme: "bearer",
          bearerFormat: "JWT",
          description: "Token dostępu JWT (EdDSA) z auth.monorise.studio, ważny 5 minut (ADR-0023).",
        },
      },
      schemas: buildComponentSchemas(ROUTE_LIST),
    },
  };
}

export function serializeOpenApiDocument(document: OpenApiSpec = buildOpenApiDocument()): string {
  return `${JSON.stringify(document, null, 2)}\n`;
}
