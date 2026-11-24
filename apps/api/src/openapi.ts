import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import {
  AccountStatus,
  ApiErrorBody,
  ApiErrorDetail,
  ApiErrorResponse,
  ApiListMeta,
  apiListSuccessSchema,
  ApiMeta,
  apiSuccessSchema,
  CreateEmployee,
  CreateUnit,
  DomainStatus,
  Employee,
  EmployeeStatus,
  ErrorCode,
  Health,
  Me,
  Organization,
  OrganizationDomain,
  OrganizationStatus,
  Permission,
  PermissionManifestEntry,
  PERMISSIONS_REGISTER_SCOPE,
  ProductKey,
  PutUnitMember,
  RegisterPermissionsResult,
  Unit,
  UnitMember,
  UnitMembershipRole,
  UnitStatus,
  UnitType,
  UpdateUnit,
} from "@core/contracts";
import { z } from "zod";
import {
  OpenApiDocument,
  ROUTE_LIST,
  TAGS,
  type ErrorStatus,
  type ParameterDefinition,
  type RouteDefinition,
} from "./routes.js";

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

export type OpenApiSecurityScheme =
  | {
      type: "http";
      scheme: "bearer";
      bearerFormat: string;
      description: string;
    }
  | {
      type: "oauth2";
      description: string;
      flows: {
        clientCredentials: {
          tokenUrl: string;
          scopes: Record<string, string>;
        };
      };
    };

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
    securitySchemes: Record<string, OpenApiSecurityScheme>;
    schemas: Record<string, Record<string, unknown>>;
  };
}

export interface OpenApiParameterObject {
  name: string;
  in: "path" | "query";
  required: boolean;
  description: string;
  schema: Record<string, unknown>;
}

export interface OpenApiRequestBodyObject {
  required: true;
  description?: string;
  content: {
    "application/json": {
      schema: { $ref: string };
    };
  };
}

export interface OpenApiResponseObject {
  description: string;
  content?: {
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
  security?: Record<string, string[]>[];
  parameters?: OpenApiParameterObject[];
  requestBody?: OpenApiRequestBodyObject;
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

function buildSchemaRegistry(routes: readonly RouteDefinition[]) {
  const registry = z.registry<{ id: string }>();
  const idBySchema = new Map<z.ZodType, string>();
  const register = (id: string, schema: z.ZodType) => {
    if (!registry.has(schema)) {
      registry.add(schema, { id });
      idBySchema.set(schema, id);
    }
  };

  register("ErrorCode", ErrorCode);
  register("ApiErrorDetail", ApiErrorDetail);
  register("ApiErrorBody", ApiErrorBody);
  register("ApiMeta", ApiMeta);
  register("ApiListMeta", ApiListMeta);
  register("ApiErrorResponse", ApiErrorResponse);
  register("Health", Health);
  register("OpenApiDocument", OpenApiDocument);
  register("OrganizationStatus", OrganizationStatus);
  register("DomainStatus", DomainStatus);
  register("OrganizationDomain", OrganizationDomain);
  register("Organization", Organization);
  register("EmployeeStatus", EmployeeStatus);
  register("Employee", Employee);
  register("CreateEmployee", CreateEmployee);
  register("AccountStatus", AccountStatus);
  register("Me", Me);
  register("UnitType", UnitType);
  register("UnitStatus", UnitStatus);
  register("UnitMembershipRole", UnitMembershipRole);
  register("Unit", Unit);
  register("CreateUnit", CreateUnit);
  register("UpdateUnit", UpdateUnit);
  register("UnitMember", UnitMember);
  register("PutUnitMember", PutUnitMember);
  register("ProductKey", ProductKey);
  register("PermissionManifestEntry", PermissionManifestEntry);
  register("RegisterPermissionsResult", RegisterPermissionsResult);
  register("Permission", Permission);

  for (const route of routes) {
    if (route.requestBodySchemaName && route.requestBodySchema) {
      register(route.requestBodySchemaName, route.requestBodySchema);
    }
    if (route.dataSchemaName && route.dataSchema) {
      register(route.dataSchemaName, route.dataSchema);
      if (route.envelope && route.responseSchemaName) {
        const envelopeSchema = route.paginated
          ? apiListSuccessSchema(route.dataSchema)
          : apiSuccessSchema(route.dataSchema);
        register(route.responseSchemaName, envelopeSchema);
      }
    }
  }

  return { registry, idBySchema };
}

function buildComponentSchemas(registry: ReturnType<typeof buildSchemaRegistry>["registry"]) {
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

function buildParameter(
  param: ParameterDefinition,
  idBySchema: ReadonlyMap<z.ZodType, string>,
): OpenApiParameterObject {
  const registeredId = idBySchema.get(param.schema);
  const schema = registeredId
    ? { $ref: `#/components/schemas/${registeredId}` }
    : stripSchemaMeta(z.toJSONSchema(param.schema, { target: "draft-2020-12" }) as Record<string, unknown>);
  return {
    name: param.name,
    in: param.in,
    required: param.required,
    description: param.description,
    schema,
  };
}

function describeError(status: ErrorStatus, codes: readonly string[]): string {
  const base = ERROR_STATUS_SUMMARY[status];
  return codes.length > 0 ? `${base} (${codes.join(", ")}).` : `${base}.`;
}

function buildOperation(route: RouteDefinition, idBySchema: ReadonlyMap<z.ZodType, string>): OpenApiOperation {
  const responses: Record<string, OpenApiResponseObject> = {};

  if (route.successStatus === 204) {
    responses["204"] = {
      description: route.responseDescription,
    };
  } else {
    const successSchemaName =
      route.envelope && route.responseSchemaName ? route.responseSchemaName : route.dataSchemaName;
    if (!successSchemaName) {
      throw new Error(`Brak schematu odpowiedzi dla operacji ${route.operationId}`);
    }
    responses[String(route.successStatus)] = {
      description: route.responseDescription,
      content: {
        "application/json": {
          schema: { $ref: `#/components/schemas/${successSchemaName}` },
        },
      },
    };
  }

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

  const parameters =
    route.parameters && route.parameters.length > 0
      ? route.parameters.map((param) => buildParameter(param, idBySchema))
      : undefined;

  const requestBody: OpenApiRequestBodyObject | undefined = route.requestBodySchemaName
    ? {
        required: true,
        ...(route.requestBodyDescription ? { description: route.requestBodyDescription } : {}),
        content: {
          "application/json": {
            schema: { $ref: `#/components/schemas/${route.requestBodySchemaName}` },
          },
        },
      }
    : undefined;

  const security: Record<string, string[]>[] | undefined =
    route.auth === false
      ? undefined
      : route.auth === "bearer"
        ? [{ bearerAuth: [] }]
        : [{ [route.auth.scheme]: [...route.auth.scopes] }];

  const operation: OpenApiOperation = {
    tags: [route.tag],
    operationId: route.operationId,
    summary: route.summary,
    ...(route.description ? { description: route.description } : {}),
    ...(security ? { security } : {}),
    ...(parameters ? { parameters } : {}),
    ...(requestBody ? { requestBody } : {}),
    responses,
  };

  return operation;
}

function buildPaths(
  routes: readonly RouteDefinition[],
  idBySchema: ReadonlyMap<z.ZodType, string>,
): Record<string, Record<string, OpenApiOperation>> {
  const grouped = new Map<string, Map<string, OpenApiOperation>>();
  for (const route of routes) {
    const method = route.method.toLowerCase();
    const methods = grouped.get(route.path) ?? new Map<string, OpenApiOperation>();
    methods.set(method, buildOperation(route, idBySchema));
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
  const { registry, idBySchema } = buildSchemaRegistry(ROUTE_LIST);

  return {
    openapi: "3.1.0",
    info: {
      title: "Monorise Core API",
      version: readRootVersion(),
      summary: "Core API platformy Monorise: tożsamość, firma, pracownicy, struktura, uprawnienia i stan usługi.",
      description:
        "Opis Core API wygenerowany automatycznie z kodu (katalog ścieżek i schematy Zod) i źródło prawdy " +
        "dla generowanego klienta `@monorise-team/sdk`. Wszystkie odpowiedzi ustawiają nagłówek `Cache-Control: no-store` " +
        "i używają koperty `{ data, meta, error }` (ADR-0044), z wyjątkiem `GET /core/v1/openapi.json`, który zwraca " +
        "czysty dokument OpenAPI JSON, oraz odpowiedzi `204 No Content`. Nieznane ścieżki zwracają status `404` z kodem " +
        "`NOT_FOUND` w kopercie błędu.",
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
    paths: buildPaths(ROUTE_LIST, idBySchema),
    components: {
      securitySchemes: {
        bearerAuth: {
          type: "http",
          scheme: "bearer",
          bearerFormat: "JWT",
          description: "Token dostępu JWT (EdDSA) z auth.monorise.studio, ważny 5 minut (ADR-0023).",
        },
        productOAuth: {
          type: "oauth2",
          description:
            "Token maszynowy OAuth 2.1 (client_credentials, JWT EdDSA) wydany dla poufnego klienta produktu.",
          flows: {
            clientCredentials: {
              tokenUrl: "https://auth.monorise.studio/api/auth/oauth2/token",
              scopes: {
                [PERMISSIONS_REGISTER_SCOPE]: "Rejestracja manifestu uprawnień produktu w Core.",
              },
            },
          },
        },
      },
      schemas: buildComponentSchemas(registry),
    },
  };
}

export function serializeOpenApiDocument(document: OpenApiSpec = buildOpenApiDocument()): string {
  return `${JSON.stringify(document, null, 2)}\n`;
}
