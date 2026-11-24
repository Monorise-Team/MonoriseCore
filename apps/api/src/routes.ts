import {
  API_PREFIX,
  CreateEmployee,
  CreateUnit,
  Employee,
  Health,
  Me,
  Organization,
  PutUnitMember,
  Unit,
  UnitMember,
  UnitStatus,
  UpdateUnit,
  type ErrorCode,
} from "@core/contracts";
import { z } from "zod";

export type HttpMethod = "GET" | "POST" | "PUT" | "PATCH" | "DELETE";

export type RouteTag = "System" | "People" | "Organization" | "Structure";

export interface TagDefinition {
  name: RouteTag;
  description: string;
}

export const TAGS: readonly TagDefinition[] = [
  { name: "System", description: "Stan usługi i opis OpenAPI." },
  { name: "People", description: "Pracownicy i konta; tu także dane zalogowanego konta." },
  { name: "Organization", description: "Firma zalogowanego użytkownika." },
  { name: "Structure", description: "Jednostki organizacyjne (oddziały, działy, zespoły) i ich członkowie." },
];

export type SuccessStatus = 200 | 201 | 204;
export type ErrorStatus = 401 | 403 | 404 | 409 | 422 | 429 | 500;
export type RouteErrors = Partial<Record<ErrorStatus, readonly ErrorCode[]>>;

export interface ParameterDefinition {
  name: string;
  in: "path" | "query";
  required: boolean;
  description: string;
  schema: z.ZodType;
}

export interface RouteDefinition {
  method: HttpMethod;
  /** Ścieżka w formacie OpenAPI (np. `/core/v1/units/{unitId}`). */
  path: string;
  operationId: string;
  tag: RouteTag;
  summary: string;
  description?: string;
  auth: boolean;
  /** Kod odpowiedzi sukcesu. */
  successStatus: SuccessStatus;
  /** Czy odpowiedź sukcesu jest owinięta w kopertę `{ data, meta, error }` (nie dotyczy 204). */
  envelope: boolean;
  /** Parametry ścieżki (`path`) i zapytania (`query`). */
  parameters?: readonly ParameterDefinition[];
  /** Nazwa i schemat treści żądania (dla POST/PUT/PATCH). */
  requestBodySchemaName?: string;
  requestBodySchema?: z.ZodType;
  requestBodyDescription?: string;
  /** Nazwa schematu danych w `components/schemas` (brak przy 204). */
  dataSchemaName?: string;
  dataSchema?: z.ZodType;
  /** Nazwa schematu odpowiedzi w `components/schemas` dla odpowiedzi z kopertą (np. `MeResponse`). */
  responseSchemaName?: string;
  responseDescription: string;
  errors: RouteErrors;
}

/** Dokument OpenAPI 3.1 zwracany przez `GET /core/v1/openapi.json` bez koperty `{ data, meta, error }`. */
export const OpenApiDocument = z
  .object({
    openapi: z.string(),
    info: z.looseObject({
      title: z.string(),
      version: z.string(),
    }),
    paths: z.record(z.string(), z.unknown()),
  })
  .loose();

export const EmployeeList = z.array(Employee);
export const UnitList = z.array(Unit);
export const UnitMemberList = z.array(UnitMember);

const UuidParam = z.uuid();

const UNIT_ID_PARAM: ParameterDefinition = {
  name: "unitId",
  in: "path",
  required: true,
  description: "Identyfikator jednostki organizacyjnej (UUID v7).",
  schema: UuidParam,
};

const EMPLOYEE_ID_PARAM: ParameterDefinition = {
  name: "employeeId",
  in: "path",
  required: true,
  description: "Identyfikator pracownika (UUID v7).",
  schema: UuidParam,
};

/** Zamienia ścieżkę OpenAPI (`/units/{unitId}`) na format Fastify (`/units/:unitId`). */
export function toFastifyPath(openApiPath: string): string {
  return openApiPath.replace(/\{([^}]+)\}/g, ":$1");
}

/** Zamienia ścieżkę Fastify (`/units/:unitId`) na format OpenAPI (`/units/{unitId}`). */
export function toOpenApiPath(fastifyPath: string): string {
  return fastifyPath.replace(/:([^/]+)/g, "{$1}");
}

/**
 * Katalog publicznych ścieżek Core API.
 * Jedno źródło prawdy dla routingu w `server.ts` i generatora OpenAPI w `openapi.ts`.
 */
export const ROUTES = {
  getHealth: {
    method: "GET",
    path: `${API_PREFIX}/health`,
    operationId: "getHealth",
    tag: "System",
    summary: "Sprawdź stan Core API",
    description: "Publiczny punkt kontrolny do sprawdzania dostępności usługi. Nie wymaga tokenu dostępu.",
    auth: false,
    successStatus: 200,
    envelope: true,
    dataSchemaName: "Health",
    dataSchema: Health,
    responseSchemaName: "HealthResponse",
    responseDescription: "Core API działa poprawnie.",
    errors: {
      500: ["INTERNAL"],
    },
  },
  getOpenApi: {
    method: "GET",
    path: `${API_PREFIX}/openapi.json`,
    operationId: "getOpenApi",
    tag: "System",
    summary: "Pobierz opis OpenAPI 3.1 Core API",
    description:
      "Zwraca wygenerowany z kodu dokument OpenAPI 3.1 w formacie JSON. " +
      "Wyjątek od standardu: odpowiedź to surowy dokument OpenAPI (bez koperty `{ data, meta, error }`), " +
      "dzięki czemu narzędzia i generatory SDK mogą go wczytać bezpośrednio.",
    auth: false,
    successStatus: 200,
    envelope: false,
    dataSchemaName: "OpenApiDocument",
    dataSchema: OpenApiDocument,
    responseDescription: "Dokument OpenAPI 3.1 w formacie JSON (bez koperty).",
    errors: {
      500: ["INTERNAL"],
    },
  },
  getMe: {
    method: "GET",
    path: `${API_PREFIX}/me`,
    operationId: "getMe",
    tag: "People",
    summary: "Pobierz dane zalogowanego konta, pracownika i firmy",
    description: "Zwraca konto (wraz z informacją `isOwner`), przypisanego pracownika oraz skrócone dane firmy.",
    auth: true,
    successStatus: 200,
    envelope: true,
    dataSchemaName: "Me",
    dataSchema: Me,
    responseSchemaName: "MeResponse",
    responseDescription: "Dane zalogowanego konta, pracownika i firmy.",
    errors: {
      401: ["UNAUTHENTICATED", "ACCOUNT_DEACTIVATED"],
      500: ["INTERNAL"],
    },
  },
  getOrganization: {
    method: "GET",
    path: `${API_PREFIX}/organization`,
    operationId: "getOrganization",
    tag: "Organization",
    summary: "Pobierz firmę zalogowanego użytkownika",
    description: "Zwraca firmę wynikającą z tokenu dostępu wraz z listą jej domen posortowaną według daty dodania.",
    auth: true,
    successStatus: 200,
    envelope: true,
    dataSchemaName: "Organization",
    dataSchema: Organization,
    responseSchemaName: "OrganizationResponse",
    responseDescription: "Dane firmy wraz z listą domen.",
    errors: {
      401: ["UNAUTHENTICATED", "ACCOUNT_DEACTIVATED"],
      500: ["INTERNAL"],
    },
  },
  listEmployees: {
    method: "GET",
    path: `${API_PREFIX}/employees`,
    operationId: "listEmployees",
    tag: "People",
    summary: "Lista pracowników firmy",
    description: "Zwraca wszystkich pracowników firmy wynikającej z tokenu dostępu.",
    auth: true,
    successStatus: 200,
    envelope: true,
    dataSchemaName: "EmployeeList",
    dataSchema: EmployeeList,
    responseSchemaName: "EmployeeListResponse",
    responseDescription: "Lista pracowników firmy.",
    errors: {
      401: ["UNAUTHENTICATED", "ACCOUNT_DEACTIVATED"],
      500: ["INTERNAL"],
    },
  },
  createEmployee: {
    method: "POST",
    path: `${API_PREFIX}/employees`,
    operationId: "createEmployee",
    tag: "People",
    summary: "Dodaj pracownika",
    description: "Tworzy pracownika firmy (może istnieć bez konta, ADR-0031). Wymaga roli Ownera firmy.",
    auth: true,
    successStatus: 201,
    envelope: true,
    requestBodySchemaName: "CreateEmployee",
    requestBodySchema: CreateEmployee,
    requestBodyDescription: "Dane nowego pracownika.",
    dataSchemaName: "Employee",
    dataSchema: Employee,
    responseSchemaName: "EmployeeResponse",
    responseDescription: "Utworzony pracownik.",
    errors: {
      401: ["UNAUTHENTICATED", "ACCOUNT_DEACTIVATED"],
      403: ["PERMISSION_DENIED"],
      422: ["VALIDATION_FAILED"],
      500: ["INTERNAL"],
    },
  },
  listUnits: {
    method: "GET",
    path: `${API_PREFIX}/units`,
    operationId: "listUnits",
    tag: "Structure",
    summary: "Lista jednostek organizacyjnych firmy",
    description: "Zwraca płaską listę jednostek organizacyjnych z polem `parentId`, opcjonalnie filtrowaną statusem.",
    auth: true,
    successStatus: 200,
    envelope: true,
    parameters: [
      {
        name: "status",
        in: "query",
        required: false,
        description: "Opcjonalny filtr statusu jednostki (`ACTIVE` albo `ARCHIVED`).",
        schema: UnitStatus,
      },
    ],
    dataSchemaName: "UnitList",
    dataSchema: UnitList,
    responseSchemaName: "UnitListResponse",
    responseDescription: "Lista jednostek organizacyjnych firmy.",
    errors: {
      401: ["UNAUTHENTICATED", "ACCOUNT_DEACTIVATED"],
      422: ["VALIDATION_FAILED"],
      500: ["INTERNAL"],
    },
  },
  createUnit: {
    method: "POST",
    path: `${API_PREFIX}/units`,
    operationId: "createUnit",
    tag: "Structure",
    summary: "Utwórz jednostkę organizacyjną",
    description: "Dodaje oddział, dział lub zespół do drzewa struktury firmy (ADR-0032). Wymaga roli Ownera firmy.",
    auth: true,
    successStatus: 201,
    envelope: true,
    requestBodySchemaName: "CreateUnit",
    requestBodySchema: CreateUnit,
    requestBodyDescription: "Dane nowej jednostki organizacyjnej.",
    dataSchemaName: "Unit",
    dataSchema: Unit,
    responseSchemaName: "UnitResponse",
    responseDescription: "Utworzona jednostka organizacyjna.",
    errors: {
      401: ["UNAUTHENTICATED", "ACCOUNT_DEACTIVATED"],
      403: ["PERMISSION_DENIED"],
      404: ["NOT_FOUND"],
      409: ["CONFLICT"],
      422: ["VALIDATION_FAILED"],
      500: ["INTERNAL"],
    },
  },
  updateUnit: {
    method: "PATCH",
    path: `${API_PREFIX}/units/{unitId}`,
    operationId: "updateUnit",
    tag: "Structure",
    summary: "Zmień jednostkę organizacyjną",
    description:
      "Zmienia nazwę, przenosi jednostkę w drzewie (z kontrolą cykli) albo zmienia jej status " +
      "(archiwizacja tylko bez aktywnych jednostek podrzędnych). Wymaga roli Ownera firmy.",
    auth: true,
    successStatus: 200,
    envelope: true,
    parameters: [UNIT_ID_PARAM],
    requestBodySchemaName: "UpdateUnit",
    requestBodySchema: UpdateUnit,
    requestBodyDescription: "Pola jednostki organizacyjnej do aktualizacji.",
    dataSchemaName: "Unit",
    dataSchema: Unit,
    responseSchemaName: "UnitResponse",
    responseDescription: "Zaktualizowana jednostka organizacyjna.",
    errors: {
      401: ["UNAUTHENTICATED", "ACCOUNT_DEACTIVATED"],
      403: ["PERMISSION_DENIED"],
      404: ["NOT_FOUND"],
      409: ["CONFLICT"],
      422: ["VALIDATION_FAILED"],
      500: ["INTERNAL"],
    },
  },
  listUnitMembers: {
    method: "GET",
    path: `${API_PREFIX}/units/{unitId}/members`,
    operationId: "listUnitMembers",
    tag: "Structure",
    summary: "Lista członków jednostki organizacyjnej",
    description: "Zwraca pracowników przypisanych do wskazanej jednostki organizacyjnej wraz z ich rolą w jednostce.",
    auth: true,
    successStatus: 200,
    envelope: true,
    parameters: [UNIT_ID_PARAM],
    dataSchemaName: "UnitMemberList",
    dataSchema: UnitMemberList,
    responseSchemaName: "UnitMemberListResponse",
    responseDescription: "Lista członków jednostki organizacyjnej.",
    errors: {
      401: ["UNAUTHENTICATED", "ACCOUNT_DEACTIVATED"],
      404: ["NOT_FOUND"],
      422: ["VALIDATION_FAILED"],
      500: ["INTERNAL"],
    },
  },
  putUnitMember: {
    method: "PUT",
    path: `${API_PREFIX}/units/{unitId}/members/{employeeId}`,
    operationId: "putUnitMember",
    tag: "Structure",
    summary: "Przypisz pracownika do jednostki lub zmień jego rolę",
    description:
      "Operacja idempotentna: przypisuje pracownika do jednostki albo aktualizuje jego rolę (`MEMBER`/`LEADER`). " +
      "Wymaga roli Ownera firmy.",
    auth: true,
    successStatus: 200,
    envelope: true,
    parameters: [UNIT_ID_PARAM, EMPLOYEE_ID_PARAM],
    requestBodySchemaName: "PutUnitMember",
    requestBodySchema: PutUnitMember,
    requestBodyDescription: "Rola pracownika w jednostce.",
    dataSchemaName: "UnitMember",
    dataSchema: UnitMember,
    responseSchemaName: "UnitMemberResponse",
    responseDescription: "Zapisane członkostwo pracownika w jednostce.",
    errors: {
      401: ["UNAUTHENTICATED", "ACCOUNT_DEACTIVATED"],
      403: ["PERMISSION_DENIED"],
      404: ["NOT_FOUND"],
      409: ["CONFLICT"],
      422: ["VALIDATION_FAILED"],
      500: ["INTERNAL"],
    },
  },
  deleteUnitMember: {
    method: "DELETE",
    path: `${API_PREFIX}/units/{unitId}/members/{employeeId}`,
    operationId: "deleteUnitMember",
    tag: "Structure",
    summary: "Usuń pracownika z jednostki organizacyjnej",
    description: "Usuwa przypisanie pracownika do wskazanej jednostki. Wymaga roli Ownera firmy.",
    auth: true,
    successStatus: 204,
    envelope: false,
    parameters: [UNIT_ID_PARAM, EMPLOYEE_ID_PARAM],
    responseDescription: "Członkostwo pracownika w jednostce zostało usunięte.",
    errors: {
      401: ["UNAUTHENTICATED", "ACCOUNT_DEACTIVATED"],
      403: ["PERMISSION_DENIED"],
      404: ["NOT_FOUND"],
      422: ["VALIDATION_FAILED"],
      500: ["INTERNAL"],
    },
  },
} as const satisfies Record<string, RouteDefinition>;

export const ROUTE_LIST: readonly RouteDefinition[] = Object.values(ROUTES);
