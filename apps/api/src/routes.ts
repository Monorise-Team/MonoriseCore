import { API_PREFIX, Health, Me, Organization, type ErrorCode } from "@core/contracts";
import { z } from "zod";

export type HttpMethod = "GET" | "POST" | "PUT" | "PATCH" | "DELETE";

export type RouteTag = "System" | "Identity" | "Organization";

export interface TagDefinition {
  name: RouteTag;
  description: string;
}

export const TAGS: readonly TagDefinition[] = [
  { name: "System", description: "Stan usługi i opis OpenAPI." },
  { name: "Identity", description: "Tożsamość zalogowanego użytkownika (konto, pracownik i firma)." },
  { name: "Organization", description: "Firma zalogowanego użytkownika." },
];

export type ErrorStatus = 401 | 403 | 404 | 409 | 422 | 429 | 500;
export type RouteErrors = Partial<Record<ErrorStatus, readonly ErrorCode[]>>;

export interface RouteDefinition {
  method: HttpMethod;
  path: string;
  operationId: string;
  tag: RouteTag;
  summary: string;
  description?: string;
  auth: boolean;
  /** Czy odpowiedź 200 jest owinięta w kopertę `{ data, meta, error }`. */
  envelope: boolean;
  /** Nazwa schematu danych w `components/schemas`. */
  dataSchemaName: string;
  dataSchema: z.ZodType;
  /** Nazwa schematu odpowiedzi w `components/schemas` dla odpowiedzi z kopertą (np. `MeResponse`). */
  responseSchemaName?: string;
  responseDescription: string;
  errors: RouteErrors;
}

/** Dokument OpenAPI 3.1 zwracany przez `GET /v1/openapi.json` bez koperty `{ data, meta, error }`. */
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
    tag: "Identity",
    summary: "Pobierz dane zalogowanego konta, pracownika i firmy",
    description: "Zwraca konto, przypisanego pracownika oraz skrócone dane firmy wynikające z tokenu dostępu.",
    auth: true,
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
} as const satisfies Record<string, RouteDefinition>;

export const ROUTE_LIST: readonly RouteDefinition[] = Object.values(ROUTES);
