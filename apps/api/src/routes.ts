import {
  API_PREFIX,
  AppAccess,
  CreateAppAccess,
  CreateEmployee,
  CreateInvitation,
  CreateRole,
  CreateRoleAssignment,
  CreateUnit,
  DEFAULT_PAGE_LIMIT,
  DIRECTORY_READ_SCOPE,
  DirectoryEmployee,
  EVENTS_READ_SCOPE,
  EventFeedPosition,
  MAX_EVENT_FEED_LIMIT,
  DEFAULT_EVENT_FEED_LIMIT,
  ProductEvent,
  DirectoryUnitMember,
  Employee,
  Entitlement,
  EntitlementStatus,
  Health,
  IDEMPOTENCY_KEY_HEADER,
  IdempotencyKeyHeader,
  Invitation,
  InvitationStatus,
  MAX_DIRECTORY_FILTER_IDS,
  MAX_PAGE_LIMIT,
  Me,
  Organization,
  OrganizationOwner,
  PageCursor,
  PageLimit,
  Permission,
  PERMISSIONS_READ_SCOPE,
  PERMISSIONS_REGISTER_SCOPE,
  PermissionSnapshot,
  ProductKey,
  PutUnitMember,
  RegisterPermissionsRequest,
  RegisterPermissionsResult,
  RegisterRoleTemplatesRequest,
  RegisterRoleTemplatesResult,
  Role,
  RoleAssignment,
  TransferOrganizationOwner,
  Unit,
  UnitMember,
  UnitStatus,
  UpdateRole,
  UpdateUnit,
  type ErrorCode,
} from "@core/contracts";
import { z } from "zod";

export type HttpMethod = "GET" | "POST" | "PUT" | "PATCH" | "DELETE";

export type RouteTag =
  | "System"
  | "People"
  | "Invitations"
  | "Organization"
  | "Structure"
  | "Permissions"
  | "Roles"
  | "AppAccess"
  | "Directory"
  | "Events";

export type RouteAuth = false | "bearer" | { scheme: "productOAuth"; scopes: readonly string[] };

export interface TagDefinition {
  name: RouteTag;
  description: string;
}

export const TAGS: readonly TagDefinition[] = [
  { name: "System", description: "Stan usługi i opis OpenAPI." },
  { name: "People", description: "Pracownicy i konta; tu także dane zalogowanego konta." },
  { name: "Invitations", description: "Zaproszenia pracowników do aktywacji konta INVITED (ADR-0021)." },
  { name: "Organization", description: "Firma zalogowanego użytkownika oraz przekazanie roli Ownera." },
  { name: "Structure", description: "Jednostki organizacyjne (oddziały, działy, zespoły) i ich członkowie." },
  { name: "Permissions", description: "Rejestr uprawnień oraz migawka uprawnień dla produktów (ADR-0036)." },
  {
    name: "Roles",
    description: "Role firmowe, gotowe szablony ról i przypisania ról z zakresem (ADR-0033, ADR-0035).",
  },
  {
    name: "AppAccess",
    description: "Dostęp firm do produktów (Entitlements) oraz włączanie aplikacji pracownikom (AppAccess, ADR-0035).",
  },
  {
    name: "Directory",
    description: "Katalog pracowników i członkostw w jednostkach dla serwerów produktów (token maszynowy).",
  },
  {
    name: "Events",
    description: "Kanał zdarzeń Core dla serwerów produktów (token maszynowy), do czasu EventBridge i SQS.",
  },
];

export type SuccessStatus = 200 | 201 | 204;
export type ErrorStatus = 400 | 401 | 403 | 404 | 409 | 422 | 429 | 500;
export type RouteErrors = Partial<Record<ErrorStatus, readonly ErrorCode[]>>;

export interface ParameterDefinition {
  name: string;
  in: "path" | "query" | "header";
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
  auth: RouteAuth;
  /** Kod odpowiedzi sukcesu. */
  successStatus: SuccessStatus;
  /** Czy odpowiedź sukcesu jest owinięta w kopertę `{ data, meta, error }` (nie dotyczy 204). */
  envelope: boolean;
  /** Czy odpowiedź listy używa stronicowania kursorowego (`meta.nextCursor`). */
  paginated?: boolean;
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
export const InvitationList = z.array(Invitation);
export const UnitList = z.array(Unit);
export const UnitMemberList = z.array(UnitMember);
export const PermissionList = z.array(Permission);
export const RoleList = z.array(Role);
export const RoleAssignmentList = z.array(RoleAssignment);
export const EntitlementList = z.array(Entitlement);
export const AppAccessList = z.array(AppAccess);
export const DirectoryUnitMemberList = z.array(DirectoryUnitMember);
export const DirectoryEmployeeList = z.array(DirectoryEmployee);
export const ProductEventList = z.array(ProductEvent);

const UuidParam = z.uuid();
const RepeatableUuidParam = z.array(z.uuid()).max(MAX_DIRECTORY_FILTER_IDS);
const IncludeDeprecatedParam = z.boolean().default(false);
const IncludeTemplatesParam = z.boolean().default(true);
const IncludeArchivedParam = z.boolean().default(false);
const IncludeRevokedParam = z.boolean().default(false);

const APP_ACCESS_ID_PARAM: ParameterDefinition = {
  name: "appAccessId",
  in: "path",
  required: true,
  description: "Identyfikator wpisu dostępu konta do aplikacji (UUID v7).",
  schema: UuidParam,
};

const ROLE_ID_PARAM: ParameterDefinition = {
  name: "roleId",
  in: "path",
  required: true,
  description: "Identyfikator roli lub gotowego szablonu roli (UUID v7).",
  schema: UuidParam,
};

const ASSIGNMENT_ID_PARAM: ParameterDefinition = {
  name: "assignmentId",
  in: "path",
  required: true,
  description: "Identyfikator przypisania roli (UUID v7).",
  schema: UuidParam,
};

const PRODUCT_KEY_PARAM: ParameterDefinition = {
  name: "productKey",
  in: "path",
  required: true,
  description: "Klucz produktu zgodny z prefiksem kluczy uprawnień (np. `timotime`).",
  schema: ProductKey,
};

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

const INVITATION_ID_PARAM: ParameterDefinition = {
  name: "invitationId",
  in: "path",
  required: true,
  description: "Identyfikator zaproszenia pracownika (UUID v7).",
  schema: UuidParam,
};

const PAGE_PARAMETERS: readonly ParameterDefinition[] = [
  {
    name: "limit",
    in: "query",
    required: false,
    description: `Liczba elementów na stronie (1–${MAX_PAGE_LIMIT}, domyślnie ${DEFAULT_PAGE_LIMIT}).`,
    schema: PageLimit,
  },
  {
    name: "cursor",
    in: "query",
    required: false,
    description: "Nieprzezroczysty kursor następnej strony z pola `meta.nextCursor`.",
    schema: PageCursor,
  },
];

/** Opcjonalny nagłówek `Idempotency-Key` dodawany automatycznie do wszystkich operacji `POST` w OpenAPI. */
export const IDEMPOTENCY_KEY_PARAMETER: ParameterDefinition = {
  name: IDEMPOTENCY_KEY_HEADER,
  in: "header",
  required: false,
  description:
    "Opcjonalny klucz powtórzenia (1–255 drukowalnych znaków ASCII, ważny 24 godziny). " +
    "Powtórzone żądanie z tym samym kluczem i treścią zwraca zapisaną odpowiedź z nagłówkiem " +
    "`Idempotency-Replayed: true` bez ponownego wykonania operacji; ten sam klucz z inną treścią zwraca `409 CONFLICT`.",
  schema: IdempotencyKeyHeader,
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
 * Czy ścieżka obsługuje nagłówek `Idempotency-Key` (obecnie wszystkie operacje `POST` z tokenem użytkownika).
 * Jedno źródło prawdy dla rejestracji tras w `server.ts`, opisu OpenAPI w `openapi.ts` i testów w `openapi.test.ts`.
 */
export function supportsIdempotencyKey(route: RouteDefinition): boolean {
  return route.method === "POST" && route.auth === "bearer";
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
      500: ["INTERNAL_ERROR"],
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
      500: ["INTERNAL_ERROR"],
    },
  },
  getMe: {
    method: "GET",
    path: `${API_PREFIX}/me`,
    operationId: "getMe",
    tag: "People",
    summary: "Pobierz dane zalogowanego konta, pracownika i firmy",
    description: "Zwraca konto (wraz z informacją `isOwner`), przypisanego pracownika oraz skrócone dane firmy.",
    auth: "bearer",
    successStatus: 200,
    envelope: true,
    dataSchemaName: "Me",
    dataSchema: Me,
    responseSchemaName: "MeResponse",
    responseDescription: "Dane zalogowanego konta, pracownika i firmy.",
    errors: {
      401: ["UNAUTHENTICATED", "ACCOUNT_DEACTIVATED"],
      500: ["INTERNAL_ERROR"],
    },
  },
  getOrganization: {
    method: "GET",
    path: `${API_PREFIX}/organization`,
    operationId: "getOrganization",
    tag: "Organization",
    summary: "Pobierz firmę zalogowanego użytkownika",
    description: "Zwraca firmę wynikającą z tokenu dostępu wraz z listą jej domen posortowaną według daty dodania.",
    auth: "bearer",
    successStatus: 200,
    envelope: true,
    dataSchemaName: "Organization",
    dataSchema: Organization,
    responseSchemaName: "OrganizationResponse",
    responseDescription: "Dane firmy wraz z listą domen.",
    errors: {
      401: ["UNAUTHENTICATED", "ACCOUNT_DEACTIVATED"],
      500: ["INTERNAL_ERROR"],
    },
  },
  transferOrganizationOwner: {
    method: "PUT",
    path: `${API_PREFIX}/organization/owner`,
    operationId: "transferOrganizationOwner",
    tag: "Organization",
    summary: "Przekaż rolę Ownera firmy innemu aktywnemu kontu",
    description:
      "Operacja wyłącznie dla bieżącego Ownera firmy. Docelowe konto musi być aktywnym kontem tej samej firmy " +
      "i nie może być już Ownerem. Poprzedni Owner zachowuje wyłącznie uprawnienia wynikające z nadanych ról.",
    auth: "bearer",
    successStatus: 200,
    envelope: true,
    requestBodySchemaName: "TransferOrganizationOwner",
    requestBodySchema: TransferOrganizationOwner,
    requestBodyDescription: "Identyfikator docelowego konta nowego Ownera.",
    dataSchemaName: "OrganizationOwner",
    dataSchema: OrganizationOwner,
    responseSchemaName: "OrganizationOwnerResponse",
    responseDescription: "Identyfikator nowego Ownera firmy.",
    errors: {
      401: ["UNAUTHENTICATED", "ACCOUNT_DEACTIVATED"],
      403: ["PERMISSION_DENIED"],
      404: ["NOT_FOUND"],
      409: ["CONFLICT"],
      422: ["VALIDATION_FAILED"],
      500: ["INTERNAL_ERROR"],
    },
  },
  listEmployees: {
    method: "GET",
    path: `${API_PREFIX}/employees`,
    operationId: "listEmployees",
    tag: "People",
    summary: "Lista pracowników firmy",
    description: "Zwraca stronicowaną listę pracowników firmy wynikającej z tokenu dostępu (kolejność utworzenia).",
    auth: "bearer",
    successStatus: 200,
    envelope: true,
    paginated: true,
    parameters: PAGE_PARAMETERS,
    dataSchemaName: "EmployeeList",
    dataSchema: EmployeeList,
    responseSchemaName: "EmployeeListResponse",
    responseDescription: "Strona listy pracowników firmy.",
    errors: {
      401: ["UNAUTHENTICATED", "ACCOUNT_DEACTIVATED"],
      422: ["VALIDATION_FAILED"],
      500: ["INTERNAL_ERROR"],
    },
  },
  createEmployee: {
    method: "POST",
    path: `${API_PREFIX}/employees`,
    operationId: "createEmployee",
    tag: "People",
    summary: "Dodaj pracownika",
    description:
      "Tworzy pracownika firmy (może istnieć bez konta, ADR-0031). Wymaga uprawnienia `core.employees.manage` " +
      "w zakresie całej firmy albo roli Ownera.",
    auth: "bearer",
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
      500: ["INTERNAL_ERROR"],
    },
  },
  listInvitations: {
    method: "GET",
    path: `${API_PREFIX}/invitations`,
    operationId: "listInvitations",
    tag: "Invitations",
    summary: "Lista zaproszeń pracowników firmy",
    description:
      "Zwraca stronicowaną listę zaproszeń pracowników firmy (wygasłe wiersze `PENDING` są raportowane jako `EXPIRED`), " +
      "opcjonalnie filtrowaną statusem. Wymaga uprawnienia `core.employees.manage` w zakresie całej firmy albo roli Ownera.",
    auth: "bearer",
    successStatus: 200,
    envelope: true,
    paginated: true,
    parameters: [
      ...PAGE_PARAMETERS,
      {
        name: "status",
        in: "query",
        required: false,
        description: "Opcjonalny filtr statusu zaproszenia (`PENDING`, `ACCEPTED`, `EXPIRED` albo `REVOKED`).",
        schema: InvitationStatus,
      },
    ],
    dataSchemaName: "InvitationList",
    dataSchema: InvitationList,
    responseSchemaName: "InvitationListResponse",
    responseDescription: "Strona listy zaproszeń pracowników firmy.",
    errors: {
      401: ["UNAUTHENTICATED", "ACCOUNT_DEACTIVATED"],
      403: ["PERMISSION_DENIED"],
      422: ["VALIDATION_FAILED"],
      500: ["INTERNAL_ERROR"],
    },
  },
  createInvitation: {
    method: "POST",
    path: `${API_PREFIX}/invitations`,
    operationId: "createInvitation",
    tag: "Invitations",
    summary: "Zaproś pracownika e-mailem",
    description:
      "Tworzy konto `INVITED` (dla nowego pracownika albo wskazanego `employeeId` bez konta), generuje jednorazowy link " +
      "aktywacyjny ważny 7 dni i wysyła wiadomość e-mail (ADR-0021). Adres musi należeć do zweryfikowanej domeny firmy. " +
      "Wymaga uprawnienia `core.employees.manage` w zakresie całej firmy albo roli Ownera.",
    auth: "bearer",
    successStatus: 201,
    envelope: true,
    requestBodySchemaName: "CreateInvitation",
    requestBodySchema: CreateInvitation,
    requestBodyDescription: "Adres e-mail oraz imię i nazwisko albo identyfikator istniejącego pracownika bez konta.",
    dataSchemaName: "Invitation",
    dataSchema: Invitation,
    responseSchemaName: "InvitationResponse",
    responseDescription: "Utworzone zaproszenie (bez tokenu aktywacyjnego).",
    errors: {
      401: ["UNAUTHENTICATED", "ACCOUNT_DEACTIVATED"],
      403: ["PERMISSION_DENIED"],
      404: ["NOT_FOUND"],
      409: ["CONFLICT"],
      422: ["VALIDATION_FAILED"],
      500: ["INTERNAL_ERROR"],
    },
  },
  resendInvitation: {
    method: "POST",
    path: `${API_PREFIX}/invitations/{invitationId}/resend`,
    operationId: "resendInvitation",
    tag: "Invitations",
    summary: "Wyślij ponownie zaproszenie pracownika",
    description:
      "Generuje nowy 7-dniowy link aktywacyjny dla zaproszenia `PENDING`, `EXPIRED` albo `REVOKED` (unieważnia poprzedni " +
      "link), ustawia status `PENDING` i wysyła nowy e-mail. Wymaga uprawnienia `core.employees.manage` w zakresie całej firmy " +
      "albo roli Ownera.",
    auth: "bearer",
    successStatus: 200,
    envelope: true,
    parameters: [INVITATION_ID_PARAM],
    dataSchemaName: "Invitation",
    dataSchema: Invitation,
    responseSchemaName: "InvitationResponse",
    responseDescription: "Zaktualizowane zaproszenie z nowym terminem ważności (bez tokenu aktywacyjnego).",
    errors: {
      401: ["UNAUTHENTICATED", "ACCOUNT_DEACTIVATED"],
      403: ["PERMISSION_DENIED"],
      404: ["NOT_FOUND"],
      409: ["CONFLICT"],
      422: ["VALIDATION_FAILED"],
      500: ["INTERNAL_ERROR"],
    },
  },
  revokeInvitation: {
    method: "DELETE",
    path: `${API_PREFIX}/invitations/{invitationId}`,
    operationId: "revokeInvitation",
    tag: "Invitations",
    summary: "Cofnij oczekujące zaproszenie",
    description:
      "Zmienia status oczekującego zaproszenia z `PENDING` na `REVOKED` (konto pozostaje w statusie `INVITED`, a zaproszenie " +
      "można później wysłać ponownie). Wymaga uprawnienia `core.employees.manage` w zakresie całej firmy albo roli Ownera.",
    auth: "bearer",
    successStatus: 204,
    envelope: false,
    parameters: [INVITATION_ID_PARAM],
    responseDescription: "Zaproszenie zostało cofnięte.",
    errors: {
      401: ["UNAUTHENTICATED", "ACCOUNT_DEACTIVATED"],
      403: ["PERMISSION_DENIED"],
      404: ["NOT_FOUND"],
      409: ["CONFLICT"],
      422: ["VALIDATION_FAILED"],
      500: ["INTERNAL_ERROR"],
    },
  },
  listUnits: {
    method: "GET",
    path: `${API_PREFIX}/units`,
    operationId: "listUnits",
    tag: "Structure",
    summary: "Lista jednostek organizacyjnych firmy",
    description:
      "Zwraca stronicowaną, płaską listę jednostek organizacyjnych z polem `parentId`, opcjonalnie filtrowaną statusem.",
    auth: "bearer",
    successStatus: 200,
    envelope: true,
    paginated: true,
    parameters: [
      ...PAGE_PARAMETERS,
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
    responseDescription: "Strona listy jednostek organizacyjnych firmy.",
    errors: {
      401: ["UNAUTHENTICATED", "ACCOUNT_DEACTIVATED"],
      422: ["VALIDATION_FAILED"],
      500: ["INTERNAL_ERROR"],
    },
  },
  createUnit: {
    method: "POST",
    path: `${API_PREFIX}/units`,
    operationId: "createUnit",
    tag: "Structure",
    summary: "Utwórz jednostkę organizacyjną",
    description:
      "Dodaje oddział, dział lub zespół do drzewa struktury firmy (ADR-0032). Wymaga uprawnienia " +
      "`core.structure.manage` na jednostce nadrzędnej (albo w zakresie całej firmy dla jednostki głównej) lub roli Ownera.",
    auth: "bearer",
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
      500: ["INTERNAL_ERROR"],
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
      "(archiwizacja tylko bez aktywnych jednostek podrzędnych). Wymaga uprawnienia `core.structure.manage` " +
      "na jednostce oraz — przy przenoszeniu — również na nowej jednostce nadrzędnej (lub całej firmie).",
    auth: "bearer",
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
      500: ["INTERNAL_ERROR"],
    },
  },
  listUnitMembers: {
    method: "GET",
    path: `${API_PREFIX}/units/{unitId}/members`,
    operationId: "listUnitMembers",
    tag: "Structure",
    summary: "Lista członków jednostki organizacyjnej",
    description:
      "Zwraca stronicowaną listę pracowników przypisanych do wskazanej jednostki organizacyjnej wraz z ich rolą.",
    auth: "bearer",
    successStatus: 200,
    envelope: true,
    paginated: true,
    parameters: [UNIT_ID_PARAM, ...PAGE_PARAMETERS],
    dataSchemaName: "UnitMemberList",
    dataSchema: UnitMemberList,
    responseSchemaName: "UnitMemberListResponse",
    responseDescription: "Strona listy członków jednostki organizacyjnej.",
    errors: {
      401: ["UNAUTHENTICATED", "ACCOUNT_DEACTIVATED"],
      404: ["NOT_FOUND"],
      422: ["VALIDATION_FAILED"],
      500: ["INTERNAL_ERROR"],
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
      "Wymaga uprawnienia `core.structure.manage` na wskazanej jednostce albo roli Ownera.",
    auth: "bearer",
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
      500: ["INTERNAL_ERROR"],
    },
  },
  deleteUnitMember: {
    method: "DELETE",
    path: `${API_PREFIX}/units/{unitId}/members/{employeeId}`,
    operationId: "deleteUnitMember",
    tag: "Structure",
    summary: "Usuń pracownika z jednostki organizacyjnej",
    description:
      "Usuwa przypisanie pracownika do wskazanej jednostki. Wymaga uprawnienia `core.structure.manage` " +
      "na tej jednostce albo roli Ownera.",
    auth: "bearer",
    successStatus: 204,
    envelope: false,
    parameters: [UNIT_ID_PARAM, EMPLOYEE_ID_PARAM],
    responseDescription: "Członkostwo pracownika w jednostce zostało usunięte.",
    errors: {
      401: ["UNAUTHENTICATED", "ACCOUNT_DEACTIVATED"],
      403: ["PERMISSION_DENIED"],
      404: ["NOT_FOUND"],
      422: ["VALIDATION_FAILED"],
      500: ["INTERNAL_ERROR"],
    },
  },
  listPermissions: {
    method: "GET",
    path: `${API_PREFIX}/permissions`,
    operationId: "listPermissions",
    tag: "Permissions",
    summary: "Lista zarejestrowanych uprawnień",
    description:
      "Zwraca stronicowaną listę uprawnień platformy i produktów. Domyślnie pomija wycofane uprawnienia; " +
      "dostępna dla każdego aktywnego konta firmy.",
    auth: "bearer",
    successStatus: 200,
    envelope: true,
    paginated: true,
    parameters: [
      ...PAGE_PARAMETERS,
      {
        name: "product",
        in: "query",
        required: false,
        description: "Opcjonalny filtr po kluczu produktu (np. `timotime`) albo `core` dla uprawnień platformy.",
        schema: ProductKey,
      },
      {
        name: "includeDeprecated",
        in: "query",
        required: false,
        description: "Czy uwzględnić wycofane uprawnienia (domyślnie `false`).",
        schema: IncludeDeprecatedParam,
      },
    ],
    dataSchemaName: "PermissionList",
    dataSchema: PermissionList,
    responseSchemaName: "PermissionListResponse",
    responseDescription: "Strona listy zarejestrowanych uprawnień.",
    errors: {
      401: ["UNAUTHENTICATED", "ACCOUNT_DEACTIVATED"],
      422: ["VALIDATION_FAILED"],
      500: ["INTERNAL_ERROR"],
    },
  },
  registerProductPermissions: {
    method: "PUT",
    path: `${API_PREFIX}/products/{productKey}/permissions`,
    operationId: "registerProductPermissions",
    tag: "Permissions",
    summary: "Zarejestruj manifest uprawnień produktu",
    description:
      "Endpoint maszynowy dla serwerów produktów (token OAuth 2.1 `client_credentials` z zakresem " +
      "`core:permissions.register`). Idempotentnie dodaje i aktualizuje uprawnienia produktu oraz oznacza " +
      "brakujące jako wycofane (bez usuwania).",
    auth: { scheme: "productOAuth", scopes: [PERMISSIONS_REGISTER_SCOPE] },
    successStatus: 200,
    envelope: true,
    parameters: [PRODUCT_KEY_PARAM],
    requestBodySchemaName: "RegisterPermissionsRequest",
    requestBodySchema: RegisterPermissionsRequest,
    requestBodyDescription: "Manifest uprawnień produktu (1–500 pozycji z prefiksem `<productKey>.`).",
    dataSchemaName: "RegisterPermissionsResult",
    dataSchema: RegisterPermissionsResult,
    responseSchemaName: "RegisterPermissionsResponse",
    responseDescription: "Podsumowanie zmian w rejestrze uprawnień produktu.",
    errors: {
      401: ["UNAUTHENTICATED"],
      403: ["PERMISSION_DENIED"],
      404: ["NOT_FOUND"],
      422: ["VALIDATION_FAILED"],
      500: ["INTERNAL_ERROR"],
    },
  },
  registerProductRoleTemplates: {
    method: "PUT",
    path: `${API_PREFIX}/products/{productKey}/role-templates`,
    operationId: "registerProductRoleTemplates",
    tag: "Roles",
    summary: "Zarejestruj gotowe role (szablony) produktu",
    description:
      "Endpoint maszynowy dla serwerów produktów (token OAuth 2.1 `client_credentials` z zakresem " +
      "`core:permissions.register`). Idempotentnie dodaje i aktualizuje szablony ról produktu, archiwizuje " +
      "brakujące i przywraca ponownie obecne.",
    auth: { scheme: "productOAuth", scopes: [PERMISSIONS_REGISTER_SCOPE] },
    successStatus: 200,
    envelope: true,
    parameters: [PRODUCT_KEY_PARAM],
    requestBodySchemaName: "RegisterRoleTemplatesRequest",
    requestBodySchema: RegisterRoleTemplatesRequest,
    requestBodyDescription: "Manifest gotowych ról produktu (klucze z prefiksem `<productKey>.`).",
    dataSchemaName: "RegisterRoleTemplatesResult",
    dataSchema: RegisterRoleTemplatesResult,
    responseSchemaName: "RegisterRoleTemplatesResponse",
    responseDescription: "Podsumowanie zmian w gotowych rolach produktu.",
    errors: {
      401: ["UNAUTHENTICATED"],
      403: ["PERMISSION_DENIED"],
      404: ["NOT_FOUND"],
      422: ["VALIDATION_FAILED"],
      500: ["INTERNAL_ERROR"],
    },
  },
  listRoles: {
    method: "GET",
    path: `${API_PREFIX}/roles`,
    operationId: "listRoles",
    tag: "Roles",
    summary: "Lista ról firmy i gotowych szablonów",
    description:
      "Zwraca stronicowaną listę ról firmy wraz z gotowymi szablonami (domyślnie bez ról zarchiwizowanych). " +
      "Dostępna dla każdego aktywnego konta firmy.",
    auth: "bearer",
    successStatus: 200,
    envelope: true,
    paginated: true,
    parameters: [
      ...PAGE_PARAMETERS,
      {
        name: "product",
        in: "query",
        required: false,
        description: "Opcjonalny filtr po kluczu produktu (np. `timotime`) albo `core` dla ról platformowych.",
        schema: ProductKey,
      },
      {
        name: "includeTemplates",
        in: "query",
        required: false,
        description: "Czy uwzględnić gotowe role (szablony) — domyślnie `true`.",
        schema: IncludeTemplatesParam,
      },
      {
        name: "includeArchived",
        in: "query",
        required: false,
        description: "Czy uwzględnić zarchiwizowane role — domyślnie `false`.",
        schema: IncludeArchivedParam,
      },
    ],
    dataSchemaName: "RoleList",
    dataSchema: RoleList,
    responseSchemaName: "RoleListResponse",
    responseDescription: "Strona listy ról.",
    errors: {
      401: ["UNAUTHENTICATED", "ACCOUNT_DEACTIVATED"],
      422: ["VALIDATION_FAILED"],
      500: ["INTERNAL_ERROR"],
    },
  },
  getRole: {
    method: "GET",
    path: `${API_PREFIX}/roles/{roleId}`,
    operationId: "getRole",
    tag: "Roles",
    summary: "Pobierz szczegóły roli wraz z kluczami uprawnień",
    description: "Zwraca rolę firmy albo gotowy szablon roli wraz z listą jej kluczy uprawnień.",
    auth: "bearer",
    successStatus: 200,
    envelope: true,
    parameters: [ROLE_ID_PARAM],
    dataSchemaName: "Role",
    dataSchema: Role,
    responseSchemaName: "RoleResponse",
    responseDescription: "Szczegóły roli.",
    errors: {
      401: ["UNAUTHENTICATED", "ACCOUNT_DEACTIVATED"],
      404: ["NOT_FOUND"],
      422: ["VALIDATION_FAILED"],
      500: ["INTERNAL_ERROR"],
    },
  },
  createRole: {
    method: "POST",
    path: `${API_PREFIX}/roles`,
    operationId: "createRole",
    tag: "Roles",
    summary: "Utwórz rolę firmy lub skopiuj istniejącą rolę",
    description:
      "Tworzy własną rolę firmy od zera albo kopiuje gotowy szablon lub istniejącą rolę firmy (`copyFromRoleId`). " +
      "Wymaga uprawnienia `core.roles.manage` w zakresie całej firmy albo roli Ownera.",
    auth: "bearer",
    successStatus: 201,
    envelope: true,
    requestBodySchemaName: "CreateRole",
    requestBodySchema: CreateRole,
    requestBodyDescription: "Dane nowej roli firmy albo identyfikator kopiowanej roli.",
    dataSchemaName: "Role",
    dataSchema: Role,
    responseSchemaName: "RoleResponse",
    responseDescription: "Utworzona rola firmy.",
    errors: {
      401: ["UNAUTHENTICATED", "ACCOUNT_DEACTIVATED"],
      403: ["PERMISSION_DENIED"],
      404: ["NOT_FOUND"],
      409: ["CONFLICT"],
      422: ["VALIDATION_FAILED"],
      500: ["INTERNAL_ERROR"],
    },
  },
  updateRole: {
    method: "PATCH",
    path: `${API_PREFIX}/roles/{roleId}`,
    operationId: "updateRole",
    tag: "Roles",
    summary: "Zmień nazwę, opis lub uprawnienia roli firmy",
    description:
      "Aktualizuje aktywną rolę firmy (szablony zwracają `403`). Zmiana listy uprawnień podbija `authzRevision` " +
      "wszystkich kont z przypisaną tą rolą. Wymaga `core.roles.manage` w zakresie całej firmy albo roli Ownera.",
    auth: "bearer",
    successStatus: 200,
    envelope: true,
    parameters: [ROLE_ID_PARAM],
    requestBodySchemaName: "UpdateRole",
    requestBodySchema: UpdateRole,
    requestBodyDescription: "Pola roli firmy do aktualizacji.",
    dataSchemaName: "Role",
    dataSchema: Role,
    responseSchemaName: "RoleResponse",
    responseDescription: "Zaktualizowana rola firmy.",
    errors: {
      401: ["UNAUTHENTICATED", "ACCOUNT_DEACTIVATED"],
      403: ["PERMISSION_DENIED"],
      404: ["NOT_FOUND"],
      409: ["CONFLICT"],
      422: ["VALIDATION_FAILED"],
      500: ["INTERNAL_ERROR"],
    },
  },
  archiveRole: {
    method: "DELETE",
    path: `${API_PREFIX}/roles/{roleId}`,
    operationId: "archiveRole",
    tag: "Roles",
    summary: "Zarchiwizuj rolę firmy",
    description:
      "Archiwizuje rolę firmy (ustawia `archivedAt`). Zwraca `409 CONFLICT`, dopóki rola ma jakiekolwiek " +
      "przypisania, oraz `403` dla szablonów. Wymaga `core.roles.manage` w zakresie całej firmy albo roli Ownera.",
    auth: "bearer",
    successStatus: 204,
    envelope: false,
    parameters: [ROLE_ID_PARAM],
    responseDescription: "Rola firmy została zarchiwizowana.",
    errors: {
      401: ["UNAUTHENTICATED", "ACCOUNT_DEACTIVATED"],
      403: ["PERMISSION_DENIED"],
      404: ["NOT_FOUND"],
      409: ["CONFLICT"],
      422: ["VALIDATION_FAILED"],
      500: ["INTERNAL_ERROR"],
    },
  },
  listRoleAssignments: {
    method: "GET",
    path: `${API_PREFIX}/role-assignments`,
    operationId: "listRoleAssignments",
    tag: "Roles",
    summary: "Lista przypisań ról w firmie",
    description:
      "Owner oraz konta z uprawnieniem `core.roles.assign` lub `core.roles.manage` (w dowolnym zakresie) widzą " +
      "wszystkie przypisania firmy; pozostałe konta widzą wyłącznie własne przypisania.",
    auth: "bearer",
    successStatus: 200,
    envelope: true,
    paginated: true,
    parameters: [
      ...PAGE_PARAMETERS,
      {
        name: "accountId",
        in: "query",
        required: false,
        description: "Opcjonalny filtr po identyfikatorze konta (UUID v7).",
        schema: UuidParam,
      },
      {
        name: "roleId",
        in: "query",
        required: false,
        description: "Opcjonalny filtr po identyfikatorze roli (UUID v7).",
        schema: UuidParam,
      },
    ],
    dataSchemaName: "RoleAssignmentList",
    dataSchema: RoleAssignmentList,
    responseSchemaName: "RoleAssignmentListResponse",
    responseDescription: "Strona listy przypisań ról.",
    errors: {
      401: ["UNAUTHENTICATED", "ACCOUNT_DEACTIVATED"],
      422: ["VALIDATION_FAILED"],
      500: ["INTERNAL_ERROR"],
    },
  },
  createRoleAssignment: {
    method: "POST",
    path: `${API_PREFIX}/role-assignments`,
    operationId: "createRoleAssignment",
    tag: "Roles",
    summary: "Nadaj rolę kontu w firmie z zakresem i opcjonalnym terminem",
    description:
      "Przypisuje aktywną rolę (firmową albo gotowy szablon) kontu w zakresie `ORGANIZATION`, `UNIT` lub `RESOURCE`. " +
      "Wymaga roli Ownera albo `core.roles.assign` obejmującego docelowy zakres oraz posiadania każdego uprawnienia " +
      "roli w tym zakresie (ADR-0035).",
    auth: "bearer",
    successStatus: 201,
    envelope: true,
    requestBodySchemaName: "CreateRoleAssignment",
    requestBodySchema: CreateRoleAssignment,
    requestBodyDescription: "Dane nowego przypisania roli.",
    dataSchemaName: "RoleAssignment",
    dataSchema: RoleAssignment,
    responseSchemaName: "RoleAssignmentResponse",
    responseDescription: "Utworzone przypisanie roli.",
    errors: {
      401: ["UNAUTHENTICATED", "ACCOUNT_DEACTIVATED"],
      403: ["PERMISSION_DENIED"],
      404: ["NOT_FOUND"],
      409: ["CONFLICT"],
      422: ["VALIDATION_FAILED"],
      500: ["INTERNAL_ERROR"],
    },
  },
  deleteRoleAssignment: {
    method: "DELETE",
    path: `${API_PREFIX}/role-assignments/{assignmentId}`,
    operationId: "deleteRoleAssignment",
    tag: "Roles",
    summary: "Odbierz przypisanie roli",
    description:
      "Usuwa przypisanie roli i podbija `authzRevision` konta (historia trafia do dziennika zdarzeń). " +
      "Wymaga tych samych uprawnień co nadanie tego przypisania albo roli Ownera.",
    auth: "bearer",
    successStatus: 204,
    envelope: false,
    parameters: [ASSIGNMENT_ID_PARAM],
    responseDescription: "Przypisanie roli zostało odebrane.",
    errors: {
      401: ["UNAUTHENTICATED", "ACCOUNT_DEACTIVATED"],
      403: ["PERMISSION_DENIED"],
      404: ["NOT_FOUND"],
      422: ["VALIDATION_FAILED"],
      500: ["INTERNAL_ERROR"],
    },
  },
  getProductPermissionSnapshot: {
    method: "GET",
    path: `${API_PREFIX}/products/{productKey}/permission-snapshot`,
    operationId: "getProductPermissionSnapshot",
    tag: "Permissions",
    summary: "Pobierz migawkę uprawnień konta dla produktu",
    description:
      "Endpoint maszynowy dla serwerów produktów (token OAuth 2.1 `client_credentials` z zakresem " +
      "`core:permissions.read`). Zwraca migawkę uprawnień zgodną ze schematem `permissionSnapshotSchema` " +
      "z `@monorise-team/permissions`: aktywność produktu dla firmy i konta, wyłącznie nadania uprawnień tego produktu " +
      "(nigdy `core.*`) oraz pełne drzewo jednostek firmy (łącznie z `ARCHIVED`).",
    auth: { scheme: "productOAuth", scopes: [PERMISSIONS_READ_SCOPE] },
    successStatus: 200,
    envelope: true,
    parameters: [
      PRODUCT_KEY_PARAM,
      {
        name: "organizationId",
        in: "query",
        required: true,
        description: "Identyfikator firmy (UUID v7), w której kontekście pobierana jest migawka.",
        schema: UuidParam,
      },
      {
        name: "accountId",
        in: "query",
        required: true,
        description: "Identyfikator konta pracownika (UUID v7).",
        schema: UuidParam,
      },
    ],
    dataSchemaName: "PermissionSnapshot",
    dataSchema: PermissionSnapshot,
    responseSchemaName: "PermissionSnapshotResponse",
    responseDescription: "Migawka uprawnień konta dla wskazanego produktu.",
    errors: {
      401: ["UNAUTHENTICATED"],
      403: ["PERMISSION_DENIED"],
      404: ["NOT_FOUND"],
      422: ["VALIDATION_FAILED"],
      500: ["INTERNAL_ERROR"],
    },
  },
  listProductEvents: {
    method: "GET",
    path: `${API_PREFIX}/products/{productKey}/events`,
    operationId: "listProductEvents",
    tag: "Events",
    summary: "Kanał zdarzeń Core dla serwera produktu",
    description:
      "Endpoint maszynowy dla serwerów produktów (token OAuth 2.1 `client_credentials` z zakresem " +
      "`core:events.read`). Zwraca wysłane zdarzenia Core (koperta `@monorise-team/events` z numerem " +
      "`sequence`) w rosnącej kolejności numerów, wyłącznie dla firm z aktywnym dostępem do produktu. Produkt " +
      "zapamiętuje numer ostatnio przetworzonego zdarzenia i pyta o kolejne (`cursor`). `meta.nextCursor` to " +
      "numer ostatniego zdarzenia, gdy strona jest pełna, a `null`, gdy produkt jest na bieżąco. Rozwiązanie " +
      "do czasu EventBridge i SQS (ADR-0045).",
    auth: { scheme: "productOAuth", scopes: [EVENTS_READ_SCOPE] },
    successStatus: 200,
    envelope: true,
    paginated: true,
    parameters: [
      PRODUCT_KEY_PARAM,
      {
        name: "cursor",
        in: "query",
        required: false,
        description:
          "Numer ostatnio przetworzonego zdarzenia (wyłącznie, jawny, nie nieprzezroczysty); brak albo `0` = od początku kanału.",
        schema: EventFeedPosition,
      },
      {
        name: "limit",
        in: "query",
        required: false,
        description: `Liczba zdarzeń na stronie (1–${MAX_EVENT_FEED_LIMIT}, domyślnie ${DEFAULT_EVENT_FEED_LIMIT}).`,
        schema: z.number().int().min(1).max(MAX_EVENT_FEED_LIMIT).default(DEFAULT_EVENT_FEED_LIMIT),
      },
    ],
    dataSchemaName: "ProductEventList",
    dataSchema: ProductEventList,
    responseSchemaName: "ProductEventListResponse",
    responseDescription: "Strona kanału zdarzeń produktu.",
    errors: {
      401: ["UNAUTHENTICATED"],
      403: ["PERMISSION_DENIED"],
      404: ["NOT_FOUND"],
      422: ["VALIDATION_FAILED"],
      500: ["INTERNAL_ERROR"],
    },
  },
  listProductDirectoryUnitMembers: {
    method: "GET",
    path: `${API_PREFIX}/products/{productKey}/directory/unit-members`,
    operationId: "listProductDirectoryUnitMembers",
    tag: "Directory",
    summary: "Lista członkostw pracowników w jednostkach dla serwera produktu",
    description:
      "Endpoint maszynowy dla serwerów produktów (token OAuth 2.1 `client_credentials` z zakresem " +
      "`core:directory.read`). Wymaga zgodności klienta z `products.registrationClientId` oraz aktywnego " +
      "dostępu firmy (`Entitlement`) do wskazanego produktu. Działa w kontekście RLS wskazanej firmy.",
    auth: { scheme: "productOAuth", scopes: [DIRECTORY_READ_SCOPE] },
    successStatus: 200,
    envelope: true,
    paginated: true,
    parameters: [
      PRODUCT_KEY_PARAM,
      {
        name: "organizationId",
        in: "query",
        required: true,
        description: "Identyfikator firmy (UUID v7), dla której pobierane są członkostwa.",
        schema: UuidParam,
      },
      {
        name: "unitId",
        in: "query",
        required: false,
        description: `Opcjonalny powtarzalny filtr po identyfikatorach jednostek (maks. ${MAX_DIRECTORY_FILTER_IDS}; brak = wszystkie jednostki firmy).`,
        schema: RepeatableUuidParam,
      },
      ...PAGE_PARAMETERS,
    ],
    dataSchemaName: "DirectoryUnitMemberList",
    dataSchema: DirectoryUnitMemberList,
    responseSchemaName: "DirectoryUnitMemberListResponse",
    responseDescription: "Strona listy członkostw pracowników w jednostkach firmy.",
    errors: {
      401: ["UNAUTHENTICATED"],
      403: ["PERMISSION_DENIED"],
      404: ["NOT_FOUND"],
      422: ["VALIDATION_FAILED"],
      500: ["INTERNAL_ERROR"],
    },
  },
  listProductDirectoryEmployees: {
    method: "GET",
    path: `${API_PREFIX}/products/{productKey}/directory/employees`,
    operationId: "listProductDirectoryEmployees",
    tag: "Directory",
    summary: "Lista podstawowych danych pracowników dla serwera produktu",
    description:
      "Endpoint maszynowy dla serwerów produktów (token OAuth 2.1 `client_credentials` z zakresem " +
      "`core:directory.read`). Zwraca wyłącznie minimalne pola identyfikacyjne (bez służbowego e-maila " +
      "i stanowiska). Wymaga zgodności klienta produktu oraz aktywnego dostępu firmy (`Entitlement`).",
    auth: { scheme: "productOAuth", scopes: [DIRECTORY_READ_SCOPE] },
    successStatus: 200,
    envelope: true,
    paginated: true,
    parameters: [
      PRODUCT_KEY_PARAM,
      {
        name: "organizationId",
        in: "query",
        required: true,
        description: "Identyfikator firmy (UUID v7), dla której pobierani są pracownicy.",
        schema: UuidParam,
      },
      {
        name: "employeeId",
        in: "query",
        required: false,
        description: `Opcjonalny powtarzalny filtr po identyfikatorach pracowników (maks. ${MAX_DIRECTORY_FILTER_IDS}; brak = wszyscy pracownicy firmy).`,
        schema: RepeatableUuidParam,
      },
      ...PAGE_PARAMETERS,
    ],
    dataSchemaName: "DirectoryEmployeeList",
    dataSchema: DirectoryEmployeeList,
    responseSchemaName: "DirectoryEmployeeListResponse",
    responseDescription: "Strona listy podstawowych danych pracowników firmy.",
    errors: {
      401: ["UNAUTHENTICATED"],
      403: ["PERMISSION_DENIED"],
      404: ["NOT_FOUND"],
      422: ["VALIDATION_FAILED"],
      500: ["INTERNAL_ERROR"],
    },
  },
  listEntitlements: {
    method: "GET",
    path: `${API_PREFIX}/entitlements`,
    operationId: "listEntitlements",
    tag: "AppAccess",
    summary: "Lista dostępów firmy do produktów",
    description:
      "Zwraca stronicowaną, wyłącznie do odczytu listę dostępów firmy do produktów (Entitlements), " +
      "dostępną dla każdego aktywnego konta firmy.",
    auth: "bearer",
    successStatus: 200,
    envelope: true,
    paginated: true,
    parameters: [
      ...PAGE_PARAMETERS,
      {
        name: "status",
        in: "query",
        required: false,
        description: "Opcjonalny filtr statusu dostępu (`ACTIVE`, `SUSPENDED` albo `ENDED`).",
        schema: EntitlementStatus,
      },
    ],
    dataSchemaName: "EntitlementList",
    dataSchema: EntitlementList,
    responseSchemaName: "EntitlementListResponse",
    responseDescription: "Strona listy dostępów firmy do produktów.",
    errors: {
      401: ["UNAUTHENTICATED", "ACCOUNT_DEACTIVATED"],
      422: ["VALIDATION_FAILED"],
      500: ["INTERNAL_ERROR"],
    },
  },
  listAppAccess: {
    method: "GET",
    path: `${API_PREFIX}/app-access`,
    operationId: "listAppAccess",
    tag: "AppAccess",
    summary: "Lista wpisów dostępu kont do aplikacji",
    description:
      "Owner oraz konta z uprawnieniem `core.app_access.manage` (w dowolnym zakresie) widzą wszystkie wpisy firmy; " +
      "pozostałe aktywne konta widzą wyłącznie własne wpisy. Domyślnie zwraca tylko aktywne dostępy.",
    auth: "bearer",
    successStatus: 200,
    envelope: true,
    paginated: true,
    parameters: [
      ...PAGE_PARAMETERS,
      {
        name: "accountId",
        in: "query",
        required: false,
        description: "Opcjonalny filtr po identyfikatorze konta (UUID v7).",
        schema: UuidParam,
      },
      {
        name: "product",
        in: "query",
        required: false,
        description: "Opcjonalny filtr po kluczu produktu (np. `timotime`).",
        schema: ProductKey,
      },
      {
        name: "includeRevoked",
        in: "query",
        required: false,
        description: "Czy uwzględnić wyłączone dostępy (`REVOKED`) — domyślnie `false`.",
        schema: IncludeRevokedParam,
      },
    ],
    dataSchemaName: "AppAccessList",
    dataSchema: AppAccessList,
    responseSchemaName: "AppAccessListResponse",
    responseDescription: "Strona listy dostępów kont do aplikacji.",
    errors: {
      401: ["UNAUTHENTICATED", "ACCOUNT_DEACTIVATED"],
      422: ["VALIDATION_FAILED"],
      500: ["INTERNAL_ERROR"],
    },
  },
  grantAppAccess: {
    method: "POST",
    path: `${API_PREFIX}/app-access`,
    operationId: "grantAppAccess",
    tag: "AppAccess",
    summary: "Włącz aplikację pracownikowi",
    description:
      "Włącza aktywnemu kontu dostęp do produktu, do którego firma ma aktywny `Entitlement` (ADR-0035). " +
      "Wymaga roli Ownera albo uprawnienia `core.app_access.manage` obejmującego jednostki pracownika " +
      "(dla pracownika bez jednostek — w zakresie całej firmy).",
    auth: "bearer",
    successStatus: 201,
    envelope: true,
    requestBodySchemaName: "CreateAppAccess",
    requestBodySchema: CreateAppAccess,
    requestBodyDescription: "Identyfikator konta i klucz produktu.",
    dataSchemaName: "AppAccess",
    dataSchema: AppAccess,
    responseSchemaName: "AppAccessResponse",
    responseDescription: "Utworzony wpis dostępu konta do aplikacji.",
    errors: {
      401: ["UNAUTHENTICATED", "ACCOUNT_DEACTIVATED"],
      403: ["PERMISSION_DENIED"],
      404: ["NOT_FOUND"],
      409: ["CONFLICT"],
      422: ["VALIDATION_FAILED"],
      500: ["INTERNAL_ERROR"],
    },
  },
  revokeAppAccess: {
    method: "DELETE",
    path: `${API_PREFIX}/app-access/{appAccessId}`,
    operationId: "revokeAppAccess",
    tag: "AppAccess",
    summary: "Wyłącz aplikację pracownikowi",
    description:
      "Oznacza dostęp konta do aplikacji jako `REVOKED` (z zachowaniem historii), podbija `authzRevision` " +
      "i zapisuje zdarzenie `organization.permissions.changed`. Wymaga roli Ownera albo `core.app_access.manage` " +
      "obejmującego jednostki pracownika.",
    auth: "bearer",
    successStatus: 204,
    envelope: false,
    parameters: [APP_ACCESS_ID_PARAM],
    responseDescription: "Dostęp konta do aplikacji został wyłączony.",
    errors: {
      401: ["UNAUTHENTICATED", "ACCOUNT_DEACTIVATED"],
      403: ["PERMISSION_DENIED"],
      404: ["NOT_FOUND"],
      409: ["CONFLICT"],
      422: ["VALIDATION_FAILED"],
      500: ["INTERNAL_ERROR"],
    },
  },
} as const satisfies Record<string, RouteDefinition>;

export const ROUTE_LIST: readonly RouteDefinition[] = Object.values(ROUTES);
