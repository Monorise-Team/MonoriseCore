import {
  CORE_PERMISSIONS,
  CreateAppAccess,
  CreateEmployee,
  CreateInvitation,
  CreateNotification,
  CreateOrganizationDomain,
  CreateRole,
  CreateRoleAssignment,
  CreateUnit,
  DIRECTORY_READ_SCOPE,
  emailDomain,
  EVENTS_READ_SCOPE,
  ProductEventsQuery,
  EntitlementStatus,
  getNotificationCategory,
  IDEMPOTENCY_REPLAYED_HEADER,
  InvitationStatus,
  isFreeEmailDomain,
  ListAuditLogQuery,
  MAX_DIRECTORY_FILTER_IDS,
  normalizeEmail,
  NOTIFICATIONS_SEND_SCOPE,
  PageQuery,
  PERMISSIONS_READ_SCOPE,
  PERMISSIONS_REGISTER_SCOPE,
  ProductKey,
  PutUnitMember,
  TransferOrganizationOwner,
  UnitStatus,
  UpdateEmployee,
  UpdateNotificationPreference,
  UpdateOrganization,
  UpdateRole,
  UpdateUnit,
  VerifyOrganizationDomain,
  type ApiErrorBody,
  type ApiListResponse,
  type ApiResponse,
  type AppAccess,
  type DirectoryEmployee,
  type DirectoryUnitMember,
  type AccountStatus,
  type Employee,
  type Entitlement,
  type ErrorCode,
  type Health,
  type MachineTokenClaims,
  type Me,
  type OrganizationDomain,
  type OrganizationOwner,
  type Permission,
  type Role,
  type RoleAssignment,
  type ScopeType,
  type Unit,
  type UnitMember,
} from "@core/contracts";
import { revokeUserAuthTokens, uuidv7, withOrganization, type PrismaClient, type Tx } from "@core/db";
import { PermissionError } from "@monorise-team/permissions";
import Fastify, { type FastifyInstance, type FastifyRequest, type RouteOptions } from "fastify";
import { z } from "zod";
import { AuditCursorError, decodeAuditCursor, listAuditLogEntries, writeAudit, type AuditLogCursor } from "./audit.js";
import {
  assertCanAssignInScope,
  assertCanDelegateRole,
  assertCanManageAppAccessForUnits,
  assertCorePermission,
  canViewAllAppAccess,
  canViewAllRoleAssignments,
  hasAnyAppAccessManagePermission,
  hasAnyRoleAssignPermission,
  loadPermissionSnapshot,
  toGrantScope,
} from "./authorization.js";
import {
  addOrganizationDomain,
  commitVerifyOrganizationDomain,
  deleteOrganizationDomain,
  DomainError,
  getOrganizationForCaller,
  lockOrganizationDomains,
  prepareVerifyOrganizationDomain,
  setPrimaryOrganizationDomain,
  updateOrganization,
  type DomainServiceOptions,
  type PreparedDomainVerification,
  type ResolveTxtFn,
} from "./domains.js";
import { isEntitlementActive } from "./entitlements.js";
import { readProductEventFeed } from "./event-feed.js";
import {
  accountPrincipal,
  clientPrincipal,
  computeRequestHash,
  executeWithIdempotency,
  extractIdempotencyKeyHeader,
  IdempotencyError,
  parseIdempotencyKeyHeader,
} from "./idempotency.js";
import {
  createInvitation,
  InvitationError,
  MAIL_OUTBOX_DELIVERY_SELECT,
  resendInvitation,
  revokeInvitation,
  serializeInvitation,
  type InvitationActor,
} from "./invitations.js";
import type { MailOutboxWorker } from "./mail-outbox.js";
import {
  createNotification,
  listNotificationPreferencesForAccount,
  NotificationError,
  resolveNotificationsUnsubscribeSecret,
  unsubscribeNotificationByToken,
  updateNotificationPreferenceForAccount,
  validateActionUrlOrigin,
  type NotificationAuditMeta,
} from "./notifications.js";
import { buildOpenApiDocument } from "./openapi.js";
import { bumpAuthzRevisions } from "./outbox.js";
import { ManifestValidationError, registerPermissions } from "./permissions-registry.js";
import { registerRoleTemplates } from "./role-templates-registry.js";
import { ROUTES, toFastifyPath, type RouteDefinition } from "./routes.js";
import type { MachineTokenVerifier, TokenVerifier } from "./tokens.js";

class ApiFailure extends Error {
  constructor(
    readonly status: number,
    readonly code: ErrorCode,
    message: string,
    readonly details: ApiErrorBody["details"] = [],
  ) {
    super(message);
  }
}

export interface ServerOptions {
  db: PrismaClient;
  verifyToken: TokenVerifier;
  verifyMachineToken: MachineTokenVerifier;
  logger?: boolean;
  /** Sekret HMAC-SHA256 do wyliczania rekordów DNS TXT domen (`CORE_DOMAIN_VERIFICATION_SECRET`). */
  domainVerificationSecret?: string | undefined;
  /** Sekret HMAC-SHA256 do podpisywania tokenów wypisania z powiadomień (`CORE_NOTIFICATIONS_UNSUBSCRIBE_SECRET`). */
  notificationsUnsubscribeSecret?: string | undefined;
  /** Tylko lokalnie: czy zezwolić na `trustLocally: true` w weryfikacji domeny (`CORE_DEV_TRUST_DOMAINS=1`). */
  devTrustDomains?: boolean | undefined;
  /** Nadpisanie funkcji odpytywania DNS TXT (np. w testach). */
  resolveTxt?: ResolveTxtFn | undefined;
  /** Opcjonalny worker kolejki poczty budzony po zatwierdzeniu tworzenia lub ponowienia zaproszenia. */
  mailOutboxWorker?: Pick<MailOutboxWorker, "wake"> | undefined;
  /** Nadpisanie bieżącego czasu (do deterministycznych testów wygasania zaproszeń). */
  now?: (() => Date) | undefined;
  /** Opcjonalny hook wywoływany przy rejestracji każdej ścieżki Fastify (używany w testach OpenAPI). */
  onRoute?: (route: RouteOptions) => void;
}

interface Caller {
  accountId: string;
  organizationId: string;
  employeeId: string;
  isOwner: boolean;
  authzRevision: number;
}

interface MachineCaller {
  clientId: string;
  scopes: Set<string>;
}

const EmployeeIdParams = z.object({ employeeId: z.uuid() });
const UnitIdParams = z.object({ unitId: z.uuid() });
const UnitMemberParams = z.object({ unitId: z.uuid(), employeeId: z.uuid() });
const ProductKeyParams = z.object({ productKey: ProductKey });
const RoleIdParams = z.object({ roleId: z.uuid() });
const AssignmentIdParams = z.object({ assignmentId: z.uuid() });
const AppAccessIdParams = z.object({ appAccessId: z.uuid() });
const InvitationIdParams = z.object({ invitationId: z.uuid() });
const DomainIdParams = z.object({ domainId: z.uuid() });
const OrganizationIdParams = z.object({ organizationId: z.uuid() });
const ListInvitationsFilter = z.object({ status: InvitationStatus.optional() });
const PermissionSnapshotQuery = z.object({
  organizationId: z.uuid(),
  accountId: z.uuid(),
});
const RepeatableUuidFilter = z
  .union([z.uuid().transform((id) => [id]), z.array(z.uuid()).max(MAX_DIRECTORY_FILTER_IDS)])
  .optional();
const DirectoryUnitMembersFilter = z.object({
  organizationId: z.uuid(),
  unitId: RepeatableUuidFilter,
});
const DirectoryEmployeesFilter = z.object({
  organizationId: z.uuid(),
  employeeId: RepeatableUuidFilter,
});
const ListUnitsFilter = z.object({ status: UnitStatus.optional() });
const ListEntitlementsFilter = z.object({ status: EntitlementStatus.optional() });
const QueryBoolean = z
  .union([z.boolean(), z.enum(["true", "false"]).transform((value) => value === "true")])
  .default(false);
const QueryBooleanDefaultTrue = z
  .union([z.boolean(), z.enum(["true", "false"]).transform((value) => value === "true")])
  .default(true);
const ListPermissionsFilter = z.object({
  product: ProductKey.optional(),
  includeDeprecated: QueryBoolean,
});
const ListRolesFilter = z.object({
  product: ProductKey.optional(),
  includeTemplates: QueryBooleanDefaultTrue,
  includeArchived: QueryBoolean,
});
const ListRoleAssignmentsFilter = z.object({
  accountId: z.uuid().optional(),
  roleId: z.uuid().optional(),
});
const ListAppAccessFilter = z.object({
  accountId: z.uuid().optional(),
  product: ProductKey.optional(),
  includeRevoked: QueryBoolean,
});
const CursorUuid = z.uuid();
const BASE64URL_RE = /^[A-Za-z0-9_-]+$/;

function parseInput<T>(schema: z.ZodType<T>, input: unknown): T {
  const result = schema.safeParse(input);
  if (!result.success) {
    const details: ApiErrorBody["details"] = result.error.issues.map((issue) => ({
      ...(issue.path.length > 0 ? { field: issue.path.map(String).join(".") } : {}),
      message: issue.message,
    }));
    throw new ApiFailure(422, "VALIDATION_FAILED", "Błędne dane wejściowe", details);
  }
  return result.data;
}

function encodeCursor(id: string): string {
  return Buffer.from(id, "utf8").toString("base64url");
}

function decodeCursor(cursor: string): string {
  if (!BASE64URL_RE.test(cursor)) {
    throw new ApiFailure(422, "VALIDATION_FAILED", "Błędne dane wejściowe", [
      { field: "cursor", message: "Nieprawidłowy kursor stronicowania" },
    ]);
  }
  const decoded = Buffer.from(cursor, "base64url").toString("utf8");
  if (!CursorUuid.safeParse(decoded).success || encodeCursor(decoded) !== cursor) {
    throw new ApiFailure(422, "VALIDATION_FAILED", "Błędne dane wejściowe", [
      { field: "cursor", message: "Nieprawidłowy kursor stronicowania" },
    ]);
  }
  return decoded;
}

interface ParsedPage {
  limit: number;
  afterId?: string;
}

function parsePageQuery<T extends z.ZodRawShape = Record<never, never>>(
  query: unknown,
  extraFilter?: z.ZodObject<T>,
): ParsedPage & z.infer<z.ZodObject<T>> {
  const schema = extraFilter ? PageQuery.extend(extraFilter.shape) : PageQuery;
  const parsed = parseInput(schema, query ?? {}) as { limit: number; cursor?: string } & z.infer<z.ZodObject<T>>;
  const afterId = parsed.cursor !== undefined ? decodeCursor(parsed.cursor) : undefined;
  return { ...parsed, limit: parsed.limit, ...(afterId ? { afterId } : {}) };
}

function paginateRows<T extends { id: string }>(
  rows: readonly T[],
  limit: number,
): { items: T[]; nextCursor: string | null } {
  const hasMore = rows.length > limit;
  const items = hasMore ? rows.slice(0, limit) : [...rows];
  const last = items[items.length - 1];
  return {
    items,
    nextCursor: hasMore && last ? encodeCursor(last.id) : null,
  };
}

/**
 * Serializuje zapisy w drzewie jednostek jednej firmy na czas transakcji (wspólny klucz z wyzwalaczem
 * `prevent_organization_unit_cycle`), żeby równoległe sprawdzenia archiwizacji, członków i cykli nie ścigały się.
 */
async function lockOrganizationUnits(tx: Tx, organizationId: string): Promise<void> {
  await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtextextended('organization_units:' || ${organizationId}::uuid::text, 0))`;
}

/** Serializuje zapisy na roli i przypisaniach tej roli (archiwizacja vs nowe przypisanie). */
async function lockRole(tx: Tx, roleId: string): Promise<void> {
  await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtextextended('role:' || ${roleId}::uuid::text, 0))`;
}

/** Serializuje zmiany stanu konta (np. wyłączenie i przywrócenie logowania) na czas transakcji. */
async function lockAccount(tx: Tx, accountId: string): Promise<void> {
  await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtextextended('account:' || ${accountId}::uuid::text, 0))`;
}

/** Serializuje zapisy tego samego służbowego adresu e-mail w jednej firmie na czas transakcji. */
async function lockEmployeeWorkEmail(tx: Tx, organizationId: string, normalizedEmail: string): Promise<void> {
  const lockKey = `employee_work_email:${organizationId}:${normalizedEmail}`;
  await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtextextended(${lockKey}::text, 0))`;
}

/**
 * Normalizuje służbowy adres e-mail pracownika i sprawdza reguły firmy: brak darmowej domeny (ADR-0019),
 * zweryfikowana domena tej firmy (`VERIFIED`) oraz brak duplikatu wśród pracowników i kont firmy.
 */
async function validateOrganizationWorkEmail(
  tx: Tx,
  organizationId: string,
  rawEmail: string,
  excludeEmployeeId?: string,
): Promise<string> {
  const normalized = normalizeEmail(rawEmail);
  const domain = emailDomain(normalized);
  if (!domain || isFreeEmailDomain(domain)) {
    throw new ApiFailure(
      422,
      "EMAIL_DOMAIN_NOT_ALLOWED",
      "Służbowy adres e-mail nie może należeć do darmowej skrzynki pocztowej",
      [{ field: "workEmail", message: "Darmowe domeny pocztowe nie mogą należeć do firmy" }],
    );
  }

  // Serializujemy względem usuwania domen firmy (DELETE /organization/domains/{domainId})
  await lockOrganizationDomains(tx, organizationId);

  const verifiedDomain = await tx.organizationDomain.findFirst({
    where: { organizationId, domain, status: "VERIFIED" },
    select: { id: true },
  });
  if (!verifiedDomain) {
    throw new ApiFailure(
      422,
      "EMAIL_DOMAIN_NOT_ALLOWED",
      "Służbowy adres e-mail musi należeć do zweryfikowanej domeny firmy",
      [{ field: "workEmail", message: "Domena adresu e-mail nie jest zweryfikowaną domeną tej firmy" }],
    );
  }

  await lockEmployeeWorkEmail(tx, organizationId, normalized);

  const [duplicateEmployee, duplicateAccount] = await Promise.all([
    tx.employee.findFirst({
      where: {
        organizationId,
        workEmail: { equals: normalized, mode: "insensitive" },
        ...(excludeEmployeeId !== undefined ? { id: { not: excludeEmployeeId } } : {}),
      },
      select: { id: true },
    }),
    tx.account.findFirst({
      where: {
        organizationId,
        normalizedEmail: { equals: normalized, mode: "insensitive" },
        ...(excludeEmployeeId !== undefined ? { employeeId: { not: excludeEmployeeId } } : {}),
      },
      select: { id: true },
    }),
  ]);
  if (duplicateEmployee || duplicateAccount) {
    throw new ApiFailure(409, "CONFLICT", "Ten służbowy adres e-mail jest już używany w tej firmie");
  }

  return normalized;
}

function isUniqueViolation(error: unknown): boolean {
  const err = error as { code?: string; message?: string } | null;
  if (err?.code === "P2002" || err?.code === "23505") return true;
  return /duplicate key value violates unique constraint/i.test(String(err?.message ?? ""));
}

function serializeEmployee(employee: {
  id: string;
  account?: { id: string; status: AccountStatus } | null;
  firstName: string;
  lastName: string;
  workEmail: string | null;
  jobTitle: string | null;
  status: Employee["status"];
}): Employee {
  return {
    id: employee.id,
    accountId: employee.account?.id ?? null,
    accountStatus: employee.account?.status ?? null,
    firstName: employee.firstName,
    lastName: employee.lastName,
    workEmail: employee.workEmail,
    jobTitle: employee.jobTitle,
    status: employee.status,
  };
}

function serializeUnit(unit: {
  id: string;
  parentId: string | null;
  name: string;
  type: Unit["type"];
  status: Unit["status"];
  createdAt: Date;
  updatedAt: Date;
}): Unit {
  return {
    id: unit.id,
    parentId: unit.parentId,
    name: unit.name,
    type: unit.type,
    status: unit.status,
    createdAt: unit.createdAt.toISOString(),
    updatedAt: unit.updatedAt.toISOString(),
  };
}

function serializeUnitMember(membership: {
  unitId: string;
  employeeId: string;
  role: UnitMember["role"];
  joinedAt: Date;
  employee: {
    id: string;
    account?: { id: string; status: AccountStatus } | null;
    firstName: string;
    lastName: string;
    workEmail: string | null;
    jobTitle: string | null;
    status: Employee["status"];
  };
}): UnitMember {
  return {
    unitId: membership.unitId,
    employeeId: membership.employeeId,
    role: membership.role,
    joinedAt: membership.joinedAt.toISOString(),
    employee: serializeEmployee(membership.employee),
  };
}

function serializePermission(permission: {
  key: string;
  description: string;
  deprecatedAt: Date | null;
  product: { key: string } | null;
}): Permission {
  return {
    key: permission.key,
    product: permission.product?.key ?? null,
    description: permission.description,
    deprecated: permission.deprecatedAt !== null,
  };
}

function serializeRole(role: {
  id: string;
  organizationId: string | null;
  key: string | null;
  name: string;
  description: string | null;
  copiedFromRoleId: string | null;
  archivedAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
  product: { key: string } | null;
  permissions: { permission: { key: string } }[];
}): Role {
  return {
    id: role.id,
    key: role.key,
    product: role.product?.key ?? null,
    name: role.name,
    description: role.description,
    isTemplate: role.organizationId === null,
    copiedFromRoleId: role.copiedFromRoleId,
    archivedAt: role.archivedAt ? role.archivedAt.toISOString() : null,
    permissions: role.permissions.map((rp) => rp.permission.key).sort(),
    createdAt: role.createdAt.toISOString(),
    updatedAt: role.updatedAt.toISOString(),
  };
}

function serializeRoleAssignment(assignment: {
  id: string;
  accountId: string;
  roleId: string;
  scopeType: ScopeType;
  scopeId: string | null;
  validFrom: Date | null;
  validUntil: Date | null;
  grantedByAccountId: string;
  createdAt: Date;
}): RoleAssignment {
  return {
    id: assignment.id,
    accountId: assignment.accountId,
    roleId: assignment.roleId,
    scopeType: assignment.scopeType,
    scopeId: assignment.scopeId,
    validFrom: assignment.validFrom ? assignment.validFrom.toISOString() : null,
    validUntil: assignment.validUntil ? assignment.validUntil.toISOString() : null,
    grantedByAccountId: assignment.grantedByAccountId,
    createdAt: assignment.createdAt.toISOString(),
  };
}

function serializeEntitlement(
  entitlement: {
    id: string;
    planId: string | null;
    sourceType: Entitlement["sourceType"];
    status: Entitlement["status"];
    startsAt: Date;
    endsAt: Date | null;
    suspendedReason: Entitlement["suspendedReason"];
    createdAt: Date;
    updatedAt: Date;
    product: { key: string };
  },
  now: Date = new Date(),
): Entitlement {
  return {
    id: entitlement.id,
    product: entitlement.product.key,
    planId: entitlement.planId,
    sourceType: entitlement.sourceType,
    status: entitlement.status,
    isActive: isEntitlementActive(entitlement, now),
    startsAt: entitlement.startsAt.toISOString(),
    endsAt: entitlement.endsAt ? entitlement.endsAt.toISOString() : null,
    suspendedReason: entitlement.suspendedReason,
    createdAt: entitlement.createdAt.toISOString(),
    updatedAt: entitlement.updatedAt.toISOString(),
  };
}

function serializeAppAccess(access: {
  id: string;
  accountId: string;
  status: AppAccess["status"];
  grantedByAccountId: string;
  createdAt: Date;
  revokedAt: Date | null;
  product: { key: string };
}): AppAccess {
  return {
    id: access.id,
    accountId: access.accountId,
    product: access.product.key,
    status: access.status,
    grantedByAccountId: access.grantedByAccountId,
    createdAt: access.createdAt.toISOString(),
    revokedAt: access.revokedAt ? access.revokedAt.toISOString() : null,
  };
}

async function resolveActiveRolePermissions(
  tx: Tx,
  productId: string | null,
  productLabel: string,
  keys: readonly string[],
): Promise<{ id: string; key: string }[]> {
  const found = await tx.permission.findMany({
    where: { key: { in: [...keys] } },
    select: { id: true, key: true, productId: true, deprecatedAt: true },
  });
  const byKey = new Map(found.map((perm) => [perm.key, perm]));
  const details: ApiErrorBody["details"] = [];
  const resolved: { id: string; key: string }[] = [];

  for (let i = 0; i < keys.length; i++) {
    const key = keys[i]!;
    const perm = byKey.get(key);
    if (!perm) {
      details.push({ field: `permissions.${i}`, message: `Nieznane uprawnienie "${key}"` });
    } else if (perm.deprecatedAt !== null) {
      details.push({ field: `permissions.${i}`, message: `Uprawnienie "${key}" jest wycofane` });
    } else if (perm.productId !== productId) {
      details.push({
        field: `permissions.${i}`,
        message: `Uprawnienie "${key}" nie należy do produktu "${productLabel}"`,
      });
    } else {
      resolved.push({ id: perm.id, key: perm.key });
    }
  }

  if (details.length > 0) {
    throw new ApiFailure(422, "VALIDATION_FAILED", "Nieprawidłowe uprawnienia roli", details);
  }
  return resolved;
}

function isCycleError(error: unknown): boolean {
  const text =
    String((error as { code?: string; message?: string })?.code ?? "") + String((error as Error)?.message ?? "");
  return text.includes("organization_units_no_cycle") || /unit cycle detected/i.test(text);
}

async function createsUnitCycle(tx: Tx, unitId: string, candidateParentId: string): Promise<boolean> {
  if (candidateParentId === unitId) return true;
  const units = await tx.organizationUnit.findMany({ select: { id: true, parentId: true } });
  const parentById = new Map(units.map((unit) => [unit.id, unit.parentId]));
  const visited = new Set<string>();
  let current: string | null | undefined = candidateParentId;
  while (current) {
    if (current === unitId) return true;
    if (visited.has(current)) break;
    visited.add(current);
    current = parentById.get(current);
  }
  return false;
}

/**
 * Najpierw istnienie jednostki (404), potem uprawnienie (403): jednostka innej firmy albo nieistniejąca
 * zawsze daje NOT_FOUND, zgodnie ze standardem API, a osoba bez uprawnień nie dostaje mylącego 403.
 */
async function assertUnitExists(tx: Tx, unitId: string, message: string): Promise<void> {
  const unit = await tx.organizationUnit.findUnique({ where: { id: unitId }, select: { id: true } });
  if (!unit) throw new ApiFailure(404, "NOT_FOUND", message);
}

/** Core API: format `{ data, meta, error }` (ADR-0044), firma zawsze z tokenu, dane przez RLS (ADR-0037). */
export function buildServer({
  db,
  verifyToken,
  verifyMachineToken,
  logger = false,
  domainVerificationSecret = process.env.CORE_DOMAIN_VERIFICATION_SECRET,
  notificationsUnsubscribeSecret,
  devTrustDomains = false,
  resolveTxt,
  mailOutboxWorker,
  now: customNow,
  onRoute,
}: ServerOptions): FastifyInstance {
  const getNow = customNow ?? (() => new Date());
  const app = Fastify({
    logger,
    routerOptions: { maxParamLength: 1024 },
    genReqId: () => `req_${crypto.randomUUID().replaceAll("-", "").slice(0, 16)}`,
  });
  const openApiDocument = buildOpenApiDocument();
  const domainOptions: DomainServiceOptions = {
    domainVerificationSecret: domainVerificationSecret?.trim() || undefined,
    devTrustDomains,
    resolveTxt,
  };

  if (onRoute) {
    app.addHook("onRoute", onRoute);
  }

  // RFC 8058: klienci pocztowi wysyłają jednoklikowe wypisanie z nagłówkiem application/x-www-form-urlencoded.
  app.addContentTypeParser("application/x-www-form-urlencoded", { parseAs: "string" }, (_request, body, done) => {
    done(null, typeof body === "string" ? body : body.toString("utf8"));
  });

  const getUnsubscribeSecret = (): string =>
    notificationsUnsubscribeSecret?.trim() ||
    resolveNotificationsUnsubscribeSecret({
      env: process.env,
      fallbackSecret: domainVerificationSecret,
    });

  const auditMetaFromRequest = (request: FastifyRequest): NotificationAuditMeta => {
    const header = request.headers["user-agent"];
    return {
      ipAddress: request.ip || null,
      userAgent: typeof header === "string" && header.length > 0 ? header : null,
      requestId: request.id,
    };
  };

  const send = <T>(request: FastifyRequest, data: T): ApiResponse<T> => ({
    data,
    meta: { requestId: request.id },
    error: null,
  });

  const sendList = <T>(request: FastifyRequest, data: T[], nextCursor: string | null): ApiListResponse<T> => ({
    data,
    meta: { requestId: request.id, nextCursor },
    error: null,
  });

  app.setErrorHandler((error, request, reply) => {
    const statusCode = (error as { statusCode?: number }).statusCode;
    const failure =
      error instanceof ApiFailure
        ? error
        : error instanceof IdempotencyError
          ? new ApiFailure(error.status, error.code, error.message, error.details)
          : error instanceof InvitationError
            ? new ApiFailure(error.status, error.code, error.message, error.details)
            : error instanceof DomainError
              ? new ApiFailure(error.status, error.code, error.message, error.details)
              : error instanceof NotificationError
                ? new ApiFailure(error.status, error.code, error.message, error.details)
                : error instanceof PermissionError
                  ? new ApiFailure(403, "PERMISSION_DENIED", "Brak uprawnień do wykonania tej operacji")
                  : statusCode === 404
                    ? new ApiFailure(404, "NOT_FOUND", "Nie ma takiego zasobu")
                    : statusCode === 400
                      ? new ApiFailure(422, "VALIDATION_FAILED", "Nieprawidłowa treść żądania")
                      : new ApiFailure(500, "INTERNAL_ERROR", "Wewnętrzny błąd serwera");
    if (failure.status >= 500) request.log.error({ err: error }, "błąd Core API");
    const body: ApiResponse<null> = {
      data: null,
      meta: { requestId: request.id },
      error: { code: failure.code, message: failure.message, details: failure.details },
    };
    void reply.status(failure.status).header("Cache-Control", "no-store").send(body);
  });

  app.setNotFoundHandler((request, reply) => {
    const body: ApiResponse<null> = {
      data: null,
      meta: { requestId: request.id },
      error: { code: "NOT_FOUND", message: "Nie ma takiego zasobu", details: [] },
    };
    void reply.status(404).send(body);
  });

  /** Kto pyta: token z nagłówka Authorization, a konto musi być aktywne w firmie. */
  async function caller(request: FastifyRequest): Promise<Caller> {
    const header = request.headers.authorization ?? "";
    const token = header.startsWith("Bearer ") ? header.slice(7) : "";
    if (!token) throw new ApiFailure(401, "UNAUTHENTICATED", "Brak tokenu dostępu");
    let claims;
    try {
      claims = await verifyToken(token);
    } catch {
      throw new ApiFailure(401, "UNAUTHENTICATED", "Token jest nieważny albo wygasł");
    }
    const account = await withOrganization(db, claims.org_id, (tx) =>
      tx.account.findUnique({
        where: { id: claims.sub },
        select: {
          status: true,
          employeeId: true,
          authzRevision: true,
          organization: { select: { ownerAccountId: true } },
        },
      }),
    );
    if (!account || account.employeeId !== claims.employee_id) {
      throw new ApiFailure(401, "UNAUTHENTICATED", "Token jest nieważny albo wygasł");
    }
    if (account.status === "DEACTIVATED") throw new ApiFailure(401, "ACCOUNT_DEACTIVATED", "Konto jest wyłączone");
    if (account.status !== "ACTIVE") throw new ApiFailure(401, "UNAUTHENTICATED", "Konto nie jest aktywne");
    return {
      accountId: claims.sub,
      organizationId: claims.org_id,
      employeeId: claims.employee_id,
      isOwner: account.organization.ownerAccountId === claims.sub,
      authzRevision: account.authzRevision,
    };
  }

  function requireOwner(who: Caller): void {
    if (!who.isOwner) {
      throw new ApiFailure(403, "PERMISSION_DENIED", "Tę operację może wykonać tylko Owner firmy");
    }
  }

  /** Klient maszynowy (OAuth 2.1 `client_credentials`): bez firmy i konta, z wymaganym zakresem. */
  async function machineCaller(request: FastifyRequest, requiredScope: string): Promise<MachineCaller> {
    const header = request.headers.authorization ?? "";
    const token = header.startsWith("Bearer ") ? header.slice(7) : "";
    if (!token) throw new ApiFailure(401, "UNAUTHENTICATED", "Brak tokenu dostępu");
    let claims: MachineTokenClaims;
    try {
      claims = await verifyMachineToken(token);
    } catch {
      throw new ApiFailure(401, "UNAUTHENTICATED", "Token jest nieważny albo wygasł");
    }
    const scopes = new Set(claims.scope.split(" ").filter(Boolean));
    if (!scopes.has(requiredScope)) {
      throw new ApiFailure(403, "PERMISSION_DENIED", "Token nie ma wymaganego zakresu uprawnień");
    }
    return { clientId: claims.client_id, scopes };
  }

  app.addHook("onSend", async (_request, reply) => {
    void reply.header("Cache-Control", "no-store");
  });

  type BearerPostRoute = RouteDefinition & { method: "POST"; auth: "bearer" };

  /**
   * Wspólna rejestracja operacji tworzących (`POST`) z katalogu `ROUTES`: uwierzytelnia konto,
   * obsługuje opcjonalny nagłówek `Idempotency-Key` w tej samej transakcji `withOrganization`
   * (blokada doradcza, wykrywanie konfliktu `409`, zapis odpowiedzi 2xx i odtwarzanie z
   * `Idempotency-Replayed: true`) oraz wysyła kopertę sukcesu. Opcjonalne `onCommit` uruchamia się
   * dopiero po zatwierdzeniu transakcji (nigdy przy wycofaniu ani odtworzeniu z `Idempotency-Key`).
   */
  function registerPostRoute<TData, TPrepared = undefined>(
    route: BearerPostRoute,
    execute: (ctx: { request: FastifyRequest; who: Caller; tx: Tx; now: Date; prepared: TPrepared }) => Promise<TData>,
    options?: {
      /** Krok wykonywany poza długą transakcją (np. zapytanie DNS); pomijany przy odtworzeniu `Idempotency-Key`. */
      prepare?: (ctx: { request: FastifyRequest; who: Caller; now: Date }) => Promise<TPrepared>;
      /** Krok po zatwierdzeniu transakcji (np. wybudzenie workera kolejki poczty); pomijany przy powtórce. */
      onCommit?: (ctx: { request: FastifyRequest; who: Caller }) => void | Promise<void>;
    },
  ): void {
    app.route({
      method: route.method,
      url: toFastifyPath(route.path),
      config: { idempotent: true },
      handler: async (request, reply) => {
        const who = await caller(request);
        const idempotencyKey = parseIdempotencyKeyHeader(extractIdempotencyKeyHeader(request));

        if (idempotencyKey === null) {
          const prepared = options?.prepare
            ? await options.prepare({ request, who, now: getNow() })
            : (undefined as TPrepared);
          const data = await withOrganization(db, who.organizationId, (tx) =>
            execute({ request, who, tx, now: getNow(), prepared }),
          );
          await options?.onCommit?.({ request, who });
          // Żadna obecna trasa POST nie zwraca 204, ale przy przyszłej 204 No Content nie wysyłamy ciała.
          if (route.successStatus === 204) {
            return reply.status(204).send();
          }
          return reply.status(route.successStatus).send(send(request, data));
        }

        const params =
          request.params && typeof request.params === "object"
            ? (request.params as Record<string, unknown>)
            : undefined;

        if (options?.prepare) {
          const requestHash = computeRequestHash(route.method, route.path, request.body, params);
          const existingReplay = await withOrganization(db, who.organizationId, async (tx) => {
            const existing = await tx.idempotencyKey.findUnique({
              where: {
                organizationId_principal_key: {
                  organizationId: who.organizationId,
                  principal: accountPrincipal(who.accountId),
                  key: idempotencyKey,
                },
              },
            });
            if (!existing || existing.expiresAt.getTime() <= getNow().getTime()) {
              return null;
            }
            if (existing.requestHash !== requestHash) {
              throw new IdempotencyError(
                409,
                "CONFLICT",
                "Ten klucz Idempotency-Key był już użyty z inną treścią żądania.",
              );
            }
            return { status: existing.responseStatus, body: existing.responseBody };
          });
          if (existingReplay) {
            void reply.header(IDEMPOTENCY_REPLAYED_HEADER, "true");
            if (existingReplay.status === 204) {
              return reply.status(204).send();
            }
            return reply.status(existingReplay.status).send(existingReplay.body);
          }
        }

        const prepared = options?.prepare
          ? await options.prepare({ request, who, now: getNow() })
          : (undefined as TPrepared);

        const outcome = await executeWithIdempotency({
          db,
          organizationId: who.organizationId,
          principal: accountPrincipal(who.accountId),
          key: idempotencyKey,
          method: route.method,
          pathTemplate: route.path,
          body: request.body,
          params,
          getNow,
          run: async (tx, now) => {
            const data = await execute({ request, who, tx, now, prepared });
            return {
              status: route.successStatus,
              body: route.successStatus === 204 ? null : send(request, data),
            };
          },
        });

        if (outcome.replayed) {
          void reply.header(IDEMPOTENCY_REPLAYED_HEADER, "true");
        } else {
          await options?.onCommit?.({ request, who });
        }
        // Żadna obecna trasa POST nie zwraca 204, ale przy przyszłej 204 No Content nie wysyłamy ciała.
        if (outcome.status === 204) {
          return reply.status(204).send();
        }
        return reply.status(outcome.status).send(outcome.body);
      },
    });
  }

  app.route({
    method: ROUTES.getHealth.method,
    url: toFastifyPath(ROUTES.getHealth.path),
    handler: async (request) => send(request, { status: "ok" } satisfies Health),
  });

  app.route({
    method: ROUTES.getOpenApi.method,
    url: toFastifyPath(ROUTES.getOpenApi.path),
    handler: async () => openApiDocument,
  });

  app.route({
    method: ROUTES.getMe.method,
    url: toFastifyPath(ROUTES.getMe.path),
    handler: async (request) => {
      const who = await caller(request);
      const me = await withOrganization(db, who.organizationId, async (tx) => {
        const account = await tx.account.findUniqueOrThrow({
          where: { id: who.accountId },
          include: { employee: true, organization: true },
        });
        return {
          account: {
            id: account.id,
            email: account.email,
            status: account.status,
            isOwner: account.organization.ownerAccountId === account.id,
          },
          employee: serializeEmployee({ ...account.employee, account: { id: account.id, status: account.status } }),
          organization: {
            id: account.organization.id,
            name: account.organization.name,
            status: account.organization.status,
          },
        } satisfies Me;
      });
      return send(request, me);
    },
  });

  app.route({
    method: ROUTES.getOrganization.method,
    url: toFastifyPath(ROUTES.getOrganization.path),
    handler: async (request) => {
      const who = await caller(request);
      const organization = await withOrganization(db, who.organizationId, (tx) =>
        getOrganizationForCaller(tx, who, domainOptions),
      );
      return send(request, organization);
    },
  });

  app.route({
    method: ROUTES.updateOrganization.method,
    url: toFastifyPath(ROUTES.updateOrganization.path),
    handler: async (request) => {
      const who = await caller(request);
      const body = parseInput(UpdateOrganization, request.body);
      const updated = await withOrganization(db, who.organizationId, (tx) =>
        updateOrganization(tx, request, who, body, domainOptions),
      );
      return send(request, updated);
    },
  });

  registerPostRoute(ROUTES.addOrganizationDomain, async ({ request, who, tx, now }) => {
    const body = parseInput(CreateOrganizationDomain, request.body);
    return addOrganizationDomain(tx, request, who, body, now, domainOptions);
  });

  registerPostRoute<OrganizationDomain, PreparedDomainVerification>(
    ROUTES.verifyOrganizationDomain,
    async ({ request, who, tx, now, prepared }) =>
      commitVerifyOrganizationDomain(tx, request, who, prepared, now, domainOptions),
    {
      prepare: async ({ request, who, now }) => {
        const params = parseInput(DomainIdParams, request.params);
        const body = parseInput(VerifyOrganizationDomain, request.body === undefined ? {} : request.body);
        return prepareVerifyOrganizationDomain(db, who, params.domainId, body, now, domainOptions);
      },
    },
  );

  app.route({
    method: ROUTES.deleteOrganizationDomain.method,
    url: toFastifyPath(ROUTES.deleteOrganizationDomain.path),
    handler: async (request, reply) => {
      const who = await caller(request);
      const params = parseInput(DomainIdParams, request.params);
      await withOrganization(db, who.organizationId, (tx) =>
        deleteOrganizationDomain(tx, request, who, params.domainId),
      );
      return reply.status(204).send();
    },
  });

  app.route({
    method: ROUTES.setPrimaryOrganizationDomain.method,
    url: toFastifyPath(ROUTES.setPrimaryOrganizationDomain.path),
    handler: async (request) => {
      const who = await caller(request);
      const params = parseInput(DomainIdParams, request.params);
      const organization = await withOrganization(db, who.organizationId, (tx) =>
        setPrimaryOrganizationDomain(tx, request, who, params.domainId, domainOptions),
      );
      return send(request, organization);
    },
  });

  app.route({
    method: ROUTES.transferOrganizationOwner.method,
    url: toFastifyPath(ROUTES.transferOrganizationOwner.path),
    handler: async (request) => {
      const who = await caller(request);
      requireOwner(who);
      const body = parseInput(TransferOrganizationOwner, request.body);
      const result = await withOrganization(db, who.organizationId, async (tx) => {
        const org = await tx.organization.findUniqueOrThrow({
          where: { id: who.organizationId },
          select: { ownerAccountId: true },
        });
        if (org.ownerAccountId !== who.accountId) {
          throw new ApiFailure(403, "PERMISSION_DENIED", "Tę operację może wykonać tylko Owner firmy");
        }
        const target = await tx.account.findUnique({
          where: { id: body.accountId },
          select: { id: true, status: true },
        });
        if (!target) {
          throw new ApiFailure(404, "NOT_FOUND", "Nie znaleziono konta");
        }
        if (target.id === who.accountId) {
          throw new ApiFailure(409, "CONFLICT", "To konto jest już Ownerem firmy");
        }
        if (target.status !== "ACTIVE") {
          throw new ApiFailure(409, "CONFLICT", "Ownerem firmy może zostać wyłącznie aktywne konto");
        }
        await tx.organization.update({
          where: { id: who.organizationId },
          data: { ownerAccountId: target.id },
        });
        await bumpAuthzRevisions(tx, who.organizationId, { id: { in: [who.accountId, target.id] } });
        await writeAudit(tx, request, who, {
          action: "organization.owner.transferred",
          resourceType: "organization",
          resourceId: who.organizationId,
          metadata: { from: who.accountId, to: target.id },
        });
        return { ownerAccountId: target.id } satisfies OrganizationOwner;
      });
      return send(request, result);
    },
  });

  app.route({
    method: ROUTES.listEmployees.method,
    url: toFastifyPath(ROUTES.listEmployees.path),
    handler: async (request) => {
      const who = await caller(request);
      const page = parsePageQuery(request.query);
      const rows = await withOrganization(db, who.organizationId, (tx) =>
        tx.employee.findMany({
          ...(page.afterId ? { where: { id: { gt: page.afterId } } } : {}),
          include: { account: { select: { id: true, status: true } } },
          orderBy: { id: "asc" },
          take: page.limit + 1,
        }),
      );
      const { items, nextCursor } = paginateRows(rows, page.limit);
      return sendList(request, items.map(serializeEmployee), nextCursor);
    },
  });

  registerPostRoute(ROUTES.createEmployee, async ({ request, who, tx }) => {
    const body = parseInput(CreateEmployee, request.body);
    const snapshot = await loadPermissionSnapshot(tx, who);
    assertCorePermission(snapshot, CORE_PERMISSIONS.keys["employees.manage"], {});
    const normalizedWorkEmail =
      body.workEmail !== undefined ? await validateOrganizationWorkEmail(tx, who.organizationId, body.workEmail) : null;
    const created = await tx.employee.create({
      data: {
        id: uuidv7(),
        organizationId: who.organizationId,
        firstName: body.firstName,
        lastName: body.lastName,
        workEmail: normalizedWorkEmail,
        jobTitle: body.jobTitle ?? null,
      },
    });
    await writeAudit(tx, request, who, {
      action: "employee.created",
      resourceType: "employee",
      resourceId: created.id,
      metadata: {},
    });
    return serializeEmployee({ ...created, account: null });
  });

  app.route({
    method: ROUTES.updateEmployee.method,
    url: toFastifyPath(ROUTES.updateEmployee.path),
    handler: async (request) => {
      const who = await caller(request);
      const params = parseInput(EmployeeIdParams, request.params);
      const body = parseInput(UpdateEmployee, request.body);

      const updated = await withOrganization(db, who.organizationId, async (tx) => {
        const employee = await tx.employee.findUnique({
          where: { id: params.employeeId },
          include: { account: { select: { id: true, status: true, normalizedEmail: true } } },
        });
        if (!employee) throw new ApiFailure(404, "NOT_FOUND", "Nie znaleziono pracownika");

        const snapshot = await loadPermissionSnapshot(tx, who);
        assertCorePermission(snapshot, CORE_PERMISSIONS.keys["employees.manage"], {});

        if (employee.status === "ANONYMIZED") {
          throw new ApiFailure(409, "CONFLICT", "Nie można edytować zanonimizowanego pracownika");
        }

        let nextWorkEmail = employee.workEmail;
        if (body.workEmail !== undefined) {
          if (employee.account !== null) {
            const accountNormalized = normalizeEmail(employee.account.normalizedEmail);
            if (body.workEmail === null || normalizeEmail(body.workEmail) !== accountNormalized) {
              throw new ApiFailure(
                409,
                "CONFLICT",
                "Nie można zmienić służbowego adresu e-mail pracownika powiązanego z kontem logowania",
              );
            }
            nextWorkEmail = accountNormalized;
          } else if (body.workEmail === null) {
            nextWorkEmail = null;
          } else {
            nextWorkEmail = await validateOrganizationWorkEmail(tx, who.organizationId, body.workEmail, employee.id);
          }
        }

        const nextFirstName = body.firstName ?? employee.firstName;
        const nextLastName = body.lastName ?? employee.lastName;
        const nextJobTitle = body.jobTitle !== undefined ? body.jobTitle : employee.jobTitle;

        const changedFields: ("firstName" | "lastName" | "workEmail" | "jobTitle")[] = [];
        if (nextFirstName !== employee.firstName) changedFields.push("firstName");
        if (nextLastName !== employee.lastName) changedFields.push("lastName");
        if (nextWorkEmail !== employee.workEmail) changedFields.push("workEmail");
        if (nextJobTitle !== employee.jobTitle) changedFields.push("jobTitle");

        if (changedFields.length === 0) {
          return serializeEmployee(employee);
        }

        const saved = await tx.employee.update({
          where: { id: employee.id },
          data: {
            ...(nextFirstName !== employee.firstName ? { firstName: nextFirstName } : {}),
            ...(nextLastName !== employee.lastName ? { lastName: nextLastName } : {}),
            ...(nextWorkEmail !== employee.workEmail ? { workEmail: nextWorkEmail } : {}),
            ...(nextJobTitle !== employee.jobTitle ? { jobTitle: nextJobTitle } : {}),
          },
          include: { account: { select: { id: true, status: true } } },
        });

        const nameChanged = nextFirstName !== employee.firstName || nextLastName !== employee.lastName;
        if (employee.account !== null && nameChanged) {
          await tx.authUser.update({
            where: { id: employee.account.id },
            data: { name: `${nextFirstName} ${nextLastName}` },
          });
        }

        await writeAudit(tx, request, who, {
          action: "employee.updated",
          resourceType: "employee",
          resourceId: saved.id,
          metadata: { fields: changedFields },
        });

        return serializeEmployee(saved);
      });

      return send(request, updated);
    },
  });

  /**
   * Wspólne sprawdzenie pracownika, uprawnienia `core.employees.manage` (zakres `ORGANIZATION` albo Owner)
   * oraz blokady doradczej konta dla wyłączenia i przywrócenia logowania pracownika.
   */
  async function loadManageableEmployeeAccount(
    tx: Tx,
    who: Caller,
    employeeId: string,
    action: "deactivate" | "reactivate",
  ) {
    const employee = await tx.employee.findUnique({
      where: { id: employeeId },
      include: { account: { select: { id: true, status: true } } },
    });
    if (!employee) throw new ApiFailure(404, "NOT_FOUND", "Nie znaleziono pracownika");

    const snapshot = await loadPermissionSnapshot(tx, who);
    assertCorePermission(snapshot, CORE_PERMISSIONS.keys["employees.manage"], {});

    if (employee.status === "ANONYMIZED") {
      throw new ApiFailure(409, "CONFLICT", "Nie można zmienić statusu konta zanonimizowanego pracownika");
    }
    if (employee.account === null) {
      throw new ApiFailure(409, "CONFLICT", "Pracownik nie ma konta do logowania");
    }

    await lockAccount(tx, employee.account.id);

    const [account, organization] = await Promise.all([
      tx.account.findUniqueOrThrow({
        where: { id: employee.account.id },
        select: { id: true, status: true },
      }),
      tx.organization.findUniqueOrThrow({
        where: { id: who.organizationId },
        select: { ownerAccountId: true },
      }),
    ]);

    if (account.id === organization.ownerAccountId) {
      throw new ApiFailure(
        409,
        "CONFLICT",
        action === "deactivate"
          ? "Nie można wyłączyć konta Ownera firmy"
          : "Nie można zmienić statusu konta Ownera firmy",
      );
    }
    if (account.id === who.accountId) {
      throw new ApiFailure(
        409,
        "CONFLICT",
        action === "deactivate" ? "Nie można wyłączyć własnego konta" : "Nie można zmienić statusu własnego konta",
      );
    }
    if (account.status === "INVITED") {
      throw new ApiFailure(
        409,
        "CONFLICT",
        action === "deactivate"
          ? "Nie można wyłączyć konta z oczekującym zaproszeniem"
          : "Nie można przywrócić konta z oczekującym zaproszeniem",
      );
    }

    return { employee, account };
  }

  registerPostRoute(ROUTES.deactivateEmployee, async ({ request, who, tx, now }) => {
    const params = parseInput(EmployeeIdParams, request.params);
    const { employee, account } = await loadManageableEmployeeAccount(tx, who, params.employeeId, "deactivate");

    if (account.status === "DEACTIVATED") {
      return serializeEmployee({ ...employee, account });
    }

    const updatedAccount = await tx.account.update({
      where: { id: account.id },
      data: { status: "DEACTIVATED", deactivatedAt: now },
      select: { id: true, status: true },
    });
    const revoked = await revokeUserAuthTokens(tx, account.id);
    await tx.invitation.updateMany({
      where: { accountId: account.id, status: "PENDING" },
      data: { status: "REVOKED" },
    });
    await bumpAuthzRevisions(tx, who.organizationId, { id: account.id });
    await writeAudit(tx, request, who, {
      action: "account.deactivated",
      resourceType: "account",
      resourceId: account.id,
      metadata: {
        employeeId: employee.id,
        revokedSessions: revoked.sessions,
        revokedOAuthRefreshes: revoked.refreshTokens,
        revokedOAuthAccesses: revoked.accessTokens,
      },
    });

    return serializeEmployee({ ...employee, account: updatedAccount });
  });

  registerPostRoute(ROUTES.reactivateEmployee, async ({ request, who, tx }) => {
    const params = parseInput(EmployeeIdParams, request.params);
    const { employee, account } = await loadManageableEmployeeAccount(tx, who, params.employeeId, "reactivate");

    if (account.status === "ACTIVE") {
      return serializeEmployee({ ...employee, account });
    }

    const updatedAccount = await tx.account.update({
      where: { id: account.id },
      data: { status: "ACTIVE", deactivatedAt: null },
      select: { id: true, status: true },
    });
    await bumpAuthzRevisions(tx, who.organizationId, { id: account.id });
    await writeAudit(tx, request, who, {
      action: "account.reactivated",
      resourceType: "account",
      resourceId: account.id,
      metadata: { employeeId: employee.id },
    });

    return serializeEmployee({ ...employee, account: updatedAccount });
  });

  function invitationActorFromRequest(request: FastifyRequest, who: Caller): InvitationActor {
    const header = request.headers["user-agent"];
    return {
      type: "ACCOUNT",
      accountId: who.accountId,
      ipAddress: request.ip || null,
      userAgent: typeof header === "string" && header.length > 0 ? header : null,
      requestId: request.id,
    };
  }

  app.route({
    method: ROUTES.listInvitations.method,
    url: toFastifyPath(ROUTES.listInvitations.path),
    handler: async (request) => {
      const who = await caller(request);
      const page = parsePageQuery(request.query, ListInvitationsFilter);
      const currentTime = getNow();

      const statusWhere =
        page.status === "PENDING"
          ? { status: "PENDING" as const, expiresAt: { gt: currentTime } }
          : page.status === "EXPIRED"
            ? {
                OR: [{ status: "EXPIRED" as const }, { status: "PENDING" as const, expiresAt: { lte: currentTime } }],
              }
            : page.status !== undefined
              ? { status: page.status }
              : {};

      const where = {
        ...statusWhere,
        ...(page.afterId ? { id: { gt: page.afterId } } : {}),
      };

      const rows = await withOrganization(db, who.organizationId, async (tx) => {
        const snapshot = await loadPermissionSnapshot(tx, who);
        assertCorePermission(snapshot, CORE_PERMISSIONS.keys["employees.manage"], {});
        return tx.invitation.findMany({
          ...(Object.keys(where).length > 0 ? { where } : {}),
          include: {
            account: { select: { employeeId: true } },
            mailOutbox: {
              select: MAIL_OUTBOX_DELIVERY_SELECT,
              orderBy: [{ createdAt: "desc" }, { id: "desc" }],
              take: 1,
            },
          },
          orderBy: { id: "asc" },
          take: page.limit + 1,
        });
      });

      const { items, nextCursor } = paginateRows(rows, page.limit);
      return sendList(
        request,
        items.map((item) => serializeInvitation(item, currentTime)),
        nextCursor,
      );
    },
  });

  registerPostRoute(
    ROUTES.createInvitation,
    async ({ request, who, tx, now }) => {
      const body = parseInput(CreateInvitation, request.body);
      const snapshot = await loadPermissionSnapshot(tx, who);
      assertCorePermission(snapshot, CORE_PERMISSIONS.keys["employees.manage"], {});
      const result = await createInvitation(tx, {
        organizationId: who.organizationId,
        email: body.email,
        firstName: body.firstName,
        lastName: body.lastName,
        employeeId: body.employeeId,
        invitedBy: who.accountId,
        actor: invitationActorFromRequest(request, who),
        now: customNow ? now : undefined,
      });
      return result.invitation;
    },
    {
      onCommit: () => {
        mailOutboxWorker?.wake();
      },
    },
  );

  registerPostRoute(
    ROUTES.resendInvitation,
    async ({ request, who, tx, now }) => {
      const params = parseInput(InvitationIdParams, request.params);
      const snapshot = await loadPermissionSnapshot(tx, who);
      assertCorePermission(snapshot, CORE_PERMISSIONS.keys["employees.manage"], {});
      const result = await resendInvitation(tx, {
        organizationId: who.organizationId,
        invitationId: params.invitationId,
        actor: invitationActorFromRequest(request, who),
        now: customNow ? now : undefined,
      });
      return result.invitation;
    },
    {
      onCommit: () => {
        mailOutboxWorker?.wake();
      },
    },
  );

  app.route({
    method: ROUTES.revokeInvitation.method,
    url: toFastifyPath(ROUTES.revokeInvitation.path),
    handler: async (request, reply) => {
      const who = await caller(request);
      const params = parseInput(InvitationIdParams, request.params);
      const explicitNow = customNow?.();

      await withOrganization(db, who.organizationId, async (tx) => {
        const snapshot = await loadPermissionSnapshot(tx, who);
        assertCorePermission(snapshot, CORE_PERMISSIONS.keys["employees.manage"], {});
        await revokeInvitation(tx, {
          organizationId: who.organizationId,
          invitationId: params.invitationId,
          actor: invitationActorFromRequest(request, who),
          now: explicitNow,
        });
      });

      return reply.status(204).send();
    },
  });

  app.route({
    method: ROUTES.listUnits.method,
    url: toFastifyPath(ROUTES.listUnits.path),
    handler: async (request) => {
      const who = await caller(request);
      const page = parsePageQuery(request.query, ListUnitsFilter);
      const where = {
        ...(page.status ? { status: page.status } : {}),
        ...(page.afterId ? { id: { gt: page.afterId } } : {}),
      };
      const rows = await withOrganization(db, who.organizationId, (tx) =>
        tx.organizationUnit.findMany({
          ...(Object.keys(where).length > 0 ? { where } : {}),
          orderBy: { id: "asc" },
          take: page.limit + 1,
        }),
      );
      const { items, nextCursor } = paginateRows(rows, page.limit);
      return sendList(request, items.map(serializeUnit), nextCursor);
    },
  });

  registerPostRoute(ROUTES.createUnit, async ({ request, who, tx }) => {
    const body = parseInput(CreateUnit, request.body);
    await lockOrganizationUnits(tx, who.organizationId);
    if (body.parentId) await assertUnitExists(tx, body.parentId, "Nie znaleziono jednostki nadrzędnej");
    const snapshot = await loadPermissionSnapshot(tx, who);
    assertCorePermission(
      snapshot,
      CORE_PERMISSIONS.keys["structure.manage"],
      body.parentId ? { unitIds: [body.parentId] } : {},
    );
    if (body.parentId) {
      const parent = await tx.organizationUnit.findUnique({
        where: { id: body.parentId },
        select: { id: true, status: true },
      });
      if (!parent) throw new ApiFailure(404, "NOT_FOUND", "Nie znaleziono jednostki nadrzędnej");
      if (parent.status === "ARCHIVED") {
        throw new ApiFailure(409, "CONFLICT", "Nie można dodać jednostki pod zarchiwizowaną jednostką");
      }
    }
    const created = await tx.organizationUnit.create({
      data: {
        id: uuidv7(),
        organizationId: who.organizationId,
        parentId: body.parentId ?? null,
        name: body.name,
        type: body.type,
      },
    });
    await writeAudit(tx, request, who, {
      action: "unit.created",
      resourceType: "unit",
      resourceId: created.id,
      metadata: {
        type: created.type,
        parentId: created.parentId,
      },
    });
    return serializeUnit(created);
  });

  app.route({
    method: ROUTES.updateUnit.method,
    url: toFastifyPath(ROUTES.updateUnit.path),
    handler: async (request) => {
      const who = await caller(request);
      const params = parseInput(UnitIdParams, request.params);
      const body = parseInput(UpdateUnit, request.body);

      try {
        const updated = await withOrganization(db, who.organizationId, async (tx) => {
          await lockOrganizationUnits(tx, who.organizationId);
          const unit = await tx.organizationUnit.findUnique({ where: { id: params.unitId } });
          if (!unit) throw new ApiFailure(404, "NOT_FOUND", "Nie znaleziono jednostki organizacyjnej");
          const snapshot = await loadPermissionSnapshot(tx, who);
          assertCorePermission(snapshot, CORE_PERMISSIONS.keys["structure.manage"], { unitIds: [params.unitId] });

          if (body.parentId !== undefined && body.parentId !== unit.parentId) {
            if (body.parentId) await assertUnitExists(tx, body.parentId, "Nie znaleziono jednostki nadrzędnej");
            assertCorePermission(
              snapshot,
              CORE_PERMISSIONS.keys["structure.manage"],
              body.parentId ? { unitIds: [body.parentId] } : {},
            );
          }

          const nextStatus = body.status ?? unit.status;
          const nextParentId = body.parentId !== undefined ? body.parentId : unit.parentId;

          if (body.parentId !== undefined && body.parentId !== null) {
            if (body.parentId === unit.id) {
              throw new ApiFailure(409, "CONFLICT", "Jednostka nie może być własnym rodzicem");
            }
            const parent = await tx.organizationUnit.findUnique({
              where: { id: body.parentId },
              select: { id: true, status: true },
            });
            if (!parent) throw new ApiFailure(404, "NOT_FOUND", "Nie znaleziono jednostki nadrzędnej");
            if (nextStatus === "ACTIVE" && parent.status === "ARCHIVED") {
              throw new ApiFailure(409, "CONFLICT", "Nie można przenieść aktywnej jednostki pod zarchiwizowaną");
            }
            if (await createsUnitCycle(tx, unit.id, body.parentId)) {
              throw new ApiFailure(409, "CONFLICT", "Przeniesienie utworzyłoby cykl w strukturze jednostek");
            }
          } else if (body.status === "ACTIVE" && unit.status !== "ACTIVE" && nextParentId) {
            const parent = await tx.organizationUnit.findUnique({
              where: { id: nextParentId },
              select: { status: true },
            });
            if (parent?.status === "ARCHIVED") {
              throw new ApiFailure(409, "CONFLICT", "Nie można przywrócić jednostki pod zarchiwizowaną jednostką");
            }
          }

          if (body.status === "ARCHIVED" && unit.status !== "ARCHIVED") {
            const activeChild = await tx.organizationUnit.findFirst({
              where: { parentId: unit.id, status: "ACTIVE" },
              select: { id: true },
            });
            if (activeChild) {
              throw new ApiFailure(
                409,
                "CONFLICT",
                "Nie można zarchiwizować jednostki, która ma aktywne jednostki podrzędne",
              );
            }
          }

          const changes: Record<string, { old: string | null; new: string | null }> = {};
          if (body.name !== undefined && body.name !== unit.name) {
            changes.name = { old: unit.name, new: body.name };
          }
          if (body.parentId !== undefined && body.parentId !== unit.parentId) {
            changes.parentId = { old: unit.parentId, new: body.parentId };
          }
          if (body.status !== undefined && body.status !== unit.status) {
            changes.status = { old: unit.status, new: body.status };
          }

          const next = await tx.organizationUnit.update({
            where: { id: unit.id },
            data: {
              ...(body.name !== undefined ? { name: body.name } : {}),
              ...(body.parentId !== undefined ? { parentId: body.parentId } : {}),
              ...(body.status !== undefined ? { status: body.status } : {}),
            },
          });

          if (Object.keys(changes).length > 0) {
            await writeAudit(tx, request, who, {
              action: "unit.updated",
              resourceType: "unit",
              resourceId: next.id,
              metadata: { changes },
            });
          }

          return next;
        });
        return send(request, serializeUnit(updated));
      } catch (error) {
        if (isCycleError(error)) {
          throw new ApiFailure(409, "CONFLICT", "Przeniesienie utworzyłoby cykl w strukturze jednostek");
        }
        throw error;
      }
    },
  });

  app.route({
    method: ROUTES.listUnitMembers.method,
    url: toFastifyPath(ROUTES.listUnitMembers.path),
    handler: async (request) => {
      const who = await caller(request);
      const params = parseInput(UnitIdParams, request.params);
      const page = parsePageQuery(request.query);
      const rows = await withOrganization(db, who.organizationId, async (tx) => {
        const unit = await tx.organizationUnit.findUnique({
          where: { id: params.unitId },
          select: { id: true },
        });
        if (!unit) throw new ApiFailure(404, "NOT_FOUND", "Nie znaleziono jednostki organizacyjnej");
        return tx.unitMembership.findMany({
          where: {
            unitId: params.unitId,
            ...(page.afterId ? { id: { gt: page.afterId } } : {}),
          },
          include: { employee: { include: { account: { select: { id: true, status: true } } } } },
          orderBy: { id: "asc" },
          take: page.limit + 1,
        });
      });
      const { items, nextCursor } = paginateRows(rows, page.limit);
      return sendList(request, items.map(serializeUnitMember), nextCursor);
    },
  });

  app.route({
    method: ROUTES.putUnitMember.method,
    url: toFastifyPath(ROUTES.putUnitMember.path),
    handler: async (request) => {
      const who = await caller(request);
      const params = parseInput(UnitMemberParams, request.params);
      const body = parseInput(PutUnitMember, request.body);
      const membership = await withOrganization(db, who.organizationId, async (tx) => {
        await lockOrganizationUnits(tx, who.organizationId);
        await assertUnitExists(tx, params.unitId, "Nie znaleziono jednostki organizacyjnej");
        const snapshot = await loadPermissionSnapshot(tx, who);
        assertCorePermission(snapshot, CORE_PERMISSIONS.keys["structure.manage"], { unitIds: [params.unitId] });
        const unit = await tx.organizationUnit.findUnique({
          where: { id: params.unitId },
          select: { id: true, status: true },
        });
        if (!unit) throw new ApiFailure(404, "NOT_FOUND", "Nie znaleziono jednostki organizacyjnej");
        if (unit.status === "ARCHIVED") {
          throw new ApiFailure(409, "CONFLICT", "Nie można zmieniać członków zarchiwizowanej jednostki");
        }
        const employee = await tx.employee.findUnique({
          where: { id: params.employeeId },
          select: { id: true },
        });
        if (!employee) throw new ApiFailure(404, "NOT_FOUND", "Nie znaleziono pracownika");
        const saved = await tx.unitMembership.upsert({
          where: { unitId_employeeId: { unitId: params.unitId, employeeId: params.employeeId } },
          create: {
            id: uuidv7(),
            organizationId: who.organizationId,
            unitId: params.unitId,
            employeeId: params.employeeId,
            role: body.role,
          },
          update: { role: body.role },
          include: { employee: { include: { account: { select: { id: true, status: true } } } } },
        });
        await writeAudit(tx, request, who, {
          action: "unit.member.set",
          resourceType: "unit_member",
          resourceId: saved.id,
          metadata: {
            unitId: params.unitId,
            employeeId: params.employeeId,
            role: saved.role,
          },
        });
        return saved;
      });
      return send(request, serializeUnitMember(membership));
    },
  });

  app.route({
    method: ROUTES.deleteUnitMember.method,
    url: toFastifyPath(ROUTES.deleteUnitMember.path),
    handler: async (request, reply) => {
      const who = await caller(request);
      const params = parseInput(UnitMemberParams, request.params);
      await withOrganization(db, who.organizationId, async (tx) => {
        await assertUnitExists(tx, params.unitId, "Nie znaleziono jednostki organizacyjnej");
        const snapshot = await loadPermissionSnapshot(tx, who);
        assertCorePermission(snapshot, CORE_PERMISSIONS.keys["structure.manage"], { unitIds: [params.unitId] });
        const unit = await tx.organizationUnit.findUnique({
          where: { id: params.unitId },
          select: { id: true },
        });
        if (!unit) throw new ApiFailure(404, "NOT_FOUND", "Nie znaleziono jednostki organizacyjnej");
        const existing = await tx.unitMembership.findUnique({
          where: { unitId_employeeId: { unitId: params.unitId, employeeId: params.employeeId } },
          select: { id: true, role: true },
        });
        if (!existing) {
          throw new ApiFailure(404, "NOT_FOUND", "Nie znaleziono przypisania pracownika do jednostki");
        }
        await tx.unitMembership.delete({ where: { id: existing.id } });
        await writeAudit(tx, request, who, {
          action: "unit.member.removed",
          resourceType: "unit_member",
          resourceId: existing.id,
          metadata: {
            unitId: params.unitId,
            employeeId: params.employeeId,
            role: existing.role,
          },
        });
      });
      return reply.status(204).send();
    },
  });

  app.route({
    method: ROUTES.listPermissions.method,
    url: toFastifyPath(ROUTES.listPermissions.path),
    handler: async (request) => {
      await caller(request);
      const page = parsePageQuery(request.query, ListPermissionsFilter);
      const where = {
        ...(page.product === "core"
          ? { productId: null }
          : page.product !== undefined
            ? { product: { is: { key: page.product } } }
            : {}),
        ...(page.includeDeprecated ? {} : { deprecatedAt: null }),
        ...(page.afterId ? { id: { gt: page.afterId } } : {}),
      };
      const rows = await db.permission.findMany({
        ...(Object.keys(where).length > 0 ? { where } : {}),
        include: { product: { select: { key: true } } },
        orderBy: { id: "asc" },
        take: page.limit + 1,
      });
      const { items, nextCursor } = paginateRows(rows, page.limit);
      return sendList(request, items.map(serializePermission), nextCursor);
    },
  });

  app.route({
    method: ROUTES.registerProductPermissions.method,
    url: toFastifyPath(ROUTES.registerProductPermissions.path),
    handler: async (request) => {
      const machine = await machineCaller(request, PERMISSIONS_REGISTER_SCOPE);
      const params = parseInput(ProductKeyParams, request.params);
      const product = await db.product.findUnique({
        where: { key: params.productKey },
        select: { id: true, key: true, registrationClientId: true },
      });
      if (!product) {
        throw new ApiFailure(404, "NOT_FOUND", "Nie znaleziono produktu");
      }
      if (!product.registrationClientId || product.registrationClientId !== machine.clientId) {
        throw new ApiFailure(403, "PERMISSION_DENIED", "Ten klient nie może rejestrować uprawnień wskazanego produktu");
      }
      const userAgent = request.headers["user-agent"];
      try {
        const summary = await registerPermissions({
          db,
          product: { id: product.id, key: product.key },
          manifest: request.body,
          actor: {
            type: "PRODUCT",
            requestId: request.id,
            ipAddress: request.ip || null,
            userAgent: typeof userAgent === "string" && userAgent.length > 0 ? userAgent : null,
          },
        });
        return send(request, summary);
      } catch (error) {
        if (error instanceof ManifestValidationError) {
          throw new ApiFailure(422, "VALIDATION_FAILED", error.message, error.details);
        }
        throw error;
      }
    },
  });

  app.route({
    method: ROUTES.registerProductRoleTemplates.method,
    url: toFastifyPath(ROUTES.registerProductRoleTemplates.path),
    handler: async (request) => {
      const machine = await machineCaller(request, PERMISSIONS_REGISTER_SCOPE);
      const params = parseInput(ProductKeyParams, request.params);
      const product = await db.product.findUnique({
        where: { key: params.productKey },
        select: { id: true, key: true, registrationClientId: true },
      });
      if (!product) {
        throw new ApiFailure(404, "NOT_FOUND", "Nie znaleziono produktu");
      }
      if (!product.registrationClientId || product.registrationClientId !== machine.clientId) {
        throw new ApiFailure(
          403,
          "PERMISSION_DENIED",
          "Ten klient nie może rejestrować szablonów ról wskazanego produktu",
        );
      }
      const userAgent = request.headers["user-agent"];
      try {
        const summary = await registerRoleTemplates({
          db,
          product: { id: product.id, key: product.key },
          manifest: request.body,
          actor: {
            type: "PRODUCT",
            requestId: request.id,
            ipAddress: request.ip || null,
            userAgent: typeof userAgent === "string" && userAgent.length > 0 ? userAgent : null,
          },
        });
        return send(request, summary);
      } catch (error) {
        if (error instanceof ManifestValidationError) {
          throw new ApiFailure(422, "VALIDATION_FAILED", error.message, error.details);
        }
        throw error;
      }
    },
  });

  app.route({
    method: ROUTES.listRoles.method,
    url: toFastifyPath(ROUTES.listRoles.path),
    handler: async (request) => {
      const who = await caller(request);
      const page = parsePageQuery(request.query, ListRolesFilter);
      const where = {
        ...(page.product === "core"
          ? { productId: null }
          : page.product !== undefined
            ? { product: { is: { key: page.product } } }
            : {}),
        ...(page.includeTemplates ? {} : { organizationId: who.organizationId }),
        ...(page.includeArchived ? {} : { archivedAt: null }),
        ...(page.afterId ? { id: { gt: page.afterId } } : {}),
      };
      const rows = await withOrganization(db, who.organizationId, (tx) =>
        tx.role.findMany({
          ...(Object.keys(where).length > 0 ? { where } : {}),
          include: {
            product: { select: { key: true } },
            permissions: { select: { permission: { select: { key: true } } } },
          },
          orderBy: { id: "asc" },
          take: page.limit + 1,
        }),
      );
      const { items, nextCursor } = paginateRows(rows, page.limit);
      return sendList(request, items.map(serializeRole), nextCursor);
    },
  });

  app.route({
    method: ROUTES.getRole.method,
    url: toFastifyPath(ROUTES.getRole.path),
    handler: async (request) => {
      const who = await caller(request);
      const params = parseInput(RoleIdParams, request.params);
      const role = await withOrganization(db, who.organizationId, (tx) =>
        tx.role.findUnique({
          where: { id: params.roleId },
          include: {
            product: { select: { key: true } },
            permissions: { select: { permission: { select: { key: true } } } },
          },
        }),
      );
      if (!role) {
        throw new ApiFailure(404, "NOT_FOUND", "Nie znaleziono roli");
      }
      return send(request, serializeRole(role));
    },
  });

  registerPostRoute(ROUTES.createRole, async ({ request, who, tx }) => {
    const body = parseInput(CreateRole, request.body);

    try {
      const snapshot = await loadPermissionSnapshot(tx, who);
      assertCorePermission(snapshot, CORE_PERMISSIONS.keys["roles.manage"], {});

      if ("copyFromRoleId" in body) {
        const source = await tx.role.findUnique({
          where: { id: body.copyFromRoleId },
          include: {
            product: { select: { key: true } },
            permissions: {
              select: { permission: { select: { id: true, key: true, deprecatedAt: true } } },
            },
          },
        });
        if (!source) {
          throw new ApiFailure(404, "NOT_FOUND", "Nie znaleziono kopiowanej roli");
        }
        if (source.archivedAt !== null) {
          throw new ApiFailure(409, "CONFLICT", "Nie można skopiować zarchiwizowanej roli");
        }
        const activePermissions = source.permissions
          .filter((rp) => rp.permission.deprecatedAt === null)
          .map((rp) => ({ id: rp.permission.id, key: rp.permission.key }));

        const roleId = uuidv7();
        const role = await tx.role.create({
          data: {
            id: roleId,
            organizationId: who.organizationId,
            productId: source.productId,
            key: null,
            name: body.name ?? source.name,
            description: body.description !== undefined ? body.description : source.description,
            copiedFromRoleId: source.id,
          },
        });
        if (activePermissions.length > 0) {
          await tx.rolePermission.createMany({
            data: activePermissions.map((perm) => ({ roleId, permissionId: perm.id })),
          });
        }
        await writeAudit(tx, request, who, {
          action: "role.created",
          resourceType: "role",
          resourceId: role.id,
          metadata: {
            copiedFromRoleId: source.id,
            product: source.product?.key ?? null,
            permissions: activePermissions.map((perm) => perm.key).sort(),
          },
        });
        return serializeRole({
          ...role,
          product: source.product,
          permissions: activePermissions.map((perm) => ({ permission: { key: perm.key } })),
        });
      }

      if (body.product === "core") {
        throw new ApiFailure(422, "VALIDATION_FAILED", "Błędne dane wejściowe", [
          { field: "product", message: 'Dla roli platformowej podaj wartość null zamiast "core"' },
        ]);
      }

      let product: { id: string; key: string } | null = null;
      if (body.product !== null) {
        product = await tx.product.findUnique({
          where: { key: body.product },
          select: { id: true, key: true },
        });
        if (!product) {
          throw new ApiFailure(404, "NOT_FOUND", "Nie znaleziono produktu");
        }
      }

      const resolvedPermissions = await resolveActiveRolePermissions(
        tx,
        product?.id ?? null,
        product?.key ?? "core",
        body.permissions,
      );

      const roleId = uuidv7();
      const role = await tx.role.create({
        data: {
          id: roleId,
          organizationId: who.organizationId,
          productId: product?.id ?? null,
          key: null,
          name: body.name,
          description: body.description ?? null,
          copiedFromRoleId: null,
        },
      });
      await tx.rolePermission.createMany({
        data: resolvedPermissions.map((perm) => ({ roleId, permissionId: perm.id })),
      });
      await writeAudit(tx, request, who, {
        action: "role.created",
        resourceType: "role",
        resourceId: role.id,
        metadata: {
          product: product?.key ?? null,
          permissions: resolvedPermissions.map((perm) => perm.key).sort(),
        },
      });
      return serializeRole({
        ...role,
        product: product ? { key: product.key } : null,
        permissions: resolvedPermissions.map((perm) => ({ permission: { key: perm.key } })),
      });
    } catch (error) {
      if (isUniqueViolation(error)) {
        throw new ApiFailure(409, "CONFLICT", "Aktywna rola o takiej nazwie już istnieje w firmie");
      }
      throw error;
    }
  });

  app.route({
    method: ROUTES.updateRole.method,
    url: toFastifyPath(ROUTES.updateRole.path),
    handler: async (request) => {
      const who = await caller(request);
      const params = parseInput(RoleIdParams, request.params);
      const body = parseInput(UpdateRole, request.body);

      try {
        const updated = await withOrganization(db, who.organizationId, async (tx) => {
          await lockRole(tx, params.roleId);
          const snapshot = await loadPermissionSnapshot(tx, who);
          assertCorePermission(snapshot, CORE_PERMISSIONS.keys["roles.manage"], {});

          const role = await tx.role.findUnique({
            where: { id: params.roleId },
            include: {
              product: { select: { key: true } },
              permissions: { select: { permissionId: true, permission: { select: { key: true } } } },
            },
          });
          if (!role) {
            throw new ApiFailure(404, "NOT_FOUND", "Nie znaleziono roli");
          }
          if (role.organizationId === null) {
            throw new ApiFailure(403, "PERMISSION_DENIED", "Nie można modyfikować gotowej roli (szablonu)");
          }
          if (role.archivedAt !== null) {
            throw new ApiFailure(409, "CONFLICT", "Nie można modyfikować zarchiwizowanej roli");
          }

          let resolvedPermissions: { id: string; key: string }[] | null = null;
          if (body.permissions !== undefined) {
            resolvedPermissions = await resolveActiveRolePermissions(
              tx,
              role.productId,
              role.product?.key ?? "core",
              body.permissions,
            );
          }

          const changes: Record<string, { old: string | string[] | null; new: string | string[] | null }> = {};
          if (body.name !== undefined && body.name !== role.name) {
            changes.name = { old: role.name, new: body.name };
          }
          if (body.description !== undefined && body.description !== role.description) {
            changes.description = { old: role.description, new: body.description };
          }

          let nextPermissions = role.permissions.map((rp) => ({ permission: { key: rp.permission.key } }));
          if (resolvedPermissions !== null) {
            const currentIds = new Set(role.permissions.map((rp) => rp.permissionId));
            const desiredIds = new Set(resolvedPermissions.map((perm) => perm.id));
            const toDelete = [...currentIds].filter((id) => !desiredIds.has(id));
            const toAdd = [...desiredIds].filter((id) => !currentIds.has(id));

            if (toDelete.length > 0 || toAdd.length > 0) {
              if (toDelete.length > 0) {
                await tx.rolePermission.deleteMany({
                  where: { roleId: role.id, permissionId: { in: toDelete } },
                });
              }
              if (toAdd.length > 0) {
                await tx.rolePermission.createMany({
                  data: toAdd.map((permissionId) => ({ roleId: role.id, permissionId })),
                });
              }
              await bumpAuthzRevisions(tx, who.organizationId, { roleAssignments: { some: { roleId: role.id } } });
              changes.permissions = {
                old: role.permissions.map((rp) => rp.permission.key).sort(),
                new: resolvedPermissions.map((perm) => perm.key).sort(),
              };
            }
            nextPermissions = resolvedPermissions.map((perm) => ({ permission: { key: perm.key } }));
          }

          const nextRole =
            body.name !== undefined || body.description !== undefined || Object.keys(changes).length > 0
              ? await tx.role.update({
                  where: { id: role.id },
                  data: {
                    ...(body.name !== undefined ? { name: body.name } : {}),
                    ...(body.description !== undefined ? { description: body.description } : {}),
                    ...(body.name === undefined && body.description === undefined ? { updatedAt: new Date() } : {}),
                  },
                })
              : role;

          if (Object.keys(changes).length > 0) {
            await writeAudit(tx, request, who, {
              action: "role.updated",
              resourceType: "role",
              resourceId: role.id,
              metadata: { changes },
            });
          }

          return {
            ...nextRole,
            product: role.product,
            permissions: nextPermissions,
          };
        });
        return send(request, serializeRole(updated));
      } catch (error) {
        if (isUniqueViolation(error)) {
          throw new ApiFailure(409, "CONFLICT", "Aktywna rola o takiej nazwie już istnieje w firmie");
        }
        throw error;
      }
    },
  });

  app.route({
    method: ROUTES.archiveRole.method,
    url: toFastifyPath(ROUTES.archiveRole.path),
    handler: async (request, reply) => {
      const who = await caller(request);
      const params = parseInput(RoleIdParams, request.params);

      await withOrganization(db, who.organizationId, async (tx) => {
        await lockRole(tx, params.roleId);
        const snapshot = await loadPermissionSnapshot(tx, who);
        assertCorePermission(snapshot, CORE_PERMISSIONS.keys["roles.manage"], {});

        const role = await tx.role.findUnique({
          where: { id: params.roleId },
          select: { id: true, organizationId: true, archivedAt: true },
        });
        if (!role) {
          throw new ApiFailure(404, "NOT_FOUND", "Nie znaleziono roli");
        }
        if (role.organizationId === null) {
          throw new ApiFailure(403, "PERMISSION_DENIED", "Nie można archiwizować gotowej roli (szablonu)");
        }
        if (role.archivedAt !== null) {
          throw new ApiFailure(409, "CONFLICT", "Rola jest już zarchiwizowana");
        }

        const assignmentCount = await tx.roleAssignment.count({ where: { roleId: role.id } });
        if (assignmentCount > 0) {
          throw new ApiFailure(409, "CONFLICT", "Nie można zarchiwizować roli, która ma aktywne przypisania");
        }

        await tx.role.update({
          where: { id: role.id },
          data: { archivedAt: new Date() },
        });
        await bumpAuthzRevisions(tx, who.organizationId, { roleAssignments: { some: { roleId: role.id } } });
        await writeAudit(tx, request, who, {
          action: "role.archived",
          resourceType: "role",
          resourceId: role.id,
          metadata: {},
        });
      });

      return reply.status(204).send();
    },
  });

  app.route({
    method: ROUTES.listRoleAssignments.method,
    url: toFastifyPath(ROUTES.listRoleAssignments.path),
    handler: async (request) => {
      const who = await caller(request);
      const page = parsePageQuery(request.query, ListRoleAssignmentsFilter);
      const rows = await withOrganization(db, who.organizationId, async (tx) => {
        const snapshot = await loadPermissionSnapshot(tx, who);
        const canViewAll = canViewAllRoleAssignments(snapshot);
        if (!canViewAll && page.accountId && page.accountId !== who.accountId) {
          return [];
        }
        const effectiveAccountId = canViewAll ? page.accountId : who.accountId;
        const where = {
          ...(effectiveAccountId ? { accountId: effectiveAccountId } : {}),
          ...(page.roleId ? { roleId: page.roleId } : {}),
          ...(page.afterId ? { id: { gt: page.afterId } } : {}),
        };
        return tx.roleAssignment.findMany({
          ...(Object.keys(where).length > 0 ? { where } : {}),
          orderBy: { id: "asc" },
          take: page.limit + 1,
        });
      });
      const { items, nextCursor } = paginateRows(rows, page.limit);
      return sendList(request, items.map(serializeRoleAssignment), nextCursor);
    },
  });

  registerPostRoute(ROUTES.createRoleAssignment, async ({ request, who, tx }) => {
    const body = parseInput(CreateRoleAssignment, request.body);
    const scopeId = body.scopeType === "ORGANIZATION" ? null : (body.scopeId ?? null);
    const grantScope = toGrantScope(body.scopeType, scopeId);

    try {
      await lockRole(tx, body.roleId);
      const snapshot = await loadPermissionSnapshot(tx, who);
      assertCanAssignInScope(snapshot, grantScope);

      const account = await tx.account.findUnique({
        where: { id: body.accountId },
        select: { id: true, status: true },
      });
      if (!account) {
        throw new ApiFailure(404, "NOT_FOUND", "Nie znaleziono konta");
      }
      if (account.status === "DEACTIVATED") {
        throw new ApiFailure(409, "CONFLICT", "Nie można nadać roli wyłączonemu kontu");
      }

      const role = await tx.role.findUnique({
        where: { id: body.roleId },
        include: {
          permissions: { select: { permission: { select: { key: true, deprecatedAt: true } } } },
        },
      });
      if (!role) {
        throw new ApiFailure(404, "NOT_FOUND", "Nie znaleziono roli");
      }
      if (role.archivedAt !== null) {
        throw new ApiFailure(409, "CONFLICT", "Nie można przypisać zarchiwizowanej roli");
      }

      if (body.scopeType === "UNIT" && scopeId) {
        const unit = await tx.organizationUnit.findUnique({
          where: { id: scopeId },
          select: { id: true, status: true },
        });
        if (!unit) {
          throw new ApiFailure(404, "NOT_FOUND", "Nie znaleziono jednostki organizacyjnej");
        }
        if (unit.status === "ARCHIVED") {
          throw new ApiFailure(409, "CONFLICT", "Nie można przypisać roli do zarchiwizowanej jednostki");
        }
      }

      const activePermissionKeys = role.permissions
        .filter((rp) => rp.permission.deprecatedAt === null)
        .map((rp) => rp.permission.key);
      assertCanDelegateRole(snapshot, activePermissionKeys, grantScope);

      const assignment = await tx.roleAssignment.create({
        data: {
          id: uuidv7(),
          organizationId: who.organizationId,
          accountId: body.accountId,
          roleId: body.roleId,
          scopeType: body.scopeType,
          scopeId,
          validFrom: body.validFrom ? new Date(body.validFrom) : null,
          validUntil: body.validUntil ? new Date(body.validUntil) : null,
          grantedByAccountId: who.accountId,
        },
      });

      await bumpAuthzRevisions(tx, who.organizationId, { id: body.accountId });

      await writeAudit(tx, request, who, {
        action: "role.assigned",
        resourceType: "role_assignment",
        resourceId: assignment.id,
        metadata: {
          accountId: assignment.accountId,
          roleId: assignment.roleId,
          scopeType: assignment.scopeType,
          scopeId: assignment.scopeId,
          validFrom: assignment.validFrom ? assignment.validFrom.toISOString() : null,
          validUntil: assignment.validUntil ? assignment.validUntil.toISOString() : null,
        },
      });

      return serializeRoleAssignment(assignment);
    } catch (error) {
      if (isUniqueViolation(error)) {
        throw new ApiFailure(409, "CONFLICT", "To konto ma już przypisaną tę rolę w tym zakresie");
      }
      throw error;
    }
  });

  app.route({
    method: ROUTES.deleteRoleAssignment.method,
    url: toFastifyPath(ROUTES.deleteRoleAssignment.path),
    handler: async (request, reply) => {
      const who = await caller(request);
      const params = parseInput(AssignmentIdParams, request.params);

      await withOrganization(db, who.organizationId, async (tx) => {
        const snapshot = await loadPermissionSnapshot(tx, who);
        if (!hasAnyRoleAssignPermission(snapshot)) {
          throw new PermissionError(CORE_PERMISSIONS.keys["roles.assign"]);
        }

        const assignment = await tx.roleAssignment.findUnique({
          where: { id: params.assignmentId },
          include: {
            role: {
              select: {
                permissions: { select: { permission: { select: { key: true, deprecatedAt: true } } } },
              },
            },
          },
        });
        if (!assignment) {
          throw new ApiFailure(404, "NOT_FOUND", "Nie znaleziono przypisania roli");
        }

        const grantScope = toGrantScope(assignment.scopeType, assignment.scopeId);
        assertCanAssignInScope(snapshot, grantScope);
        const activePermissionKeys = assignment.role.permissions
          .filter((rp) => rp.permission.deprecatedAt === null)
          .map((rp) => rp.permission.key);
        assertCanDelegateRole(snapshot, activePermissionKeys, grantScope);

        await tx.roleAssignment.delete({ where: { id: assignment.id } });
        await bumpAuthzRevisions(tx, who.organizationId, { id: assignment.accountId });
        await writeAudit(tx, request, who, {
          action: "role.revoked",
          resourceType: "role_assignment",
          resourceId: assignment.id,
          metadata: {
            accountId: assignment.accountId,
            roleId: assignment.roleId,
            scopeType: assignment.scopeType,
            scopeId: assignment.scopeId,
          },
        });
      });

      return reply.status(204).send();
    },
  });

  app.route({
    method: ROUTES.getProductPermissionSnapshot.method,
    url: toFastifyPath(ROUTES.getProductPermissionSnapshot.path),
    handler: async (request) => {
      const machine = await machineCaller(request, PERMISSIONS_READ_SCOPE);
      const params = parseInput(ProductKeyParams, request.params);
      const query = parseInput(PermissionSnapshotQuery, request.query);

      const product = await db.product.findUnique({
        where: { key: params.productKey },
        select: { id: true, key: true, registrationClientId: true },
      });
      if (!product) {
        throw new ApiFailure(404, "NOT_FOUND", "Nie znaleziono produktu");
      }
      if (!product.registrationClientId || product.registrationClientId !== machine.clientId) {
        throw new ApiFailure(
          403,
          "PERMISSION_DENIED",
          "Ten klient nie może odczytywać migawki uprawnień wskazanego produktu",
        );
      }

      const snapshot = await withOrganization(db, query.organizationId, async (tx) => {
        const account = await tx.account.findUnique({
          where: { id: query.accountId },
          select: {
            id: true,
            organizationId: true,
            status: true,
            authzRevision: true,
            organization: { select: { ownerAccountId: true } },
          },
        });
        if (!account) {
          throw new ApiFailure(404, "NOT_FOUND", "Nie znaleziono konta w firmie");
        }
        return loadPermissionSnapshot(tx, {
          accountId: account.id,
          organizationId: account.organizationId,
          authzRevision: account.authzRevision,
          isOwner: account.organization.ownerAccountId === account.id,
          accountStatus: account.status,
          product: { id: product.id, key: product.key },
        });
      });

      return send(request, snapshot);
    },
  });

  async function requireProductForMachine(productKey: string, clientId: string, deniedMessage: string) {
    const product = await db.product.findUnique({
      where: { key: productKey },
      select: { id: true, key: true, registrationClientId: true },
    });
    if (!product) {
      throw new ApiFailure(404, "NOT_FOUND", "Nie znaleziono produktu");
    }
    if (!product.registrationClientId || product.registrationClientId !== clientId) {
      throw new ApiFailure(403, "PERMISSION_DENIED", deniedMessage);
    }
    return product;
  }

  async function assertOrganizationHasActiveEntitlement(tx: Tx, organizationId: string, productId: string) {
    const org = await tx.organization.findUnique({
      where: { id: organizationId },
      select: { id: true },
    });
    if (!org) {
      throw new ApiFailure(404, "NOT_FOUND", "Nie znaleziono firmy");
    }
    const now = new Date();
    const entitlement = await tx.entitlement.findFirst({
      where: {
        productId,
        status: "ACTIVE",
        startsAt: { lte: now },
        OR: [{ endsAt: null }, { endsAt: { gt: now } }],
      },
      select: { id: true },
    });
    if (!entitlement) {
      throw new ApiFailure(403, "PERMISSION_DENIED", "Firma nie ma aktywnego dostępu do tego produktu");
    }
  }

  app.route({
    method: ROUTES.listProductDirectoryUnitMembers.method,
    url: toFastifyPath(ROUTES.listProductDirectoryUnitMembers.path),
    handler: async (request) => {
      const machine = await machineCaller(request, DIRECTORY_READ_SCOPE);
      const params = parseInput(ProductKeyParams, request.params);
      const page = parsePageQuery(request.query, DirectoryUnitMembersFilter);
      const product = await requireProductForMachine(
        params.productKey,
        machine.clientId,
        "Ten klient nie może odczytywać katalogu wskazanego produktu",
      );

      const unitIds = page.unitId ? [...new Set(page.unitId)] : undefined;
      const rows = await withOrganization(db, page.organizationId, async (tx) => {
        await assertOrganizationHasActiveEntitlement(tx, page.organizationId, product.id);
        return tx.unitMembership.findMany({
          where: {
            ...(unitIds ? { unitId: { in: unitIds } } : {}),
            ...(page.afterId ? { id: { gt: page.afterId } } : {}),
          },
          select: {
            id: true,
            unitId: true,
            employeeId: true,
            role: true,
            employee: { select: { account: { select: { id: true } } } },
          },
          orderBy: { id: "asc" },
          take: page.limit + 1,
        });
      });

      const { items, nextCursor } = paginateRows(rows, page.limit);
      return sendList(
        request,
        items.map((row): DirectoryUnitMember => ({
          unitId: row.unitId,
          employeeId: row.employeeId,
          accountId: row.employee.account?.id ?? null,
          role: row.role,
        })),
        nextCursor,
      );
    },
  });

  app.route({
    method: ROUTES.listProductEvents.method,
    url: toFastifyPath(ROUTES.listProductEvents.path),
    handler: async (request) => {
      const machine = await machineCaller(request, EVENTS_READ_SCOPE);
      const params = parseInput(ProductKeyParams, request.params);
      const query = parseInput(ProductEventsQuery, request.query ?? {});
      const product = await requireProductForMachine(
        params.productKey,
        machine.clientId,
        "Ten klient nie może odczytywać zdarzeń wskazanego produktu",
      );
      // Funkcja bazy (SECURITY DEFINER) zwraca tylko zdarzenia firm z aktywnym dostępem do tego produktu
      const items = await readProductEventFeed(db, product.id, BigInt(query.cursor ?? "0"), query.limit);
      const last = items.at(-1);
      return sendList(request, items, items.length === query.limit && last ? last.sequence : null);
    },
  });

  app.route({
    method: ROUTES.listProductDirectoryEmployees.method,
    url: toFastifyPath(ROUTES.listProductDirectoryEmployees.path),
    handler: async (request) => {
      const machine = await machineCaller(request, DIRECTORY_READ_SCOPE);
      const params = parseInput(ProductKeyParams, request.params);
      const page = parsePageQuery(request.query, DirectoryEmployeesFilter);
      const product = await requireProductForMachine(
        params.productKey,
        machine.clientId,
        "Ten klient nie może odczytywać katalogu wskazanego produktu",
      );

      const employeeIds = page.employeeId ? [...new Set(page.employeeId)] : undefined;
      const rows = await withOrganization(db, page.organizationId, async (tx) => {
        await assertOrganizationHasActiveEntitlement(tx, page.organizationId, product.id);
        return tx.employee.findMany({
          where: {
            ...(employeeIds ? { id: { in: employeeIds } } : {}),
            ...(page.afterId ? { id: { gt: page.afterId } } : {}),
          },
          select: {
            id: true,
            firstName: true,
            lastName: true,
            status: true,
            account: { select: { id: true } },
          },
          orderBy: { id: "asc" },
          take: page.limit + 1,
        });
      });

      const { items, nextCursor } = paginateRows(rows, page.limit);
      return sendList(
        request,
        items.map((row): DirectoryEmployee => ({
          id: row.id,
          accountId: row.account?.id ?? null,
          firstName: row.firstName,
          lastName: row.lastName,
          status: row.status,
        })),
        nextCursor,
      );
    },
  });

  app.route({
    method: ROUTES.listEntitlements.method,
    url: toFastifyPath(ROUTES.listEntitlements.path),
    handler: async (request) => {
      const who = await caller(request);
      const page = parsePageQuery(request.query, ListEntitlementsFilter);
      const where = {
        ...(page.status ? { status: page.status } : {}),
        ...(page.afterId ? { id: { gt: page.afterId } } : {}),
      };
      const rows = await withOrganization(db, who.organizationId, (tx) =>
        tx.entitlement.findMany({
          ...(Object.keys(where).length > 0 ? { where } : {}),
          include: { product: { select: { key: true } } },
          orderBy: { id: "asc" },
          take: page.limit + 1,
        }),
      );
      const now = new Date();
      const { items, nextCursor } = paginateRows(rows, page.limit);
      return sendList(
        request,
        items.map((item) => serializeEntitlement(item, now)),
        nextCursor,
      );
    },
  });

  app.route({
    method: ROUTES.listAppAccess.method,
    url: toFastifyPath(ROUTES.listAppAccess.path),
    handler: async (request) => {
      const who = await caller(request);
      const page = parsePageQuery(request.query, ListAppAccessFilter);
      const rows = await withOrganization(db, who.organizationId, async (tx) => {
        const snapshot = await loadPermissionSnapshot(tx, who);
        const canViewAll = canViewAllAppAccess(snapshot);
        if (!canViewAll && page.accountId && page.accountId !== who.accountId) {
          return [];
        }
        const effectiveAccountId = canViewAll ? page.accountId : who.accountId;
        const where = {
          ...(effectiveAccountId ? { accountId: effectiveAccountId } : {}),
          ...(page.product !== undefined ? { product: { is: { key: page.product } } } : {}),
          ...(page.includeRevoked ? {} : { status: "ACTIVE" as const }),
          ...(page.afterId ? { id: { gt: page.afterId } } : {}),
        };
        return tx.appAccess.findMany({
          ...(Object.keys(where).length > 0 ? { where } : {}),
          include: { product: { select: { key: true } } },
          orderBy: { id: "asc" },
          take: page.limit + 1,
        });
      });
      const { items, nextCursor } = paginateRows(rows, page.limit);
      return sendList(request, items.map(serializeAppAccess), nextCursor);
    },
  });

  registerPostRoute(ROUTES.grantAppAccess, async ({ request, who, tx, now }) => {
    const body = parseInput(CreateAppAccess, request.body);

    try {
      const snapshot = await loadPermissionSnapshot(tx, who);
      if (!hasAnyAppAccessManagePermission(snapshot)) {
        throw new PermissionError(CORE_PERMISSIONS.keys["app_access.manage"]);
      }

      const account = await tx.account.findUnique({
        where: { id: body.accountId },
        select: {
          id: true,
          status: true,
          employee: {
            select: { unitMemberships: { select: { unitId: true } } },
          },
        },
      });
      if (!account) {
        throw new ApiFailure(404, "NOT_FOUND", "Nie znaleziono konta");
      }

      const unitIds = account.employee.unitMemberships.map((m) => m.unitId);
      assertCanManageAppAccessForUnits(snapshot, unitIds);

      const product = await tx.product.findUnique({
        where: { key: body.product },
        select: { id: true, key: true },
      });
      if (!product) {
        throw new ApiFailure(404, "NOT_FOUND", "Nie znaleziono produktu");
      }

      if (account.status !== "ACTIVE") {
        throw new ApiFailure(409, "CONFLICT", "Dostęp do aplikacji można włączyć wyłącznie aktywnemu kontu");
      }

      const entitlement = await tx.entitlement.findFirst({
        where: {
          productId: product.id,
          status: "ACTIVE",
          startsAt: { lte: now },
          OR: [{ endsAt: null }, { endsAt: { gt: now } }],
        },
        select: { id: true },
      });
      if (!entitlement) {
        throw new ApiFailure(409, "CONFLICT", "Firma nie ma aktywnego dostępu do tego produktu");
      }

      const existing = await tx.appAccess.findFirst({
        where: { accountId: account.id, productId: product.id, status: "ACTIVE" },
        select: { id: true },
      });
      if (existing) {
        throw new ApiFailure(409, "CONFLICT", "To konto ma już włączony dostęp do tego produktu");
      }

      const access = await tx.appAccess.create({
        data: {
          id: uuidv7(),
          organizationId: who.organizationId,
          accountId: account.id,
          productId: product.id,
          status: "ACTIVE",
          grantedByAccountId: who.accountId,
          revokedAt: null,
        },
        include: { product: { select: { key: true } } },
      });

      await bumpAuthzRevisions(tx, who.organizationId, { id: account.id });

      await writeAudit(tx, request, who, {
        action: "app_access.granted",
        resourceType: "app_access",
        resourceId: access.id,
        metadata: {
          accountId: access.accountId,
          product: product.key,
        },
      });

      return serializeAppAccess(access);
    } catch (error) {
      if (isUniqueViolation(error)) {
        throw new ApiFailure(409, "CONFLICT", "To konto ma już włączony dostęp do tego produktu");
      }
      throw error;
    }
  });

  app.route({
    method: ROUTES.revokeAppAccess.method,
    url: toFastifyPath(ROUTES.revokeAppAccess.path),
    handler: async (request, reply) => {
      const who = await caller(request);
      const params = parseInput(AppAccessIdParams, request.params);

      await withOrganization(db, who.organizationId, async (tx) => {
        const snapshot = await loadPermissionSnapshot(tx, who);
        if (!hasAnyAppAccessManagePermission(snapshot)) {
          throw new PermissionError(CORE_PERMISSIONS.keys["app_access.manage"]);
        }

        const access = await tx.appAccess.findUnique({
          where: { id: params.appAccessId },
          select: {
            id: true,
            accountId: true,
            status: true,
            product: { select: { key: true } },
            account: {
              select: {
                employee: {
                  select: { unitMemberships: { select: { unitId: true } } },
                },
              },
            },
          },
        });
        if (!access) {
          throw new ApiFailure(404, "NOT_FOUND", "Nie znaleziono dostępu do aplikacji");
        }

        const unitIds = access.account.employee.unitMemberships.map((m) => m.unitId);
        assertCanManageAppAccessForUnits(snapshot, unitIds);

        if (access.status === "REVOKED") {
          throw new ApiFailure(409, "CONFLICT", "Dostęp do aplikacji został już wyłączony");
        }

        await tx.appAccess.update({
          where: { id: access.id },
          data: { status: "REVOKED", revokedAt: new Date() },
        });

        await bumpAuthzRevisions(tx, who.organizationId, { id: access.accountId });

        await writeAudit(tx, request, who, {
          action: "app_access.revoked",
          resourceType: "app_access",
          resourceId: access.id,
          metadata: {
            accountId: access.accountId,
            product: access.product.key,
          },
        });
      });

      return reply.status(204).send();
    },
  });

  app.route({
    method: ROUTES.listAuditLog.method,
    url: toFastifyPath(ROUTES.listAuditLog.path),
    handler: async (request) => {
      const who = await caller(request);
      const query = parseInput(ListAuditLogQuery, request.query ?? {});
      let cursor: AuditLogCursor | undefined;
      if (query.cursor !== undefined) {
        try {
          cursor = decodeAuditCursor(query.cursor);
        } catch (error) {
          if (error instanceof AuditCursorError) {
            throw new ApiFailure(422, "VALIDATION_FAILED", "Błędne dane wejściowe", [
              { field: "cursor", message: error.message },
            ]);
          }
          throw error;
        }
      }

      const currentTime = getNow();
      const { items, nextCursor } = await withOrganization(db, who.organizationId, async (tx) => {
        const snapshot = await loadPermissionSnapshot(tx, who);
        assertCorePermission(snapshot, CORE_PERMISSIONS.keys["audit.read"], {});
        return listAuditLogEntries(tx, {
          organizationId: who.organizationId,
          query,
          ...(cursor ? { cursor } : {}),
          now: currentTime,
        });
      });

      return sendList(request, items, nextCursor);
    },
  });

  app.route({
    method: ROUTES.sendNotification.method,
    url: toFastifyPath(ROUTES.sendNotification.path),
    config: { idempotent: true },
    handler: async (request, reply) => {
      const machine = await machineCaller(request, NOTIFICATIONS_SEND_SCOPE);
      const idempotencyKey = parseIdempotencyKeyHeader(extractIdempotencyKeyHeader(request));
      const params = parseInput(OrganizationIdParams, request.params);

      const product = await db.product.findUnique({
        where: { registrationClientId: machine.clientId },
        select: { id: true, key: true, name: true },
      });
      if (!product) {
        throw new ApiFailure(403, "PERMISSION_DENIED", "Ten klient nie jest przypisany do żadnego produktu");
      }

      const runSend = async (tx: Tx, now: Date) => {
        const body = parseInput(CreateNotification, request.body);
        const categoryDef = getNotificationCategory(body.category);
        if (!categoryDef) {
          throw new ApiFailure(422, "VALIDATION_FAILED", "Nieznana kategoria powiadomień", [
            { field: "category", message: "Nieznana kategoria powiadomień" },
          ]);
        }
        if (categoryDef.channel !== "notifications" || categoryDef.product !== product.key) {
          throw new ApiFailure(403, "PERMISSION_DENIED", "Ten produkt nie może wysyłać powiadomień w tej kategorii");
        }

        const normalizedActionUrl = body.actionUrl ?? null;
        if (normalizedActionUrl !== null) {
          const oauthClient = await tx.authOAuthClient.findUnique({
            where: { clientId: machine.clientId },
            select: { uri: true },
          });
          validateActionUrlOrigin(normalizedActionUrl, oauthClient?.uri ?? null);
        }

        return createNotification(tx, {
          organizationId: params.organizationId,
          productId: product.id,
          productKey: product.key,
          category: categoryDef.key,
          recipientAccountId: body.recipientAccountId,
          title: body.title,
          body: body.body,
          actionUrl: normalizedActionUrl,
          now: customNow ? now : undefined,
        });
      };

      if (idempotencyKey === null) {
        const created = await withOrganization(db, params.organizationId, (tx) => runSend(tx, getNow()));
        if (created.queued) {
          mailOutboxWorker?.wake();
        }
        return reply.status(ROUTES.sendNotification.successStatus).send(send(request, created.result));
      }

      const routeParams =
        request.params && typeof request.params === "object" ? (request.params as Record<string, unknown>) : undefined;
      let queued = false;
      const outcome = await executeWithIdempotency({
        db,
        organizationId: params.organizationId,
        principal: clientPrincipal(machine.clientId),
        key: idempotencyKey,
        method: ROUTES.sendNotification.method,
        pathTemplate: ROUTES.sendNotification.path,
        body: request.body,
        params: routeParams,
        getNow,
        run: async (tx, now) => {
          const created = await runSend(tx, now);
          queued = created.queued;
          return {
            status: ROUTES.sendNotification.successStatus,
            body: send(request, created.result),
          };
        },
      });

      if (outcome.replayed) {
        void reply.header(IDEMPOTENCY_REPLAYED_HEADER, "true");
      } else if (queued) {
        mailOutboxWorker?.wake();
      }
      return reply.status(outcome.status).send(outcome.body);
    },
  });

  app.route({
    method: ROUTES.listMyNotificationPreferences.method,
    url: toFastifyPath(ROUTES.listMyNotificationPreferences.path),
    handler: async (request) => {
      const who = await caller(request);
      const now = getNow();
      const items = await withOrganization(db, who.organizationId, (tx) =>
        listNotificationPreferencesForAccount(tx, {
          organizationId: who.organizationId,
          accountId: who.accountId,
          now,
        }),
      );
      return send(request, items);
    },
  });

  app.route({
    method: ROUTES.updateMyNotificationPreference.method,
    url: toFastifyPath(ROUTES.updateMyNotificationPreference.path),
    handler: async (request) => {
      const who = await caller(request);
      const rawCategory = (request.params as { category?: unknown } | undefined)?.category;
      if (typeof rawCategory !== "string" || !rawCategory) {
        throw new ApiFailure(422, "VALIDATION_FAILED", "Nieznana kategoria powiadomień", [
          { field: "category", message: "Nieznana kategoria powiadomień" },
        ]);
      }
      const body = parseInput(UpdateNotificationPreference, request.body);
      const now = getNow();
      const updated = await withOrganization(db, who.organizationId, (tx) =>
        updateNotificationPreferenceForAccount(tx, {
          organizationId: who.organizationId,
          accountId: who.accountId,
          category: rawCategory,
          enabled: body.enabled,
          now,
          auditMeta: auditMetaFromRequest(request),
          source: "api",
        }),
      );
      return send(request, updated);
    },
  });

  app.route({
    method: ROUTES.unsubscribeNotification.method,
    url: toFastifyPath(ROUTES.unsubscribeNotification.path),
    handler: async (request) => {
      const rawToken = (request.params as { token?: unknown } | undefined)?.token;
      if (typeof rawToken !== "string" || !rawToken) {
        throw new ApiFailure(404, "NOT_FOUND", "Nieprawidłowy link wypisania z powiadomień");
      }
      const result = await unsubscribeNotificationByToken(db, {
        token: rawToken,
        secret: getUnsubscribeSecret(),
        now: getNow(),
        auditMeta: auditMetaFromRequest(request),
      });
      return send(request, result);
    },
  });

  return app;
}
