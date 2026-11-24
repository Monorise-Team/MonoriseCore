import {
  CORE_PERMISSIONS,
  CreateAppAccess,
  CreateEmployee,
  CreateInvitation,
  CreateRole,
  CreateRoleAssignment,
  CreateUnit,
  DIRECTORY_READ_SCOPE,
  EntitlementStatus,
  InvitationStatus,
  MAX_DIRECTORY_FILTER_IDS,
  PageQuery,
  PERMISSIONS_READ_SCOPE,
  PERMISSIONS_REGISTER_SCOPE,
  ProductKey,
  PutUnitMember,
  TransferOrganizationOwner,
  UnitStatus,
  UpdateRole,
  UpdateUnit,
  type ApiErrorBody,
  type ApiListResponse,
  type ApiResponse,
  type AppAccess,
  type DirectoryEmployee,
  type DirectoryUnitMember,
  type Employee,
  type Entitlement,
  type ErrorCode,
  type Health,
  type MachineTokenClaims,
  type Me,
  type Organization,
  type OrganizationOwner,
  type Permission,
  type Role,
  type RoleAssignment,
  type ScopeType,
  type Unit,
  type UnitMember,
} from "@core/contracts";
import { uuidv7, withOrganization, type PrismaClient, type Tx } from "@core/db";
import { PermissionError } from "@monorise-team/permissions";
import Fastify, { type FastifyInstance, type FastifyRequest, type RouteOptions } from "fastify";
import { z } from "zod";
import { writeAudit } from "./audit.js";
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
import { isEntitlementActive } from "./entitlements.js";
import {
  createInvitation,
  InvitationError,
  resendInvitation,
  revokeInvitation,
  serializeInvitation,
  type InvitationActor,
} from "./invitations.js";
import type { MailSender } from "./mail.js";
import { buildOpenApiDocument } from "./openapi.js";
import { bumpAuthzRevisions } from "./outbox.js";
import { ManifestValidationError, registerPermissions } from "./permissions-registry.js";
import { registerRoleTemplates } from "./role-templates-registry.js";
import { ROUTES, toFastifyPath } from "./routes.js";
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
  /** Adres serwera logowania używany do budowania linków zaproszeń (`CORE_AUTH_URL`). */
  authUrl?: string | undefined;
  /** Nadpisanie nadawcy wiadomości e-mail (np. w testach). */
  mailer?: MailSender | undefined;
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

const UnitIdParams = z.object({ unitId: z.uuid() });
const UnitMemberParams = z.object({ unitId: z.uuid(), employeeId: z.uuid() });
const ProductKeyParams = z.object({ productKey: ProductKey });
const RoleIdParams = z.object({ roleId: z.uuid() });
const AssignmentIdParams = z.object({ assignmentId: z.uuid() });
const AppAccessIdParams = z.object({ appAccessId: z.uuid() });
const InvitationIdParams = z.object({ invitationId: z.uuid() });
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

function isUniqueViolation(error: unknown): boolean {
  const err = error as { code?: string; message?: string } | null;
  if (err?.code === "P2002" || err?.code === "23505") return true;
  return /duplicate key value violates unique constraint/i.test(String(err?.message ?? ""));
}

function serializeEmployee(employee: {
  id: string;
  account?: { id: string } | null;
  firstName: string;
  lastName: string;
  workEmail: string | null;
  jobTitle: string | null;
  status: Employee["status"];
}): Employee {
  return {
    id: employee.id,
    accountId: employee.account?.id ?? null,
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
    account?: { id: string } | null;
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
  authUrl,
  mailer,
  now: getNow = () => new Date(),
  onRoute,
}: ServerOptions): FastifyInstance {
  const app = Fastify({ logger, genReqId: () => `req_${crypto.randomUUID().replaceAll("-", "").slice(0, 16)}` });
  const openApiDocument = buildOpenApiDocument();

  if (onRoute) {
    app.addHook("onRoute", onRoute);
  }

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
        : error instanceof InvitationError
          ? new ApiFailure(error.status, error.code, error.message, error.details)
          : error instanceof PermissionError
            ? new ApiFailure(403, "PERMISSION_DENIED", "Brak uprawnień do wykonania tej operacji")
            : statusCode === 404
              ? new ApiFailure(404, "NOT_FOUND", "Nie ma takiego zasobu")
              : statusCode === 400
                ? new ApiFailure(422, "VALIDATION_FAILED", "Nieprawidłowa treść żądania")
                : new ApiFailure(500, "INTERNAL", "Wewnętrzny błąd serwera");
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
          employee: serializeEmployee({ ...account.employee, account: { id: account.id } }),
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
        tx.organization.findUniqueOrThrow({
          where: { id: who.organizationId },
          include: { domains: { orderBy: { createdAt: "asc" } } },
        }),
      );
      return send(request, {
        id: organization.id,
        name: organization.name,
        status: organization.status,
        createdAt: organization.createdAt.toISOString(),
        domains: organization.domains.map((d) => ({
          domain: d.domain,
          status: d.status,
          isPrimary: d.isPrimary,
          verifiedAt: d.verifiedAt?.toISOString() ?? null,
        })),
      } satisfies Organization);
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
          include: { account: { select: { id: true } } },
          orderBy: { id: "asc" },
          take: page.limit + 1,
        }),
      );
      const { items, nextCursor } = paginateRows(rows, page.limit);
      return sendList(request, items.map(serializeEmployee), nextCursor);
    },
  });

  app.route({
    method: ROUTES.createEmployee.method,
    url: toFastifyPath(ROUTES.createEmployee.path),
    handler: async (request, reply) => {
      const who = await caller(request);
      const body = parseInput(CreateEmployee, request.body);
      const employee = await withOrganization(db, who.organizationId, async (tx) => {
        const snapshot = await loadPermissionSnapshot(tx, who);
        assertCorePermission(snapshot, CORE_PERMISSIONS.keys["employees.manage"], {});
        const created = await tx.employee.create({
          data: {
            id: uuidv7(),
            organizationId: who.organizationId,
            firstName: body.firstName,
            lastName: body.lastName,
            workEmail: body.workEmail ?? null,
            jobTitle: body.jobTitle ?? null,
          },
        });
        await writeAudit(tx, request, who, {
          action: "employee.created",
          resourceType: "employee",
          resourceId: created.id,
          metadata: {},
        });
        return created;
      });
      return reply.status(201).send(send(request, serializeEmployee({ ...employee, account: null })));
    },
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
          include: { account: { select: { employeeId: true } } },
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

  app.route({
    method: ROUTES.createInvitation.method,
    url: toFastifyPath(ROUTES.createInvitation.path),
    handler: async (request, reply) => {
      const who = await caller(request);
      const body = parseInput(CreateInvitation, request.body);
      const currentTime = getNow();

      const result = await withOrganization(db, who.organizationId, async (tx) => {
        const snapshot = await loadPermissionSnapshot(tx, who);
        assertCorePermission(snapshot, CORE_PERMISSIONS.keys["employees.manage"], {});
        return createInvitation(tx, {
          organizationId: who.organizationId,
          email: body.email,
          firstName: body.firstName,
          lastName: body.lastName,
          employeeId: body.employeeId,
          invitedBy: who.accountId,
          actor: invitationActorFromRequest(request, who),
          now: currentTime,
          authUrl,
          mailer,
        });
      });

      return reply.status(201).send(send(request, result.invitation));
    },
  });

  app.route({
    method: ROUTES.resendInvitation.method,
    url: toFastifyPath(ROUTES.resendInvitation.path),
    handler: async (request) => {
      const who = await caller(request);
      const params = parseInput(InvitationIdParams, request.params);
      const currentTime = getNow();

      const result = await withOrganization(db, who.organizationId, async (tx) => {
        const snapshot = await loadPermissionSnapshot(tx, who);
        assertCorePermission(snapshot, CORE_PERMISSIONS.keys["employees.manage"], {});
        return resendInvitation(tx, {
          organizationId: who.organizationId,
          invitationId: params.invitationId,
          actor: invitationActorFromRequest(request, who),
          now: currentTime,
          authUrl,
          mailer,
        });
      });

      return send(request, result.invitation);
    },
  });

  app.route({
    method: ROUTES.revokeInvitation.method,
    url: toFastifyPath(ROUTES.revokeInvitation.path),
    handler: async (request, reply) => {
      const who = await caller(request);
      const params = parseInput(InvitationIdParams, request.params);
      const currentTime = getNow();

      await withOrganization(db, who.organizationId, async (tx) => {
        const snapshot = await loadPermissionSnapshot(tx, who);
        assertCorePermission(snapshot, CORE_PERMISSIONS.keys["employees.manage"], {});
        await revokeInvitation(tx, {
          organizationId: who.organizationId,
          invitationId: params.invitationId,
          actor: invitationActorFromRequest(request, who),
          now: currentTime,
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

  app.route({
    method: ROUTES.createUnit.method,
    url: toFastifyPath(ROUTES.createUnit.path),
    handler: async (request, reply) => {
      const who = await caller(request);
      const body = parseInput(CreateUnit, request.body);
      const unit = await withOrganization(db, who.organizationId, async (tx) => {
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
        return created;
      });
      return reply.status(201).send(send(request, serializeUnit(unit)));
    },
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
          include: { employee: { include: { account: { select: { id: true } } } } },
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
          include: { employee: { include: { account: { select: { id: true } } } } },
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

  app.route({
    method: ROUTES.createRole.method,
    url: toFastifyPath(ROUTES.createRole.path),
    handler: async (request, reply) => {
      const who = await caller(request);
      const body = parseInput(CreateRole, request.body);

      try {
        const created = await withOrganization(db, who.organizationId, async (tx) => {
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
            return {
              ...role,
              product: source.product,
              permissions: activePermissions.map((perm) => ({ permission: { key: perm.key } })),
            };
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
          return {
            ...role,
            product: product ? { key: product.key } : null,
            permissions: resolvedPermissions.map((perm) => ({ permission: { key: perm.key } })),
          };
        });
        return reply.status(201).send(send(request, serializeRole(created)));
      } catch (error) {
        if (isUniqueViolation(error)) {
          throw new ApiFailure(409, "CONFLICT", "Aktywna rola o takiej nazwie już istnieje w firmie");
        }
        throw error;
      }
    },
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

  app.route({
    method: ROUTES.createRoleAssignment.method,
    url: toFastifyPath(ROUTES.createRoleAssignment.path),
    handler: async (request, reply) => {
      const who = await caller(request);
      const body = parseInput(CreateRoleAssignment, request.body);
      const scopeId = body.scopeType === "ORGANIZATION" ? null : (body.scopeId ?? null);
      const grantScope = toGrantScope(body.scopeType, scopeId);

      try {
        const created = await withOrganization(db, who.organizationId, async (tx) => {
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

          return assignment;
        });
        return reply.status(201).send(send(request, serializeRoleAssignment(created)));
      } catch (error) {
        if (isUniqueViolation(error)) {
          throw new ApiFailure(409, "CONFLICT", "To konto ma już przypisaną tę rolę w tym zakresie");
        }
        throw error;
      }
    },
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

  app.route({
    method: ROUTES.grantAppAccess.method,
    url: toFastifyPath(ROUTES.grantAppAccess.path),
    handler: async (request, reply) => {
      const who = await caller(request);
      const body = parseInput(CreateAppAccess, request.body);

      try {
        const created = await withOrganization(db, who.organizationId, async (tx) => {
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

          const now = new Date();
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

          return access;
        });

        return reply.status(201).send(send(request, serializeAppAccess(created)));
      } catch (error) {
        if (isUniqueViolation(error)) {
          throw new ApiFailure(409, "CONFLICT", "To konto ma już włączony dostęp do tego produktu");
        }
        throw error;
      }
    },
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

  return app;
}
