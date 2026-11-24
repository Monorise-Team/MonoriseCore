import {
  CreateEmployee,
  CreateUnit,
  PageQuery,
  PutUnitMember,
  UnitStatus,
  UpdateUnit,
  type ApiErrorBody,
  type ApiListResponse,
  type ApiResponse,
  type Employee,
  type ErrorCode,
  type Health,
  type Me,
  type Organization,
  type Unit,
  type UnitMember,
} from "@core/contracts";
import { uuidv7, withOrganization, type PrismaClient, type Tx } from "@core/db";
import Fastify, { type FastifyInstance, type FastifyRequest, type RouteOptions } from "fastify";
import { z } from "zod";
import { buildOpenApiDocument } from "./openapi.js";
import { ROUTES, toFastifyPath } from "./routes.js";
import type { TokenVerifier } from "./tokens.js";

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
  logger?: boolean;
  /** Opcjonalny hook wywoływany przy rejestracji każdej ścieżki Fastify (używany w testach OpenAPI). */
  onRoute?: (route: RouteOptions) => void;
}

interface Caller {
  accountId: string;
  organizationId: string;
  employeeId: string;
  isOwner: boolean;
}

const UnitIdParams = z.object({ unitId: z.uuid() });
const UnitMemberParams = z.object({ unitId: z.uuid(), employeeId: z.uuid() });
const ListUnitsFilter = z.object({ status: UnitStatus.optional() });
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

function serializeEmployee(employee: {
  id: string;
  firstName: string;
  lastName: string;
  workEmail: string | null;
  jobTitle: string | null;
  status: Employee["status"];
}): Employee {
  return {
    id: employee.id,
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

/** Core API: format `{ data, meta, error }` (ADR-0044), firma zawsze z tokenu, dane przez RLS (ADR-0037). */
export function buildServer({ db, verifyToken, logger = false, onRoute }: ServerOptions): FastifyInstance {
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
        select: { status: true, employeeId: true, organization: { select: { ownerAccountId: true } } },
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
    };
  }

  function requireOwner(who: Caller): void {
    if (!who.isOwner) {
      throw new ApiFailure(403, "PERMISSION_DENIED", "Tę operację może wykonać tylko Owner firmy");
    }
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
          employee: serializeEmployee(account.employee),
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
    method: ROUTES.listEmployees.method,
    url: toFastifyPath(ROUTES.listEmployees.path),
    handler: async (request) => {
      const who = await caller(request);
      const page = parsePageQuery(request.query);
      const rows = await withOrganization(db, who.organizationId, (tx) =>
        tx.employee.findMany({
          ...(page.afterId ? { where: { id: { gt: page.afterId } } } : {}),
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
      requireOwner(who);
      const body = parseInput(CreateEmployee, request.body);
      const employee = await withOrganization(db, who.organizationId, (tx) =>
        tx.employee.create({
          data: {
            id: uuidv7(),
            organizationId: who.organizationId,
            firstName: body.firstName,
            lastName: body.lastName,
            workEmail: body.workEmail ?? null,
            jobTitle: body.jobTitle ?? null,
          },
        }),
      );
      return reply.status(201).send(send(request, serializeEmployee(employee)));
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
      requireOwner(who);
      const body = parseInput(CreateUnit, request.body);
      const unit = await withOrganization(db, who.organizationId, async (tx) => {
        await lockOrganizationUnits(tx, who.organizationId);
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
        return tx.organizationUnit.create({
          data: {
            id: uuidv7(),
            organizationId: who.organizationId,
            parentId: body.parentId ?? null,
            name: body.name,
            type: body.type,
          },
        });
      });
      return reply.status(201).send(send(request, serializeUnit(unit)));
    },
  });

  app.route({
    method: ROUTES.updateUnit.method,
    url: toFastifyPath(ROUTES.updateUnit.path),
    handler: async (request) => {
      const who = await caller(request);
      requireOwner(who);
      const params = parseInput(UnitIdParams, request.params);
      const body = parseInput(UpdateUnit, request.body);

      try {
        const updated = await withOrganization(db, who.organizationId, async (tx) => {
          await lockOrganizationUnits(tx, who.organizationId);
          const unit = await tx.organizationUnit.findUnique({ where: { id: params.unitId } });
          if (!unit) throw new ApiFailure(404, "NOT_FOUND", "Nie znaleziono jednostki organizacyjnej");

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

          return tx.organizationUnit.update({
            where: { id: unit.id },
            data: {
              ...(body.name !== undefined ? { name: body.name } : {}),
              ...(body.parentId !== undefined ? { parentId: body.parentId } : {}),
              ...(body.status !== undefined ? { status: body.status } : {}),
            },
          });
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
          include: { employee: true },
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
      requireOwner(who);
      const params = parseInput(UnitMemberParams, request.params);
      const body = parseInput(PutUnitMember, request.body);
      const membership = await withOrganization(db, who.organizationId, async (tx) => {
        await lockOrganizationUnits(tx, who.organizationId);
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
        return tx.unitMembership.upsert({
          where: { unitId_employeeId: { unitId: params.unitId, employeeId: params.employeeId } },
          create: {
            id: uuidv7(),
            organizationId: who.organizationId,
            unitId: params.unitId,
            employeeId: params.employeeId,
            role: body.role,
          },
          update: { role: body.role },
          include: { employee: true },
        });
      });
      return send(request, serializeUnitMember(membership));
    },
  });

  app.route({
    method: ROUTES.deleteUnitMember.method,
    url: toFastifyPath(ROUTES.deleteUnitMember.path),
    handler: async (request, reply) => {
      const who = await caller(request);
      requireOwner(who);
      const params = parseInput(UnitMemberParams, request.params);
      await withOrganization(db, who.organizationId, async (tx) => {
        const unit = await tx.organizationUnit.findUnique({
          where: { id: params.unitId },
          select: { id: true },
        });
        if (!unit) throw new ApiFailure(404, "NOT_FOUND", "Nie znaleziono jednostki organizacyjnej");
        const deleted = await tx.unitMembership.deleteMany({
          where: { unitId: params.unitId, employeeId: params.employeeId },
        });
        if (deleted.count === 0) {
          throw new ApiFailure(404, "NOT_FOUND", "Nie znaleziono przypisania pracownika do jednostki");
        }
      });
      return reply.status(204).send();
    },
  });

  return app;
}
