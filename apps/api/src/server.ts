import {
  type ApiErrorBody,
  type ApiResponse,
  type ErrorCode,
  type Health,
  type Me,
  type Organization,
} from "@core/contracts";
import { withOrganization, type PrismaClient } from "@core/db";
import Fastify, { type FastifyInstance, type FastifyRequest, type RouteOptions } from "fastify";
import { buildOpenApiDocument } from "./openapi.js";
import { ROUTES } from "./routes.js";
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

  app.setErrorHandler((error, request, reply) => {
    const failure =
      error instanceof ApiFailure
        ? error
        : (error as { statusCode?: number }).statusCode === 404
          ? new ApiFailure(404, "NOT_FOUND", "Nie ma takiego zasobu")
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

  /** Kto pyta: token z nagłówka Authorization, a konto musi być aktywne w aktywnej firmie. */
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
      tx.account.findUnique({ where: { id: claims.sub }, select: { status: true, employeeId: true } }),
    );
    if (!account || account.employeeId !== claims.employee_id) {
      throw new ApiFailure(401, "UNAUTHENTICATED", "Token jest nieważny albo wygasł");
    }
    if (account.status === "DEACTIVATED") throw new ApiFailure(401, "ACCOUNT_DEACTIVATED", "Konto jest wyłączone");
    return { accountId: claims.sub, organizationId: claims.org_id, employeeId: claims.employee_id };
  }

  app.addHook("onSend", async (_request, reply) => {
    void reply.header("Cache-Control", "no-store");
  });

  app.route({
    method: ROUTES.getHealth.method,
    url: ROUTES.getHealth.path,
    handler: async (request) => send(request, { status: "ok" } satisfies Health),
  });

  app.route({
    method: ROUTES.getOpenApi.method,
    url: ROUTES.getOpenApi.path,
    handler: async () => openApiDocument,
  });

  app.route({
    method: ROUTES.getMe.method,
    url: ROUTES.getMe.path,
    handler: async (request) => {
      const who = await caller(request);
      const me = await withOrganization(db, who.organizationId, async (tx) => {
        const account = await tx.account.findUniqueOrThrow({
          where: { id: who.accountId },
          include: { employee: true, organization: true },
        });
        return {
          account: { id: account.id, email: account.email, status: account.status },
          employee: {
            id: account.employee.id,
            firstName: account.employee.firstName,
            lastName: account.employee.lastName,
            workEmail: account.employee.workEmail,
            jobTitle: account.employee.jobTitle,
            status: account.employee.status,
          },
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
    url: ROUTES.getOrganization.path,
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

  return app;
}
