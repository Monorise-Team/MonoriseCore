import { uuidv7, type Prisma, type Tx } from "@core/db";
import type { FastifyRequest } from "fastify";

export interface AuditActorAccount {
  accountId: string;
  organizationId: string;
}

export interface AuditEntryInput {
  action: string;
  resourceType: string;
  resourceId: string;
  metadata?: Prisma.InputJsonValue;
}

function extractUserAgent(request: FastifyRequest): string | null {
  const header = request.headers["user-agent"];
  return typeof header === "string" && header.length > 0 ? header : null;
}

/**
 * Zapisuje wpis w centralnym dzienniku zdarzeń firmy w tej samej transakcji co zmiana (`withOrganization`).
 * W polu `metadata` nie zapisujemy danych osobowych poza identyfikatorami (ADR-0039).
 */
export async function writeAudit(
  tx: Tx,
  request: FastifyRequest,
  who: AuditActorAccount,
  entry: AuditEntryInput,
): Promise<void> {
  await tx.auditLog.create({
    data: {
      id: uuidv7(),
      organizationId: who.organizationId,
      actorType: "ACCOUNT",
      actorAccountId: who.accountId,
      action: entry.action,
      resourceType: entry.resourceType,
      resourceId: entry.resourceId,
      metadata: entry.metadata ?? {},
      ipAddress: request.ip || null,
      userAgent: extractUserAgent(request),
      requestId: request.id,
    },
  });
}
