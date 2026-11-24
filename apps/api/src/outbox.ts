import type { Prisma, Tx } from "@core/db";
import { organizationPermissionsChanged, toOutboxRecord } from "@monorise-team/events";

export interface PermissionsChangedInput {
  organizationId: string;
  accountId: string;
  authzRevision: number;
}

export interface BumpedAccountRevision {
  accountId: string;
  authzRevision: number;
}

/**
 * Buduje rekord `OutboxEvent` ze zdarzeniem `organization.permissions.changed` przez `@monorise-team/events`.
 * `resourceType = "account"`, `resourceId = accountId`, a `resourceVersion` i `data.authzRevision` niosą nową rewizję.
 */
export function buildPermissionsChangedRecord(input: PermissionsChangedInput): Prisma.OutboxEventUncheckedCreateInput {
  const envelope = organizationPermissionsChanged.create({
    source: "core",
    organizationId: input.organizationId,
    resourceType: "account",
    resourceId: input.accountId,
    resourceVersion: input.authzRevision,
    data: { authzRevision: input.authzRevision },
  });
  const record = toOutboxRecord(envelope);
  return {
    id: record.id,
    organizationId: record.organizationId,
    type: record.type,
    version: record.version,
    resourceType: record.resourceType,
    resourceId: record.resourceId,
    resourceVersion: record.resourceVersion,
    payload: record.payload as Prisma.InputJsonValue,
    occurredAt: record.occurredAt,
    publishedAt: record.publishedAt,
  };
}

/**
 * Zapisuje zdarzenie `organization.permissions.changed` w tabeli `outbox_events`
 * w tej samej transakcji co zmiana uprawnień (ADR-0045).
 */
export async function emitPermissionsChanged(tx: Tx, input: PermissionsChangedInput): Promise<void> {
  await tx.outboxEvent.create({ data: buildPermissionsChangedRecord(input) });
}

/**
 * Podbija `accounts.authzRevision` wszystkim kontom spełniającym `where` w bieżącej transakcji firmy
 * i zapisuje po jednym zdarzeniu `organization.permissions.changed` w `outbox_events` dla każdego zmienionego konta.
 */
export async function bumpAuthzRevisions(
  tx: Tx,
  organizationId: string,
  where: Prisma.AccountWhereInput,
): Promise<BumpedAccountRevision[]> {
  const updated = await tx.account.updateManyAndReturn({
    where,
    data: { authzRevision: { increment: 1 } },
    select: { id: true, authzRevision: true },
  });
  if (updated.length === 0) return [];

  const records = updated.map((account) =>
    buildPermissionsChangedRecord({
      organizationId,
      accountId: account.id,
      authzRevision: account.authzRevision,
    }),
  );

  if (records.length === 1) {
    await tx.outboxEvent.create({ data: records[0]! });
  } else {
    await tx.outboxEvent.createMany({ data: records });
  }

  return updated.map((account) => ({ accountId: account.id, authzRevision: account.authzRevision }));
}
