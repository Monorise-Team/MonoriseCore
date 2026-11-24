import { ProductKey } from "@core/contracts";
import { domainOwner, uuidv7, type EntitlementStatus, type PrismaClient, type Tx } from "@core/db";
import { z } from "zod";
import { bumpAuthzRevisions } from "./outbox.js";

const UuidSchema = z.uuid();

export class EntitlementCliError extends Error {
  constructor(
    message: string,
    readonly code: "VALIDATION_FAILED" | "NOT_FOUND" | "CONFLICT" = "VALIDATION_FAILED",
  ) {
    super(message);
  }
}

export interface EntitlementTiming {
  status: EntitlementStatus;
  startsAt: Date;
  endsAt: Date | null;
}

/**
 * Dostęp firmy do produktu jest aktywny, gdy status to `ACTIVE`, początek już nastąpił (`startsAt <= now`)
 * oraz nie upłynął koniec (`endsAt === null || endsAt > now`).
 */
export function isEntitlementActive(entitlement: EntitlementTiming, now: Date = new Date()): boolean {
  const nowMs = now.getTime();
  return (
    entitlement.status === "ACTIVE" &&
    entitlement.startsAt.getTime() <= nowMs &&
    (entitlement.endsAt === null || entitlement.endsAt.getTime() > nowMs)
  );
}

export interface GrantEntitlementInput {
  /** Identyfikator UUID firmy albo jej zarejestrowana domena (np. `acme.com`). */
  organization: string;
  /** Klucz produktu (np. `timotime`, nigdy `core`). */
  product: string;
  startsAt?: Date;
  endsAt?: Date | null;
  now?: Date;
}

export interface GrantEntitlementResult {
  entitlementId: string;
  organizationId: string;
  productKey: string;
  status: EntitlementStatus;
  startsAt: Date;
  endsAt: Date | null;
  updated: boolean;
  affectedAccounts: number;
}

export interface EndEntitlementInput {
  /** Identyfikator UUID firmy albo jej zarejestrowana domena (np. `acme.com`). */
  organization: string;
  /** Klucz produktu (np. `timotime`, nigdy `core`). */
  product: string;
  now?: Date;
}

export interface EndEntitlementResult {
  entitlementId: string;
  organizationId: string;
  productKey: string;
  previousStatus: EntitlementStatus;
  endsAt: Date | null;
  affectedAccounts: number;
}

function validateProductKey(product: string): string {
  const parsed = ProductKey.safeParse(product);
  if (!parsed.success || parsed.data === "core") {
    throw new EntitlementCliError(`Nieprawidłowy klucz produktu: "${product}"`, "VALIDATION_FAILED");
  }
  return parsed.data;
}

async function resolveOrganizationId(tx: Tx, organization: string): Promise<string> {
  const trimmed = organization.trim();
  if (!trimmed) {
    throw new EntitlementCliError("Podaj identyfikator lub domenę firmy (--organization)", "VALIDATION_FAILED");
  }

  let organizationId: string;
  if (UuidSchema.safeParse(trimmed).success) {
    organizationId = trimmed;
  } else {
    const owner = await domainOwner(tx, trimmed.toLowerCase());
    if (!owner) {
      throw new EntitlementCliError(`Nie znaleziono firmy dla domeny "${trimmed}"`, "NOT_FOUND");
    }
    organizationId = owner.organizationId;
  }

  await tx.$executeRaw`SELECT set_config('app.organization_id', ${organizationId}, true)`;
  const found = await tx.organization.findUnique({ where: { id: organizationId }, select: { id: true } });
  await tx.$executeRaw`SELECT set_config('app.organization_id', '', true)`;
  if (!found) {
    throw new EntitlementCliError(`Nie znaleziono firmy "${trimmed}"`, "NOT_FOUND");
  }
  return found.id;
}

/**
 * Przyznaje (lub odnawia/aktualizuje otwarty) dostęp firmy do produktu w trybie ręcznym (`MANUAL`),
 * podbija `authzRevision` wszystkim kontom firmy, dopisuje zdarzenia `organization.permissions.changed`
 * i zapisuje wpis audytu (`actorType = SYSTEM`, `metadata.source = "cli"`).
 */
export async function grantEntitlement(
  db: PrismaClient,
  input: GrantEntitlementInput,
): Promise<GrantEntitlementResult> {
  const productKey = validateProductKey(input.product);
  const now = input.now ?? new Date();
  const requestedStartsAt = input.startsAt ?? now;
  const endsAt = input.endsAt ?? null;

  if (Number.isNaN(requestedStartsAt.getTime())) {
    throw new EntitlementCliError("Nieprawidłowa data startsAt", "VALIDATION_FAILED");
  }
  if (endsAt !== null) {
    if (Number.isNaN(endsAt.getTime())) {
      throw new EntitlementCliError("Nieprawidłowa data endsAt", "VALIDATION_FAILED");
    }
    if (endsAt.getTime() <= requestedStartsAt.getTime()) {
      throw new EntitlementCliError("Data endsAt musi być późniejsza niż startsAt", "VALIDATION_FAILED");
    }
  }

  return db.$transaction(async (tx) => {
    const product = await tx.product.findUnique({
      where: { key: productKey },
      select: { id: true, key: true },
    });
    if (!product) {
      throw new EntitlementCliError(`Nie znaleziono produktu "${productKey}"`, "NOT_FOUND");
    }

    const organizationId = await resolveOrganizationId(tx, input.organization);

    // Serializujemy równoległe operacje na (firma, produkt) w ścieżce operatora bez kontekstu firmy.
    await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtextextended('entitlement:' || ${organizationId}::uuid::text || ':' || ${product.id}::uuid::text, 0))`;

    const existing = await tx.entitlement.findFirst({
      where: { organizationId, productId: product.id, status: { not: "ENDED" } },
    });

    let entitlement;
    if (existing) {
      const effectiveStartsAt =
        input.startsAt !== undefined ? input.startsAt : existing.startsAt > now ? now : existing.startsAt;
      if (endsAt !== null && endsAt.getTime() <= effectiveStartsAt.getTime()) {
        throw new EntitlementCliError("Data endsAt musi być późniejsza niż startsAt", "VALIDATION_FAILED");
      }
      entitlement = await tx.entitlement.update({
        where: { id: existing.id },
        data: {
          sourceType: "MANUAL",
          status: "ACTIVE",
          startsAt: effectiveStartsAt,
          endsAt,
          suspendedReason: null,
        },
      });
    } else {
      entitlement = await tx.entitlement.create({
        data: {
          id: uuidv7(),
          organizationId,
          productId: product.id,
          planId: null,
          sourceType: "MANUAL",
          sourceId: null,
          status: "ACTIVE",
          startsAt: requestedStartsAt,
          endsAt,
          suspendedReason: null,
        },
      });
    }

    // Przełączamy transakcję na kontekst firmy, żeby podbić authzRevision kont, zapisać outbox i audyt przez RLS.
    await tx.$executeRaw`SELECT set_config('app.organization_id', ${organizationId}, true)`;
    const bumped = await bumpAuthzRevisions(tx, organizationId, { organizationId });

    await tx.auditLog.create({
      data: {
        id: uuidv7(),
        organizationId,
        actorType: "SYSTEM",
        productId: product.id,
        action: "entitlement.granted",
        resourceType: "entitlement",
        resourceId: entitlement.id,
        metadata: {
          source: "cli",
          productKey: product.key,
          sourceType: entitlement.sourceType,
          status: entitlement.status,
          startsAt: entitlement.startsAt.toISOString(),
          endsAt: entitlement.endsAt ? entitlement.endsAt.toISOString() : null,
          updated: Boolean(existing),
        },
      },
    });

    return {
      entitlementId: entitlement.id,
      organizationId,
      productKey: product.key,
      status: entitlement.status,
      startsAt: entitlement.startsAt,
      endsAt: entitlement.endsAt,
      updated: Boolean(existing),
      affectedAccounts: bumped.length,
    };
  });
}

/**
 * Kończy otwarty (`ACTIVE` lub `SUSPENDED`) dostęp firmy do produktu (`status = ENDED`),
 * podbija `authzRevision` wszystkim kontom firmy, dopisuje zdarzenia `organization.permissions.changed`
 * i zapisuje wpis audytu (`actorType = SYSTEM`, `metadata.source = "cli"`).
 */
export async function endEntitlement(db: PrismaClient, input: EndEntitlementInput): Promise<EndEntitlementResult> {
  const productKey = validateProductKey(input.product);
  const now = input.now ?? new Date();

  return db.$transaction(async (tx) => {
    const product = await tx.product.findUnique({
      where: { key: productKey },
      select: { id: true, key: true },
    });
    if (!product) {
      throw new EntitlementCliError(`Nie znaleziono produktu "${productKey}"`, "NOT_FOUND");
    }

    const organizationId = await resolveOrganizationId(tx, input.organization);

    await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtextextended('entitlement:' || ${organizationId}::uuid::text || ':' || ${product.id}::uuid::text, 0))`;

    const existing = await tx.entitlement.findFirst({
      where: { organizationId, productId: product.id, status: { not: "ENDED" } },
    });
    if (!existing) {
      throw new EntitlementCliError(
        `Firma nie ma aktywnego ani wstrzymanego dostępu do produktu "${productKey}"`,
        "NOT_FOUND",
      );
    }

    const nextEndsAt =
      now.getTime() > existing.startsAt.getTime()
        ? existing.endsAt !== null && existing.endsAt.getTime() < now.getTime()
          ? existing.endsAt
          : now
        : existing.endsAt;

    const updated = await tx.entitlement.update({
      where: { id: existing.id },
      data: {
        status: "ENDED",
        suspendedReason: null,
        endsAt: nextEndsAt,
      },
    });

    await tx.$executeRaw`SELECT set_config('app.organization_id', ${organizationId}, true)`;
    const bumped = await bumpAuthzRevisions(tx, organizationId, { organizationId });

    await tx.auditLog.create({
      data: {
        id: uuidv7(),
        organizationId,
        actorType: "SYSTEM",
        productId: product.id,
        action: "entitlement.ended",
        resourceType: "entitlement",
        resourceId: updated.id,
        metadata: {
          source: "cli",
          productKey: product.key,
          previousStatus: existing.status,
          endsAt: updated.endsAt ? updated.endsAt.toISOString() : null,
        },
      },
    });

    return {
      entitlementId: updated.id,
      organizationId,
      productKey: product.key,
      previousStatus: existing.status,
      endsAt: updated.endsAt,
      affectedAccounts: bumped.length,
    };
  });
}
