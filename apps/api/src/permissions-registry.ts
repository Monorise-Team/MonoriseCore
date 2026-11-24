import {
  CORE_PERMISSIONS,
  RegisterPermissionsRequest,
  type ApiErrorBody,
  type RegisterPermissionsResult,
} from "@core/contracts";
import { uuidv7, type PrismaClient } from "@core/db";
import { parsePermissionKey } from "@monorise-team/permissions";

export class ManifestValidationError extends Error {
  constructor(
    message: string,
    readonly details: ApiErrorBody["details"],
  ) {
    super(message);
  }
}

export type RegistryActor =
  { type: "SYSTEM" } | { type: "PRODUCT"; requestId?: string; ipAddress?: string | null; userAgent?: string | null };

export interface RegisterPermissionsOptions {
  db: PrismaClient;
  /** Produkt z tabeli `products` albo `null` dla własnych uprawnień platformy Core (`core.*`). */
  product: { id: string; key: string } | null;
  manifest: unknown;
  actor: RegistryActor;
}

/**
 * Waliduje manifest uprawnień produktu lub platformy (`core`) i idempotentnie aktualizuje tabelę `permissions`
 * w jednej transakcji (bez kontekstu firmy). Brakujące klucze oznacza `deprecatedAt` (nigdy ich nie usuwa),
 * a przywróconym czyści `deprecatedAt`. Wpis w dzienniku zdarzeń powstaje tylko wtedy, gdy coś się zmieniło.
 */
export async function registerPermissions({
  db,
  product,
  manifest,
  actor,
}: RegisterPermissionsOptions): Promise<RegisterPermissionsResult> {
  const expectedProductKey = product ? product.key : "core";
  const parsed = RegisterPermissionsRequest.safeParse(manifest);
  if (!parsed.success) {
    const details: ApiErrorBody["details"] = parsed.error.issues.map((issue) => ({
      ...(issue.path.length > 0 ? { field: issue.path.map(String).join(".") } : {}),
      message: issue.message,
    }));
    throw new ManifestValidationError("Błędny manifest uprawnień", details);
  }

  const prefixIssues: ApiErrorBody["details"] = [];
  for (let i = 0; i < parsed.data.length; i++) {
    const entry = parsed.data[i]!;
    const { product: keyProduct } = parsePermissionKey(entry.key);
    if (keyProduct !== expectedProductKey) {
      prefixIssues.push({
        field: `${i}.key`,
        message: `Klucz uprawnienia "${entry.key}" musi zaczynać się od prefiksu "${expectedProductKey}."`,
      });
    }
  }
  if (prefixIssues.length > 0) {
    throw new ManifestValidationError("Błędny prefiks klucza uprawnienia", prefixIssues);
  }

  const productId = product?.id ?? null;

  return db.$transaction(async (tx) => {
    // Serializujemy równoległe rejestracje tego samego produktu, żeby nie ścigały się przy upsert/deprecate.
    await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtextextended('permissions:' || ${expectedProductKey}::text, 0))`;

    const existing = await tx.permission.findMany({ where: { productId } });
    const existingByKey = new Map(existing.map((permission) => [permission.key, permission]));
    const incomingKeys = new Set<string>();

    const added: string[] = [];
    const updated: string[] = [];
    const deprecated: string[] = [];
    const restored: string[] = [];
    let unchanged = 0;

    for (const entry of parsed.data) {
      incomingKeys.add(entry.key);
      const current = existingByKey.get(entry.key);
      if (!current) {
        await tx.permission.create({
          data: {
            id: uuidv7(),
            key: entry.key,
            productId,
            description: entry.description,
            deprecatedAt: null,
          },
        });
        added.push(entry.key);
      } else if (current.deprecatedAt !== null) {
        await tx.permission.update({
          where: { id: current.id },
          data: { description: entry.description, deprecatedAt: null },
        });
        restored.push(entry.key);
      } else if (current.description !== entry.description) {
        await tx.permission.update({
          where: { id: current.id },
          data: { description: entry.description },
        });
        updated.push(entry.key);
      } else {
        unchanged += 1;
      }
    }

    const now = new Date();
    for (const current of existing) {
      if (!incomingKeys.has(current.key) && current.deprecatedAt === null) {
        await tx.permission.update({
          where: { id: current.id },
          data: { deprecatedAt: now },
        });
        deprecated.push(current.key);
      }
    }

    added.sort();
    updated.sort();
    deprecated.sort();
    restored.sort();

    const summary: RegisterPermissionsResult = { added, updated, deprecated, restored, unchanged };
    const changed = added.length > 0 || updated.length > 0 || deprecated.length > 0 || restored.length > 0;

    if (changed) {
      await tx.auditLog.create({
        data: {
          id: uuidv7(),
          organizationId: null,
          actorType: actor.type,
          productId,
          action: "product.permissions.registered",
          resourceType: "product",
          resourceId: product ? product.id : "core",
          metadata: {
            productKey: expectedProductKey,
            ...summary,
          },
          ipAddress: actor.type === "PRODUCT" ? (actor.ipAddress ?? null) : null,
          userAgent: actor.type === "PRODUCT" ? (actor.userAgent ?? null) : null,
          requestId: actor.type === "PRODUCT" ? (actor.requestId ?? null) : null,
        },
      });
    }

    return summary;
  });
}

/** Rejestruje własne uprawnienia platformy Core (`core.*`) przy starcie Core API. */
export function registerCorePermissions(db: PrismaClient): Promise<RegisterPermissionsResult> {
  return registerPermissions({
    db,
    product: null,
    manifest: CORE_PERMISSIONS.manifest,
    actor: { type: "SYSTEM" },
  });
}
