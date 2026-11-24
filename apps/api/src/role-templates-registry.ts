import {
  CORE_ROLE_TEMPLATES,
  RegisterRoleTemplatesRequest,
  type ApiErrorBody,
  type RegisterRoleTemplatesResult,
} from "@core/contracts";
import { uuidv7, type PrismaClient } from "@core/db";
import { ManifestValidationError, type RegistryActor } from "./permissions-registry.js";

export interface RegisterRoleTemplatesOptions {
  db: PrismaClient;
  /** Produkt z tabeli `products` albo `null` dla gotowych ról platformy Core (`core.*`). */
  product: { id: string; key: string } | null;
  manifest: unknown;
  actor: RegistryActor;
}

function sameIdSet(a: readonly string[], b: readonly string[]): boolean {
  if (a.length !== b.length) return false;
  const setA = new Set(a);
  return b.every((id) => setA.has(id));
}

/**
 * Waliduje manifest gotowych ról (szablonów) produktu lub platformy (`core`) i idempotentnie
 * aktualizuje tabele `roles` oraz `role_permissions` bez kontekstu firmy (`organizationId = null`).
 * Brakujące szablony oznacza `archivedAt`, a powracające przywraca. Wpis w dzienniku powstaje tylko
 * wtedy, gdy coś się zmieniło.
 */
export async function registerRoleTemplates({
  db,
  product,
  manifest,
  actor,
}: RegisterRoleTemplatesOptions): Promise<RegisterRoleTemplatesResult> {
  const expectedProductKey = product ? product.key : "core";
  const parsed = RegisterRoleTemplatesRequest.safeParse(manifest);
  if (!parsed.success) {
    const details: ApiErrorBody["details"] = parsed.error.issues.map((issue) => ({
      ...(issue.path.length > 0 ? { field: issue.path.map(String).join(".") } : {}),
      message: issue.message,
    }));
    throw new ManifestValidationError("Błędny manifest szablonów ról", details);
  }

  const prefixIssues: ApiErrorBody["details"] = [];
  for (let i = 0; i < parsed.data.length; i++) {
    const entry = parsed.data[i]!;
    if (!entry.key.startsWith(`${expectedProductKey}.`)) {
      prefixIssues.push({
        field: `${i}.key`,
        message: `Klucz szablonu roli "${entry.key}" musi zaczynać się od prefiksu "${expectedProductKey}."`,
      });
    }
  }
  if (prefixIssues.length > 0) {
    throw new ManifestValidationError("Błędny prefiks klucza szablonu roli", prefixIssues);
  }

  const productId = product?.id ?? null;

  return db.$transaction(async (tx) => {
    await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtextextended('role_templates:' || ${expectedProductKey}::text, 0))`;

    const activePermissions = await tx.permission.findMany({
      where: { productId, deprecatedAt: null },
      select: { id: true, key: true },
    });
    const permissionIdByKey = new Map(activePermissions.map((permission) => [permission.key, permission.id]));

    const permIssues: ApiErrorBody["details"] = [];
    for (let i = 0; i < parsed.data.length; i++) {
      const entry = parsed.data[i]!;
      for (let j = 0; j < entry.permissions.length; j++) {
        const permKey = entry.permissions[j]!;
        if (!permissionIdByKey.has(permKey)) {
          permIssues.push({
            field: `${i}.permissions.${j}`,
            message: `Uprawnienie "${permKey}" nie jest zarejestrowanym, aktywnym uprawnieniem produktu "${expectedProductKey}"`,
          });
        }
      }
    }
    if (permIssues.length > 0) {
      throw new ManifestValidationError("Nieznane lub wycofane uprawnienie w szablonie roli", permIssues);
    }

    const existing = await tx.role.findMany({
      where: { organizationId: null, productId },
      include: { permissions: { select: { permissionId: true } } },
    });
    const existingByKey = new Map(existing.filter((r) => r.key !== null).map((r) => [r.key!, r]));
    const incomingKeys = new Set<string>();

    const added: string[] = [];
    const updated: string[] = [];
    const archived: string[] = [];
    const restored: string[] = [];
    let unchanged = 0;

    for (const entry of parsed.data) {
      incomingKeys.add(entry.key);
      const description = entry.description ?? null;
      const desiredPermissionIds = entry.permissions.map((key) => permissionIdByKey.get(key)!);
      const current = existingByKey.get(entry.key);

      if (!current) {
        const roleId = uuidv7();
        await tx.role.create({
          data: {
            id: roleId,
            organizationId: null,
            productId,
            key: entry.key,
            name: entry.name,
            description,
            archivedAt: null,
          },
        });
        await tx.rolePermission.createMany({
          data: desiredPermissionIds.map((permissionId) => ({ roleId, permissionId })),
        });
        added.push(entry.key);
        continue;
      }

      const currentPermissionIds = current.permissions.map((rp) => rp.permissionId);
      const permissionsChanged = !sameIdSet(currentPermissionIds, desiredPermissionIds);
      const metadataChanged = current.name !== entry.name || current.description !== description;

      if (current.archivedAt !== null) {
        await tx.role.update({
          where: { id: current.id },
          data: { name: entry.name, description, archivedAt: null },
        });
        if (permissionsChanged) {
          const desiredSet = new Set(desiredPermissionIds);
          const currentSet = new Set(currentPermissionIds);
          const toDelete = currentPermissionIds.filter((id) => !desiredSet.has(id));
          const toAdd = desiredPermissionIds.filter((id) => !currentSet.has(id));
          if (toDelete.length > 0) {
            await tx.rolePermission.deleteMany({ where: { roleId: current.id, permissionId: { in: toDelete } } });
          }
          if (toAdd.length > 0) {
            await tx.rolePermission.createMany({
              data: toAdd.map((permissionId) => ({ roleId: current.id, permissionId })),
            });
          }
        }
        restored.push(entry.key);
      } else if (metadataChanged || permissionsChanged) {
        if (metadataChanged) {
          await tx.role.update({
            where: { id: current.id },
            data: { name: entry.name, description },
          });
        }
        if (permissionsChanged) {
          const desiredSet = new Set(desiredPermissionIds);
          const currentSet = new Set(currentPermissionIds);
          const toDelete = currentPermissionIds.filter((id) => !desiredSet.has(id));
          const toAdd = desiredPermissionIds.filter((id) => !currentSet.has(id));
          if (toDelete.length > 0) {
            await tx.rolePermission.deleteMany({ where: { roleId: current.id, permissionId: { in: toDelete } } });
          }
          if (toAdd.length > 0) {
            await tx.rolePermission.createMany({
              data: toAdd.map((permissionId) => ({ roleId: current.id, permissionId })),
            });
          }
        }
        updated.push(entry.key);
      } else {
        unchanged += 1;
      }
    }

    const now = new Date();
    for (const current of existing) {
      if (current.key !== null && !incomingKeys.has(current.key) && current.archivedAt === null) {
        await tx.role.update({
          where: { id: current.id },
          data: { archivedAt: now },
        });
        archived.push(current.key);
      }
    }

    added.sort();
    updated.sort();
    archived.sort();
    restored.sort();

    const summary: RegisterRoleTemplatesResult = { added, updated, archived, restored, unchanged };
    const changed = added.length > 0 || updated.length > 0 || archived.length > 0 || restored.length > 0;

    if (changed) {
      await tx.auditLog.create({
        data: {
          id: uuidv7(),
          organizationId: null,
          actorType: actor.type,
          productId,
          action: product ? "product.role_templates.registered" : "role_templates.registered",
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

/** Rejestruje gotowe role platformy Core (`core.company_admin`) przy starcie Core API. */
export function registerCoreRoleTemplates(db: PrismaClient): Promise<RegisterRoleTemplatesResult> {
  return registerRoleTemplates({
    db,
    product: null,
    manifest: CORE_ROLE_TEMPLATES,
    actor: { type: "SYSTEM" },
  });
}
