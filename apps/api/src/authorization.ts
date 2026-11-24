import { CORE_PERMISSIONS, type ScopeType } from "@core/contracts";
import type { Tx } from "@core/db";
import {
  assertCan,
  can,
  canDelegate,
  PermissionError,
  permissionSnapshotSchema,
  type GrantScope,
  type PermissionGrant,
  type PermissionSnapshot,
  type PermissionTarget,
} from "@monorise-team/permissions";

export interface AuthzSubject {
  accountId: string;
  organizationId: string;
  isOwner: boolean;
  authzRevision: number;
}

export function toGrantScope(scopeType: ScopeType, scopeId: string | null): GrantScope {
  if (scopeType === "ORGANIZATION") {
    return { type: "ORGANIZATION" };
  }
  if (scopeType === "UNIT") {
    return { type: "UNIT", unitId: scopeId ?? "" };
  }
  return { type: "RESOURCE", resourceId: scopeId ?? "" };
}

/**
 * Buduje wewnętrzną migawkę uprawnień zalogowanego konta w bieżącej transakcji firmy (`withOrganization`)
 * i waliduje ją schematem z `@monorise-team/permissions`, żeby Core i produkty rozstrzygały dostęp
 * dokładnie tymi samymi regułami (ADR-0033, ADR-0034, ADR-0035).
 */
export async function loadPermissionSnapshot(tx: Tx, who: AuthzSubject): Promise<PermissionSnapshot> {
  const units = await tx.organizationUnit.findMany({ select: { id: true, parentId: true } });
  const assignments = await tx.roleAssignment.findMany({
    where: { accountId: who.accountId },
    select: {
      scopeType: true,
      scopeId: true,
      validFrom: true,
      validUntil: true,
      role: {
        select: {
          product: { select: { key: true } },
          permissions: {
            select: {
              permission: { select: { key: true, deprecatedAt: true } },
            },
          },
        },
      },
    },
  });

  const products = new Set<string>(["core"]);
  const grants: PermissionGrant[] = [];

  for (const assignment of assignments) {
    const productKey = assignment.role.product?.key;
    if (productKey) {
      products.add(productKey);
    }
    const scope = toGrantScope(assignment.scopeType, assignment.scopeId);
    const validFrom = assignment.validFrom ? assignment.validFrom.toISOString() : null;
    const validUntil = assignment.validUntil ? assignment.validUntil.toISOString() : null;

    for (const rp of assignment.role.permissions) {
      if (rp.permission.deprecatedAt !== null) continue;
      grants.push({
        permission: rp.permission.key,
        scope,
        validFrom,
        validUntil,
      });
    }
  }

  return permissionSnapshotSchema.parse({
    accountId: who.accountId,
    organizationId: who.organizationId,
    authzRevision: who.authzRevision,
    isOwner: who.isOwner,
    products: [...products],
    grants,
    units,
  });
}

export function assertCorePermission(
  snapshot: PermissionSnapshot,
  permission: (typeof CORE_PERMISSIONS.keys)[keyof typeof CORE_PERMISSIONS.keys],
  target: PermissionTarget,
): void {
  assertCan(snapshot, permission, target);
}

/**
 * Sprawdza uprawnienie `core.roles.assign` dla docelowego zakresu:
 * - `UNIT` wymaga pokrycia wskazanej jednostki (bezpośrednio, przez przodka albo w całej firmie),
 * - `ORGANIZATION` oraz `RESOURCE` wymagają zakresu całej firmy (`{}`).
 * Owner firmy omija to sprawdzenie.
 */
export function assertCanAssignInScope(snapshot: PermissionSnapshot, scope: GrantScope): void {
  if (snapshot.isOwner) return;
  const target: PermissionTarget = scope.type === "UNIT" ? { unitIds: [scope.unitId] } : {};
  assertCan(snapshot, CORE_PERMISSIONS.keys["roles.assign"], target);
}

/**
 * Sprawdza regułę delegowania (ADR-0035): dla każdego aktywnego uprawnienia roli wywołujący
 * musi sam mieć to uprawnienie w zakresie obejmującym nadanie. Owner omija to sprawdzenie.
 */
export function assertCanDelegateRole(
  snapshot: PermissionSnapshot,
  permissionKeys: readonly string[],
  scope: GrantScope,
): void {
  if (snapshot.isOwner) return;
  for (const permissionKey of permissionKeys) {
    if (!canDelegate(snapshot, permissionKey, scope)) {
      throw new PermissionError(permissionKey);
    }
  }
}

/** Czy konto widzi wszystkie przypisania ról firmy (Owner lub `core.roles.assign` / `core.roles.manage` w dowolnym zakresie). */
export function canViewAllRoleAssignments(snapshot: PermissionSnapshot): boolean {
  return (
    snapshot.isOwner ||
    can(snapshot, CORE_PERMISSIONS.keys["roles.assign"]) ||
    can(snapshot, CORE_PERMISSIONS.keys["roles.manage"])
  );
}

/** Czy konto ma w ogóle aktywne prawo przypisywania lub odbierania ról w dowolnym zakresie. */
export function hasAnyRoleAssignPermission(snapshot: PermissionSnapshot): boolean {
  return snapshot.isOwner || can(snapshot, CORE_PERMISSIONS.keys["roles.assign"]);
}
