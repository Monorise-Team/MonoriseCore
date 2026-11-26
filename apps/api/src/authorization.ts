import { CORE_PERMISSIONS, type AccountStatus, type ScopeType } from "@core/contracts";
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

export interface ProductSnapshotTarget {
  id: string;
  key: string;
}

export interface LoadPermissionSnapshotOptions extends AuthzSubject {
  /** Gdy podano: buduje migawkę wyłącznie dla wskazanego produktu (endpoint dla serwerów produktów). */
  product?: ProductSnapshotTarget;
  /** Status konta (dla kont `INVITED` i `DEACTIVATED` migawka produktu zwraca puste `products` i `grants`). */
  accountStatus?: AccountStatus;
  /** Czas odniesienia do sprawdzania aktywności dostępu firmy (`Entitlement`). */
  now?: Date;
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

interface RawSnapshotAssignment {
  scopeType: ScopeType;
  scopeId: string | null;
  validFrom: Date | null;
  validUntil: Date | null;
  role: {
    archivedAt: Date | null;
    product: { key: string } | null;
    permissions: {
      permission: { key: string; deprecatedAt: Date | null };
    }[];
  };
}

const SNAPSHOT_ASSIGNMENT_SELECT = {
  scopeType: true,
  scopeId: true,
  validFrom: true,
  validUntil: true,
  role: {
    select: {
      archivedAt: true,
      product: { select: { key: true } },
      permissions: {
        select: {
          permission: { select: { key: true, deprecatedAt: true } },
        },
      },
    },
  },
} as const;

function flattenAssignmentGrants(assignments: readonly RawSnapshotAssignment[]): {
  grants: PermissionGrant[];
  assignmentProducts: Set<string>;
} {
  const assignmentProducts = new Set<string>();
  const grants: PermissionGrant[] = [];

  for (const assignment of assignments) {
    // Zarchiwizowana rola (np. gotowa rola wycofana przez produkt) nie daje już uprawnień.
    if (assignment.role.archivedAt !== null) continue;
    const productKey = assignment.role.product?.key;
    if (productKey) {
      assignmentProducts.add(productKey);
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

  return { grants, assignmentProducts };
}

/**
 * Buduje migawkę uprawnień konta w bieżącej transakcji firmy (`withOrganization`) i waliduje ją schematem
 * z `@monorise-team/permissions`, żeby Core i produkty rozstrzygały dostęp dokładnie tymi samymi regułami
 * (ADR-0033, ADR-0034, ADR-0035, ADR-0036).
 *
 * - Bez `product`: wewnętrzna migawka Core (zawsze zawiera produkt `core` i wszystkie aktywne nadania konta).
 * - Z `product`: migawka dla serwera produktu — zawiera wyłącznie nadania tego produktu (nigdy `core.*`),
 *   a `products` zawiera `[product.key]` tylko gdy konto jest `ACTIVE`, firma ma aktywny `Entitlement`
 *   oraz konto jest Ownerem albo ma aktywny `AppAccess`.
 */
export async function loadPermissionSnapshot(
  tx: Tx,
  options: LoadPermissionSnapshotOptions,
): Promise<PermissionSnapshot> {
  // Zwracamy wszystkie jednostki firmy, włącznie z ARCHIVED, żeby stare zasoby produktu nadal pasowały do zakresów.
  const units = await tx.organizationUnit.findMany({ select: { id: true, parentId: true } });

  if (options.product) {
    const { product } = options;
    if (options.accountStatus && options.accountStatus !== "ACTIVE") {
      return permissionSnapshotSchema.parse({
        accountId: options.accountId,
        organizationId: options.organizationId,
        authzRevision: options.authzRevision,
        isOwner: options.isOwner,
        products: [],
        grants: [],
        units,
      });
    }

    const now = options.now ?? new Date();
    const activeEntitlement = await tx.entitlement.findFirst({
      where: {
        productId: product.id,
        status: "ACTIVE",
        startsAt: { lte: now },
        OR: [{ endsAt: null }, { endsAt: { gt: now } }],
      },
      select: { id: true },
    });

    let hasProductAccess = false;
    if (activeEntitlement) {
      if (options.isOwner) {
        hasProductAccess = true;
      } else {
        const activeAccess = await tx.appAccess.findFirst({
          where: {
            accountId: options.accountId,
            productId: product.id,
            status: "ACTIVE",
          },
          select: { id: true },
        });
        hasProductAccess = activeAccess !== null;
      }
    }

    const assignments = await tx.roleAssignment.findMany({
      where: {
        accountId: options.accountId,
        role: { productId: product.id, archivedAt: null },
      },
      select: SNAPSHOT_ASSIGNMENT_SELECT,
    });
    const { grants } = flattenAssignmentGrants(assignments);

    return permissionSnapshotSchema.parse({
      accountId: options.accountId,
      organizationId: options.organizationId,
      authzRevision: options.authzRevision,
      isOwner: options.isOwner,
      products: hasProductAccess ? [product.key] : [],
      grants,
      units,
    });
  }

  const assignments = await tx.roleAssignment.findMany({
    where: { accountId: options.accountId },
    select: SNAPSHOT_ASSIGNMENT_SELECT,
  });
  const { grants, assignmentProducts } = flattenAssignmentGrants(assignments);
  const products = new Set<string>(["core", ...assignmentProducts]);

  return permissionSnapshotSchema.parse({
    accountId: options.accountId,
    organizationId: options.organizationId,
    authzRevision: options.authzRevision,
    isOwner: options.isOwner,
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

/** Czy konto może zarządzać danymi firmy i jej domenami (Owner lub `core.organization.manage` w zakresie całej firmy). */
export function canManageOrganization(snapshot: PermissionSnapshot): boolean {
  return snapshot.isOwner || can(snapshot, CORE_PERMISSIONS.keys["organization.manage"], {});
}

/**
 * Sprawdza uprawnienie `core.app_access.manage` dla pracownika o wskazanych jednostkach organizacyjnych:
 * - pracownik w co najmniej jednej jednostce wymaga pokrycia przynajmniej jednej z nich (`{ unitIds }`),
 * - pracownik bez przypisanych jednostek wymaga zakresu całej firmy (`{}`).
 * Owner firmy omija to sprawdzenie.
 */
export function assertCanManageAppAccessForUnits(snapshot: PermissionSnapshot, unitIds: readonly string[]): void {
  if (snapshot.isOwner) return;
  const target: PermissionTarget = unitIds.length > 0 ? { unitIds } : {};
  assertCan(snapshot, CORE_PERMISSIONS.keys["app_access.manage"], target);
}

/** Czy konto widzi wszystkie wpisy dostępu do aplikacji w firmie (Owner lub `core.app_access.manage` w dowolnym zakresie). */
export function canViewAllAppAccess(snapshot: PermissionSnapshot): boolean {
  return snapshot.isOwner || can(snapshot, CORE_PERMISSIONS.keys["app_access.manage"]);
}

/** Czy konto ma w ogóle aktywne prawo zarządzania dostępem do aplikacji w dowolnym zakresie. */
export function hasAnyAppAccessManagePermission(snapshot: PermissionSnapshot): boolean {
  return snapshot.isOwner || can(snapshot, CORE_PERMISSIONS.keys["app_access.manage"]);
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
