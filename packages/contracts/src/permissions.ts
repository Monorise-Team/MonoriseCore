import {
  can,
  definePermissions,
  permissionSnapshotSchema,
  type PermissionGrant,
  type PermissionKeyOf,
  type PermissionSnapshot,
} from "@monorise-team/permissions";

/**
 * Własne uprawnienia platformy Core (ADR-0036). Rejestrowane automatycznie przy starcie Core API
 * z `productId = null` (prefiks `core.`).
 */
export const CORE_PERMISSIONS = definePermissions("core", {
  "structure.manage": "Zarządzanie strukturą firmy: jednostki i członkowie",
  "employees.manage": "Dodawanie i zmiana pracowników",
  "roles.manage": "Tworzenie i zmiana ról firmy",
  "roles.assign": "Nadawanie i odbieranie ról w swoim zakresie",
  "app_access.manage": "Włączanie i wyłączanie aplikacji pracownikom",
  "audit.read": "Przegląd dziennika zdarzeń firmy",
  "organization.manage": "Zmiana danych firmy i zarządzanie jej domenami",
});

export type CorePermissionKey = PermissionKeyOf<typeof CORE_PERMISSIONS>;

/**
 * Gotowe role (szablony) platformy Core rejestrowane przy starcie Core API zaraz po uprawnieniach `core.*`.
 */
export const CORE_ROLE_TEMPLATES = [
  {
    key: "core.company_admin",
    name: "Administrator firmy",
    description: "Zarządza firmą, pracownikami, strukturą, rolami, dostępem do aplikacji i dziennikiem zdarzeń",
    permissions: CORE_PERMISSIONS.manifest.map((entry) => entry.key),
  },
] as const;

export interface RawRoleAssignmentRecord {
  scopeType: "ORGANIZATION" | "UNIT" | "RESOURCE";
  scopeId: string | null;
  validFrom: Date | null;
  validUntil: Date | null;
  role: {
    archivedAt: Date | null;
    permissions: readonly {
      permission: { key: string; deprecatedAt: Date | null };
    }[];
  };
}

/**
 * Czy migawka uprawnień pozwala zarządzać danymi firmy i jej domenami (Owner albo aktywne uprawnienie
 * `core.organization.manage` w zakresie całej firmy `ORGANIZATION`).
 */
export function canManageOrganizationSnapshot(snapshot: PermissionSnapshot, now?: Date): boolean {
  return snapshot.isOwner || can(snapshot, CORE_PERMISSIONS.keys["organization.manage"], {}, now ? { now } : undefined);
}

/**
 * Wspólna ocena uprawnienia `core.organization.manage` (zakres `ORGANIZATION` lub Owner) dla `apps/api`
 * i `apps/auth`, oparta na tych samych regułach `@monorise-team/permissions` (pomija zarchiwizowane role,
 * wycofane uprawnienia oraz wygasłe/przyszłe przypisania).
 */
export function canManageOrganizationAssignments(options: {
  accountId: string;
  organizationId: string;
  isOwner: boolean;
  authzRevision: number;
  assignments: readonly RawRoleAssignmentRecord[];
  now?: Date | undefined;
}): boolean {
  if (options.isOwner) return true;

  const grants: PermissionGrant[] = [];
  for (const assignment of options.assignments) {
    if (assignment.role.archivedAt !== null) continue;
    const scope =
      assignment.scopeType === "ORGANIZATION"
        ? ({ type: "ORGANIZATION" } as const)
        : assignment.scopeType === "UNIT"
          ? ({ type: "UNIT", unitId: assignment.scopeId ?? "" } as const)
          : ({ type: "RESOURCE", resourceId: assignment.scopeId ?? "" } as const);
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

  const snapshot = permissionSnapshotSchema.parse({
    accountId: options.accountId,
    organizationId: options.organizationId,
    authzRevision: options.authzRevision,
    isOwner: false,
    products: ["core"],
    grants,
    units: [],
  });
  return canManageOrganizationSnapshot(snapshot, options.now);
}
