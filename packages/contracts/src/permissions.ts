import { definePermissions, type PermissionKeyOf } from "@monorise-team/permissions";

/**
 * Własne uprawnienia platformy Core (ADR-0036). Rejestrowane automatycznie przy starcie Core API
 * z `productId = null` (prefiks `core.`). Do egzekwowania dostępu wejdą razem z rolami (etap 2b).
 */
export const CORE_PERMISSIONS = definePermissions("core", {
  "structure.manage": "Zarządzanie strukturą firmy: jednostki i członkowie",
  "employees.manage": "Dodawanie i zmiana pracowników",
  "roles.manage": "Tworzenie i zmiana ról firmy",
  "roles.assign": "Nadawanie i odbieranie ról w swoim zakresie",
  "audit.read": "Przegląd dziennika zdarzeń firmy",
});

export type CorePermissionKey = PermissionKeyOf<typeof CORE_PERMISSIONS>;
