import { definePermissions, type PermissionKeyOf } from "@monorise-team/permissions";

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
