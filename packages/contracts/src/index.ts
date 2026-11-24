/**
 * Kontrakt Core API (`https://api.monorise.studio/core/v1`) i serwera logowania (`https://auth.monorise.studio`).
 * Format odpowiedzi jak w standardzie API Monorise (ADR-0044): `{ data, meta, error }`.
 */
import {
  permissionKeySchema,
  permissionManifestEntrySchema,
  permissionManifestSchema,
  productNameSchema,
} from "@monorise-team/permissions";
import { z } from "zod";

export { CORE_PERMISSIONS, type CorePermissionKey } from "./permissions.js";

export const API_PREFIX = "/core/v1";
export const PERMISSIONS_REGISTER_SCOPE = "core:permissions.register";
export const MAX_PERMISSION_MANIFEST_ENTRIES = 500;

// ── Odpowiedzi i błędy ──────────────────────────────────────────────────────────────────────────

export const ERROR_CODES = [
  "UNAUTHENTICATED",
  "PERMISSION_DENIED",
  "NOT_FOUND",
  "VALIDATION_FAILED",
  "RATE_LIMITED",
  "CONFLICT",
  "EMAIL_DOMAIN_NOT_ALLOWED",
  "ORGANIZATION_EXISTS",
  "ORGANIZATION_NOT_ACTIVE",
  "ACCOUNT_DEACTIVATED",
  "INTERNAL",
] as const;
export const ErrorCode = z.enum(ERROR_CODES);
export type ErrorCode = (typeof ERROR_CODES)[number];

export const ApiErrorDetail = z.object({
  field: z.string().optional(),
  message: z.string(),
});
export type ApiErrorDetail = z.infer<typeof ApiErrorDetail>;

export const ApiErrorBody = z.object({
  code: ErrorCode,
  message: z.string(),
  details: z.array(ApiErrorDetail),
});
export type ApiErrorBody = z.infer<typeof ApiErrorBody>;

export const ApiMeta = z.object({
  requestId: z.string(),
});
export type ApiMeta = z.infer<typeof ApiMeta>;

export const DEFAULT_PAGE_LIMIT = 50;
export const MAX_PAGE_LIMIT = 100;

export const PageLimit = z.coerce.number().int().min(1).max(MAX_PAGE_LIMIT).default(DEFAULT_PAGE_LIMIT);
export const PageCursor = z.string().min(1).max(256);

export const PageQuery = z.object({
  limit: PageLimit,
  cursor: PageCursor.optional(),
});
export type PageQuery = z.infer<typeof PageQuery>;

export const ApiListMeta = ApiMeta.extend({
  nextCursor: z.string().nullable(),
});
export type ApiListMeta = z.infer<typeof ApiListMeta>;

/** Koperta udanej odpowiedzi Core API: `{ data, meta, error: null }` (ADR-0044). */
export function apiSuccessSchema<T extends z.ZodType>(data: T) {
  return z.object({
    data,
    meta: ApiMeta,
    error: z.null(),
  });
}

/** Koperta udanej odpowiedzi listy Core API ze stronicowaniem kursorowym (`meta.nextCursor`). */
export function apiListSuccessSchema<T extends z.ZodType>(data: T) {
  return z.object({
    data,
    meta: ApiListMeta,
    error: z.null(),
  });
}

/** Koperta odpowiedzi błędu Core API: `{ data: null, meta, error }` (ADR-0044). */
export function apiErrorSchema<T extends z.ZodType = typeof ApiErrorBody>(error?: T) {
  return z.object({
    data: z.null(),
    meta: ApiMeta,
    error: (error ?? ApiErrorBody) as T,
  });
}

export const ApiErrorResponse = apiErrorSchema();
export type ApiErrorResponse = z.infer<typeof ApiErrorResponse>;

export interface ApiResponse<T> {
  data: T | null;
  meta: { requestId?: string; [key: string]: unknown };
  error: ApiErrorBody | null;
}

export interface ApiListResponse<T> {
  data: T[];
  meta: { requestId: string; nextCursor: string | null };
  error: null;
}

export const Health = z.object({
  status: z.literal("ok"),
});
export type Health = z.infer<typeof Health>;

// ── Token dostępu (ADR-0023) ────────────────────────────────────────────────────────────────────

/** Pola tokenu ustalane przez Core; uprawnień w tokenie nie ma (pobiera się je z Core). */
export const AccessTokenClaims = z.object({
  iss: z.string(),
  sub: z.uuid(),
  aud: z.union([z.string(), z.array(z.string())]),
  org_id: z.uuid(),
  employee_id: z.uuid(),
  sid: z.string().optional(),
  amr: z.array(z.string()).default([]),
  authz_rev: z.number().int().nonnegative(),
  iat: z.number(),
  exp: z.number(),
});
export type AccessTokenClaims = z.infer<typeof AccessTokenClaims>;

/**
 * Pola tokenu maszynowego (OAuth 2.1 `client_credentials`) wydawanego poufnym klientom produktów.
 * Taki token nie należy do żadnego użytkownika ani firmy, więc nigdy nie ma `org_id`.
 */
export const MachineTokenClaims = z.object({
  iss: z.string(),
  sub: z.string().min(1).optional(),
  aud: z.union([z.string(), z.array(z.string())]),
  client_id: z.string().min(1),
  scope: z.string().default(""),
  org_id: z.never().optional(),
  iat: z.number(),
  exp: z.number(),
});
export type MachineTokenClaims = z.infer<typeof MachineTokenClaims>;

// ── Firmy ───────────────────────────────────────────────────────────────────────────────────────

export const OrganizationStatus = z.enum(["PENDING_VERIFICATION", "ACTIVE", "SUSPENDED", "OFFBOARDING", "DELETED"]);
export type OrganizationStatus = z.infer<typeof OrganizationStatus>;

export const DomainStatus = z.enum(["PENDING", "VERIFIED", "FAILED", "REVOKED"]);
export type DomainStatus = z.infer<typeof DomainStatus>;

export const OrganizationDomain = z.object({
  domain: z.string(),
  status: DomainStatus,
  isPrimary: z.boolean(),
  verifiedAt: z.string().nullable(),
});
export type OrganizationDomain = z.infer<typeof OrganizationDomain>;

export const Organization = z.object({
  id: z.uuid(),
  name: z.string(),
  status: OrganizationStatus,
  domains: z.array(OrganizationDomain),
  createdAt: z.string(),
});
export type Organization = z.infer<typeof Organization>;

export const EmployeeStatus = z.enum(["ACTIVE", "FORMER", "ANONYMIZED"]);
export type EmployeeStatus = z.infer<typeof EmployeeStatus>;

export const Employee = z.object({
  id: z.uuid(),
  firstName: z.string(),
  lastName: z.string(),
  workEmail: z.string().nullable(),
  jobTitle: z.string().nullable(),
  status: EmployeeStatus,
});
export type Employee = z.infer<typeof Employee>;

export const CreateEmployee = z.object({
  firstName: z.string().trim().min(1).max(80),
  lastName: z.string().trim().min(1).max(80),
  workEmail: z.email().max(254).optional(),
  jobTitle: z.string().trim().min(1).max(120).optional(),
});
export type CreateEmployee = z.infer<typeof CreateEmployee>;

export const AccountStatus = z.enum(["INVITED", "ACTIVE", "DEACTIVATED"]);
export type AccountStatus = z.infer<typeof AccountStatus>;

/** Kim jestem: konto, pracownik i firma z tokenu. */
export const Me = z.object({
  account: z.object({
    id: z.uuid(),
    email: z.string(),
    status: AccountStatus,
    isOwner: z.boolean(),
  }),
  employee: Employee,
  organization: Organization.pick({ id: true, name: true, status: true }),
});
export type Me = z.infer<typeof Me>;

// ── Struktura firmy (ADR-0032) ──────────────────────────────────────────────────────────────────

export const UnitType = z.enum(["BRANCH", "DEPARTMENT", "TEAM"]);
export type UnitType = z.infer<typeof UnitType>;

export const UnitStatus = z.enum(["ACTIVE", "ARCHIVED"]);
export type UnitStatus = z.infer<typeof UnitStatus>;

export const Unit = z.object({
  id: z.uuid(),
  parentId: z.uuid().nullable(),
  name: z.string(),
  type: UnitType,
  status: UnitStatus,
  createdAt: z.string(),
  updatedAt: z.string(),
});
export type Unit = z.infer<typeof Unit>;

export const CreateUnit = z.object({
  name: z.string().trim().min(1).max(120),
  type: UnitType,
  parentId: z.uuid().nullable().optional(),
});
export type CreateUnit = z.infer<typeof CreateUnit>;

export const UpdateUnit = z
  .object({
    name: z.string().trim().min(1).max(120).optional(),
    parentId: z.uuid().nullable().optional(),
    status: UnitStatus.optional(),
  })
  .refine((data) => data.name !== undefined || data.parentId !== undefined || data.status !== undefined, {
    message: "Podaj co najmniej jedno pole do zmiany",
  });
export type UpdateUnit = z.infer<typeof UpdateUnit>;

export const UnitMembershipRole = z.enum(["MEMBER", "LEADER"]);
export type UnitMembershipRole = z.infer<typeof UnitMembershipRole>;

export const UnitMember = z.object({
  unitId: z.uuid(),
  employeeId: z.uuid(),
  role: UnitMembershipRole,
  joinedAt: z.string(),
  employee: Employee,
});
export type UnitMember = z.infer<typeof UnitMember>;

export const PutUnitMember = z.object({
  role: UnitMembershipRole,
});
export type PutUnitMember = z.infer<typeof PutUnitMember>;

// ── Rejestr uprawnień produktów (ADR-0036) ──────────────────────────────────────────────────────

export const ProductKey = productNameSchema;
export type ProductKey = z.infer<typeof ProductKey>;

export const PermissionManifestEntry = permissionManifestEntrySchema;
export type PermissionManifestEntry = z.infer<typeof PermissionManifestEntry>;

export const RegisterPermissionsRequest = permissionManifestSchema.max(
  MAX_PERMISSION_MANIFEST_ENTRIES,
  `Manifest uprawnień może zawierać co najwyżej ${MAX_PERMISSION_MANIFEST_ENTRIES} pozycji`,
);
export type RegisterPermissionsRequest = z.infer<typeof RegisterPermissionsRequest>;

export const RegisterPermissionsResult = z.object({
  added: z.array(z.string()),
  updated: z.array(z.string()),
  deprecated: z.array(z.string()),
  restored: z.array(z.string()),
  unchanged: z.number().int().nonnegative(),
});
export type RegisterPermissionsResult = z.infer<typeof RegisterPermissionsResult>;

export const Permission = z.object({
  key: permissionKeySchema,
  product: z.string().nullable(),
  description: z.string(),
  deprecated: z.boolean(),
});
export type Permission = z.infer<typeof Permission>;

// ── Samorejestracja firmy (ADR-0021) ────────────────────────────────────────────────────────────

export const SignUpRequest = z.object({
  organizationName: z.string().trim().min(2).max(120),
  firstName: z.string().trim().min(1).max(80),
  lastName: z.string().trim().min(1).max(80),
  email: z.email().max(254),
  password: z.string().min(12).max(128),
});
export type SignUpRequest = z.infer<typeof SignUpRequest>;

// ── Domeny e-mail ───────────────────────────────────────────────────────────────────────────────

/**
 * Darmowe domeny pocztowe nie zakładają firm i do nich nie należą (ADR-0019). Lista jest w Core;
 * uzupełniamy ją, gdy pojawi się nowa popularna skrzynka.
 */
export const FREE_EMAIL_DOMAINS = new Set([
  "gmail.com",
  "googlemail.com",
  "outlook.com",
  "hotmail.com",
  "live.com",
  "msn.com",
  "yahoo.com",
  "icloud.com",
  "me.com",
  "mac.com",
  "aol.com",
  "proton.me",
  "protonmail.com",
  "gmx.com",
  "gmx.net",
  "zoho.com",
  "wp.pl",
  "o2.pl",
  "onet.pl",
  "onet.eu",
  "op.pl",
  "poczta.onet.pl",
  "interia.pl",
  "interia.eu",
  "poczta.fm",
  "tlen.pl",
  "gazeta.pl",
  "vp.pl",
  "spoko.pl",
  "go2.pl",
  "buziaczek.pl",
  "autograf.pl",
  "int.pl",
]);

/** Adres w postaci do porównań: małe litery, bez spacji (ADR-0018). */
export function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}

/** Domena adresu e-mail w małych literach. */
export function emailDomain(email: string): string {
  const at = email.lastIndexOf("@");
  return at === -1 ? "" : normalizeEmail(email.slice(at + 1));
}

export function isFreeEmailDomain(domain: string): boolean {
  return FREE_EMAIL_DOMAINS.has(domain.toLowerCase());
}

/** Rekord DNS TXT potwierdzający domenę firmy: `_monorise-verification.<domena>` = `monorise-verification=<kod>`. */
export const DOMAIN_TXT_PREFIX = "monorise-verification=";
export function domainVerificationHost(domain: string): string {
  return `_monorise-verification.${domain}`;
}
