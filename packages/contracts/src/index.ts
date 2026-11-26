/**
 * Kontrakt Core API (`https://api.monorise.studio/core/v1`) i serwera logowania (`https://auth.monorise.studio`).
 * Format odpowiedzi jak w standardzie API Monorise (ADR-0044): `{ data, meta, error }`.
 */
import {
  grantScopeSchema,
  permissionGrantSchema,
  permissionKeySchema,
  permissionManifestEntrySchema,
  permissionManifestSchema,
  permissionSnapshotSchema,
  productNameSchema,
  snapshotUnitSchema,
} from "@monorise-team/permissions";
import { z } from "zod";

export { CORE_PERMISSIONS, CORE_ROLE_TEMPLATES, type CorePermissionKey } from "./permissions.js";

export const API_PREFIX = "/core/v1";
export const PERMISSIONS_REGISTER_SCOPE = "core:permissions.register";
export const PERMISSIONS_READ_SCOPE = "core:permissions.read";
export const DIRECTORY_READ_SCOPE = "core:directory.read";
export const EVENTS_READ_SCOPE = "core:events.read";
export const MAX_EVENT_FEED_LIMIT = 500;
export const DEFAULT_EVENT_FEED_LIMIT = 100;
export const MAX_PERMISSION_MANIFEST_ENTRIES = 500;
export const MAX_ROLE_TEMPLATE_ENTRIES = 100;
export const MAX_ROLE_PERMISSIONS = 200;
export const MAX_DIRECTORY_FILTER_IDS = 100;
export const INVITATION_TTL_DAYS = 7;
export const INVITATION_TTL_MS = INVITATION_TTL_DAYS * 24 * 60 * 60 * 1000;
export const IDEMPOTENCY_KEY_HEADER = "Idempotency-Key";
export const IDEMPOTENCY_REPLAYED_HEADER = "Idempotency-Replayed";
export const IDEMPOTENCY_KEY_MAX_LENGTH = 255;
export const IDEMPOTENCY_KEY_TTL_HOURS = 24;
export const IDEMPOTENCY_KEY_TTL_MS = IDEMPOTENCY_KEY_TTL_HOURS * 60 * 60 * 1000;
/** Drukowalne znaki ASCII (0x20–0x7E), bez wiodących/końcowych spacji ani samych spacji. */
export const IDEMPOTENCY_KEY_REGEX = /^[!-~]([ -~]*[!-~])?$/;

/** Klucz powtórzenia z nagłówka `Idempotency-Key` (1–255 drukowalnych znaków ASCII). */
export const IdempotencyKeyHeader = z
  .string()
  .min(1, "Nagłówek Idempotency-Key nie może być pusty")
  .max(
    IDEMPOTENCY_KEY_MAX_LENGTH,
    `Nagłówek Idempotency-Key może mieć co najwyżej ${IDEMPOTENCY_KEY_MAX_LENGTH} znaków`,
  )
  .regex(IDEMPOTENCY_KEY_REGEX, "Nagłówek Idempotency-Key może zawierać wyłącznie drukowalne znaki ASCII");
export type IdempotencyKeyHeader = z.infer<typeof IdempotencyKeyHeader>;

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
  "INTERNAL_ERROR",
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

export const OrganizationOwner = z.object({
  ownerAccountId: z.uuid(),
});
export type OrganizationOwner = z.infer<typeof OrganizationOwner>;

export const TransferOrganizationOwner = z.object({
  accountId: z.uuid(),
});
export type TransferOrganizationOwner = z.infer<typeof TransferOrganizationOwner>;

export const EmployeeStatus = z.enum(["ACTIVE", "FORMER", "ANONYMIZED"]);
export type EmployeeStatus = z.infer<typeof EmployeeStatus>;

export const AccountStatus = z.enum(["INVITED", "ACTIVE", "DEACTIVATED"]);
export type AccountStatus = z.infer<typeof AccountStatus>;

export const Employee = z.object({
  id: z.uuid(),
  accountId: z.uuid().nullable(),
  /** Stan konta logowania (zaproszone, aktywne, dezaktywowane); `null`, gdy pracownik nie ma konta. */
  accountStatus: AccountStatus.nullable(),
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

// ── Role, gotowe szablony i przypisania ról (ADR-0033, ADR-0034, ADR-0035) ──────────────────────

export const ROLE_TEMPLATE_KEY_REGEX = /^[a-z][a-z0-9]*(\.[a-z][a-z0-9_]*)+$/;
export const RoleTemplateKey = z.string().regex(ROLE_TEMPLATE_KEY_REGEX, "Nieprawidłowy klucz szablonu roli");
export type RoleTemplateKey = z.infer<typeof RoleTemplateKey>;

const UniqueRolePermissionKeys = z
  .array(permissionKeySchema)
  .min(1, "Rola musi zawierać co najmniej jedno uprawnienie")
  .max(MAX_ROLE_PERMISSIONS, `Rola może zawierać co najwyżej ${MAX_ROLE_PERMISSIONS} uprawnień`)
  .superRefine((keys, ctx) => {
    const seen = new Set<string>();
    for (let i = 0; i < keys.length; i++) {
      const key = keys[i]!;
      if (seen.has(key)) {
        ctx.addIssue({
          code: "custom",
          path: [i],
          message: `Zduplikowany klucz uprawnienia: "${key}"`,
        });
      } else {
        seen.add(key);
      }
    }
  });

export const RoleTemplateManifestEntry = z.object({
  key: RoleTemplateKey,
  name: z.string().trim().min(1).max(120),
  description: z.string().trim().min(1).max(500).nullable().optional(),
  permissions: UniqueRolePermissionKeys,
});
export type RoleTemplateManifestEntry = z.infer<typeof RoleTemplateManifestEntry>;

export const RegisterRoleTemplatesRequest = z
  .array(RoleTemplateManifestEntry)
  .max(
    MAX_ROLE_TEMPLATE_ENTRIES,
    `Manifest szablonów ról może zawierać co najwyżej ${MAX_ROLE_TEMPLATE_ENTRIES} pozycji`,
  )
  .superRefine((entries, ctx) => {
    const seen = new Set<string>();
    for (let i = 0; i < entries.length; i++) {
      const entry = entries[i]!;
      if (seen.has(entry.key)) {
        ctx.addIssue({
          code: "custom",
          path: [i, "key"],
          message: `Zduplikowany klucz szablonu roli: "${entry.key}"`,
        });
      } else {
        seen.add(entry.key);
      }
    }
  });
export type RegisterRoleTemplatesRequest = z.infer<typeof RegisterRoleTemplatesRequest>;

export const RegisterRoleTemplatesResult = z.object({
  added: z.array(z.string()),
  updated: z.array(z.string()),
  archived: z.array(z.string()),
  restored: z.array(z.string()),
  unchanged: z.number().int().nonnegative(),
});
export type RegisterRoleTemplatesResult = z.infer<typeof RegisterRoleTemplatesResult>;

export const Role = z.object({
  id: z.uuid(),
  key: z.string().nullable(),
  product: z.string().nullable(),
  name: z.string(),
  description: z.string().nullable(),
  isTemplate: z.boolean(),
  copiedFromRoleId: z.uuid().nullable(),
  archivedAt: z.string().nullable(),
  permissions: z.array(permissionKeySchema),
  createdAt: z.string(),
  updatedAt: z.string(),
});
export type Role = z.infer<typeof Role>;

export const CreateRoleFromScratch = z
  .object({
    name: z.string().trim().min(1).max(120),
    description: z.string().trim().min(1).max(500).nullable().optional(),
    product: ProductKey.nullable(),
    permissions: UniqueRolePermissionKeys,
  })
  .strict();
export type CreateRoleFromScratch = z.infer<typeof CreateRoleFromScratch>;

export const CopyRole = z
  .object({
    copyFromRoleId: z.uuid(),
    name: z.string().trim().min(1).max(120).optional(),
    description: z.string().trim().min(1).max(500).nullable().optional(),
  })
  .strict();
export type CopyRole = z.infer<typeof CopyRole>;

export const CreateRole = z.union([CreateRoleFromScratch, CopyRole]);
export type CreateRole = z.infer<typeof CreateRole>;

export const UpdateRole = z
  .object({
    name: z.string().trim().min(1).max(120).optional(),
    description: z.string().trim().min(1).max(500).nullable().optional(),
    permissions: UniqueRolePermissionKeys.optional(),
  })
  .refine((data) => data.name !== undefined || data.description !== undefined || data.permissions !== undefined, {
    message: "Podaj co najmniej jedno pole do zmiany",
  });
export type UpdateRole = z.infer<typeof UpdateRole>;

export const ScopeType = z.enum(["ORGANIZATION", "UNIT", "RESOURCE"]);
export type ScopeType = z.infer<typeof ScopeType>;

export const RoleAssignment = z.object({
  id: z.uuid(),
  accountId: z.uuid(),
  roleId: z.uuid(),
  scopeType: ScopeType,
  scopeId: z.string().nullable(),
  validFrom: z.string().nullable(),
  validUntil: z.string().nullable(),
  grantedByAccountId: z.uuid(),
  createdAt: z.string(),
});
export type RoleAssignment = z.infer<typeof RoleAssignment>;

export const IsoDatetime = z.iso.datetime({ offset: true });

export const CreateRoleAssignment = z
  .object({
    accountId: z.uuid(),
    roleId: z.uuid(),
    scopeType: ScopeType,
    scopeId: z.string().trim().min(1).max(256).nullable().optional(),
    validFrom: IsoDatetime.nullable().optional(),
    validUntil: IsoDatetime.nullable().optional(),
  })
  .superRefine((data, ctx) => {
    if (data.scopeType === "ORGANIZATION") {
      if (data.scopeId !== undefined && data.scopeId !== null) {
        ctx.addIssue({
          code: "custom",
          path: ["scopeId"],
          message: "Zakres ORGANIZATION nie przyjmuje scopeId",
        });
      }
    } else if (!data.scopeId) {
      ctx.addIssue({
        code: "custom",
        path: ["scopeId"],
        message: `Zakres ${data.scopeType} wymaga podania scopeId`,
      });
    } else if (data.scopeType === "UNIT" && !z.uuid().safeParse(data.scopeId).success) {
      ctx.addIssue({
        code: "custom",
        path: ["scopeId"],
        message: "Dla zakresu UNIT pole scopeId musi być poprawnym identyfikatorem UUID",
      });
    }

    if (data.validFrom && data.validUntil && Date.parse(data.validUntil) <= Date.parse(data.validFrom)) {
      ctx.addIssue({
        code: "custom",
        path: ["validUntil"],
        message: "Data validUntil musi być późniejsza niż validFrom",
      });
    }
  });
export type CreateRoleAssignment = z.infer<typeof CreateRoleAssignment>;

// ── Dostęp do produktów, aplikacji i migawka uprawnień (ADR-0035, ADR-0036, ADR-0051) ──────────

export const EntitlementSourceType = z.enum(["CONTRACT", "SUBSCRIPTION", "TRIAL", "MANUAL", "OFFER", "PACKAGE"]);
export type EntitlementSourceType = z.infer<typeof EntitlementSourceType>;

export const EntitlementStatus = z.enum(["ACTIVE", "SUSPENDED", "ENDED"]);
export type EntitlementStatus = z.infer<typeof EntitlementStatus>;

export const EntitlementSuspendedReason = z.enum(["OVERDUE"]);
export type EntitlementSuspendedReason = z.infer<typeof EntitlementSuspendedReason>;

export const Entitlement = z.object({
  id: z.uuid(),
  product: ProductKey,
  planId: z.uuid().nullable(),
  sourceType: EntitlementSourceType,
  status: EntitlementStatus,
  isActive: z.boolean(),
  startsAt: z.string(),
  endsAt: z.string().nullable(),
  suspendedReason: EntitlementSuspendedReason.nullable(),
  createdAt: z.string(),
  updatedAt: z.string(),
});
export type Entitlement = z.infer<typeof Entitlement>;

export const AppAccessStatus = z.enum(["ACTIVE", "REVOKED"]);
export type AppAccessStatus = z.infer<typeof AppAccessStatus>;

export const AppAccess = z.object({
  id: z.uuid(),
  accountId: z.uuid(),
  product: ProductKey,
  status: AppAccessStatus,
  grantedByAccountId: z.uuid(),
  createdAt: z.string(),
  revokedAt: z.string().nullable(),
});
export type AppAccess = z.infer<typeof AppAccess>;

export const CreateAppAccess = z.object({
  accountId: z.uuid(),
  product: ProductKey,
});
export type CreateAppAccess = z.infer<typeof CreateAppAccess>;

export const GrantScope = grantScopeSchema;
export type GrantScope = z.infer<typeof GrantScope>;

export const PermissionGrant = permissionGrantSchema;
export type PermissionGrant = z.infer<typeof PermissionGrant>;

export const SnapshotUnit = snapshotUnitSchema;
export type SnapshotUnit = z.infer<typeof SnapshotUnit>;

export const PermissionSnapshot = permissionSnapshotSchema;
export type PermissionSnapshot = z.infer<typeof PermissionSnapshot>;

export const DirectoryUnitMember = z.object({
  unitId: z.uuid(),
  employeeId: z.uuid(),
  accountId: z.uuid().nullable(),
  role: UnitMembershipRole,
});
export type DirectoryUnitMember = z.infer<typeof DirectoryUnitMember>;

export const DirectoryEmployee = z.object({
  id: z.uuid(),
  accountId: z.uuid().nullable(),
  firstName: z.string(),
  lastName: z.string(),
  status: EmployeeStatus,
});
export type DirectoryEmployee = z.infer<typeof DirectoryEmployee>;

// ── Zaproszenia pracowników (ADR-0021) ──────────────────────────────────────────────────────────

export const InvitationStatus = z.enum(["PENDING", "ACCEPTED", "EXPIRED", "REVOKED"]);
export type InvitationStatus = z.infer<typeof InvitationStatus>;

export const Invitation = z.object({
  id: z.uuid(),
  accountId: z.uuid(),
  employeeId: z.uuid(),
  email: z.string(),
  status: InvitationStatus,
  expiresAt: z.string(),
  invitedByAccountId: z.uuid().nullable(),
  acceptedAt: z.string().nullable(),
  createdAt: z.string(),
  updatedAt: z.string(),
});
export type Invitation = z.infer<typeof Invitation>;

export const CreateInvitation = z
  .object({
    email: z.email().max(254),
    firstName: z.string().trim().min(1).max(80).optional(),
    lastName: z.string().trim().min(1).max(80).optional(),
    employeeId: z.uuid().optional(),
  })
  .superRefine((data, ctx) => {
    if (!data.employeeId) {
      if (!data.firstName) {
        ctx.addIssue({
          code: "custom",
          path: ["firstName"],
          message: "Imię jest wymagane, gdy nie podano employeeId",
        });
      }
      if (!data.lastName) {
        ctx.addIssue({
          code: "custom",
          path: ["lastName"],
          message: "Nazwisko jest wymagane, gdy nie podano employeeId",
        });
      }
    }
  });
export type CreateInvitation = z.infer<typeof CreateInvitation>;

export const AcceptInvitationRequest = z.object({
  token: z.string().trim().min(1).max(256),
  password: z.string().min(12).max(128),
});
export type AcceptInvitationRequest = z.infer<typeof AcceptInvitationRequest>;

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

// ── Kanał zdarzeń dla produktów (MonoriseCore#53, do czasu EventBridge i SQS z ADR-0045) ─────────────

/** Numer zdarzenia w kanale: dodatnia liczba 64-bitowa zapisana dziesiętnie (bez zer wiodących). */
export const EventSequence = z.string().regex(/^[1-9][0-9]{0,18}$/);

/** Kursor kanału: numer ostatnio przetworzonego zdarzenia (wyłącznie) albo `0` = od początku. */
export const EventFeedPosition = z.string().regex(/^(0|[1-9][0-9]{0,18})$/);

export const ProductEventsQuery = z.object({
  cursor: EventFeedPosition.optional(),
  limit: z.coerce.number().int().min(1).max(MAX_EVENT_FEED_LIMIT).default(DEFAULT_EVENT_FEED_LIMIT),
});
export type ProductEventsQuery = z.infer<typeof ProductEventsQuery>;

/** Zdarzenie w kanale produktu: koperta z `@monorise-team/events` plus numer `sequence`. */
export const ProductEvent = z.object({
  sequence: EventSequence,
  id: z.uuid(),
  type: z.string(),
  version: z.number().int().min(1),
  source: z.literal("core"),
  organizationId: z.uuid(),
  resourceType: z.string(),
  resourceId: z.string(),
  resourceVersion: z.number().int().min(0),
  occurredAt: z.string(),
  data: z.record(z.string(), z.unknown()),
});
export type ProductEvent = z.infer<typeof ProductEvent>;

// ── Dziennik zdarzeń firmy (MonoriseCore#63, ADR-0039, ADR-0041) ──────────────────────────────────

export const AUDIT_LOG_RETENTION_DAYS = 730;
export const AUDIT_LOG_RETENTION_MS = AUDIT_LOG_RETENTION_DAYS * 24 * 60 * 60 * 1000;

export const AuditActorType = z.enum(["ACCOUNT", "OPERATOR", "SYSTEM", "PRODUCT"]);
export type AuditActorType = z.infer<typeof AuditActorType>;

export const AuditActionFilter = z.string().trim().min(1).max(120);
export const AuditResourceTypeFilter = z.string().trim().min(1).max(64);
export const AuditResourceIdFilter = z.string().trim().min(1).max(256);

export const ListAuditLogQuery = PageQuery.extend({
  actorAccountId: z.uuid().optional(),
  actorType: AuditActorType.optional(),
  action: AuditActionFilter.optional(),
  resourceType: AuditResourceTypeFilter.optional(),
  resourceId: AuditResourceIdFilter.optional(),
  from: IsoDatetime.optional(),
  to: IsoDatetime.optional(),
}).superRefine((data, ctx) => {
  if (data.from && data.to && Date.parse(data.from) > Date.parse(data.to)) {
    ctx.addIssue({
      code: "custom",
      path: ["to"],
      message: "Data to nie może być wcześniejsza niż from",
    });
  }
});
export type ListAuditLogQuery = z.infer<typeof ListAuditLogQuery>;

export const AuditLogEntry = z.object({
  id: z.uuid(),
  actorType: AuditActorType,
  actorAccountId: z.uuid().nullable(),
  actorDisplayName: z.string().nullable(),
  product: ProductKey.nullable(),
  action: z.string(),
  actionLabel: z.string(),
  resourceType: z.string(),
  resourceId: z.string(),
  metadata: z.record(z.string(), z.unknown()),
  ipAddress: z.string().nullable(),
  userAgent: z.string().nullable(),
  requestId: z.string().nullable(),
  supportAccessGrantId: z.uuid().nullable(),
  createdAt: z.string(),
});
export type AuditLogEntry = z.infer<typeof AuditLogEntry>;
