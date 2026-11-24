/**
 * Kontrakt Core API (`https://api.monorise.studio/v1`) i serwera logowania (`https://auth.monorise.studio`).
 * Format odpowiedzi jak w standardzie API Monorise (ADR-0044): `{ data, meta, error }`.
 */
import { z } from "zod";

export const API_PREFIX = "/v1";

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

/** Koperta udanej odpowiedzi Core API: `{ data, meta, error: null }` (ADR-0044). */
export function apiSuccessSchema<T extends z.ZodType>(data: T) {
  return z.object({
    data,
    meta: ApiMeta,
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

export const Employee = z.object({
  id: z.uuid(),
  firstName: z.string(),
  lastName: z.string(),
  workEmail: z.string().nullable(),
  jobTitle: z.string().nullable(),
  status: z.enum(["ACTIVE", "FORMER", "ANONYMIZED"]),
});
export type Employee = z.infer<typeof Employee>;

/** Kim jestem: konto, pracownik i firma z tokenu. */
export const Me = z.object({
  account: z.object({ id: z.uuid(), email: z.string(), status: z.enum(["INVITED", "ACTIVE", "DEACTIVATED"]) }),
  employee: Employee,
  organization: Organization.pick({ id: true, name: true, status: true }),
});
export type Me = z.infer<typeof Me>;

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
