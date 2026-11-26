import "server-only";
import { isIP } from "node:net";
import { accountClaims, revokeUserAuthTokens, uuidv7, withOrganization } from "@core/db";
import { db } from "./db";

/** Ważność linku do zmiany hasła: 30 minut (02-identity/flows.md). */
export const PASSWORD_RESET_TOKEN_EXPIRES_IN_SECONDS = 30 * 60;

/** Firmy w tych stanach nie mogą resetować hasła ani się logować. */
const BLOCKED_ORGANIZATIONS = new Set(["SUSPENDED", "DELETED"]);

/** Jednolity komunikat dla nieaktualnego, wygasłego lub zużytego linku do zmiany hasła. */
export const INVALID_RESET_LINK_MESSAGE =
  "Ten link do zmiany hasła wygasł lub został już użyty. Poproś o nowy link — jest ważny przez 30 minut.";

function sanitizeIpAddress(value: string | null | undefined): string | null {
  if (!value) return null;
  const candidate = value.split(",")[0]?.trim() ?? "";
  return candidate && isIP(candidate) !== 0 ? candidate : null;
}

/**
 * Zwraca `false` dla kont nieaktywnych (`INVITED`, `DEACTIVATED`) i zablokowanych firm (`SUSPENDED`, `DELETED`),
 * żeby nie wysyłać linku resetu i nie tworzyć hasła przed aktywacją zaproszenia.
 * Konta bez organizacji (`claims === null`) pozostają dozwolone (audyt jest wtedy pomijany).
 */
export async function canRequestPasswordReset(userId: string): Promise<boolean> {
  const claims = await accountClaims(db, userId);
  if (!claims) return true;
  if (claims.accountStatus !== "ACTIVE") return false;
  if (BLOCKED_ORGANIZATIONS.has(claims.organizationStatus)) return false;
  return true;
}

export interface VerificationLookup {
  findVerificationValue: (identifier: string) => Promise<{ expiresAt: Date } | null>;
}

/**
 * Sprawdza (bez zużycia), czy token z linku `/reset-password?token=...` istnieje i nie wygasł.
 */
export async function isPasswordResetTokenValid(
  lookup: VerificationLookup,
  token: string,
  now: Date = new Date(),
): Promise<boolean> {
  const trimmed = token.trim();
  if (!trimmed) return false;
  const verification = await lookup.findVerificationValue(`reset-password:${trimmed}`);
  return verification !== null && verification.expiresAt.getTime() > now.getTime();
}

export interface HandlePasswordResetOptions {
  ipAddress?: string | null | undefined;
  userAgent?: string | null | undefined;
  requestId?: string | null | undefined;
  now?: Date | undefined;
}

/**
 * Wywoływane z haka `onPasswordReset` Better Auth po zmianie hasła i usunięciu sesji:
 * - usuwa wszystkie tokeny dostępu i odświeżania OAuth użytkownika (`revokeUserAuthTokens`),
 *   żeby produkty (np. TimoTime, AvenMail) natychmiast straciły dostęp,
 * - zapisuje wpis audytu `account.password_reset` w firmie konta (aktor = to konto);
 *   konta bez organizacji pomijają wpis audytu.
 */
export async function handlePasswordReset(userId: string, options: HandlePasswordResetOptions = {}): Promise<void> {
  const now = options.now ?? new Date();
  const claims = await accountClaims(db, userId);

  if (!claims) {
    await db.$transaction((tx) => revokeUserAuthTokens(tx, userId));
    return;
  }

  const ipAddress = sanitizeIpAddress(options.ipAddress);
  const userAgent = options.userAgent && options.userAgent.length > 0 ? options.userAgent : null;

  await withOrganization(db, claims.organizationId, async (tx) => {
    const revoked = await revokeUserAuthTokens(tx, userId);
    await tx.auditLog.create({
      data: {
        id: uuidv7(now.getTime()),
        organizationId: claims.organizationId,
        actorType: "ACCOUNT",
        actorAccountId: userId,
        action: "account.password_reset",
        resourceType: "account",
        resourceId: userId,
        metadata: {
          revokedOAuthRefreshes: revoked.refreshTokens,
          revokedOAuthAccesses: revoked.accessTokens,
        },
        ipAddress,
        userAgent,
        requestId: options.requestId ?? null,
      },
    });
  });
}
