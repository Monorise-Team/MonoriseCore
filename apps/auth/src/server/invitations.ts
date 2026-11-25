import "server-only";
import { isIP } from "node:net";
import { hashToken, invitationByTokenHash, uuidv7, withOrganization } from "@core/db";
import { auth } from "./auth";
import { db } from "./db";
import { CoreError } from "./errors";

/** Jednolity komunikat dla każdego nieaktualnego linku — nie zdradza stanu ani istnienia zaproszenia. */
export const INVALID_INVITATION_MESSAGE = "Link jest nieaktualny. Poproś o nowe zaproszenie.";

const BLOCKED_ORGANIZATIONS = new Set(["SUSPENDED", "DELETED"]);

export type InvitationInspection = { valid: true; organizationName: string; email: string } | { valid: false };

export interface AcceptInvitationOptions {
  ipAddress?: string | null | undefined;
  userAgent?: string | null | undefined;
  requestId?: string | null | undefined;
  now?: Date | undefined;
}

function sanitizeIpAddress(value: string | null | undefined): string | null {
  if (!value) return null;
  const candidate = value.split(",")[0]?.trim() ?? "";
  return candidate && isIP(candidate) !== 0 ? candidate : null;
}

/**
 * Sprawdza token z linku aktywacyjnego dla ekranu `/invite?token=...`.
 * Wyszukuje firmę i zaproszenie przez wąską funkcję `invitation_by_token_hash`, a resztę wykonuje w RLS.
 * Jeśli zaproszenie `PENDING` wygasło, utrwala status `EXPIRED`. Nie ujawnia szczegółów nieaktualnych linków.
 */
export async function inspectInvitation(token: string, options?: { now?: Date }): Promise<InvitationInspection> {
  const trimmed = token.trim();
  if (!trimmed) return { valid: false };

  const now = options?.now ?? new Date();
  const tokenHash = hashToken(trimmed);
  const ref = await invitationByTokenHash(db, tokenHash);
  if (!ref) return { valid: false };

  return withOrganization(db, ref.organizationId, async (tx) => {
    const invitation = await tx.invitation.findUnique({
      where: { id: ref.invitationId },
      include: {
        organization: { select: { name: true, status: true } },
        account: { select: { status: true } },
      },
    });
    if (!invitation || invitation.tokenHash !== tokenHash) {
      return { valid: false };
    }
    if (invitation.status === "PENDING" && invitation.expiresAt.getTime() <= now.getTime()) {
      await tx.invitation.update({
        where: { id: invitation.id },
        data: { status: "EXPIRED" },
      });
      return { valid: false };
    }
    if (
      invitation.status !== "PENDING" ||
      invitation.account.status !== "INVITED" ||
      BLOCKED_ORGANIZATIONS.has(invitation.organization.status)
    ) {
      return { valid: false };
    }
    return {
      valid: true,
      organizationName: invitation.organization.name,
      email: invitation.email,
    };
  });
}

/**
 * Aktywuje konto pracownika na podstawie linku z zaproszenia (ADR-0021, ADR-0024):
 * 1. Sprawdza reguły hasła skonfigurowane w Better Auth (min. 12, maks. 128 znaków) i hashuje hasło
 *    funkcją `password.hash` z kontekstu Better Auth (`auth.$context`).
 * 2. W jednej transakcji z blokadą doradczą na zaproszeniu (równoległe żądania -> wygrywa dokładnie jedno):
 *    - weryfikuje ważność i status zaproszenia (wygasłe utrwala jako `EXPIRED`),
 *    - zapisuje poświadczenie hasła (`providerId = "credential"`, `accountId = userId`) zgodne z Better Auth,
 *    - oznacza adres jako zweryfikowany (`emailVerified = true`), konto jako `ACTIVE`, zaproszenie jako `ACCEPTED`,
 *    - dopisuje wpis `invitation.accepted` w dzienniku zdarzeń (aktor = aktywowane konto).
 * Nie tworzy sesji — użytkownik loguje się na `/sign-in`.
 */
export async function acceptInvitation(
  input: { token: string; password: string },
  options?: AcceptInvitationOptions,
): Promise<{ activated: true }> {
  const now = options?.now ?? new Date();
  const authCtx = await auth.$context;
  const minPasswordLength = authCtx.options.emailAndPassword?.minPasswordLength ?? 12;
  const maxPasswordLength = authCtx.options.emailAndPassword?.maxPasswordLength ?? 128;

  if (input.password.length < minPasswordLength) {
    throw new CoreError("VALIDATION_FAILED", 422, `Hasło musi mieć co najmniej ${minPasswordLength} znaków`, [
      { field: "password", message: `Hasło musi mieć co najmniej ${minPasswordLength} znaków` },
    ]);
  }
  if (input.password.length > maxPasswordLength) {
    throw new CoreError("VALIDATION_FAILED", 422, `Hasło może mieć co najwyżej ${maxPasswordLength} znaków`, [
      { field: "password", message: `Hasło może mieć co najwyżej ${maxPasswordLength} znaków` },
    ]);
  }

  const trimmedToken = input.token.trim();
  if (!trimmedToken) {
    throw new CoreError("CONFLICT", 409, INVALID_INVITATION_MESSAGE);
  }

  const tokenHash = hashToken(trimmedToken);
  const ref = await invitationByTokenHash(db, tokenHash);
  if (!ref) {
    throw new CoreError("CONFLICT", 409, INVALID_INVITATION_MESSAGE);
  }

  // Hashowanie hasła poza blokadą transakcji bazy, z użyciem dokładnie tego samego mechanizmu co Better Auth.
  const passwordHash = await authCtx.password.hash(input.password);
  const ipAddress = sanitizeIpAddress(options?.ipAddress);
  const userAgent = options?.userAgent && options.userAgent.length > 0 ? options.userAgent : null;

  const outcome = await withOrganization(db, ref.organizationId, async (tx) => {
    await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtextextended('invitation:' || ${ref.invitationId}::uuid::text, 0))`;

    const invitation = await tx.invitation.findUnique({
      where: { id: ref.invitationId },
      include: {
        account: { select: { id: true, status: true } },
        organization: { select: { status: true } },
      },
    });
    if (!invitation || invitation.tokenHash !== tokenHash) {
      return { ok: false as const };
    }

    if (invitation.status === "PENDING" && invitation.expiresAt.getTime() <= now.getTime()) {
      await tx.invitation.update({
        where: { id: invitation.id },
        data: { status: "EXPIRED" },
      });
      return { ok: false as const };
    }

    if (
      invitation.status !== "PENDING" ||
      invitation.account.status !== "INVITED" ||
      BLOCKED_ORGANIZATIONS.has(invitation.organization.status)
    ) {
      return { ok: false as const };
    }

    const existingCredential = await tx.authCredential.findFirst({
      where: { userId: invitation.accountId, providerId: "credential" },
      select: { id: true },
    });
    if (existingCredential) {
      return { ok: false as const };
    }

    await tx.invitation.update({
      where: { id: invitation.id },
      data: { status: "ACCEPTED", acceptedAt: now },
    });

    await tx.account.update({
      where: { id: invitation.accountId },
      data: { status: "ACTIVE" },
    });

    await tx.authUser.update({
      where: { id: invitation.accountId },
      data: { emailVerified: true },
    });

    await tx.authCredential.create({
      data: {
        id: uuidv7(now.getTime()),
        userId: invitation.accountId,
        accountId: invitation.accountId,
        providerId: "credential",
        password: passwordHash,
      },
    });

    await tx.auditLog.create({
      data: {
        id: uuidv7(now.getTime()),
        organizationId: ref.organizationId,
        actorType: "ACCOUNT",
        actorAccountId: invitation.accountId,
        action: "invitation.accepted",
        resourceType: "invitation",
        resourceId: invitation.id,
        metadata: { accountId: invitation.accountId },
        ipAddress,
        userAgent,
        requestId: options?.requestId ?? null,
      },
    });

    return { ok: true as const };
  });

  if (!outcome.ok) {
    throw new CoreError("CONFLICT", 409, INVALID_INVITATION_MESSAGE);
  }

  return { activated: true };
}
