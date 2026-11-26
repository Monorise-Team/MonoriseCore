import { randomBytes } from "node:crypto";
import {
  emailDomain,
  INVITATION_TTL_MS,
  isFreeEmailDomain,
  normalizeEmail,
  type ApiErrorBody,
  type ErrorCode,
  type Invitation,
  type InvitationDelivery,
  type InvitationStatus,
  type MailDeliveryStatus,
} from "@core/contracts";
import { domainOwner, hashToken, uuidv7, withOrganization, type Prisma, type PrismaClient, type Tx } from "@core/db";
import { z } from "zod";
import { lockOrganizationDomains } from "./domains.js";

const UuidSchema = z.uuid();
const EmailSchema = z.email().max(254);

/** Pola kolejki `mail_outbox` ujawniane w API (nigdy nie obejmują wewnętrznego `lastError`). */
export const MAIL_OUTBOX_DELIVERY_SELECT = {
  status: true,
  attempts: true,
  lastAttemptAt: true,
  sentAt: true,
} as const;

export class InvitationError extends Error {
  constructor(
    readonly status: number,
    readonly code: ErrorCode,
    message: string,
    readonly details: ApiErrorBody["details"] = [],
  ) {
    super(message);
  }
}

export type InvitationActor =
  | {
      type: "ACCOUNT";
      accountId: string;
      ipAddress?: string | null;
      userAgent?: string | null;
      requestId?: string | null;
      metadata?: Record<string, Prisma.InputJsonValue>;
    }
  | {
      type: "SYSTEM";
      metadata?: Record<string, Prisma.InputJsonValue>;
    };

export interface CreateInvitationInput {
  organizationId: string;
  email: string;
  firstName?: string | undefined;
  lastName?: string | undefined;
  employeeId?: string | undefined;
  invitedBy: string | null;
  actor: InvitationActor;
  now?: Date | undefined;
}

export interface CreateInvitationResult {
  invitation: Invitation;
  mailJobId: string;
}

export interface ResendInvitationInput {
  organizationId: string;
  invitationId: string;
  actor: InvitationActor;
  now?: Date | undefined;
}

export interface ResendInvitationResult {
  invitation: Invitation;
  mailJobId: string;
}

export interface RevokeInvitationInput {
  organizationId: string;
  invitationId: string;
  actor: InvitationActor;
  now?: Date | undefined;
}

export interface CliCreateInvitationInput {
  /** Identyfikator UUID firmy albo jej zarejestrowana domena (np. `acme.com`). */
  organization: string;
  email: string;
  firstName?: string | undefined;
  lastName?: string | undefined;
  employeeId?: string | undefined;
  now?: Date | undefined;
}

export interface SerializableMailDeliveryRow {
  status: MailDeliveryStatus;
  attempts: number;
  lastAttemptAt: Date | null;
  sentAt: Date | null;
}

export interface SerializableInvitationRow {
  id: string;
  accountId: string;
  email: string;
  status: InvitationStatus;
  expiresAt: Date;
  invitedByAccountId: string | null;
  acceptedAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
  account: { employeeId: string };
  mailOutbox?: readonly SerializableMailDeliveryRow[] | undefined;
}

/** Wyznacza rzeczywisty status zaproszenia: wygasłe `PENDING` raportujemy jako `EXPIRED`. */
export function effectiveInvitationStatus(
  status: InvitationStatus,
  expiresAt: Date,
  now: Date = new Date(),
): InvitationStatus {
  if (status === "PENDING" && expiresAt.getTime() <= now.getTime()) {
    return "EXPIRED";
  }
  return status;
}

/** Serializuje stan dostarczenia wiadomości e-mail z najnowszego wiersza `mail_outbox` (bez `lastError`). */
export function serializeInvitationDelivery(row?: SerializableMailDeliveryRow | null): InvitationDelivery {
  if (!row) {
    return {
      status: null,
      attempts: 0,
      lastAttemptAt: null,
      sentAt: null,
    };
  }
  return {
    status: row.status,
    attempts: row.attempts,
    lastAttemptAt: row.lastAttemptAt ? row.lastAttemptAt.toISOString() : null,
    sentAt: row.sentAt ? row.sentAt.toISOString() : null,
  };
}

export function serializeInvitation(row: SerializableInvitationRow, now: Date = new Date()): Invitation {
  return {
    id: row.id,
    accountId: row.accountId,
    employeeId: row.account.employeeId,
    email: row.email,
    status: effectiveInvitationStatus(row.status, row.expiresAt, now),
    expiresAt: row.expiresAt.toISOString(),
    invitedByAccountId: row.invitedByAccountId,
    acceptedAt: row.acceptedAt ? row.acceptedAt.toISOString() : null,
    delivery: serializeInvitationDelivery(row.mailOutbox?.[0]),
    createdAt: row.createdAt.toISOString(),
    updatedAt: row.updatedAt.toISOString(),
  };
}

export function buildInviteUrl(token: string, authUrl?: string): string {
  const base = (authUrl ?? process.env.CORE_AUTH_URL ?? "http://localhost:3100").replace(/\/+$/, "");
  return `${base}/invite?token=${encodeURIComponent(token)}`;
}

export function generateInvitationToken(): string {
  return randomBytes(32).toString("base64url");
}

function isUniqueViolation(error: unknown): boolean {
  const err = error as { code?: string; message?: string } | null;
  if (err?.code === "P2002" || err?.code === "23505") return true;
  return /duplicate key value violates unique constraint/i.test(String(err?.message ?? ""));
}

/** Serializuje operacje na pojedynczym zaproszeniu (resend, revoke, wysyłka w workerze, akceptacja) do końca transakcji. */
export async function lockInvitation(tx: Tx, invitationId: string): Promise<void> {
  await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtextextended('invitation:' || ${invitationId}::uuid::text, 0))`;
}

export async function resolveInviterName(tx: Tx, accountId: string | null): Promise<string | null> {
  if (!accountId) return null;
  const inviter = await tx.account.findUnique({
    where: { id: accountId },
    select: { employee: { select: { firstName: true, lastName: true } } },
  });
  if (!inviter) return null;
  return `${inviter.employee.firstName} ${inviter.employee.lastName}`;
}

async function writeInvitationAudit(
  tx: Tx,
  organizationId: string,
  actor: InvitationActor,
  entry: {
    action: "invitation.created" | "invitation.resent" | "invitation.revoked";
    invitationId: string;
    metadata: Record<string, Prisma.InputJsonValue>;
  },
): Promise<void> {
  const metadata: Record<string, Prisma.InputJsonValue> = {
    ...entry.metadata,
    ...(actor.metadata ?? {}),
  };

  await tx.auditLog.create({
    data: {
      id: uuidv7(),
      organizationId,
      actorType: actor.type,
      actorAccountId: actor.type === "ACCOUNT" ? actor.accountId : null,
      action: entry.action,
      resourceType: "invitation",
      resourceId: entry.invitationId,
      metadata,
      ipAddress: actor.type === "ACCOUNT" ? (actor.ipAddress ?? null) : null,
      userAgent: actor.type === "ACCOUNT" ? (actor.userAgent ?? null) : null,
      requestId: actor.type === "ACCOUNT" ? (actor.requestId ?? null) : null,
    },
  });
}

/**
 * Tworzy zaproszenie pracownika w kontekście transakcji firmy (`withOrganization`):
 * 1. Sprawdza, czy domena adresu e-mail należy do zweryfikowanych domen firmy (nigdy darmowa skrzynka).
 * 2. Sprawdza, czy adres nie jest zajęty przez żadne konto logowania (`auth.users`) ani konto firmy.
 * 3. Używa istniejącego pracownika bez konta (`employeeId`) albo tworzy nowego pracownika.
 * 4. Tworzy konto logowania (`auth.users` bez hasła, `emailVerified = false`), konto firmy (`INVITED`)
 *    oraz zaproszenie ważne 7 dni ze skrótem losowego tokenu, którego nikt nie otrzymuje.
 * 5. Zapisuje wpis w dzienniku zdarzeń (`invitation.created`) oraz zadanie w transakcyjnej kolejce
 *    poczty (`mail_outbox`, `PENDING`); faktyczny token aktywacyjny powstaje dopiero przy wysyłce.
 */
export async function createInvitation(tx: Tx, input: CreateInvitationInput): Promise<CreateInvitationResult> {
  const now = input.now ?? new Date();

  const normalized = normalizeEmail(input.email);
  if (!EmailSchema.safeParse(normalized).success) {
    throw new InvitationError(422, "VALIDATION_FAILED", "Nieprawidłowy adres e-mail", [
      { field: "email", message: "Podaj poprawny adres e-mail" },
    ]);
  }

  const domain = emailDomain(normalized);
  if (!domain || isFreeEmailDomain(domain)) {
    throw new InvitationError(
      422,
      "VALIDATION_FAILED",
      "Adres zaproszenia nie może należeć do darmowej skrzynki pocztowej",
      [{ field: "email", message: "Darmowe domeny pocztowe nie mogą należeć do firmy" }],
    );
  }

  const organization = await tx.organization.findUnique({
    where: { id: input.organizationId },
    select: { id: true },
  });
  if (!organization) {
    throw new InvitationError(404, "NOT_FOUND", "Nie znaleziono firmy");
  }

  // Serializujemy względem usuwania domen firmy (DELETE /organization/domains/{domainId})
  await lockOrganizationDomains(tx, input.organizationId);

  const verifiedDomain = await tx.organizationDomain.findFirst({
    where: { domain, status: "VERIFIED" },
    select: { id: true },
  });
  if (!verifiedDomain) {
    throw new InvitationError(
      422,
      "VALIDATION_FAILED",
      "Adres zaproszenia musi należeć do zweryfikowanej domeny firmy",
      [{ field: "email", message: "Domena adresu e-mail nie jest zweryfikowaną domeną tej firmy" }],
    );
  }

  let employeeId: string;
  let firstName: string;
  let lastName: string;
  let backfillWorkEmail = false;

  if (input.employeeId !== undefined) {
    const employee = await tx.employee.findUnique({
      where: { id: input.employeeId },
      select: {
        id: true,
        firstName: true,
        lastName: true,
        workEmail: true,
        status: true,
        account: { select: { id: true } },
      },
    });
    if (!employee) {
      throw new InvitationError(404, "NOT_FOUND", "Nie znaleziono pracownika");
    }
    if (employee.account !== null) {
      throw new InvitationError(409, "CONFLICT", "Ten pracownik ma już konto");
    }
    if (employee.status !== "ACTIVE") {
      throw new InvitationError(409, "CONFLICT", "Nie można zaprosić pracownika o statusie innym niż ACTIVE");
    }
    employeeId = employee.id;
    firstName = employee.firstName;
    lastName = employee.lastName;
    backfillWorkEmail = employee.workEmail === null;
  } else {
    const trimmedFirst = input.firstName?.trim() ?? "";
    const trimmedLast = input.lastName?.trim() ?? "";
    const missing: ApiErrorBody["details"] = [];
    if (!trimmedFirst) {
      missing.push({ field: "firstName", message: "Imię jest wymagane, gdy nie podano employeeId" });
    }
    if (!trimmedLast) {
      missing.push({ field: "lastName", message: "Nazwisko jest wymagane, gdy nie podano employeeId" });
    }
    if (missing.length > 0) {
      throw new InvitationError(422, "VALIDATION_FAILED", "Błędne dane wejściowe", missing);
    }
    firstName = trimmedFirst;
    lastName = trimmedLast;
    employeeId = uuidv7(now.getTime());
  }

  // Globalne sprawdzenie adresu e-mail (auth.users bez RLS + konta bieżącej firmy) bez zdradzania innych firm.
  const [existingAuthUser, existingAccount] = await Promise.all([
    tx.authUser.findFirst({
      where: { email: { equals: normalized, mode: "insensitive" } },
      select: { id: true },
    }),
    tx.account.findFirst({
      where: { normalizedEmail: normalized },
      select: { id: true },
    }),
  ]);
  if (existingAuthUser || existingAccount) {
    throw new InvitationError(409, "CONFLICT", "Nie można użyć tego adresu e-mail");
  }

  const accountId = uuidv7(now.getTime());
  const invitationId = uuidv7(now.getTime());
  // Skrót świeżego losowego tokenu, którego nikt nie otrzymuje; właściwy token powstanie przy wysyłce z mail_outbox.
  const tokenHash = hashToken(generateInvitationToken());
  const expiresAt = new Date(now.getTime() + INVITATION_TTL_MS);

  let created: SerializableInvitationRow;
  try {
    if (input.employeeId === undefined) {
      await tx.employee.create({
        data: {
          id: employeeId,
          organizationId: input.organizationId,
          firstName,
          lastName,
          workEmail: normalized,
        },
      });
    } else if (backfillWorkEmail) {
      await tx.employee.update({
        where: { id: employeeId },
        data: { workEmail: normalized },
      });
    }

    await tx.authUser.create({
      data: {
        id: accountId,
        name: `${firstName} ${lastName}`,
        email: normalized,
        emailVerified: false,
      },
    });

    await tx.account.create({
      data: {
        id: accountId,
        organizationId: input.organizationId,
        employeeId,
        email: normalized,
        normalizedEmail: normalized,
        status: "INVITED",
      },
    });

    created = await tx.invitation.create({
      data: {
        id: invitationId,
        organizationId: input.organizationId,
        accountId,
        email: normalized,
        normalizedEmail: normalized,
        tokenHash,
        status: "PENDING",
        expiresAt,
        invitedByAccountId: input.invitedBy,
        acceptedAt: null,
      },
      include: {
        account: { select: { employeeId: true } },
      },
    });
  } catch (error) {
    if (isUniqueViolation(error)) {
      throw new InvitationError(409, "CONFLICT", "Nie można użyć tego adresu e-mail");
    }
    throw error;
  }

  const mailJob = await tx.mailOutbox.create({
    data: {
      id: uuidv7(now.getTime()),
      organizationId: input.organizationId,
      kind: "INVITATION",
      invitationId: created.id,
      status: "PENDING",
      attempts: 0,
      nextAttemptAt: now,
      createdAt: now,
      updatedAt: now,
    },
    select: {
      id: true,
      ...MAIL_OUTBOX_DELIVERY_SELECT,
    },
  });

  await writeInvitationAudit(tx, input.organizationId, input.actor, {
    action: "invitation.created",
    invitationId: created.id,
    metadata: {
      accountId,
      employeeId,
      existingEmployee: input.employeeId !== undefined,
    },
  });

  return {
    invitation: serializeInvitation({ ...created, mailOutbox: [mailJob] }, now),
    mailJobId: mailJob.id,
  };
}

/**
 * Ponownie wysyła zaproszenie (`PENDING`, `EXPIRED` lub `REVOKED`) dla konta w statusie `INVITED`:
 * natychmiast unieważnia poprzedni link (zapisuje skrót świeżego losowego tokenu, którego nikt nie otrzymuje),
 * ustawia nowy 7-dniowy termin ważności i status `PENDING`, anuluje poprzednie oczekujące zadania w `mail_outbox`,
 * kolejkuje nowe zadanie wysyłki i zapisuje wpis audytu `invitation.resent`.
 */
export async function resendInvitation(tx: Tx, input: ResendInvitationInput): Promise<ResendInvitationResult> {
  const now = input.now ?? new Date();

  await lockInvitation(tx, input.invitationId);

  const invitation = await tx.invitation.findUnique({
    where: { id: input.invitationId },
    include: {
      account: { select: { id: true, employeeId: true, status: true } },
    },
  });
  if (!invitation) {
    throw new InvitationError(404, "NOT_FOUND", "Nie znaleziono zaproszenia");
  }

  if (invitation.status === "ACCEPTED" || invitation.account.status !== "INVITED") {
    throw new InvitationError(409, "CONFLICT", "Nie można ponownie wysłać zaakceptowanego zaproszenia");
  }

  const previousStatus = effectiveInvitationStatus(invitation.status, invitation.expiresAt, now);
  // Natychmiastowe unieważnienie poprzedniego linku; właściwy token powstanie przy wysyłce z mail_outbox.
  const tokenHash = hashToken(generateInvitationToken());
  const expiresAt = new Date(now.getTime() + INVITATION_TTL_MS);

  let updated: SerializableInvitationRow;
  try {
    updated = await tx.invitation.update({
      where: { id: invitation.id },
      data: {
        tokenHash,
        status: "PENDING",
        expiresAt,
        acceptedAt: null,
      },
      include: {
        account: { select: { employeeId: true } },
      },
    });
  } catch (error) {
    if (isUniqueViolation(error)) {
      throw new InvitationError(409, "CONFLICT", "Dla tego konta istnieje już aktywne zaproszenie");
    }
    throw error;
  }

  await tx.mailOutbox.updateMany({
    where: {
      organizationId: input.organizationId,
      invitationId: updated.id,
      status: "PENDING",
    },
    data: {
      status: "CANCELLED",
      lockedUntil: null,
      updatedAt: now,
    },
  });

  // Pilnujemy ściśle rosnącego createdAt względem poprzedniego zadania tego zaproszenia (także przy
  // stałym zegarze w testach albo dwóch wywołaniach w tej samej milisekundzie).
  const latestExisting = await tx.mailOutbox.findFirst({
    where: { organizationId: input.organizationId, invitationId: updated.id },
    orderBy: [{ createdAt: "desc" }, { id: "desc" }],
    select: { createdAt: true },
  });
  const jobCreatedAt =
    latestExisting && latestExisting.createdAt.getTime() >= now.getTime()
      ? new Date(latestExisting.createdAt.getTime() + 1)
      : now;

  const mailJob = await tx.mailOutbox.create({
    data: {
      id: uuidv7(jobCreatedAt.getTime()),
      organizationId: input.organizationId,
      kind: "INVITATION",
      invitationId: updated.id,
      status: "PENDING",
      attempts: 0,
      nextAttemptAt: now,
      createdAt: jobCreatedAt,
      updatedAt: jobCreatedAt,
    },
    select: {
      id: true,
      ...MAIL_OUTBOX_DELIVERY_SELECT,
    },
  });

  await writeInvitationAudit(tx, input.organizationId, input.actor, {
    action: "invitation.resent",
    invitationId: updated.id,
    metadata: {
      accountId: updated.accountId,
      previousStatus,
    },
  });

  return {
    invitation: serializeInvitation({ ...updated, mailOutbox: [mailJob] }, now),
    mailJobId: mailJob.id,
  };
}

/**
 * Cofa oczekujące zaproszenie (`PENDING` -> `REVOKED`) i anuluje oczekujące zadania wysyłki w `mail_outbox`.
 * Konto pozostaje w statusie `INVITED`, a zaproszenie można później wysłać ponownie przez `resendInvitation`.
 */
export async function revokeInvitation(tx: Tx, input: RevokeInvitationInput): Promise<void> {
  const now = input.now ?? new Date();

  await lockInvitation(tx, input.invitationId);

  const invitation = await tx.invitation.findUnique({
    where: { id: input.invitationId },
    select: { id: true, accountId: true, status: true, expiresAt: true },
  });
  if (!invitation) {
    throw new InvitationError(404, "NOT_FOUND", "Nie znaleziono zaproszenia");
  }

  if (effectiveInvitationStatus(invitation.status, invitation.expiresAt, now) !== "PENDING") {
    throw new InvitationError(409, "CONFLICT", "Można cofnąć wyłącznie oczekujące zaproszenie");
  }

  await tx.invitation.update({
    where: { id: invitation.id },
    data: { status: "REVOKED" },
  });

  await tx.mailOutbox.updateMany({
    where: {
      organizationId: input.organizationId,
      invitationId: invitation.id,
      status: "PENDING",
    },
    data: {
      status: "CANCELLED",
      lockedUntil: null,
      updatedAt: now,
    },
  });

  await writeInvitationAudit(tx, input.organizationId, input.actor, {
    action: "invitation.revoked",
    invitationId: invitation.id,
    metadata: {
      accountId: invitation.accountId,
    },
  });
}

/**
 * Tworzy zaproszenie z poziomu CLI operatora (aktor `SYSTEM`, `metadata.source = "cli"`) i kolejkuje
 * wysyłkę wiadomości e-mail w `mail_outbox`. Przyjmuje identyfikator UUID firmy albo jej zweryfikowaną domenę.
 */
export async function createInvitationByOrganization(
  db: PrismaClient,
  input: CliCreateInvitationInput,
): Promise<CreateInvitationResult & { organizationId: string }> {
  const trimmedOrg = input.organization.trim();
  if (!trimmedOrg) {
    throw new InvitationError(422, "VALIDATION_FAILED", "Podaj identyfikator lub domenę firmy (--organization)");
  }

  let organizationId: string;
  if (UuidSchema.safeParse(trimmedOrg).success) {
    organizationId = trimmedOrg;
  } else {
    const owner = await domainOwner(db, trimmedOrg.toLowerCase());
    if (!owner) {
      throw new InvitationError(404, "NOT_FOUND", `Nie znaleziono firmy dla domeny "${trimmedOrg}"`);
    }
    organizationId = owner.organizationId;
  }

  const result = await withOrganization(db, organizationId, (tx) =>
    createInvitation(tx, {
      organizationId,
      email: input.email,
      firstName: input.firstName,
      lastName: input.lastName,
      employeeId: input.employeeId,
      invitedBy: null,
      actor: { type: "SYSTEM", metadata: { source: "cli" } },
      now: input.now,
    }),
  );

  return { ...result, organizationId };
}
