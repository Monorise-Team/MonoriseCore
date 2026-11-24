import { randomBytes } from "node:crypto";
import { INVITATION_TTL_MS } from "@core/contracts";
import { hashToken, uuidv7, withOrganization } from "@core/db";
import { createLocalJWKSet, jwtVerify } from "jose";
import { NextRequest } from "next/server";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { POST as acceptInvitationRoute } from "@/app/api/invitations/accept/route";
import { auth } from "@/server/auth";
import { db } from "@/server/db";
import { acceptInvitation, inspectInvitation, INVALID_INVITATION_MESSAGE } from "@/server/invitations";

const PASSWORD = "bardzo-bezpieczne-haslo-43";

let organizationId: string;
let ownerAccountId: string;
let domain: string;
const createdUserIds: string[] = [];

async function seedInvitedUser(options: {
  label: string;
  status?: "PENDING" | "REVOKED" | "EXPIRED" | "ACCEPTED";
  expiresAt?: Date;
}) {
  const token = randomBytes(32).toString("base64url");
  const employeeId = uuidv7();
  const accountId = uuidv7();
  const invitationId = uuidv7();
  const email = `${options.label}-${accountId.slice(-6)}@${domain}`;
  const status = options.status ?? "PENDING";
  const expiresAt = options.expiresAt ?? new Date(Date.now() + INVITATION_TTL_MS);

  await db.authUser.create({
    data: { id: accountId, name: `Jan ${options.label}`, email, emailVerified: false },
  });
  createdUserIds.push(accountId);

  await withOrganization(db, organizationId, async (tx) => {
    await tx.employee.create({
      data: { id: employeeId, organizationId, firstName: "Jan", lastName: options.label, workEmail: email },
    });
    await tx.account.create({
      data: {
        id: accountId,
        organizationId,
        employeeId,
        email,
        normalizedEmail: email,
        status: status === "ACCEPTED" ? "ACTIVE" : "INVITED",
      },
    });
    await tx.invitation.create({
      data: {
        id: invitationId,
        organizationId,
        accountId,
        email,
        normalizedEmail: email,
        tokenHash: hashToken(token),
        status,
        expiresAt,
        invitedByAccountId: ownerAccountId,
        acceptedAt: status === "ACCEPTED" ? new Date() : null,
      },
    });
  });

  return { token, employeeId, accountId, invitationId, email };
}

beforeAll(async () => {
  organizationId = uuidv7();
  ownerAccountId = uuidv7();
  const ownerEmployeeId = uuidv7();
  domain = `${organizationId.slice(-8)}-invite.test`;
  const ownerEmail = `owner@${domain}`;

  await db.authUser.create({
    data: { id: ownerAccountId, name: "Anna Owner", email: ownerEmail, emailVerified: true },
  });
  createdUserIds.push(ownerAccountId);

  await withOrganization(db, organizationId, async (tx) => {
    await tx.organization.create({
      data: { id: organizationId, name: "Acme Zaproszenia", createdVia: "SELF_SIGNUP", status: "ACTIVE" },
    });
    await tx.organizationDomain.create({
      data: {
        id: uuidv7(),
        organizationId,
        domain,
        status: "VERIFIED",
        verificationMethod: "DNS_TXT",
        verifiedAt: new Date(),
        isPrimary: true,
      },
    });
    await tx.employee.create({
      data: { id: ownerEmployeeId, organizationId, firstName: "Anna", lastName: "Owner", workEmail: ownerEmail },
    });
    await tx.account.create({
      data: {
        id: ownerAccountId,
        organizationId,
        employeeId: ownerEmployeeId,
        email: ownerEmail,
        normalizedEmail: ownerEmail,
        status: "ACTIVE",
      },
    });
    await tx.organization.update({ where: { id: organizationId }, data: { ownerAccountId } });
  });
});

afterAll(async () => {
  if (organizationId) {
    await withOrganization(db, organizationId, (tx) => tx.organization.deleteMany({ where: { id: organizationId } }));
  }
  if (createdUserIds.length > 0) {
    await db.authUser.deleteMany({ where: { id: { in: createdUserIds } } });
  }
  await db.$disconnect();
});

describe("akceptacja zaproszeń pracownika", () => {
  it("blokuje logowanie konta INVITED przed aktywacją, a po akceptacji pozwala się zalogować i wydaje token z org_id i employee_id", async () => {
    const invited = await seedInvitedUser({ label: "sukces" });

    // Konto INVITED nie może się zalogować przed aktywacją (brak hasła)
    await expect(auth.api.signInEmail({ body: { email: invited.email, password: PASSWORD } })).rejects.toThrow();

    // Podgląd zaproszenia zwraca nazwę firmy i e-mail
    const inspected = await inspectInvitation(invited.token);
    expect(inspected).toEqual({
      valid: true,
      organizationName: "Acme Zaproszenia",
      email: invited.email,
    });

    // Akceptacja przez route handler POST /api/invitations/accept
    const req = new NextRequest("http://localhost:3100/api/invitations/accept", {
      method: "POST",
      headers: { "content-type": "application/json", "user-agent": "vitest-agent", "x-forwarded-for": "127.0.0.1" },
      body: JSON.stringify({ token: invited.token, password: PASSWORD }),
    });
    const res = await acceptInvitationRoute(req);
    expect(res.status).toBe(200);
    expect(await res.json()).toMatchObject({ data: { activated: true }, error: null });
    // Brak automatycznego logowania (brak ciasteczka sesji)
    expect(res.headers.getSetCookie()).toEqual([]);

    // Stan w bazie: emailVerified=true, account=ACTIVE, invitation=ACCEPTED + acceptedAt, audyt=invitation.accepted
    const authUser = await db.authUser.findUniqueOrThrow({
      where: { id: invited.accountId },
      include: { credentials: true },
    });
    expect(authUser.emailVerified).toBe(true);
    expect(authUser.credentials).toHaveLength(1);
    expect(authUser.credentials[0]?.providerId).toBe("credential");
    expect(authUser.credentials[0]?.accountId).toBe(invited.accountId);

    const dbState = await withOrganization(db, organizationId, async (tx) => ({
      account: await tx.account.findUniqueOrThrow({ where: { id: invited.accountId } }),
      invitation: await tx.invitation.findUniqueOrThrow({ where: { id: invited.invitationId } }),
      audit: await tx.auditLog.findFirstOrThrow({
        where: { action: "invitation.accepted", resourceId: invited.invitationId },
      }),
    }));
    expect(dbState.account.status).toBe("ACTIVE");
    expect(dbState.invitation.status).toBe("ACCEPTED");
    expect(dbState.invitation.acceptedAt).not.toBeNull();
    expect(dbState.audit.actorType).toBe("ACCOUNT");
    expect(dbState.audit.actorAccountId).toBe(invited.accountId);
    expect(dbState.audit.ipAddress).toBe("127.0.0.1");

    // Po aktywacji pracownik loguje się hasłem i dostaje token JWT EdDSA z org_id i employee_id
    const signInResponse = await auth.api.signInEmail({
      body: { email: invited.email, password: PASSWORD },
      asResponse: true,
    });
    expect(signInResponse.status).toBe(200);
    const cookie = signInResponse.headers
      .getSetCookie()
      .map((c) => c.split(";")[0])
      .join("; ");
    const { token: jwt } = await auth.api.getToken({ headers: new Headers({ cookie }) });
    const jwks = createLocalJWKSet(await auth.api.getJwks());
    const { payload, protectedHeader } = await jwtVerify(jwt, jwks, {
      issuer: "http://localhost:3100",
      audience: "http://localhost:3200",
    });
    expect(protectedHeader.alg).toBe("EdDSA");
    expect(payload.sub).toBe(invited.accountId);
    expect(payload.org_id).toBe(organizationId);
    expect(payload.employee_id).toBe(invited.employeeId);
    expect(payload.authz_rev).toBe(0);

    // Ponowne użycie tego samego linku nie działa
    expect(await inspectInvitation(invited.token)).toEqual({ valid: false });
    await expect(acceptInvitation({ token: invited.token, password: PASSWORD })).rejects.toMatchObject({
      status: 409,
      code: "CONFLICT",
      message: INVALID_INVITATION_MESSAGE,
    });
  });

  it("oznacza wygasłe zaproszenie jako EXPIRED i odrzuca cofnięte, nieznane oraz słabe hasło", async () => {
    const baseTime = new Date("2026-11-25T10:00:00.000Z");
    const expiredInvite = await seedInvitedUser({
      label: "wygasle",
      expiresAt: new Date(baseTime.getTime() + 1000),
    });
    const afterExpiry = new Date(baseTime.getTime() + 2000);

    // Wygasły link przy akceptacji: 409 i trwały status EXPIRED w bazie
    await expect(
      acceptInvitation({ token: expiredInvite.token, password: PASSWORD }, { now: afterExpiry }),
    ).rejects.toMatchObject({
      status: 409,
      code: "CONFLICT",
      message: INVALID_INVITATION_MESSAGE,
    });

    const expiredRow = await withOrganization(db, organizationId, (tx) =>
      tx.invitation.findUniqueOrThrow({ where: { id: expiredInvite.invitationId } }),
    );
    expect(expiredRow.status).toBe("EXPIRED");

    // Wygasły link przy inspectInvitation też utrwala EXPIRED
    const expiredInspect = await seedInvitedUser({
      label: "wygasle-podglad",
      expiresAt: new Date(baseTime.getTime() + 1000),
    });
    expect(await inspectInvitation(expiredInspect.token, { now: afterExpiry })).toEqual({ valid: false });
    const expiredInspectRow = await withOrganization(db, organizationId, (tx) =>
      tx.invitation.findUniqueOrThrow({ where: { id: expiredInspect.invitationId } }),
    );
    expect(expiredInspectRow.status).toBe("EXPIRED");

    // Cofnięty link
    const revokedInvite = await seedInvitedUser({ label: "cofniete", status: "REVOKED" });
    expect(await inspectInvitation(revokedInvite.token)).toEqual({ valid: false });
    await expect(acceptInvitation({ token: revokedInvite.token, password: PASSWORD })).rejects.toMatchObject({
      status: 409,
      code: "CONFLICT",
      message: INVALID_INVITATION_MESSAGE,
    });

    // Nieznany token
    expect(await inspectInvitation("nieistniejacy-token")).toEqual({ valid: false });
    await expect(acceptInvitation({ token: "nieistniejacy-token", password: PASSWORD })).rejects.toMatchObject({
      status: 409,
      code: "CONFLICT",
      message: INVALID_INVITATION_MESSAGE,
    });

    // Słabe hasło (< 12 znaków) i zbyt długie (> 128 znaków) -> 422 VALIDATION_FAILED
    const validForWeak = await seedInvitedUser({ label: "slabe" });
    await expect(acceptInvitation({ token: validForWeak.token, password: "za-krotkie" })).rejects.toMatchObject({
      status: 422,
      code: "VALIDATION_FAILED",
    });
    await expect(acceptInvitation({ token: validForWeak.token, password: "x".repeat(129) })).rejects.toMatchObject({
      status: 422,
      code: "VALIDATION_FAILED",
    });
  });

  it("równoległa akceptacja tego samego linku pozwala wygrać dokładnie jednemu żądaniu", async () => {
    const invited = await seedInvitedUser({ label: "rownolegle" });

    const results = await Promise.allSettled([
      acceptInvitation({ token: invited.token, password: PASSWORD }),
      acceptInvitation({ token: invited.token, password: `${PASSWORD}-2` }),
      acceptInvitation({ token: invited.token, password: `${PASSWORD}-3` }),
    ]);

    const fulfilled = results.filter((r) => r.status === "fulfilled");
    const rejected = results.filter((r): r is PromiseRejectedResult => r.status === "rejected");

    expect(fulfilled).toHaveLength(1);
    expect(rejected).toHaveLength(2);
    for (const failure of rejected) {
      expect(failure.reason).toMatchObject({
        status: 409,
        code: "CONFLICT",
        message: INVALID_INVITATION_MESSAGE,
      });
    }

    const credentials = await db.authCredential.findMany({
      where: { userId: invited.accountId, providerId: "credential" },
    });
    expect(credentials).toHaveLength(1);

    const audits = await withOrganization(db, organizationId, (tx) =>
      tx.auditLog.findMany({
        where: { action: "invitation.accepted", resourceId: invited.invitationId },
      }),
    );
    expect(audits).toHaveLength(1);
  });
});
