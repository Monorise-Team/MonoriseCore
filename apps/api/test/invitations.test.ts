import { CORE_PERMISSIONS, INVITATION_TTL_MS } from "@core/contracts";
import { createDb, hashToken, invitationByTokenHash, uuidv7, withOrganization } from "@core/db";
import { createLocalJWKSet, exportJWK, generateKeyPair, SignJWT, type CryptoKey } from "jose";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import {
  createInvitation,
  createInvitationByOrganization,
  resendInvitation,
  revokeInvitation,
} from "../src/invitations.js";
import { clearSentMails, sentMails } from "../src/mail.js";
import { claimMailJobById, deliverMailJob, deliverPendingMail } from "../src/mail-outbox.js";
import { registerCorePermissions } from "../src/permissions-registry.js";
import { buildServer } from "../src/server.js";
import { createMachineTokenVerifier, createTokenVerifier } from "../src/tokens.js";

const ISSUER = "http://localhost:3100";
const AUDIENCE = "http://localhost:3200";
const AUTH_URL = "http://localhost:3100";

const db = createDb(
  process.env.CORE_TEST_APP_DATABASE_URL ?? "postgresql://core_app:core_app@localhost:5433/monorise_core_test",
);
const ownerDb = createDb(
  process.env.CORE_TEST_DATABASE_URL ?? "postgresql://core_owner:core_owner@localhost:5433/monorise_core_test",
);

interface Identity {
  organizationId: string;
  employeeId: string;
  accountId: string;
}

interface Company extends Identity {
  id: string;
  domain: string;
  pendingDomain: string;
  extraAccountIds: string[];
}

let signingKey: CryptoKey;
let currentNow = new Date("2026-11-25T10:00:00.000Z");
let app: ReturnType<typeof buildServer>;
let acme: Company;
let globex: Company;
let acmeRegular: Identity;
let acmeOrgHr: Identity;
let acmeUnitHr: Identity;
let acmeUnitId: string;

async function createCompany(name: string): Promise<Company> {
  const id = uuidv7();
  const domain = `${id.slice(-8)}-${name.toLowerCase()}.test`;
  const pendingDomain = `pending-${domain}`;
  const employeeId = uuidv7();
  const accountId = uuidv7();
  const email = `anna@${domain}`;

  await db.authUser.create({ data: { id: accountId, name: `Anna ${name}`, email, emailVerified: true } });
  await withOrganization(db, id, async (tx) => {
    await tx.organization.create({ data: { id, name, createdVia: "SELF_SIGNUP", status: "ACTIVE" } });
    await tx.organizationDomain.create({
      data: {
        id: uuidv7(),
        organizationId: id,
        domain,
        status: "VERIFIED",
        verificationMethod: "DNS_TXT",
        verifiedAt: new Date("2026-11-20T00:00:00.000Z"),
        isPrimary: true,
      },
    });
    await tx.organizationDomain.create({
      data: {
        id: uuidv7(),
        organizationId: id,
        domain: pendingDomain,
        status: "PENDING",
        verificationMethod: "DNS_TXT",
        isPrimary: false,
      },
    });
    await tx.employee.create({ data: { id: employeeId, organizationId: id, firstName: "Anna", lastName: name } });
    await tx.account.create({
      data: { id: accountId, organizationId: id, employeeId, email, normalizedEmail: email, status: "ACTIVE" },
    });
    await tx.organization.update({ where: { id }, data: { ownerAccountId: accountId } });
  });

  return { id, domain, pendingDomain, organizationId: id, employeeId, accountId, extraAccountIds: [] };
}

async function createMember(company: Company, firstName: string, lastName: string): Promise<Identity> {
  const employeeId = uuidv7();
  const accountId = uuidv7();
  const email = `${firstName.toLowerCase()}-${accountId.slice(-6)}@${company.domain}`;
  await db.authUser.create({ data: { id: accountId, name: `${firstName} ${lastName}`, email, emailVerified: true } });
  await withOrganization(db, company.id, async (tx) => {
    await tx.employee.create({ data: { id: employeeId, organizationId: company.id, firstName, lastName } });
    await tx.account.create({
      data: { id: accountId, organizationId: company.id, employeeId, email, normalizedEmail: email, status: "ACTIVE" },
    });
  });
  company.extraAccountIds.push(accountId);
  return { organizationId: company.id, employeeId, accountId };
}

function token(identity: Identity) {
  return new SignJWT({
    org_id: identity.organizationId,
    employee_id: identity.employeeId,
    authz_rev: 0,
    amr: ["pwd"],
  })
    .setProtectedHeader({ alg: "EdDSA" })
    .setIssuer(ISSUER)
    .setAudience(AUDIENCE)
    .setSubject(identity.accountId)
    .setIssuedAt()
    .setExpirationTime("5m")
    .sign(signingKey);
}

function request(method: "GET" | "POST" | "DELETE", url: string, bearer?: string, payload?: Record<string, unknown>) {
  return app.inject({
    method,
    url,
    headers: bearer ? { authorization: `Bearer ${bearer}` } : {},
    ...(payload !== undefined ? { payload } : {}),
  });
}

function extractTokenFromMail(to: string): string {
  const mail = [...sentMails()].reverse().find((m) => m.to === to);
  expect(mail).toBeDefined();
  const match = /https?:\/\/\S+/.exec(mail!.text);
  expect(match).not.toBeNull();
  const parsed = new URL(match![0]);
  expect(parsed.pathname).toBe("/invite");
  const rawToken = parsed.searchParams.get("token");
  expect(rawToken).toBeTruthy();
  return rawToken!;
}

beforeAll(async () => {
  process.env.CORE_SMTP_URL = "memory";
  await registerCorePermissions(db);

  const pair = await generateKeyPair("EdDSA", { crv: "Ed25519" });
  signingKey = pair.privateKey;
  const jwk = { ...(await exportJWK(pair.publicKey)), alg: "EdDSA", kid: "test-inv" };
  const tokenOptions = { keys: createLocalJWKSet({ keys: [jwk] }), issuer: ISSUER, audience: AUDIENCE };

  app = buildServer({
    db,
    verifyToken: createTokenVerifier(tokenOptions),
    verifyMachineToken: createMachineTokenVerifier(tokenOptions),
    now: () => currentNow,
  });

  acme = await createCompany("Acme");
  globex = await createCompany("Globex");
  acmeRegular = await createMember(acme, "Piotr", "Zwykly");
  acmeOrgHr = await createMember(acme, "Marta", "Kadry");
  acmeUnitHr = await createMember(acme, "Tomasz", "Oddzial");

  acmeUnitId = uuidv7();
  const hrRoleId = uuidv7();
  const empManagePerm = await db.permission.findUniqueOrThrow({
    where: { key: CORE_PERMISSIONS.keys["employees.manage"] },
    select: { id: true },
  });

  await withOrganization(db, acme.id, async (tx) => {
    await tx.organizationUnit.create({
      data: { id: acmeUnitId, organizationId: acme.id, name: "Kraków", type: "BRANCH" },
    });
    await tx.role.create({
      data: { id: hrRoleId, organizationId: acme.id, productId: null, name: "Kadry" },
    });
    await tx.rolePermission.create({
      data: { roleId: hrRoleId, permissionId: empManagePerm.id },
    });
    await tx.roleAssignment.create({
      data: {
        id: uuidv7(),
        organizationId: acme.id,
        accountId: acmeOrgHr.accountId,
        roleId: hrRoleId,
        scopeType: "ORGANIZATION",
        grantedByAccountId: acme.accountId,
      },
    });
    await tx.roleAssignment.create({
      data: {
        id: uuidv7(),
        organizationId: acme.id,
        accountId: acmeUnitHr.accountId,
        roleId: hrRoleId,
        scopeType: "UNIT",
        scopeId: acmeUnitId,
        grantedByAccountId: acme.accountId,
      },
    });
  });
});

beforeEach(async () => {
  clearSentMails();
  currentNow = new Date("2026-11-25T10:00:00.000Z");
  // Anulujemy ewentualne nieodebrane zadania z poprzednich przypadków testowych dla izolacji kolejki
  for (const company of [acme, globex]) {
    if (!company) continue;
    await withOrganization(db, company.id, (tx) =>
      tx.mailOutbox.updateMany({
        where: { status: "PENDING" },
        data: { status: "CANCELLED", lockedUntil: null },
      }),
    );
  }
});

afterAll(async () => {
  await app?.close();
  for (const company of [acme, globex]) {
    if (!company) continue;
    const allAccounts = await withOrganization(db, company.id, (tx) => tx.account.findMany({ select: { id: true } }));
    const ids = [...new Set([company.accountId, ...company.extraAccountIds, ...allAccounts.map((a) => a.id)])];
    await withOrganization(db, company.id, async (tx) => {
      await tx.roleAssignment.deleteMany({});
      await tx.organization.delete({ where: { id: company.id } });
    });
    await db.authUser.deleteMany({ where: { id: { in: ids } } });
  }
  await db.$disconnect();
  await ownerDb.$disconnect();
});

describe("Zaproszenia pracowników — Core API i serwis", () => {
  it("tworzy zaproszenie z kontem INVITED, wysyła e-mail z linkiem na 7 dni, nie zwraca tokenu i zapisuje audyt", async () => {
    const ownerToken = await token(acme);
    const email = `Jan.Kowalski@${acme.domain.toUpperCase()}`;

    const res = await request("POST", "/core/v1/invitations", ownerToken, {
      email,
      firstName: "Jan",
      lastName: "Kowalski",
    });
    expect(res.statusCode).toBe(201);
    const body = res.json();
    expect(body.error).toBeNull();

    const inv = body.data;
    expect(inv).toMatchObject({
      email: email.toLowerCase(),
      status: "PENDING",
      invitedByAccountId: acme.accountId,
      acceptedAt: null,
      delivery: {
        status: "PENDING",
        attempts: 0,
        lastAttemptAt: null,
        sentAt: null,
      },
    });
    expect(inv).not.toHaveProperty("token");
    expect(inv).not.toHaveProperty("tokenHash");
    expect(inv.delivery).not.toHaveProperty("lastError");
    expect(Date.parse(inv.expiresAt) - currentNow.getTime()).toBe(INVITATION_TTL_MS);

    // W trakcie żądania HTTP żaden e-mail jeszcze nie wychodzi — dostarcza go kolejka mail_outbox po COMMIT
    expect(sentMails()).toHaveLength(0);
    const deliverySummary = await deliverPendingMail(db, { authUrl: AUTH_URL, now: currentNow });
    expect(deliverySummary).toMatchObject({ claimed: 1, sent: 1, retried: 0, failed: 0, cancelled: 0 });

    // Lista pracowników pokazuje stan konta: zaproszony Jan (INVITED) i aktywna Anna (ACTIVE)
    const employees = (await request("GET", "/core/v1/employees?limit=100", ownerToken)).json().data as Array<{
      id: string;
      accountStatus: string | null;
    }>;
    expect(employees.find((employee) => employee.id === inv.employeeId)?.accountStatus).toBe("INVITED");
    expect(employees.find((employee) => employee.id === acme.employeeId)?.accountStatus).toBe("ACTIVE");

    // E-mail przechwycony w pamięci zawiera nazwę firmy, zapraszającego i link /invite?token=...
    const rawToken = extractTokenFromMail(inv.email);
    const mail = sentMails().find((m) => m.to === inv.email)!;
    expect(mail.subject).toBe("Zaproszenie do Monorise od firmy Acme");
    expect(mail.text).toContain("Anna Acme");
    expect(mail.text).toContain("Acme");
    expect(mail.text).toContain(`${AUTH_URL}/invite?token=${rawToken}`);

    // GET /invitations odzwierciedla stan dostarczenia SENT
    const listedAfterSend = (await request("GET", "/core/v1/invitations", ownerToken)).json().data as Array<{
      id: string;
      delivery: { status: string | null; attempts: number; lastAttemptAt: string | null; sentAt: string | null };
    }>;
    expect(listedAfterSend.find((row) => row.id === inv.id)?.delivery).toEqual({
      status: "SENT",
      attempts: 1,
      lastAttemptAt: currentNow.toISOString(),
      sentAt: currentNow.toISOString(),
    });

    // W bazie: auth.users (bez hasła, emailVerified=false), account (INVITED), invitation (tylko hashToken)
    const authUser = await db.authUser.findUniqueOrThrow({
      where: { id: inv.accountId },
      include: { credentials: true },
    });
    expect(authUser.email).toBe(inv.email);
    expect(authUser.name).toBe("Jan Kowalski");
    expect(authUser.emailVerified).toBe(false);
    expect(authUser.credentials).toEqual([]);

    const dbState = await withOrganization(db, acme.id, async (tx) => ({
      account: await tx.account.findUniqueOrThrow({ where: { id: inv.accountId } }),
      employee: await tx.employee.findUniqueOrThrow({ where: { id: inv.employeeId } }),
      invitation: await tx.invitation.findUniqueOrThrow({ where: { id: inv.id } }),
      audit: await tx.auditLog.findFirstOrThrow({
        where: { action: "invitation.created", resourceId: inv.id },
      }),
    }));
    expect(dbState.account.status).toBe("INVITED");
    expect(dbState.employee.workEmail).toBe(inv.email);
    expect(dbState.invitation.tokenHash).toBe(hashToken(rawToken));
    expect(dbState.invitation.tokenHash).not.toBe(rawToken);
    expect(dbState.audit.actorType).toBe("ACCOUNT");
    expect(dbState.audit.actorAccountId).toBe(acme.accountId);
    expect(JSON.stringify(dbState.audit.metadata)).not.toContain(rawToken);
    expect(dbState.audit.metadata).toMatchObject({
      accountId: inv.accountId,
      employeeId: inv.employeeId,
      existingEmployee: false,
    });
  });

  it("odrzuca darmowe skrzynki, niezweryfikowaną domenę, cudzą domenę oraz istniejące adresy e-mail", async () => {
    const ownerToken = await token(acme);

    // Darmowa skrzynka -> 422
    const freeRes = await request("POST", "/core/v1/invitations", ownerToken, {
      email: "jan@gmail.com",
      firstName: "Jan",
      lastName: "Nowak",
    });
    expect(freeRes.statusCode).toBe(422);
    expect(freeRes.json().error.code).toBe("VALIDATION_FAILED");

    const wpRes = await request("POST", "/core/v1/invitations", ownerToken, {
      email: "jan@wp.pl",
      firstName: "Jan",
      lastName: "Nowak",
    });
    expect(wpRes.statusCode).toBe(422);

    // Domena PENDING firmy -> 422
    const pendingRes = await request("POST", "/core/v1/invitations", ownerToken, {
      email: `jan@${acme.pendingDomain}`,
      firstName: "Jan",
      lastName: "Nowak",
    });
    expect(pendingRes.statusCode).toBe(422);
    expect(pendingRes.json().error.code).toBe("VALIDATION_FAILED");

    // Domena innej firmy -> 422
    const foreignDomainRes = await request("POST", "/core/v1/invitations", ownerToken, {
      email: `nowy@${globex.domain}`,
      firstName: "Jan",
      lastName: "Nowak",
    });
    expect(foreignDomainRes.statusCode).toBe(422);

    // Istniejący adres w tej samej firmie (inna wielkość liter) -> 409
    const dupRes = await request("POST", "/core/v1/invitations", ownerToken, {
      email: `ANNA@${acme.domain}`,
      firstName: "Anna",
      lastName: "Inna",
    });
    expect(dupRes.statusCode).toBe(409);
    expect(dupRes.json().error.code).toBe("CONFLICT");

    // Globalnie istniejący user w auth.users z adresem w naszej zweryfikowanej domenie -> 409 z ogólnym komunikatem
    const orphanUserId = uuidv7();
    const orphanEmail = `zajety@${acme.domain}`;
    await db.authUser.create({ data: { id: orphanUserId, name: "Ktos", email: orphanEmail, emailVerified: true } });
    try {
      const conflictRes = await request("POST", "/core/v1/invitations", ownerToken, {
        email: orphanEmail.toUpperCase(),
        firstName: "Ktos",
        lastName: "Nowy",
      });
      expect(conflictRes.statusCode).toBe(409);
      expect(conflictRes.json().error.code).toBe("CONFLICT");
      expect(conflictRes.json().error.message).not.toMatch(/globex|inna firma/i);
    } finally {
      await db.authUser.deleteMany({ where: { id: orphanUserId } });
    }

    expect(sentMails()).toHaveLength(0);
  });

  it("obsługuje employeeId (istniejący pracownik bez konta -> 201, z kontem -> 409, z innej firmy -> 404)", async () => {
    const ownerToken = await token(acme);

    // Brak employeeId i brak imienia/nazwiska -> 422
    const missingNames = await request("POST", "/core/v1/invitations", ownerToken, {
      email: `bez-imienia@${acme.domain}`,
    });
    expect(missingNames.statusCode).toBe(422);

    // Pracownik bez konta -> 201 bez podawania firstName/lastName
    const empRes = await request("POST", "/core/v1/employees", ownerToken, {
      firstName: "Katarzyna",
      lastName: "Zielinska",
    });
    expect(empRes.statusCode).toBe(201);
    const employeeId = empRes.json().data.id as string;

    const inviteEmpRes = await request("POST", "/core/v1/invitations", ownerToken, {
      email: `katarzyna@${acme.domain}`,
      employeeId,
    });
    expect(inviteEmpRes.statusCode).toBe(201);
    expect(inviteEmpRes.json().data.employeeId).toBe(employeeId);

    const authUser = await db.authUser.findUniqueOrThrow({ where: { id: inviteEmpRes.json().data.accountId } });
    expect(authUser.name).toBe("Katarzyna Zielinska");

    // Brakujący workEmail pracownika zostaje uzupełniony znormalizowanym adresem zaproszenia
    const updatedEmployee = await withOrganization(db, acme.id, (tx) =>
      tx.employee.findUniqueOrThrow({ where: { id: employeeId } }),
    );
    expect(updatedEmployee.workEmail).toBe(`katarzyna@${acme.domain}`);

    // Ten sam pracownik (ma już konto INVITED) -> 409
    const alreadyHasAccount = await request("POST", "/core/v1/invitations", ownerToken, {
      email: `katarzyna2@${acme.domain}`,
      employeeId,
    });
    expect(alreadyHasAccount.statusCode).toBe(409);
    expect(alreadyHasAccount.json().error.code).toBe("CONFLICT");

    // Pracownik z innej firmy -> 404
    const foreignEmployee = await request("POST", "/core/v1/invitations", ownerToken, {
      email: `obcy@${acme.domain}`,
      employeeId: globex.employeeId,
    });
    expect(foreignEmployee.statusCode).toBe(404);
    expect(foreignEmployee.json().error.code).toBe("NOT_FOUND");
  });

  it("egzekwuje uprawnienie core.employees.manage w zakresie ORGANIZATION (Owner i HR org -> 200/201, zwykły i HR unit -> 403)", async () => {
    const regularToken = await token(acmeRegular);
    const unitHrToken = await token(acmeUnitHr);
    const orgHrToken = await token(acmeOrgHr);

    expect((await request("GET", "/core/v1/invitations", regularToken)).statusCode).toBe(403);
    expect(
      (
        await request("POST", "/core/v1/invitations", regularToken, {
          email: `no-perm@${acme.domain}`,
          firstName: "A",
          lastName: "B",
        })
      ).statusCode,
    ).toBe(403);

    // Zakres UNIT nie wystarcza — wymagany jest ORGANIZATION
    expect((await request("GET", "/core/v1/invitations", unitHrToken)).statusCode).toBe(403);
    expect(
      (
        await request("POST", "/core/v1/invitations", unitHrToken, {
          email: `unit-perm@${acme.domain}`,
          firstName: "A",
          lastName: "B",
        })
      ).statusCode,
    ).toBe(403);

    // core.employees.manage w zakresie ORGANIZATION działa
    const created = await request("POST", "/core/v1/invitations", orgHrToken, {
      email: `hr-invited@${acme.domain}`,
      firstName: "Marek",
      lastName: "Nowak",
    });
    expect(created.statusCode).toBe(201);
    const invId = created.json().data.id as string;

    expect((await request("POST", `/core/v1/invitations/${invId}/resend`, regularToken)).statusCode).toBe(403);
    expect((await request("DELETE", `/core/v1/invitations/${invId}`, regularToken)).statusCode).toBe(403);
    expect((await request("GET", "/core/v1/invitations", orgHrToken)).statusCode).toBe(200);
  });

  it("ponowne wysłanie unieważnia stary token, cofnięcie zmienia na REVOKED (z możliwością resend), a lista raportuje wygasłe jako EXPIRED", async () => {
    const ownerToken = await token(acme);

    const createRes = await request("POST", "/core/v1/invitations", ownerToken, {
      email: `cykl@${acme.domain}`,
      firstName: "Alicja",
      lastName: "Cykl",
    });
    expect(createRes.statusCode).toBe(201);
    const inv = createRes.json().data;
    await deliverPendingMail(db, { authUrl: AUTH_URL, now: currentNow });
    const firstToken = extractTokenFromMail(inv.email);

    expect(await invitationByTokenHash(db, hashToken(firstToken))).toEqual({
      organizationId: acme.id,
      invitationId: inv.id,
    });

    // Przesuwamy zegar o 8 dni: zaproszenie jest wygasłe i lista raportuje je jako EXPIRED
    currentNow = new Date("2026-12-03T10:00:00.000Z");
    const expiredList = await request("GET", "/core/v1/invitations?status=EXPIRED", ownerToken);
    expect(expiredList.statusCode).toBe(200);
    expect(
      expiredList
        .json()
        .data.some((row: { id: string; status: string }) => row.id === inv.id && row.status === "EXPIRED"),
    ).toBe(true);

    const pendingList = await request("GET", "/core/v1/invitations?status=PENDING", ownerToken);
    expect(pendingList.json().data.some((row: { id: string }) => row.id === inv.id)).toBe(false);

    // Cofnięcie wygasłego zaproszenia -> 409
    const revokeExpired = await request("DELETE", `/core/v1/invitations/${inv.id}`, ownerToken);
    expect(revokeExpired.statusCode).toBe(409);

    // Resend wygasłego zaproszenia -> 200, natychmiast unieważnia stary hash i kolejkuje nową wysyłkę
    const resendRes = await request("POST", `/core/v1/invitations/${inv.id}/resend`, ownerToken);
    expect(resendRes.statusCode).toBe(200);
    expect(resendRes.json().data.status).toBe("PENDING");
    expect(resendRes.json().data.delivery.status).toBe("PENDING");
    expect(Date.parse(resendRes.json().data.expiresAt) - currentNow.getTime()).toBe(INVITATION_TTL_MS);
    expect(await invitationByTokenHash(db, hashToken(firstToken))).toBeNull();

    await deliverPendingMail(db, { authUrl: AUTH_URL, now: currentNow });
    const secondToken = extractTokenFromMail(inv.email);
    expect(secondToken).not.toBe(firstToken);
    expect(await invitationByTokenHash(db, hashToken(firstToken))).toBeNull();
    expect(await invitationByTokenHash(db, hashToken(secondToken))).toEqual({
      organizationId: acme.id,
      invitationId: inv.id,
    });

    // Cofnięcie PENDING -> 204 (REVOKED), konto pozostaje INVITED
    const revokeRes = await request("DELETE", `/core/v1/invitations/${inv.id}`, ownerToken);
    expect(revokeRes.statusCode).toBe(204);

    const accountAfterRevoke = await withOrganization(db, acme.id, (tx) =>
      tx.account.findUniqueOrThrow({ where: { id: inv.accountId } }),
    );
    expect(accountAfterRevoke.status).toBe("INVITED");

    // Powtórne cofnięcie -> 409
    expect((await request("DELETE", `/core/v1/invitations/${inv.id}`, ownerToken)).statusCode).toBe(409);

    // Cofnięte zaproszenie można ponownie wysłać -> status wraca do PENDING
    const resendRevoked = await request("POST", `/core/v1/invitations/${inv.id}/resend`, ownerToken);
    expect(resendRevoked.statusCode).toBe(200);
    expect(resendRevoked.json().data.status).toBe("PENDING");
    expect(await invitationByTokenHash(db, hashToken(secondToken))).toBeNull();

    await deliverPendingMail(db, { authUrl: AUTH_URL, now: currentNow });
    const thirdToken = extractTokenFromMail(inv.email);
    expect(await invitationByTokenHash(db, hashToken(secondToken))).toBeNull();
    expect(await invitationByTokenHash(db, hashToken(thirdToken))).toEqual({
      organizationId: acme.id,
      invitationId: inv.id,
    });

    // Sprawdzenie wpisów w dzienniku zdarzeń (bez tokenów w metadata)
    const audits = await withOrganization(db, acme.id, (tx) =>
      tx.auditLog.findMany({
        where: { resourceType: "invitation", resourceId: inv.id },
        orderBy: { createdAt: "asc" },
      }),
    );
    expect(audits.map((a) => a.action)).toEqual([
      "invitation.created",
      "invitation.resent",
      "invitation.revoked",
      "invitation.resent",
    ]);
    for (const entry of audits) {
      const serialized = JSON.stringify(entry.metadata);
      expect(serialized).not.toContain(firstToken);
      expect(serialized).not.toContain(secondToken);
      expect(serialized).not.toContain(thirdToken);
    }

    // Stronicowanie listy (limit=1)
    const page1 = await request("GET", "/core/v1/invitations?limit=1", ownerToken);
    expect(page1.statusCode).toBe(200);
    expect(page1.json().data).toHaveLength(1);
    expect(page1.json().meta.nextCursor).toBeTruthy();

    const page2 = await request(
      "GET",
      `/core/v1/invitations?limit=1&cursor=${encodeURIComponent(page1.json().meta.nextCursor)}`,
      ownerToken,
    );
    expect(page2.statusCode).toBe(200);
    expect(page2.json().data).toHaveLength(1);
    expect(page2.json().data[0].id).not.toBe(page1.json().data[0].id);
  });

  it("CLI tworzy zaproszenie po domenie z aktorem SYSTEM i metadata.source='cli', a serwis obsługuje resend/revoke bezpośrednio", async () => {
    const cliResult = await createInvitationByOrganization(db, {
      organization: acme.domain,
      email: `cli-user@${acme.domain}`,
      firstName: "Karol",
      lastName: "Pilot",
      now: currentNow,
    });

    expect(cliResult.organizationId).toBe(acme.id);
    expect(cliResult.invitation.invitedByAccountId).toBeNull();
    expect(cliResult.invitation.status).toBe("PENDING");
    expect(cliResult.invitation.delivery.status).toBe("PENDING");
    expect(sentMails()).toHaveLength(0);

    // Bezpośrednia dostawa zadania z CLI (tak jak w scripts/invitation.ts)
    const claimedCliJob = await claimMailJobById(db, cliResult.organizationId, cliResult.mailJobId, {
      now: currentNow,
    });
    expect(claimedCliJob).not.toBeNull();
    const cliDelivery = await deliverMailJob(db, claimedCliJob!, { authUrl: AUTH_URL, now: currentNow });
    expect(cliDelivery.status).toBe("SENT");
    expect(cliDelivery.inviteUrl).toContain(`${AUTH_URL}/invite?token=`);

    const mail = sentMails().find((m) => m.to === `cli-user@${acme.domain}`)!;
    expect(mail.to).toBe(`cli-user@${acme.domain}`);
    expect(mail.subject).toBe("Zaproszenie do Monorise od firmy Acme");
    expect(mail.text).toContain(cliDelivery.inviteUrl!);

    const cliAudit = await withOrganization(db, acme.id, (tx) =>
      tx.auditLog.findFirstOrThrow({
        where: { action: "invitation.created", resourceId: cliResult.invitation.id },
      }),
    );
    expect(cliAudit.actorType).toBe("SYSTEM");
    expect(cliAudit.actorAccountId).toBeNull();
    expect(cliAudit.metadata).toMatchObject({ source: "cli", accountId: cliResult.invitation.accountId });

    // Bezpośrednie wywołanie serwisu: create -> revoke -> resend -> po ACCEPTED resend zwraca 409
    const direct = await withOrganization(db, acme.id, async (tx) => {
      const created = await createInvitation(tx, {
        organizationId: acme.id,
        email: `serwis@${acme.domain}`,
        firstName: "Ewa",
        lastName: "Serwis",
        invitedBy: acme.accountId,
        actor: { type: "ACCOUNT", accountId: acme.accountId },
        now: currentNow,
      });
      await revokeInvitation(tx, {
        organizationId: acme.id,
        invitationId: created.invitation.id,
        actor: { type: "ACCOUNT", accountId: acme.accountId },
        now: currentNow,
      });
      return resendInvitation(tx, {
        organizationId: acme.id,
        invitationId: created.invitation.id,
        actor: { type: "ACCOUNT", accountId: acme.accountId },
        now: currentNow,
      });
    });
    expect(direct.invitation.status).toBe("PENDING");
    expect(direct.invitation.delivery.status).toBe("PENDING");

    // Zaakceptowane zaproszenie nie może zostać wysłane ponownie
    await withOrganization(db, acme.id, async (tx) => {
      await tx.invitation.update({
        where: { id: direct.invitation.id },
        data: { status: "ACCEPTED", acceptedAt: currentNow },
      });
      await tx.account.update({
        where: { id: direct.invitation.accountId },
        data: { status: "ACTIVE" },
      });
    });

    await expect(
      withOrganization(db, acme.id, (tx) =>
        resendInvitation(tx, {
          organizationId: acme.id,
          invitationId: direct.invitation.id,
          actor: { type: "ACCOUNT", accountId: acme.accountId },
          now: currentNow,
        }),
      ),
    ).rejects.toMatchObject({ status: 409, code: "CONFLICT" });
  });
});
