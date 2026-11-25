import {
  CORE_PERMISSIONS,
  IDEMPOTENCY_KEY_HEADER,
  IDEMPOTENCY_KEY_TTL_MS,
  IDEMPOTENCY_REPLAYED_HEADER,
} from "@core/contracts";
import { createDb, uuidv7, withOrganization } from "@core/db";
import { createLocalJWKSet, exportJWK, generateKeyPair, SignJWT, type CryptoKey } from "jose";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { clearSentMails, sentMails } from "../src/mail.js";
import { registerCorePermissions } from "../src/permissions-registry.js";
import { buildServer } from "../src/server.js";
import { createMachineTokenVerifier, createTokenVerifier } from "../src/tokens.js";

const ISSUER = "http://localhost:3100";
const AUDIENCE = "http://localhost:3200";
const AUTH_URL = "http://localhost:3100";

const db = createDb(
  process.env.CORE_TEST_APP_DATABASE_URL ?? "postgresql://core_app:core_app@localhost:5433/monorise_core_test",
);

interface Identity {
  organizationId: string;
  employeeId: string;
  accountId: string;
}

interface Company extends Identity {
  id: string;
  domain: string;
  extraAccountIds: string[];
}

let signingKey: CryptoKey;
let currentNow = new Date("2026-11-25T10:00:00.000Z");
let app: ReturnType<typeof buildServer>;
let acme: Company;
let globex: Company;
let acmeManager: Identity;
let acmeRegular: Identity;
let acmeManagerRoleId: string;

async function createCompany(name: string): Promise<Company> {
  const id = uuidv7();
  const domain = `${id.slice(-8)}-${name.toLowerCase()}.test`;
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
    await tx.employee.create({ data: { id: employeeId, organizationId: id, firstName: "Anna", lastName: name } });
    await tx.account.create({
      data: { id: accountId, organizationId: id, employeeId, email, normalizedEmail: email, status: "ACTIVE" },
    });
    await tx.organization.update({ where: { id }, data: { ownerAccountId: accountId } });
  });

  return { id, domain, organizationId: id, employeeId, accountId, extraAccountIds: [] };
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

function post(url: string, bearer: string, payload?: Record<string, unknown>, idempotencyKey?: string) {
  const headers: Record<string, string> = { authorization: `Bearer ${bearer}` };
  if (idempotencyKey !== undefined) {
    headers[IDEMPOTENCY_KEY_HEADER] = idempotencyKey;
  }
  return app.inject({
    method: "POST",
    url,
    headers,
    ...(payload !== undefined ? { payload } : {}),
  });
}

beforeAll(async () => {
  process.env.CORE_SMTP_URL = "memory";
  await registerCorePermissions(db);

  const pair = await generateKeyPair("EdDSA", { crv: "Ed25519" });
  signingKey = pair.privateKey;
  const jwk = { ...(await exportJWK(pair.publicKey)), alg: "EdDSA", kid: "test-idem" };
  const tokenOptions = { keys: createLocalJWKSet({ keys: [jwk] }), issuer: ISSUER, audience: AUDIENCE };

  app = buildServer({
    db,
    verifyToken: createTokenVerifier(tokenOptions),
    verifyMachineToken: createMachineTokenVerifier(tokenOptions),
    authUrl: AUTH_URL,
    now: () => currentNow,
  });

  acme = await createCompany("Acme");
  globex = await createCompany("Globex");
  acmeManager = await createMember(acme, "Marta", "Kadry");
  acmeRegular = await createMember(acme, "Piotr", "Zwykly");

  const [empPerm, structPerm] = await Promise.all([
    db.permission.findUniqueOrThrow({
      where: { key: CORE_PERMISSIONS.keys["employees.manage"] },
      select: { id: true },
    }),
    db.permission.findUniqueOrThrow({
      where: { key: CORE_PERMISSIONS.keys["structure.manage"] },
      select: { id: true },
    }),
  ]);

  acmeManagerRoleId = uuidv7();
  await withOrganization(db, acme.id, async (tx) => {
    await tx.role.create({
      data: { id: acmeManagerRoleId, organizationId: acme.id, productId: null, name: "Zarządzanie firmą" },
    });
    await tx.rolePermission.createMany({
      data: [
        { roleId: acmeManagerRoleId, permissionId: empPerm.id },
        { roleId: acmeManagerRoleId, permissionId: structPerm.id },
      ],
    });
    await tx.roleAssignment.create({
      data: {
        id: uuidv7(),
        organizationId: acme.id,
        accountId: acmeManager.accountId,
        roleId: acmeManagerRoleId,
        scopeType: "ORGANIZATION",
        grantedByAccountId: acme.accountId,
      },
    });
  });
});

beforeEach(() => {
  clearSentMails();
  currentNow = new Date("2026-11-25T10:00:00.000Z");
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
});

describe("Nagłówek Idempotency-Key dla operacji POST Core API (MonoriseCore#30)", () => {
  it("powtórzone POST /core/v1/employees z tym samym kluczem zwraca tę samą odpowiedź, ustawia Idempotency-Replayed i tworzy 1 rekord", async () => {
    const ownerToken = await token(acme);
    const key = `emp-${uuidv7()}`;
    const workEmail = `jan-idem-${uuidv7().slice(-6)}@${acme.domain}`;

    const first = await post(
      "/core/v1/employees",
      ownerToken,
      { firstName: "Jan", lastName: "Kowalski", workEmail, jobTitle: "Magazyn" },
      key,
    );
    expect(first.statusCode).toBe(201);
    expect(first.headers[IDEMPOTENCY_REPLAYED_HEADER.toLowerCase()]).toBeUndefined();

    // Taka sama treść z polami w innej kolejności -> ta sama odpowiedź (kanoniczny JSON)
    const replay = await post(
      "/core/v1/employees",
      ownerToken,
      { jobTitle: "Magazyn", workEmail, lastName: "Kowalski", firstName: "Jan" },
      key,
    );
    expect(replay.statusCode).toBe(201);
    expect(replay.headers[IDEMPOTENCY_REPLAYED_HEADER.toLowerCase()]).toBe("true");
    expect(replay.json()).toEqual(first.json());

    const createdId = first.json().data.id as string;
    const [employees, audits] = await withOrganization(db, acme.id, (tx) =>
      Promise.all([
        tx.employee.findMany({ where: { workEmail } }),
        tx.auditLog.findMany({ where: { action: "employee.created", resourceId: createdId } }),
      ]),
    );
    expect(employees).toHaveLength(1);
    expect(employees[0]?.id).toBe(createdId);
    expect(audits).toHaveLength(1);
  });

  it("powtórzone POST /core/v1/units z tym samym kluczem zwraca tę samą jednostkę i nie tworzy duplikatu", async () => {
    const ownerToken = await token(acme);
    const key = `unit-${uuidv7()}`;
    const unitName = `Oddział Idem ${uuidv7().slice(-6)}`;

    const first = await post("/core/v1/units", ownerToken, { name: unitName, type: "BRANCH" }, key);
    expect(first.statusCode).toBe(201);
    expect(first.headers[IDEMPOTENCY_REPLAYED_HEADER.toLowerCase()]).toBeUndefined();

    const replay = await post("/core/v1/units", ownerToken, { type: "BRANCH", name: unitName }, key);
    expect(replay.statusCode).toBe(201);
    expect(replay.headers[IDEMPOTENCY_REPLAYED_HEADER.toLowerCase()]).toBe("true");
    expect(replay.json()).toEqual(first.json());

    const units = await withOrganization(db, acme.id, (tx) =>
      tx.organizationUnit.findMany({ where: { name: unitName } }),
    );
    expect(units).toHaveLength(1);
    expect(units[0]?.id).toBe(first.json().data.id);
  });

  it("powtórzone zaproszenie i ponowne wysłanie zaproszenia nie dublują rekordu ani wiadomości e-mail", async () => {
    const ownerToken = await token(acme);
    const inviteKey = `inv-${uuidv7()}`;
    const email = `zaproszony-${uuidv7().slice(-6)}@${acme.domain}`;

    const firstInvite = await post(
      "/core/v1/invitations",
      ownerToken,
      { email, firstName: "Karol", lastName: "Zaproszony" },
      inviteKey,
    );
    expect(firstInvite.statusCode).toBe(201);
    expect(firstInvite.headers[IDEMPOTENCY_REPLAYED_HEADER.toLowerCase()]).toBeUndefined();
    expect(sentMails()).toHaveLength(1);

    const replayInvite = await post(
      "/core/v1/invitations",
      ownerToken,
      { lastName: "Zaproszony", firstName: "Karol", email },
      inviteKey,
    );
    expect(replayInvite.statusCode).toBe(201);
    expect(replayInvite.headers[IDEMPOTENCY_REPLAYED_HEADER.toLowerCase()]).toBe("true");
    expect(replayInvite.json()).toEqual(firstInvite.json());
    expect(sentMails()).toHaveLength(1);

    // Ponowne wysłanie zaproszenia z Idempotency-Key nie wysyła drugiego maila; inny invitationId z tym samym kluczem -> 409
    const invitationId = firstInvite.json().data.id as string;
    const resendKey = `resend-${uuidv7()}`;
    clearSentMails();

    const firstResend = await post(`/core/v1/invitations/${invitationId}/resend`, ownerToken, undefined, resendKey);
    expect(firstResend.statusCode).toBe(200);
    expect(firstResend.headers[IDEMPOTENCY_REPLAYED_HEADER.toLowerCase()]).toBeUndefined();
    expect(sentMails()).toHaveLength(1);

    const replayResend = await post(`/core/v1/invitations/${invitationId}/resend`, ownerToken, undefined, resendKey);
    expect(replayResend.statusCode).toBe(200);
    expect(replayResend.headers[IDEMPOTENCY_REPLAYED_HEADER.toLowerCase()]).toBe("true");
    expect(replayResend.json()).toEqual(firstResend.json());
    expect(sentMails()).toHaveLength(1);

    const otherTargetResend = await post(`/core/v1/invitations/${uuidv7()}/resend`, ownerToken, undefined, resendKey);
    expect(otherTargetResend.statusCode).toBe(409);
    expect(otherTargetResend.json().error.code).toBe("CONFLICT");
  });

  it("zwraca 409 CONFLICT, gdy ten sam klucz jest użyty z inną treścią albo na innej ścieżce POST", async () => {
    const ownerToken = await token(acme);
    const key = `conflict-${uuidv7()}`;

    const first = await post("/core/v1/employees", ownerToken, { firstName: "Ewa", lastName: "Pierwsza" }, key);
    expect(first.statusCode).toBe(201);

    const differentBody = await post("/core/v1/employees", ownerToken, { firstName: "Ewa", lastName: "Druga" }, key);
    expect(differentBody.statusCode).toBe(409);
    expect(differentBody.json()).toMatchObject({
      data: null,
      meta: { requestId: expect.any(String) },
      error: { code: "CONFLICT" },
    });

    const differentPath = await post("/core/v1/units", ownerToken, { name: "Dział", type: "DEPARTMENT" }, key);
    expect(differentPath.statusCode).toBe(409);
    expect(differentPath.json().error.code).toBe("CONFLICT");
  });

  it("dwa równoległe żądania z tym samym kluczem tworzą jeden rekord i zwracają tę samą odpowiedź", async () => {
    const ownerToken = await token(acme);
    const key = `concurrent-${uuidv7()}`;
    const workEmail = `parallel-${uuidv7().slice(-6)}@${acme.domain}`;
    const payload = { firstName: "Tomasz", lastName: "Równoległy", workEmail };

    const [res1, res2] = await Promise.all([
      post("/core/v1/employees", ownerToken, payload, key),
      post("/core/v1/employees", ownerToken, payload, key),
    ]);

    expect(res1.statusCode).toBe(201);
    expect(res2.statusCode).toBe(201);
    expect(res1.json()).toEqual(res2.json());

    const replayedHeaders = [
      res1.headers[IDEMPOTENCY_REPLAYED_HEADER.toLowerCase()],
      res2.headers[IDEMPOTENCY_REPLAYED_HEADER.toLowerCase()],
    ].filter((value) => value === "true");
    expect(replayedHeaders).toHaveLength(1);

    const employees = await withOrganization(db, acme.id, (tx) => tx.employee.findMany({ where: { workEmail } }));
    expect(employees).toHaveLength(1);
    expect(employees[0]?.id).toBe(res1.json().data.id);
  });

  it("ten sam klucz u innego konta w tej samej firmie oraz w innej firmie działa niezależnie", async () => {
    const ownerToken = await token(acme);
    const managerToken = await token(acmeManager);
    const globexToken = await token(globex);
    const sharedKey = `shared-${uuidv7()}`;

    const ownerRes = await post(
      "/core/v1/employees",
      ownerToken,
      { firstName: "Anna", lastName: "Ownerowa" },
      sharedKey,
    );
    expect(ownerRes.statusCode).toBe(201);
    expect(ownerRes.headers[IDEMPOTENCY_REPLAYED_HEADER.toLowerCase()]).toBeUndefined();

    // Inne konto w tej samej firmie (inna treść też przechodzi, bo klucz jest niezależny na principal)
    const managerRes = await post(
      "/core/v1/employees",
      managerToken,
      { firstName: "Marta", lastName: "Kadrowa" },
      sharedKey,
    );
    expect(managerRes.statusCode).toBe(201);
    expect(managerRes.headers[IDEMPOTENCY_REPLAYED_HEADER.toLowerCase()]).toBeUndefined();
    expect(managerRes.json().data.id).not.toBe(ownerRes.json().data.id);

    // Inna firma z tym samym kluczem
    const globexRes = await post(
      "/core/v1/employees",
      globexToken,
      { firstName: "Adam", lastName: "Globexowy" },
      sharedKey,
    );
    expect(globexRes.statusCode).toBe(201);
    expect(globexRes.headers[IDEMPOTENCY_REPLAYED_HEADER.toLowerCase()]).toBeUndefined();
    expect(globexRes.json().data.id).not.toBe(ownerRes.json().data.id);
  });

  it("odrzuca nieprawidłowy nagłówek Idempotency-Key kodem 400 i standardową kopertą błędu", async () => {
    const ownerToken = await token(acme);
    const invalidKeys = ["", "   ", " leading", "trailing ", "x".repeat(256), "bad\tkey", "bad\x7fkey", "klucz-ą"];

    for (const invalidKey of invalidKeys) {
      const res = await post("/core/v1/employees", ownerToken, { firstName: "Jan", lastName: "Błąd" }, invalidKey);
      expect(res.statusCode, `Klucz: ${JSON.stringify(invalidKey)}`).toBe(400);
      expect(res.json()).toMatchObject({
        data: null,
        meta: { requestId: expect.any(String) },
        error: {
          code: "VALIDATION_FAILED",
          details: [{ field: IDEMPOTENCY_KEY_HEADER }],
        },
      });
    }
  });

  it("bez nagłówka Idempotency-Key zachowanie pozostaje bez zmian (tworzy osobne rekordy)", async () => {
    const ownerToken = await token(acme);
    const first = await post("/core/v1/employees", ownerToken, { firstName: "Bez", lastName: "Klucza" });
    const second = await post("/core/v1/employees", ownerToken, { firstName: "Bez", lastName: "Klucza" });

    expect(first.statusCode).toBe(201);
    expect(second.statusCode).toBe(201);
    expect(first.headers[IDEMPOTENCY_REPLAYED_HEADER.toLowerCase()]).toBeUndefined();
    expect(second.headers[IDEMPOTENCY_REPLAYED_HEADER.toLowerCase()]).toBeUndefined();
    expect(second.json().data.id).not.toBe(first.json().data.id);
  });

  it("nie zapisuje odpowiedzi błędów (422, 403, 404), więc ponowienie po naprawieniu przyczyny z tym samym kluczem udaje się", async () => {
    const ownerToken = await token(acme);
    const regularToken = await token(acmeRegular);

    // 422 -> naprawa treści -> 201 z tym samym kluczem
    const key422 = `err-422-${uuidv7()}`;
    const badRes = await post("/core/v1/employees", ownerToken, { firstName: "   ", lastName: "Nowak" }, key422);
    expect(badRes.statusCode).toBe(422);

    const fixedRes = await post(
      "/core/v1/employees",
      ownerToken,
      { firstName: "Marek", lastName: "Naprawiony" },
      key422,
    );
    expect(fixedRes.statusCode).toBe(201);
    expect(fixedRes.headers[IDEMPOTENCY_REPLAYED_HEADER.toLowerCase()]).toBeUndefined();

    // 404 -> naprawa parentId -> 201 z tym samym kluczem
    const key404 = `err-404-${uuidv7()}`;
    const missingParent = await post(
      "/core/v1/units",
      ownerToken,
      { name: "Zespół po 404", type: "TEAM", parentId: uuidv7() },
      key404,
    );
    expect(missingParent.statusCode).toBe(404);

    const fixedUnit = await post(
      "/core/v1/units",
      ownerToken,
      { name: "Zespół po 404", type: "TEAM", parentId: null },
      key404,
    );
    expect(fixedUnit.statusCode).toBe(201);
    expect(fixedUnit.headers[IDEMPOTENCY_REPLAYED_HEADER.toLowerCase()]).toBeUndefined();

    // 403 -> nadanie uprawnienia -> 201 z tym samym kluczem i tą samą treścią
    const key403 = `err-403-${uuidv7()}`;
    const forbiddenPayload = { firstName: "Piotr", lastName: "Uprawniony" };
    const forbiddenRes = await post("/core/v1/employees", regularToken, forbiddenPayload, key403);
    expect(forbiddenRes.statusCode).toBe(403);

    const assignmentId = uuidv7();
    await withOrganization(db, acme.id, (tx) =>
      tx.roleAssignment.create({
        data: {
          id: assignmentId,
          organizationId: acme.id,
          accountId: acmeRegular.accountId,
          roleId: acmeManagerRoleId,
          scopeType: "ORGANIZATION",
          grantedByAccountId: acme.accountId,
        },
      }),
    );

    try {
      const allowedRes = await post("/core/v1/employees", regularToken, forbiddenPayload, key403);
      expect(allowedRes.statusCode).toBe(201);
      expect(allowedRes.headers[IDEMPOTENCY_REPLAYED_HEADER.toLowerCase()]).toBeUndefined();
    } finally {
      await withOrganization(db, acme.id, (tx) => tx.roleAssignment.deleteMany({ where: { id: assignmentId } }));
    }
  });

  it("po wygaśnięciu klucza (24 godziny) traktuje go jak nowy i nadpisuje zapisaną odpowiedź", async () => {
    const ownerToken = await token(acme);
    const key = `exp-${uuidv7()}`;

    const first = await post("/core/v1/employees", ownerToken, { firstName: "Stary", lastName: "Wpis" }, key);
    expect(first.statusCode).toBe(201);

    // Przesuwamy czas o 24 godziny: klucz wygasł
    currentNow = new Date(currentNow.getTime() + IDEMPOTENCY_KEY_TTL_MS);

    const renewed = await post("/core/v1/employees", ownerToken, { firstName: "Nowy", lastName: "Wpis" }, key);
    expect(renewed.statusCode).toBe(201);
    expect(renewed.headers[IDEMPOTENCY_REPLAYED_HEADER.toLowerCase()]).toBeUndefined();
    expect(renewed.json().data.id).not.toBe(first.json().data.id);

    const replayedNew = await post("/core/v1/employees", ownerToken, { firstName: "Nowy", lastName: "Wpis" }, key);
    expect(replayedNew.statusCode).toBe(201);
    expect(replayedNew.headers[IDEMPOTENCY_REPLAYED_HEADER.toLowerCase()]).toBe("true");
    expect(replayedNew.json()).toEqual(renewed.json());
  });
});
