import {
  CORE_PERMISSIONS,
  IDEMPOTENCY_KEY_HEADER,
  IDEMPOTENCY_REPLAYED_HEADER,
  PERMISSIONS_READ_SCOPE,
  PERMISSIONS_REGISTER_SCOPE,
} from "@core/contracts";
import { createDb, hashToken, uuidv7, withOrganization } from "@core/db";
import { can } from "@monorise-team/permissions";
import { createLocalJWKSet, exportJWK, generateKeyPair, SignJWT, type CryptoKey } from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { grantEntitlement } from "../src/entitlements.js";
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
  email: string;
}

interface Company extends Identity {
  id: string;
  domain: string;
  extraAccountIds: string[];
}

const suffix = uuidv7()
  .slice(-6)
  .replace(/[^a-z0-9]/g, "a");
const testProductKey = `deact${suffix}`;
const testProductId = uuidv7();
const testProductClientId = `deact-client-${suffix}`;
const testOAuthClientId = `deact-oauth-${suffix}`;

let signingKey: CryptoKey;
let currentNow = new Date("2026-11-26T10:00:00.000Z");
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
    await tx.employee.create({
      data: { id: employeeId, organizationId: id, firstName: "Anna", lastName: name, workEmail: email },
    });
    await tx.account.create({
      data: { id: accountId, organizationId: id, employeeId, email, normalizedEmail: email, status: "ACTIVE" },
    });
    await tx.organization.update({ where: { id }, data: { ownerAccountId: accountId } });
  });

  return { id, domain, organizationId: id, employeeId, accountId, email, extraAccountIds: [] };
}

async function createMember(
  company: Company,
  firstName: string,
  lastName: string,
  options?: { status?: "ACTIVE" | "INVITED" | "DEACTIVATED" },
): Promise<Identity> {
  const employeeId = uuidv7();
  const accountId = uuidv7();
  const email = `${firstName.toLowerCase()}-${accountId.slice(-6)}@${company.domain}`;
  const accountStatus = options?.status ?? "ACTIVE";

  await db.authUser.create({
    data: { id: accountId, name: `${firstName} ${lastName}`, email, emailVerified: accountStatus === "ACTIVE" },
  });
  await withOrganization(db, company.id, async (tx) => {
    await tx.employee.create({
      data: { id: employeeId, organizationId: company.id, firstName, lastName, workEmail: email },
    });
    await tx.account.create({
      data: {
        id: accountId,
        organizationId: company.id,
        employeeId,
        email,
        normalizedEmail: email,
        status: accountStatus,
        ...(accountStatus === "DEACTIVATED" ? { deactivatedAt: new Date() } : {}),
      },
    });
  });
  company.extraAccountIds.push(accountId);
  return { organizationId: company.id, employeeId, accountId, email };
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

function machineToken(clientId: string, scope: string) {
  return new SignJWT({
    client_id: clientId,
    azp: clientId,
    scope,
  })
    .setProtectedHeader({ alg: "EdDSA" })
    .setIssuer(ISSUER)
    .setAudience(AUDIENCE)
    .setSubject(clientId)
    .setIssuedAt()
    .setExpirationTime("5m")
    .sign(signingKey);
}

function request(
  method: "GET" | "POST" | "PUT" | "DELETE",
  url: string,
  bearer?: string,
  payload?: Record<string, unknown> | unknown[],
  extraHeaders?: Record<string, string>,
) {
  return app.inject({
    method,
    url,
    headers: {
      ...(bearer ? { authorization: `Bearer ${bearer}` } : {}),
      ...(extraHeaders ?? {}),
    },
    ...(payload !== undefined ? { payload } : {}),
  });
}

beforeAll(async () => {
  process.env.CORE_SMTP_URL = "memory";
  await registerCorePermissions(db);

  const pair = await generateKeyPair("EdDSA", { crv: "Ed25519" });
  signingKey = pair.privateKey;
  const jwk = { ...(await exportJWK(pair.publicKey)), alg: "EdDSA", kid: "test-emp-deact" };
  const tokenOptions = { keys: createLocalJWKSet({ keys: [jwk] }), issuer: ISSUER, audience: AUDIENCE };

  app = buildServer({
    db,
    verifyToken: createTokenVerifier(tokenOptions),
    verifyMachineToken: createMachineTokenVerifier(tokenOptions),
    authUrl: AUTH_URL,
    now: () => currentNow,
  });

  await db.authOAuthClient.create({
    data: {
      id: uuidv7(),
      clientId: testOAuthClientId,
      name: "Test Deactivation Client",
      redirectUris: ["http://localhost:3300/api/auth/callback"],
    },
  });

  await ownerDb.product.create({
    data: {
      id: testProductId,
      key: testProductKey,
      name: "Test Deactivation Product",
      registrationClientId: testProductClientId,
    },
  });

  const registerToken = await machineToken(testProductClientId, PERMISSIONS_REGISTER_SCOPE);
  const regRes = await request("PUT", `/core/v1/products/${testProductKey}/permissions`, registerToken, [
    { key: `${testProductKey}.entries.read`, description: "Odczyt wpisów" },
    { key: `${testProductKey}.entries.approve`, description: "Zatwierdzanie wpisów" },
  ]);
  expect(regRes.statusCode).toBe(200);

  acme = await createCompany("Acme");
  globex = await createCompany("Globex");
  acmeRegular = await createMember(acme, "Jan", "Zwykly");
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

  await grantEntitlement(db, { organization: acme.id, product: testProductKey });
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
  await db.authOAuthClient.deleteMany({ where: { clientId: testOAuthClientId } });
  await ownerDb.permission.deleteMany({ where: { productId: testProductId } });
  await ownerDb.auditLog.deleteMany({ where: { productId: testProductId } });
  await ownerDb.product.deleteMany({ where: { id: testProductId } });
  await db.$disconnect();
  await ownerDb.$disconnect();
});

describe("Wyłączanie i przywracanie konta pracownika (POST /core/v1/employees/{employeeId}/deactivate i /reactivate)", () => {
  it("wyłącza konto, usuwa sesje i tokeny OAuth (w tym obrócony w oknie 20s), cofa stray zaproszenie, podbija authzRevision + outbox + audyt, zachowuje role/AppAccess i przywraca dostęp po /reactivate", async () => {
    currentNow = new Date("2026-11-26T10:00:00.000Z");
    const ownerToken = await token(acme);
    const readPermToken = await machineToken(testProductClientId, PERMISSIONS_READ_SCOPE);

    const piotr = await createMember(acme, "Piotr", "Urlopowy");
    const bystander = await createMember(acme, "Ewa", "Pozostala");
    const piotrToken = await token(piotr);

    // Dwie role produktowe + AppAccess dla Piotra
    const readRole = (
      await request("POST", "/core/v1/roles", ownerToken, {
        name: "Czytelnik wpisów",
        product: testProductKey,
        permissions: [`${testProductKey}.entries.read`],
      })
    ).json().data as { id: string };
    const approveRole = (
      await request("POST", "/core/v1/roles", ownerToken, {
        name: "Zatwierdzający wpisy",
        product: testProductKey,
        permissions: [`${testProductKey}.entries.approve`],
      })
    ).json().data as { id: string };

    const readAssign = (
      await request("POST", "/core/v1/role-assignments", ownerToken, {
        accountId: piotr.accountId,
        roleId: readRole.id,
        scopeType: "ORGANIZATION",
      })
    ).json().data as { id: string };
    const approveAssign = (
      await request("POST", "/core/v1/role-assignments", ownerToken, {
        accountId: piotr.accountId,
        roleId: approveRole.id,
        scopeType: "ORGANIZATION",
      })
    ).json().data as { id: string };
    const appAccessRes = await request("POST", "/core/v1/app-access", ownerToken, {
      accountId: piotr.accountId,
      product: testProductKey,
    });
    expect(appAccessRes.statusCode).toBe(201);

    // Przed wyłączeniem Piotr ma dostęp do produktu i oba uprawnienia
    const snapBefore = await request(
      "GET",
      `/core/v1/products/${testProductKey}/permission-snapshot?organizationId=${acme.id}&accountId=${piotr.accountId}`,
      readPermToken,
    );
    expect(snapBefore.statusCode).toBe(200);
    expect(snapBefore.json().data.products).toEqual([testProductKey]);
    expect(can(snapBefore.json().data, `${testProductKey}.entries.read`)).toBe(true);
    expect(can(snapBefore.json().data, `${testProductKey}.entries.approve`)).toBe(true);

    // Zasiewamy sesje Better Auth, aktywny i obrócony refresh token (z rotationReplayResponse) oraz access token
    // dla Piotra oraz osoby postronnej (Ewy), plus defensywne stray zaproszenie PENDING dla Piotra.
    const future = new Date("2026-12-26T10:00:00.000Z");
    const piotrSessionId = uuidv7();
    const bystanderSessionId = uuidv7();
    const piotrActiveRefreshId = uuidv7();
    const piotrRotatedRefreshId = uuidv7();
    const bystanderRefreshId = uuidv7();
    const strayInvitationId = uuidv7();

    await db.authSession.createMany({
      data: [
        { id: piotrSessionId, userId: piotr.accountId, token: `sess-${uuidv7()}`, expiresAt: future },
        { id: bystanderSessionId, userId: bystander.accountId, token: `sess-${uuidv7()}`, expiresAt: future },
      ],
    });
    await db.authOAuthRefreshToken.createMany({
      data: [
        {
          id: piotrActiveRefreshId,
          token: `rt-${uuidv7()}`,
          clientId: testOAuthClientId,
          sessionId: piotrSessionId,
          userId: piotr.accountId,
          expiresAt: future,
          scopes: ["openid", "offline_access"],
        },
        {
          id: piotrRotatedRefreshId,
          token: `rt-rot-${uuidv7()}`,
          clientId: testOAuthClientId,
          sessionId: null,
          userId: piotr.accountId,
          expiresAt: future,
          revoked: currentNow,
          rotatedAt: currentNow,
          rotationReplayResponse: '{"access_token":"cached","refresh_token":"cached"}',
          rotationReplayExpiresAt: new Date(currentNow.getTime() + 20_000),
          scopes: ["openid", "offline_access"],
        },
        {
          id: bystanderRefreshId,
          token: `rt-other-${uuidv7()}`,
          clientId: testOAuthClientId,
          sessionId: bystanderSessionId,
          userId: bystander.accountId,
          expiresAt: future,
          scopes: ["openid", "offline_access"],
        },
      ],
    });
    await db.authOAuthAccessToken.createMany({
      data: [
        {
          id: uuidv7(),
          token: `at-${uuidv7()}`,
          clientId: testOAuthClientId,
          sessionId: piotrSessionId,
          userId: piotr.accountId,
          refreshId: piotrActiveRefreshId,
          expiresAt: future,
          scopes: ["openid"],
        },
        {
          id: uuidv7(),
          token: `at-other-${uuidv7()}`,
          clientId: testOAuthClientId,
          sessionId: bystanderSessionId,
          userId: bystander.accountId,
          refreshId: bystanderRefreshId,
          expiresAt: future,
          scopes: ["openid"],
        },
      ],
    });
    await withOrganization(db, acme.id, (tx) =>
      tx.invitation.create({
        data: {
          id: strayInvitationId,
          organizationId: acme.id,
          accountId: piotr.accountId,
          email: piotr.email,
          normalizedEmail: piotr.email,
          tokenHash: hashToken(`stray-${uuidv7()}`),
          status: "PENDING",
          expiresAt: future,
          invitedByAccountId: acme.accountId,
        },
      }),
    );

    const revBeforeDeactivate = (
      await withOrganization(db, acme.id, (tx) =>
        tx.account.findUniqueOrThrow({ where: { id: piotr.accountId }, select: { authzRevision: true } }),
      )
    ).authzRevision;

    // 1. POST /deactivate z Idempotency-Key
    const idemKey = `deact-${uuidv7()}`;
    const deactivateRes = await request(
      "POST",
      `/core/v1/employees/${piotr.employeeId}/deactivate`,
      ownerToken,
      undefined,
      { [IDEMPOTENCY_KEY_HEADER]: idemKey },
    );
    expect(deactivateRes.statusCode).toBe(200);
    expect(deactivateRes.headers[IDEMPOTENCY_REPLAYED_HEADER.toLowerCase()]).toBeUndefined();
    expect(deactivateRes.json()).toMatchObject({
      data: {
        id: piotr.employeeId,
        accountId: piotr.accountId,
        accountStatus: "DEACTIVATED",
        firstName: "Piotr",
        lastName: "Urlopowy",
        status: "ACTIVE",
      },
      error: null,
    });

    // Stan w bazie: status DEACTIVATED, deactivatedAt ustawione, authzRevision + 1, Employee.status nadal ACTIVE
    const accountAfterDeactivate = await withOrganization(db, acme.id, (tx) =>
      tx.account.findUniqueOrThrow({
        where: { id: piotr.accountId },
        include: { employee: { select: { status: true } } },
      }),
    );
    expect(accountAfterDeactivate.status).toBe("DEACTIVATED");
    expect(accountAfterDeactivate.deactivatedAt).toEqual(currentNow);
    expect(accountAfterDeactivate.authzRevision).toBe(revBeforeDeactivate + 1);
    expect(accountAfterDeactivate.employee.status).toBe("ACTIVE");

    // Wszystkie sesje i tokeny OAuth Piotra usunięte; Ewy pozostały nienaruszone
    expect(await db.authSession.count({ where: { userId: piotr.accountId } })).toBe(0);
    expect(await db.authOAuthRefreshToken.count({ where: { userId: piotr.accountId } })).toBe(0);
    expect(await db.authOAuthAccessToken.count({ where: { userId: piotr.accountId } })).toBe(0);

    expect(await db.authSession.count({ where: { userId: bystander.accountId } })).toBe(1);
    expect(await db.authOAuthRefreshToken.count({ where: { userId: bystander.accountId } })).toBe(1);
    expect(await db.authOAuthAccessToken.count({ where: { userId: bystander.accountId } })).toBe(1);

    // Stray zaproszenie PENDING -> REVOKED
    const strayInv = await withOrganization(db, acme.id, (tx) =>
      tx.invitation.findUniqueOrThrow({ where: { id: strayInvitationId }, select: { status: true } }),
    );
    expect(strayInv.status).toBe("REVOKED");

    // Zdarzenie outbox organization.permissions.changed zapisane z nową rewizją
    const outboxAfterDeactivate = await withOrganization(db, acme.id, (tx) =>
      tx.outboxEvent.findMany({
        where: {
          type: "organization.permissions.changed",
          resourceType: "account",
          resourceId: piotr.accountId,
          resourceVersion: revBeforeDeactivate + 1,
        },
      }),
    );
    expect(outboxAfterDeactivate).toHaveLength(1);

    // Audyt account.deactivated widoczny w GET /core/v1/audit-log z polską etykietą i metadanymi bez PII
    const auditAfterDeactivate = await request(
      "GET",
      `/core/v1/audit-log?action=account.deactivated&resourceId=${piotr.accountId}`,
      ownerToken,
    );
    expect(auditAfterDeactivate.statusCode).toBe(200);
    expect(auditAfterDeactivate.json().data).toHaveLength(1);
    expect(auditAfterDeactivate.json().data[0]).toMatchObject({
      action: "account.deactivated",
      actionLabel: "Wyłączono konto pracownika",
      resourceType: "account",
      resourceId: piotr.accountId,
      metadata: {
        employeeId: piotr.employeeId,
        revokedSessions: 1,
        revokedOAuthRefreshes: 2,
        revokedOAuthAccesses: 1,
      },
    });
    expect(JSON.stringify(auditAfterDeactivate.json().data[0].metadata)).not.toContain("Piotr");
    expect(JSON.stringify(auditAfterDeactivate.json().data[0].metadata)).not.toContain(piotr.email);

    // 2. Powtórka z tym samym Idempotency-Key -> 200 + Idempotency-Replayed: true bez drugiego podbicia rewizji
    const replayDeactivate = await request(
      "POST",
      `/core/v1/employees/${piotr.employeeId}/deactivate`,
      ownerToken,
      undefined,
      { [IDEMPOTENCY_KEY_HEADER]: idemKey },
    );
    expect(replayDeactivate.statusCode).toBe(200);
    expect(replayDeactivate.headers[IDEMPOTENCY_REPLAYED_HEADER.toLowerCase()]).toBe("true");
    expect(replayDeactivate.json()).toEqual(deactivateRes.json());

    // Ten sam klucz Idempotency-Key dla innego pracownika -> 409 CONFLICT
    const keyConflict = await request(
      "POST",
      `/core/v1/employees/${bystander.employeeId}/deactivate`,
      ownerToken,
      undefined,
      { [IDEMPOTENCY_KEY_HEADER]: idemKey },
    );
    expect(keyConflict.statusCode).toBe(409);
    expect(keyConflict.json().error.code).toBe("CONFLICT");

    // 3. Idempotentne powtórzenie /deactivate bez klucza (później) -> 200, brak drugiego zdarzenia/audytu/zmiany deactivatedAt
    currentNow = new Date("2026-11-26T10:15:00.000Z");
    const repeatDeactivate = await request("POST", `/core/v1/employees/${piotr.employeeId}/deactivate`, ownerToken);
    expect(repeatDeactivate.statusCode).toBe(200);
    expect(repeatDeactivate.headers[IDEMPOTENCY_REPLAYED_HEADER.toLowerCase()]).toBeUndefined();
    expect(repeatDeactivate.json().data.accountStatus).toBe("DEACTIVATED");

    const accountAfterRepeat = await withOrganization(db, acme.id, (tx) =>
      tx.account.findUniqueOrThrow({ where: { id: piotr.accountId } }),
    );
    expect(accountAfterRepeat.authzRevision).toBe(revBeforeDeactivate + 1);
    expect(accountAfterRepeat.deactivatedAt).toEqual(new Date("2026-11-26T10:00:00.000Z"));
    expect(
      (
        await withOrganization(db, acme.id, (tx) =>
          tx.auditLog.findMany({ where: { action: "account.deactivated", resourceId: piotr.accountId } }),
        )
      ).length,
    ).toBe(1);

    // 4. Niewygasły bearer JWT Piotra dostaje 401 ACCOUNT_DEACTIVATED, a migawka produktu zwraca puste products i grants
    const meBlocked = await request("GET", "/core/v1/me", piotrToken);
    expect(meBlocked.statusCode).toBe(401);
    expect(meBlocked.json().error.code).toBe("ACCOUNT_DEACTIVATED");

    const snapDeactivated = await request(
      "GET",
      `/core/v1/products/${testProductKey}/permission-snapshot?organizationId=${acme.id}&accountId=${piotr.accountId}`,
      readPermToken,
    );
    expect(snapDeactivated.statusCode).toBe(200);
    expect(snapDeactivated.json().data).toMatchObject({
      accountId: piotr.accountId,
      authzRevision: revBeforeDeactivate + 1,
      products: [],
      grants: [],
    });

    // Podczas wyłączenia nie można nadać nowej roli, ale można odebrać jedną z zachowanych ról
    const revokeWhileDeactivated = await request("DELETE", `/core/v1/role-assignments/${approveAssign.id}`, ownerToken);
    expect(revokeWhileDeactivated.statusCode).toBe(204);
    expect(readAssign.id).toBeTruthy();

    const revBeforeReactivate = (
      await withOrganization(db, acme.id, (tx) =>
        tx.account.findUniqueOrThrow({ where: { id: piotr.accountId }, select: { authzRevision: true } }),
      )
    ).authzRevision;

    // 5. Przywrócenie konta przez HR (core.employees.manage w zakresie ORGANIZATION)
    const orgHrToken = await token(acmeOrgHr);
    const reactivateRes = await request("POST", `/core/v1/employees/${piotr.employeeId}/reactivate`, orgHrToken);
    expect(reactivateRes.statusCode).toBe(200);
    expect(reactivateRes.json().data).toMatchObject({
      id: piotr.employeeId,
      accountId: piotr.accountId,
      accountStatus: "ACTIVE",
      status: "ACTIVE",
    });

    const accountAfterReactivate = await withOrganization(db, acme.id, (tx) =>
      tx.account.findUniqueOrThrow({ where: { id: piotr.accountId } }),
    );
    expect(accountAfterReactivate.status).toBe("ACTIVE");
    expect(accountAfterReactivate.deactivatedAt).toBeNull();
    expect(accountAfterReactivate.authzRevision).toBe(revBeforeReactivate + 1);

    // Audyt account.reactivated i outbox zapisane raz
    const auditAfterReactivate = await request(
      "GET",
      `/core/v1/audit-log?action=account.reactivated&resourceId=${piotr.accountId}`,
      ownerToken,
    );
    expect(auditAfterReactivate.statusCode).toBe(200);
    expect(auditAfterReactivate.json().data).toHaveLength(1);
    expect(auditAfterReactivate.json().data[0]).toMatchObject({
      action: "account.reactivated",
      actionLabel: "Przywrócono konto pracownika",
      resourceType: "account",
      resourceId: piotr.accountId,
      metadata: { employeeId: piotr.employeeId },
    });

    // Idempotentne powtórzenie /reactivate na aktywnym koncie -> 200 bez drugiego podbicia rewizji ani audytu
    const repeatReactivate = await request("POST", `/core/v1/employees/${piotr.employeeId}/reactivate`, ownerToken);
    expect(repeatReactivate.statusCode).toBe(200);
    expect(repeatReactivate.json().data.accountStatus).toBe("ACTIVE");
    expect(
      (
        await withOrganization(db, acme.id, (tx) =>
          tx.account.findUniqueOrThrow({ where: { id: piotr.accountId }, select: { authzRevision: true } }),
        )
      ).authzRevision,
    ).toBe(revBeforeReactivate + 1);
    expect(
      (
        await withOrganization(db, acme.id, (tx) =>
          tx.auditLog.findMany({ where: { action: "account.reactivated", resourceId: piotr.accountId } }),
        )
      ).length,
    ).toBe(1);

    // Po przywróceniu GET /me działa, a migawka produktu przywraca AppAccess i zachowaną rolę (bez odebranej!)
    const meRestored = await request("GET", "/core/v1/me", piotrToken);
    expect(meRestored.statusCode).toBe(200);
    expect(meRestored.json().data.account.status).toBe("ACTIVE");

    const snapRestored = await request(
      "GET",
      `/core/v1/products/${testProductKey}/permission-snapshot?organizationId=${acme.id}&accountId=${piotr.accountId}`,
      readPermToken,
    );
    expect(snapRestored.statusCode).toBe(200);
    expect(snapRestored.json().data.products).toEqual([testProductKey]);
    expect(can(snapRestored.json().data, `${testProductKey}.entries.read`)).toBe(true);
    expect(can(snapRestored.json().data, `${testProductKey}.entries.approve`)).toBe(false);
  });

  it("egzekwuje uprawnienia (403), izolację firm (404), walidację UUID (422) oraz reguły 409 (Owner, self, brak konta, INVITED, ANONYMIZED)", async () => {
    const ownerToken = await token(acme);
    const regularToken = await token(acmeRegular);
    const unitHrToken = await token(acmeUnitHr);
    const orgHrToken = await token(acmeOrgHr);
    const globexToken = await token(globex);

    const invitedMember = await createMember(acme, "Karol", "Zaproszony", { status: "INVITED" });
    const anonymizedMember = await createMember(acme, "Anon", "Usuniety");
    await withOrganization(db, acme.id, (tx) =>
      tx.employee.update({
        where: { id: anonymizedMember.employeeId },
        data: { status: "ANONYMIZED", anonymizedAt: new Date() },
      }),
    );

    const noAccountRes = await request("POST", "/core/v1/employees", ownerToken, {
      firstName: "Marek",
      lastName: "BezKonta",
    });
    expect(noAccountRes.statusCode).toBe(201);
    const noAccountEmpId = noAccountRes.json().data.id as string;

    for (const action of ["deactivate", "reactivate"] as const) {
      // Brak uprawnienia albo zakres UNIT -> 403 PERMISSION_DENIED
      for (const deniedToken of [regularToken, unitHrToken]) {
        const res = await request("POST", `/core/v1/employees/${acmeRegular.employeeId}/${action}`, deniedToken);
        expect(res.statusCode).toBe(403);
        expect(res.json().error.code).toBe("PERMISSION_DENIED");
      }

      // Pracownik innej firmy (nawet bez uprawnień) lub nieistniejący UUID -> 404 NOT_FOUND
      for (const [bearer, empId] of [
        [globexToken, acmeRegular.employeeId],
        [regularToken, globex.employeeId],
        [ownerToken, uuidv7()],
      ] as const) {
        const res = await request("POST", `/core/v1/employees/${empId}/${action}`, bearer);
        expect(res.statusCode).toBe(404);
        expect(res.json().error.code).toBe("NOT_FOUND");
      }

      // Nieprawidłowy UUID -> 422 VALIDATION_FAILED
      const badUuid = await request("POST", `/core/v1/employees/not-a-uuid/${action}`, ownerToken);
      expect(badUuid.statusCode).toBe(422);
      expect(badUuid.json().error.code).toBe("VALIDATION_FAILED");

      // Owner (przez Ownera i HR), własne konto (HR), brak konta, INVITED, ANONYMIZED -> 409 CONFLICT
      for (const [bearer, empId] of [
        [ownerToken, acme.employeeId],
        [orgHrToken, acme.employeeId],
        [orgHrToken, acmeOrgHr.employeeId],
        [ownerToken, noAccountEmpId],
        [ownerToken, invitedMember.employeeId],
        [ownerToken, anonymizedMember.employeeId],
      ] as const) {
        const res = await request("POST", `/core/v1/employees/${empId}/${action}`, bearer);
        expect(res.statusCode).toBe(409);
        expect(res.json().error.code).toBe("CONFLICT");
      }
    }
  });
});
