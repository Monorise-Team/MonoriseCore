import { AUDIT_LOG_RETENTION_DAYS, CORE_PERMISSIONS, type AuditLogEntry } from "@core/contracts";
import { createDb, uuidv7, withOrganization } from "@core/db";
import { createLocalJWKSet, exportJWK, generateKeyPair, SignJWT, type CryptoKey } from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { grantEntitlement } from "../src/entitlements.js";
import { registerCorePermissions } from "../src/permissions-registry.js";
import { registerCoreRoleTemplates } from "../src/role-templates-registry.js";
import { buildServer } from "../src/server.js";
import { createMachineTokenVerifier, createTokenVerifier } from "../src/tokens.js";

const ISSUER = "http://localhost:3100";
const AUDIENCE = "http://localhost:3200";
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
  extraAccountIds: string[];
}

let signingKey: CryptoKey;
let app: ReturnType<typeof buildServer>;
let acme: Company;
let globex: Company;
let janAdmin: Identity;
let ewaMember: Identity;
let unitAuditor: Identity;
let productId: string;
let productKey: string;
const platformAuditIds: string[] = [];

async function createCompany(name: string): Promise<Company> {
  const id = uuidv7();
  const domain = `${id.slice(-8)}-${name.toLowerCase()}.test`;
  const employeeId = uuidv7();
  const accountId = uuidv7();
  const email = `anna@${domain}`;

  await db.authUser.create({ data: { id: accountId, name: `Anna ${name}`, email, emailVerified: true } });
  await withOrganization(db, id, async (tx) => {
    await tx.organization.create({ data: { id, name, createdVia: "SELF_SIGNUP", status: "ACTIVE" } });
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

const request = (
  method: "GET" | "POST" | "PUT" | "PATCH" | "DELETE",
  url: string,
  bearer?: string,
  payload?: Record<string, unknown>,
) =>
  app.inject({
    method,
    url,
    headers: bearer ? { authorization: `Bearer ${bearer}` } : {},
    ...(payload !== undefined ? { payload } : {}),
  });

beforeAll(async () => {
  await registerCorePermissions(db);
  await registerCoreRoleTemplates(db);

  const pair = await generateKeyPair("EdDSA", { crv: "Ed25519" });
  signingKey = pair.privateKey;
  const jwk = { ...(await exportJWK(pair.publicKey)), alg: "EdDSA", kid: "audit-test" };
  const tokenOptions = { keys: createLocalJWKSet({ keys: [jwk] }), issuer: ISSUER, audience: AUDIENCE };

  app = buildServer({
    db,
    verifyToken: createTokenVerifier(tokenOptions),
    verifyMachineToken: createMachineTokenVerifier(tokenOptions),
  });

  acme = await createCompany("Acme");
  globex = await createCompany("Globex");
  janAdmin = await createMember(acme, "Jan", "Kowalski");
  ewaMember = await createMember(acme, "Ewa", "Nowak");
  unitAuditor = await createMember(acme, "Kasia", "Działowa");

  productId = uuidv7();
  productKey = `auditprod${productId.replaceAll("-", "").slice(-6)}`;
  await ownerDb.product.create({
    data: {
      id: productId,
      key: productKey,
      name: "Audit Test Product",
      registrationClientId: `${productKey}-web`,
    },
  });
});

afterAll(async () => {
  await app?.close();
  for (const company of [acme, globex]) {
    if (!company) continue;
    await withOrganization(db, company.id, (tx) => tx.organization.delete({ where: { id: company.id } }));
    for (const accountId of [company.accountId, ...company.extraAccountIds]) {
      await db.authUser.deleteMany({ where: { id: accountId } });
    }
  }
  if (platformAuditIds.length > 0) {
    await ownerDb.auditLog.deleteMany({ where: { id: { in: platformAuditIds } } });
  }
  if (productId) {
    await ownerDb.auditLog.deleteMany({ where: { productId } });
    await ownerDb.product.deleteMany({ where: { id: productId } });
  }
  await db.$disconnect();
  await ownerDb.$disconnect();
});

describe("GET /core/v1/audit-log — dziennik zdarzeń firmy", () => {
  it("zwraca wpisy firmy od najnowszych z uprawnieniami, filtrami, kursorem, redakcją, retencją 730 dni i izolacją RLS", async () => {
    const ownerToken = await token(acme);
    const adminToken = await token(janAdmin);
    const regularToken = await token(ewaMember);
    const unitAuditorToken = await token(unitAuditor);
    const globexToken = await token(globex);

    // 1. Nadaj Janowi szablon core.company_admin (ma core.audit.read w zakresie ORGANIZATION)
    const companyAdminRole = await withOrganization(db, acme.id, (tx) =>
      tx.role.findUniqueOrThrow({ where: { key: "core.company_admin" }, select: { id: true } }),
    );
    const assignAdminRes = await request("POST", "/core/v1/role-assignments", ownerToken, {
      accountId: janAdmin.accountId,
      roleId: companyAdminRole.id,
      scopeType: "ORGANIZATION",
    });
    expect(assignAdminRes.statusCode).toBe(201);

    // 2. Utwórz jednostkę i nadaj Kasi rolę z core.audit.read tylko w zakresie UNIT (musi dostać 403)
    const unitRes = await request("POST", "/core/v1/units", ownerToken, { name: "Dział Produktu", type: "DEPARTMENT" });
    expect(unitRes.statusCode).toBe(201);
    const unitId = (unitRes.json().data as { id: string }).id;

    const unitAuditRoleRes = await request("POST", "/core/v1/roles", ownerToken, {
      name: "Audytor jednostki",
      product: null,
      permissions: [CORE_PERMISSIONS.keys["audit.read"]],
    });
    expect(unitAuditRoleRes.statusCode).toBe(201);
    const unitAuditRoleId = (unitAuditRoleRes.json().data as { id: string }).id;

    const assignUnitAuditorRes = await request("POST", "/core/v1/role-assignments", ownerToken, {
      accountId: unitAuditor.accountId,
      roleId: unitAuditRoleId,
      scopeType: "UNIT",
      scopeId: unitId,
    });
    expect(assignUnitAuditorRes.statusCode).toBe(201);

    // 3. Przyznaj firmie Entitlement, potem Jan włącza i wyłącza Ewie dostęp do produktu
    await grantEntitlement(db, { organization: acme.id, product: productKey });

    const grantAccessRes = await request("POST", "/core/v1/app-access", adminToken, {
      accountId: ewaMember.accountId,
      product: productKey,
    });
    expect(grantAccessRes.statusCode).toBe(201);
    const appAccessId = (grantAccessRes.json().data as { id: string }).id;

    const revokeAccessRes = await request("DELETE", `/core/v1/app-access/${appAccessId}`, adminToken);
    expect(revokeAccessRes.statusCode).toBe(204);

    // 4. Globex wykonuje swoją akcję — nigdy nie może pojawić się w dzienniku Acme
    const globexUnitRes = await request("POST", "/core/v1/units", globexToken, {
      name: "Tajny Oddział",
      type: "BRANCH",
    });
    expect(globexUnitRes.statusCode).toBe(201);
    const globexUnitId = (globexUnitRes.json().data as { id: string }).id;

    // 5. Zasadź wpisy brzegowe w bazie:
    //    - dwa wpisy z identycznym createdAt (test złożonego kursora)
    //    - wpis OPERATOR z actorOperatorId i wrażliwym metadata (tokenHash, clientSecret)
    //    - wpis PRODUCT z nieznaną akcją produktu (test fallbacku actionLabel)
    //    - wpis sprzed 731 dni (poza oknem retencji)
    //    - wpis platformy bez organizationId (RLS ukrywa przed firmami)
    const now = new Date();
    const tiedAt = new Date(now.getTime() - 10_000);
    const tiedIdLow = "01900000-0000-7000-8000-000000000001";
    const tiedIdHigh = "01900000-0000-7000-8000-000000000002";
    const operatorAuditId = uuidv7();
    const productAuditId = uuidv7();
    const expiredAuditId = uuidv7();
    const supportGrantId = uuidv7();
    const secretOperatorId = uuidv7();
    const expiredAt = new Date(now.getTime() - (AUDIT_LOG_RETENTION_DAYS + 1) * 24 * 60 * 60 * 1000);

    await withOrganization(db, acme.id, async (tx) => {
      await tx.auditLog.create({
        data: {
          id: tiedIdLow,
          organizationId: acme.id,
          actorType: "SYSTEM",
          action: "entitlement.granted",
          resourceType: "entitlement",
          resourceId: "tied-low",
          metadata: { seq: "low" },
          createdAt: tiedAt,
        },
      });
      await tx.auditLog.create({
        data: {
          id: tiedIdHigh,
          organizationId: acme.id,
          actorType: "SYSTEM",
          action: "entitlement.granted",
          resourceType: "entitlement",
          resourceId: "tied-high",
          metadata: { seq: "high" },
          createdAt: tiedAt,
        },
      });
      await tx.auditLog.create({
        data: {
          id: operatorAuditId,
          organizationId: acme.id,
          actorType: "OPERATOR",
          actorOperatorId: secretOperatorId,
          supportAccessGrantId: supportGrantId,
          action: "organization.updated",
          resourceType: "organization",
          resourceId: acme.id,
          metadata: {
            changed: "name",
            tokenHash: "sha256-never-leak",
            clientSecret: "oauth-secret-never-leak",
            nested: { passwordHash: "bcrypt-never-leak", safe: "ok" },
          },
          createdAt: new Date(now.getTime() - 20_000),
        },
      });
      await tx.auditLog.create({
        data: {
          id: productAuditId,
          organizationId: acme.id,
          actorType: "PRODUCT",
          productId,
          action: `${productKey}.timesheet.approved`,
          resourceType: "timesheet",
          resourceId: "ts-123",
          metadata: { days: 5 },
          createdAt: new Date(now.getTime() - 30_000),
        },
      });
      await tx.auditLog.create({
        data: {
          id: expiredAuditId,
          organizationId: acme.id,
          actorType: "ACCOUNT",
          actorAccountId: acme.accountId,
          action: "unit.created",
          resourceType: "unit",
          resourceId: "ancient-unit",
          metadata: {},
          createdAt: expiredAt,
        },
      });
    });

    const platformAuditId = uuidv7();
    platformAuditIds.push(platformAuditId);
    await db.auditLog.create({
      data: {
        id: platformAuditId,
        organizationId: null,
        actorType: "SYSTEM",
        action: "role_templates.registered",
        resourceType: "product",
        resourceId: "core",
        metadata: {},
      },
    });

    // 6. Kontrola dostępu: brak tokenu -> 401; zwykły pracownik i zakres UNIT -> 403; Owner i company_admin -> 200
    expect((await request("GET", "/core/v1/audit-log")).statusCode).toBe(401);

    const regularRes = await request("GET", "/core/v1/audit-log", regularToken);
    expect(regularRes.statusCode).toBe(403);
    expect(regularRes.json().error.code).toBe("PERMISSION_DENIED");

    const unitRes403 = await request("GET", "/core/v1/audit-log", unitAuditorToken);
    expect(unitRes403.statusCode).toBe(403);
    expect(unitRes403.json().error.code).toBe("PERMISSION_DENIED");

    const ownerListRes = await request("GET", "/core/v1/audit-log?limit=100", ownerToken);
    expect(ownerListRes.statusCode).toBe(200);
    const ownerEntries = ownerListRes.json().data as AuditLogEntry[];

    const adminListRes = await request("GET", "/core/v1/audit-log?limit=100", adminToken);
    expect(adminListRes.statusCode).toBe(200);
    expect((adminListRes.json().data as AuditLogEntry[]).map((e) => e.id)).toEqual(ownerEntries.map((e) => e.id));

    // 7. Kolejność od najnowszych, brak wpisu innej firmy, brak wpisu platformowego, brak wpisu sprzed 731 dni
    for (let i = 1; i < ownerEntries.length; i++) {
      const prev = ownerEntries[i - 1]!;
      const curr = ownerEntries[i]!;
      const prevTime = Date.parse(prev.createdAt);
      const currTime = Date.parse(curr.createdAt);
      expect(prevTime >= currTime).toBe(true);
      if (prevTime === currTime) {
        expect(prev.id > curr.id).toBe(true);
      }
    }
    expect(ownerEntries.some((e) => e.resourceId === globexUnitId)).toBe(false);
    expect(ownerEntries.some((e) => e.id === platformAuditId)).toBe(false);
    expect(ownerEntries.some((e) => e.id === expiredAuditId)).toBe(false);

    // 8. Nazwa aktora, polskie etykiety akcji, fallback produktu, redakcja i brak actorOperatorId
    const revokeEntry = ownerEntries.find((e) => e.action === "app_access.revoked" && e.resourceId === appAccessId);
    expect(revokeEntry).toMatchObject({
      actorType: "ACCOUNT",
      actorAccountId: janAdmin.accountId,
      actorDisplayName: "Jan Kowalski",
      action: "app_access.revoked",
      actionLabel: "Wyłączono dostęp do aplikacji",
      resourceType: "app_access",
      resourceId: appAccessId,
    });

    const operatorEntry = ownerEntries.find((e) => e.id === operatorAuditId);
    expect(operatorEntry).toBeDefined();
    expect(operatorEntry?.actorType).toBe("OPERATOR");
    expect(operatorEntry?.actorAccountId).toBeNull();
    expect(operatorEntry?.actorDisplayName).toBeNull();
    expect(operatorEntry?.supportAccessGrantId).toBe(supportGrantId);
    expect(operatorEntry?.metadata).toEqual({ changed: "name", nested: { safe: "ok" } });
    expect("actorOperatorId" in (operatorEntry as Record<string, unknown>)).toBe(false);

    const productEntry = ownerEntries.find((e) => e.id === productAuditId);
    expect(productEntry).toMatchObject({
      actorType: "PRODUCT",
      actorAccountId: null,
      actorDisplayName: null,
      product: productKey,
      action: `${productKey}.timesheet.approved`,
      actionLabel: `${productKey}.timesheet.approved`,
    });

    // 9. Stronicowanie kursorowe przez wszystkie strony (limit=2) włącznie z remisem czasu (tiedIdHigh -> tiedIdLow)
    const pagedIds: string[] = [];
    let cursor: string | null = null;
    do {
      const url = cursor
        ? `/core/v1/audit-log?limit=2&cursor=${encodeURIComponent(cursor)}`
        : "/core/v1/audit-log?limit=2";
      const pageRes = await request("GET", url, ownerToken);
      expect(pageRes.statusCode).toBe(200);
      const body = pageRes.json() as { data: AuditLogEntry[]; meta: { nextCursor: string | null } };
      pagedIds.push(...body.data.map((item) => item.id));
      cursor = body.meta.nextCursor;
    } while (cursor !== null);

    expect(pagedIds).toEqual(ownerEntries.map((e) => e.id));
    expect(new Set(pagedIds).size).toBe(pagedIds.length);
    expect(pagedIds.indexOf(tiedIdHigh)).toBeGreaterThan(-1);
    expect(pagedIds.indexOf(tiedIdLow)).toBe(pagedIds.indexOf(tiedIdHigh) + 1);

    // 10. Filtry: actorAccountId, actorType, action, resourceType, resourceId, from/to
    const byJan = await request("GET", `/core/v1/audit-log?actorAccountId=${janAdmin.accountId}`, ownerToken);
    expect(byJan.statusCode).toBe(200);
    const byJanData = byJan.json().data as AuditLogEntry[];
    expect(byJanData.length).toBeGreaterThanOrEqual(2);
    expect(byJanData.every((e) => e.actorAccountId === janAdmin.accountId)).toBe(true);

    const byAction = await request("GET", "/core/v1/audit-log?action=app_access.revoked", ownerToken);
    expect(byAction.statusCode).toBe(200);
    expect((byAction.json().data as AuditLogEntry[]).map((e) => e.resourceId)).toEqual([appAccessId]);

    const byActorType = await request("GET", "/core/v1/audit-log?actorType=OPERATOR", ownerToken);
    expect(byActorType.statusCode).toBe(200);
    expect((byActorType.json().data as AuditLogEntry[]).map((e) => e.id)).toEqual([operatorAuditId]);

    const byResource = await request("GET", `/core/v1/audit-log?resourceType=unit&resourceId=${unitId}`, ownerToken);
    expect(byResource.statusCode).toBe(200);
    expect((byResource.json().data as AuditLogEntry[]).map((e) => e.action)).toEqual(["unit.created"]);

    const byDateRange = await request(
      "GET",
      `/core/v1/audit-log?from=${encodeURIComponent(tiedAt.toISOString())}&to=${encodeURIComponent(tiedAt.toISOString())}`,
      ownerToken,
    );
    expect(byDateRange.statusCode).toBe(200);
    expect((byDateRange.json().data as AuditLogEntry[]).map((e) => e.id)).toEqual([tiedIdHigh, tiedIdLow]);

    // 11. Walidacja parametrów (422): from > to, limit > 100, nieprawidłowy kursor
    expect(
      (await request("GET", "/core/v1/audit-log?from=2026-11-26T15:00:00.000Z&to=2026-11-26T14:00:00.000Z", ownerToken))
        .statusCode,
    ).toBe(422);
    expect((await request("GET", "/core/v1/audit-log?limit=101", ownerToken)).statusCode).toBe(422);
    expect((await request("GET", "/core/v1/audit-log?cursor=zly-kursor", ownerToken)).statusCode).toBe(422);
  });
});
