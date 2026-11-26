import {
  CORE_PERMISSIONS,
  domainVerificationHost,
  IDEMPOTENCY_KEY_HEADER,
  IDEMPOTENCY_REPLAYED_HEADER,
  MAX_ORGANIZATION_DOMAINS,
} from "@core/contracts";
import { createDb, domainTxtValue, hashToken, uuidv7, withOrganization } from "@core/db";
import { createLocalJWKSet, exportJWK, generateKeyPair, SignJWT, type CryptoKey } from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { registerCorePermissions } from "../src/permissions-registry.js";
import { registerCoreRoleTemplates } from "../src/role-templates-registry.js";
import { buildServer } from "../src/server.js";
import { createMachineTokenVerifier, createTokenVerifier } from "../src/tokens.js";

const ISSUER = "http://localhost:3100";
const AUDIENCE = "http://localhost:3200";
const AUTH_URL = "http://localhost:3100";
const DOMAIN_SECRET = "test-domain-verification-secret-0123456789";

const db = createDb(
  process.env.CORE_TEST_APP_DATABASE_URL ?? "postgresql://core_app:core_app@localhost:5433/monorise_core_test",
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
  primaryDomainId: string;
  extraAccountIds: string[];
}

const createdCompanies: Company[] = [];
const dnsRecordsByHost = new Map<string, string[][]>();
let dnsLookupCount = 0;

let signingKey: CryptoKey;
let app: ReturnType<typeof buildServer>;
let devTrustApp: ReturnType<typeof buildServer>;
let acme: Company;
let globex: Company;
let acmeRegular: Identity;
let acmeCompanyAdmin: Identity;
let acmeUnitOrgAdmin: Identity;

async function createCompany(name: string, options?: { primaryStatus?: "VERIFIED" | "PENDING" }): Promise<Company> {
  const id = uuidv7();
  const domain = `${id.slice(-8)}-${name.toLowerCase()}.test`;
  const primaryDomainId = uuidv7();
  const employeeId = uuidv7();
  const accountId = uuidv7();
  const email = `anna@${domain}`;
  const primaryStatus = options?.primaryStatus ?? "VERIFIED";

  await db.authUser.create({ data: { id: accountId, name: `Anna ${name}`, email, emailVerified: true } });
  await withOrganization(db, id, async (tx) => {
    await tx.organization.create({ data: { id, name, createdVia: "SELF_SIGNUP", status: "ACTIVE" } });
    await tx.organizationDomain.create({
      data: {
        id: primaryDomainId,
        organizationId: id,
        domain,
        status: primaryStatus,
        verificationMethod: "DNS_TXT",
        verificationTokenHash: hashToken(domainTxtValue(DOMAIN_SECRET, id, domain)),
        verifiedAt: primaryStatus === "VERIFIED" ? new Date("2026-11-20T00:00:00.000Z") : null,
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

  const company: Company = {
    id,
    domain,
    primaryDomainId,
    organizationId: id,
    employeeId,
    accountId,
    email,
    extraAccountIds: [],
  };
  createdCompanies.push(company);
  return company;
}

async function createMember(company: Company, firstName: string, lastName: string): Promise<Identity> {
  const employeeId = uuidv7();
  const accountId = uuidv7();
  const email = `${firstName.toLowerCase()}-${accountId.slice(-6)}@${company.domain}`;

  await db.authUser.create({ data: { id: accountId, name: `${firstName} ${lastName}`, email, emailVerified: true } });
  await withOrganization(db, company.id, async (tx) => {
    await tx.employee.create({
      data: { id: employeeId, organizationId: company.id, firstName, lastName, workEmail: email },
    });
    await tx.account.create({
      data: { id: accountId, organizationId: company.id, employeeId, email, normalizedEmail: email, status: "ACTIVE" },
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

function inject(
  target: ReturnType<typeof buildServer>,
  method: "GET" | "POST" | "PUT" | "PATCH" | "DELETE",
  url: string,
  bearer?: string,
  payload?: Record<string, unknown>,
  extraHeaders?: Record<string, string>,
) {
  return target.inject({
    method,
    url,
    headers: {
      ...(bearer ? { authorization: `Bearer ${bearer}` } : {}),
      ...extraHeaders,
    },
    ...(payload !== undefined ? { payload } : {}),
  });
}

beforeAll(async () => {
  process.env.CORE_SMTP_URL = "memory";
  await registerCorePermissions(db);
  await registerCoreRoleTemplates(db);

  const pair = await generateKeyPair("EdDSA", { crv: "Ed25519" });
  signingKey = pair.privateKey;
  const jwk = { ...(await exportJWK(pair.publicKey)), alg: "EdDSA", kid: "test-domains" };
  const tokenOptions = { keys: createLocalJWKSet({ keys: [jwk] }), issuer: ISSUER, audience: AUDIENCE };

  const resolveTxt = async (hostname: string) => {
    dnsLookupCount += 1;
    const records = dnsRecordsByHost.get(hostname.toLowerCase());
    if (!records) {
      throw Object.assign(new Error("ENOTFOUND"), { code: "ENOTFOUND" });
    }
    return records;
  };

  app = buildServer({
    db,
    verifyToken: createTokenVerifier(tokenOptions),
    verifyMachineToken: createMachineTokenVerifier(tokenOptions),
    authUrl: AUTH_URL,
    domainVerificationSecret: DOMAIN_SECRET,
    devTrustDomains: false,
    resolveTxt,
  });

  devTrustApp = buildServer({
    db,
    verifyToken: createTokenVerifier(tokenOptions),
    verifyMachineToken: createMachineTokenVerifier(tokenOptions),
    authUrl: AUTH_URL,
    domainVerificationSecret: DOMAIN_SECRET,
    devTrustDomains: true,
    resolveTxt,
  });

  acme = await createCompany("Acme");
  globex = await createCompany("Globex");
  acmeRegular = await createMember(acme, "Piotr", "Zwykly");
  acmeCompanyAdmin = await createMember(acme, "Marta", "Admin");
  acmeUnitOrgAdmin = await createMember(acme, "Tomasz", "Oddzial");

  const companyAdminTemplate = await db.role.findFirstOrThrow({
    where: { key: "core.company_admin" },
    select: { id: true },
  });
  const orgManagePerm = await db.permission.findUniqueOrThrow({
    where: { key: CORE_PERMISSIONS.keys["organization.manage"] },
    select: { id: true },
  });

  const unitId = uuidv7();
  const unitRoleId = uuidv7();
  await withOrganization(db, acme.id, async (tx) => {
    await tx.organizationUnit.create({
      data: { id: unitId, organizationId: acme.id, name: "Kraków", type: "BRANCH" },
    });
    await tx.role.create({
      data: { id: unitRoleId, organizationId: acme.id, productId: null, name: "Zarzad Oddzialu" },
    });
    await tx.rolePermission.create({
      data: { roleId: unitRoleId, permissionId: orgManagePerm.id },
    });
    await tx.roleAssignment.create({
      data: {
        id: uuidv7(),
        organizationId: acme.id,
        accountId: acmeCompanyAdmin.accountId,
        roleId: companyAdminTemplate.id,
        scopeType: "ORGANIZATION",
        grantedByAccountId: acme.accountId,
      },
    });
    await tx.roleAssignment.create({
      data: {
        id: uuidv7(),
        organizationId: acme.id,
        accountId: acmeUnitOrgAdmin.accountId,
        roleId: unitRoleId,
        scopeType: "UNIT",
        scopeId: unitId,
        grantedByAccountId: acme.accountId,
      },
    });
  });
});

afterAll(async () => {
  await app?.close();
  await devTrustApp?.close();
  for (const company of createdCompanies) {
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

describe("Dane firmy i zarządzanie domenami (MonoriseCore#66)", () => {
  it("szablon core.company_admin zawiera core.organization.manage i uzupełnia je przy starcie, a PUT /organization/owner pozostaje tylko dla Ownera", async () => {
    const companyAdmin = await db.role.findFirstOrThrow({
      where: { key: "core.company_admin" },
      include: { permissions: { select: { permission: { select: { id: true, key: true } } } } },
    });
    const orgPerm = companyAdmin.permissions.find(
      (rp) => rp.permission.key === CORE_PERMISSIONS.keys["organization.manage"],
    );
    expect(orgPerm).toBeDefined();

    // Symulacja aktualizacji istniejącej bazy przy starcie Core API
    await db.rolePermission.delete({
      where: { roleId_permissionId: { roleId: companyAdmin.id, permissionId: orgPerm!.permission.id } },
    });
    const summary = await registerCoreRoleTemplates(db);
    expect(summary.updated).toContain("core.company_admin");

    const refreshed = await db.role.findFirstOrThrow({
      where: { key: "core.company_admin" },
      include: { permissions: { select: { permission: { select: { key: true } } } } },
    });
    expect(refreshed.permissions.map((rp) => rp.permission.key)).toContain(
      CORE_PERMISSIONS.keys["organization.manage"],
    );

    // Administrator firmy nadal dostaje 403 przy próbie przekazania roli Ownera
    const adminToken = await token(acmeCompanyAdmin);
    const transferAttempt = await inject(app, "PUT", "/core/v1/organization/owner", adminToken, {
      accountId: acmeCompanyAdmin.accountId,
    });
    expect(transferAttempt.statusCode).toBe(403);
    expect(transferAttempt.json().error.code).toBe("PERMISSION_DENIED");
  });

  it("PATCH /core/v1/organization: pozwala Ownerowi i Administratorowi firmy, odrzuca brak uprawnień / zakres UNIT / błędne dane i pomija duplikat audytu", async () => {
    const ownerToken = await token(acme);
    const adminToken = await token(acmeCompanyAdmin);
    const unitAdminToken = await token(acmeUnitOrgAdmin);
    const regularToken = await token(acmeRegular);

    for (const deniedToken of [regularToken, unitAdminToken]) {
      const denied = await inject(app, "PATCH", "/core/v1/organization", deniedToken, { name: "Acme Zmiana" });
      expect(denied.statusCode).toBe(403);
      expect(denied.json().error.code).toBe("PERMISSION_DENIED");
    }

    for (const payload of [{ name: "A" }, { name: "   " }, { name: "x".repeat(121) }, { name: "Acme", extra: true }]) {
      const bad = await inject(app, "PATCH", "/core/v1/organization", ownerToken, payload);
      expect(bad.statusCode).toBe(422);
      expect(bad.json().error.code).toBe("VALIDATION_FAILED");
    }

    const updatedByOwner = await inject(app, "PATCH", "/core/v1/organization", ownerToken, {
      name: "  Acme Sp. z o.o.  ",
    });
    expect(updatedByOwner.statusCode).toBe(200);
    expect(updatedByOwner.json().data.name).toBe("Acme Sp. z o.o.");

    // Brak zmiany nazwy -> 200 i brak drugiego wpisu audytu
    const noop = await inject(app, "PATCH", "/core/v1/organization", adminToken, { name: "Acme Sp. z o.o." });
    expect(noop.statusCode).toBe(200);

    const updatedByAdmin = await inject(app, "PATCH", "/core/v1/organization", adminToken, { name: "Acme Europe" });
    expect(updatedByAdmin.statusCode).toBe(200);
    expect(updatedByAdmin.json().data.name).toBe("Acme Europe");

    const auditRows = await withOrganization(db, acme.id, (tx) =>
      tx.auditLog.findMany({
        where: { action: "organization.updated", resourceId: acme.id },
        orderBy: [{ createdAt: "asc" }, { id: "asc" }],
      }),
    );
    expect(auditRows).toHaveLength(2);
    expect(auditRows[0]?.metadata).toEqual({
      fields: ["name"],
      previousName: "Acme",
      name: "Acme Sp. z o.o.",
    });
    expect(auditRows[1]?.metadata).toEqual({
      fields: ["name"],
      previousName: "Acme Sp. z o.o.",
      name: "Acme Europe",
    });
  });

  it("dodaje domenę, weryfikuje DNS TXT i trustLocally, obsługuje Idempotency-Key oraz umożliwia zaproszenia w nowej domenie", async () => {
    const ownerToken = await token(acme);
    const adminToken = await token(acmeCompanyAdmin);
    const unitAdminToken = await token(acmeUnitOrgAdmin);
    const regularToken = await token(acmeRegular);

    const secondaryDomain = `${uuidv7().slice(-8)}-eu.acme.test`;
    const devTrustDomain = `${uuidv7().slice(-8)}-dev.acme.test`;

    // Uprawnienia, darmowa skrzynka, błędna składnia, duplikat własny i innej firmy
    expect(
      (await inject(app, "POST", "/core/v1/organization/domains", regularToken, { domain: secondaryDomain }))
        .statusCode,
    ).toBe(403);

    const freeRes = await inject(app, "POST", "/core/v1/organization/domains", ownerToken, { domain: "gmail.com" });
    expect(freeRes.statusCode).toBe(422);
    expect(freeRes.json().error.code).toBe("EMAIL_DOMAIN_NOT_ALLOWED");

    const invalidRes = await inject(app, "POST", "/core/v1/organization/domains", ownerToken, { domain: "localhost" });
    expect(invalidRes.statusCode).toBe(422);
    expect(invalidRes.json().error.code).toBe("VALIDATION_FAILED");

    const dupOwn = await inject(app, "POST", "/core/v1/organization/domains", ownerToken, { domain: acme.domain });
    const dupOther = await inject(app, "POST", "/core/v1/organization/domains", ownerToken, { domain: globex.domain });
    expect(dupOwn.statusCode).toBe(409);
    expect(dupOther.statusCode).toBe(409);
    expect(dupOther.json().error.code).toBe("CONFLICT");
    expect(dupOther.json().error.message).toBe(dupOwn.json().error.message);

    // Dodanie domeny z Idempotency-Key
    const idemAddKey = `add-dom-${uuidv7()}`;
    const added = await inject(
      app,
      "POST",
      "/core/v1/organization/domains",
      ownerToken,
      { domain: `  ${secondaryDomain.toUpperCase()}  ` },
      { [IDEMPOTENCY_KEY_HEADER]: idemAddKey },
    );
    expect(added.statusCode).toBe(201);
    const domainId = added.json().data.id as string;
    const expectedTxtName = domainVerificationHost(secondaryDomain);
    const expectedTxtValue = domainTxtValue(DOMAIN_SECRET, acme.id, secondaryDomain);
    expect(added.json().data).toMatchObject({
      id: domainId,
      domain: secondaryDomain,
      status: "PENDING",
      isPrimary: false,
      verifiedAt: null,
      lastCheckedAt: null,
      verificationTxtName: expectedTxtName,
      verificationTxtValue: expectedTxtValue,
    });
    expect(added.json().data).not.toHaveProperty("verificationTokenHash");

    // Powtórka Idempotency-Key -> 201 + Idempotency-Replayed: true
    const replayedAdd = await inject(
      app,
      "POST",
      "/core/v1/organization/domains",
      ownerToken,
      { domain: `  ${secondaryDomain.toUpperCase()}  ` },
      { [IDEMPOTENCY_KEY_HEADER]: idemAddKey },
    );
    expect(replayedAdd.statusCode).toBe(201);
    expect(replayedAdd.headers[IDEMPOTENCY_REPLAYED_HEADER.toLowerCase()]).toBe("true");
    expect(replayedAdd.json().data).toEqual(added.json().data);

    // GET /core/v1/organization: Owner i admin widzą TXT; zwykły pracownik i zakres UNIT widzą null
    for (const t of [ownerToken, adminToken]) {
      const orgRes = await inject(app, "GET", "/core/v1/organization", t);
      expect(orgRes.statusCode).toBe(200);
      const sec = (
        orgRes.json().data.domains as {
          id: string;
          verificationTxtName: string | null;
          verificationTxtValue: string | null;
        }[]
      ).find((d) => d.id === domainId);
      expect(sec).toMatchObject({
        verificationTxtName: expectedTxtName,
        verificationTxtValue: expectedTxtValue,
      });
    }
    for (const t of [regularToken, unitAdminToken]) {
      const orgRes = await inject(app, "GET", "/core/v1/organization", t);
      expect(orgRes.statusCode).toBe(200);
      const sec = (
        orgRes.json().data.domains as {
          id: string;
          verificationTxtName: string | null;
          verificationTxtValue: string | null;
        }[]
      ).find((d) => d.id === domainId);
      expect(sec).toMatchObject({
        verificationTxtName: null,
        verificationTxtValue: null,
      });
    }

    // Weryfikacja domeny innej firmy -> 404 nawet bez uprawnień (404 przed 403)
    const foreignVerify = await inject(
      app,
      "POST",
      `/core/v1/organization/domains/${globex.primaryDomainId}/verify`,
      regularToken,
      {},
    );
    expect(foreignVerify.statusCode).toBe(404);
    expect(foreignVerify.json().error.code).toBe("NOT_FOUND");

    // Zwykły pracownik -> 403; trustLocally=true gdy devTrustDomains=false -> 403
    expect(
      (await inject(app, "POST", `/core/v1/organization/domains/${domainId}/verify`, regularToken, {})).statusCode,
    ).toBe(403);
    expect(
      (
        await inject(app, "POST", `/core/v1/organization/domains/${domainId}/verify`, ownerToken, {
          trustLocally: true,
        })
      ).statusCode,
    ).toBe(403);

    // Brak rekordu TXT -> 422 + zapisane lastCheckedAt w bazie + brak zapisu Idempotency-Key
    const idemVerifyKey = `verify-dom-${uuidv7()}`;
    const missingTxt = await inject(
      app,
      "POST",
      `/core/v1/organization/domains/${domainId}/verify`,
      ownerToken,
      {},
      { [IDEMPOTENCY_KEY_HEADER]: idemVerifyKey },
    );
    expect(missingTxt.statusCode).toBe(422);
    expect(missingTxt.json().error.code).toBe("VALIDATION_FAILED");
    const rowAfterFail = await withOrganization(db, acme.id, (tx) =>
      tx.organizationDomain.findUniqueOrThrow({ where: { id: domainId } }),
    );
    expect(rowAfterFail.status).toBe("PENDING");
    expect(rowAfterFail.lastCheckedAt).not.toBeNull();

    // Publikacja podzielonego rekordu TXT -> ten sam Idempotency-Key kończy się 200 VERIFIED
    dnsRecordsByHost.set(expectedTxtName.toLowerCase(), [[expectedTxtValue.slice(0, 14), expectedTxtValue.slice(14)]]);
    const verified = await inject(
      app,
      "POST",
      `/core/v1/organization/domains/${domainId}/verify`,
      adminToken,
      {},
      { [IDEMPOTENCY_KEY_HEADER]: idemVerifyKey },
    );
    expect(verified.statusCode).toBe(200);
    expect(verified.json().data).toMatchObject({
      id: domainId,
      domain: secondaryDomain,
      status: "VERIFIED",
      verificationTxtName: null,
      verificationTxtValue: null,
    });
    expect(verified.json().data.verifiedAt).not.toBeNull();
    expect(verified.json().data.lastCheckedAt).not.toBeNull();

    // Powtórka Idempotency-Key -> replay bez kolejnego zapytania DNS
    const lookupsBeforeReplay = dnsLookupCount;
    const replayedVerify = await inject(
      app,
      "POST",
      `/core/v1/organization/domains/${domainId}/verify`,
      adminToken,
      {},
      { [IDEMPOTENCY_KEY_HEADER]: idemVerifyKey },
    );
    expect(replayedVerify.statusCode).toBe(200);
    expect(replayedVerify.headers[IDEMPOTENCY_REPLAYED_HEADER.toLowerCase()]).toBe("true");
    expect(dnsLookupCount).toBe(lookupsBeforeReplay);

    // Zaproszenie pracownika w zweryfikowanej drugiej domenie działa!
    const inviteRes = await inject(app, "POST", "/core/v1/invitations", ownerToken, {
      email: `ewa@${secondaryDomain}`,
      firstName: "Ewa",
      lastName: "Nowak",
    });
    expect(inviteRes.statusCode).toBe(201);
    expect(inviteRes.json().data.email).toBe(`ewa@${secondaryDomain}`);

    // Lokalna ścieżka trustLocally=true gdy devTrustDomains=true
    const devAdd = await inject(devTrustApp, "POST", "/core/v1/organization/domains", ownerToken, {
      domain: devTrustDomain,
    });
    expect(devAdd.statusCode).toBe(201);
    const devDomainId = devAdd.json().data.id as string;
    const devVerify = await inject(
      devTrustApp,
      "POST",
      `/core/v1/organization/domains/${devDomainId}/verify`,
      ownerToken,
      { trustLocally: true },
    );
    expect(devVerify.statusCode).toBe(200);
    expect(devVerify.json().data.status).toBe("VERIFIED");

    // Sprawdzenie wpisów audytu (bez żadnych sekretów ani skrótów)
    const domainAudits = await withOrganization(db, acme.id, (tx) =>
      tx.auditLog.findMany({
        where: { resourceId: { in: [domainId, devDomainId] } },
        orderBy: [{ createdAt: "asc" }, { id: "asc" }],
      }),
    );
    expect(domainAudits.map((row) => ({ action: row.action, metadata: row.metadata }))).toEqual([
      { action: "organization.domain.added", metadata: { domain: secondaryDomain } },
      { action: "organization.domain.verified", metadata: { domain: secondaryDomain, method: "DNS_TXT" } },
      { action: "organization.domain.added", metadata: { domain: devTrustDomain } },
      { action: "organization.domain.verified", metadata: { domain: devTrustDomain, method: "DEV_TRUST" } },
    ]);
  });

  it("PUT .../primary i DELETE .../domains/{domainId}: atomowa zamiana głównej domeny, ochrona używanych i ostatniej zweryfikowanej domeny, limit 20 domen i zwolnienie po usunięciu", async () => {
    const swapCo = await createCompany("SwapCo");
    const swapRegular = await createMember(swapCo, "Jan", "Zwykly");
    const swapOwnerToken = await token(swapCo);
    const swapRegularToken = await token(swapRegular);
    const globexOwnerToken = await token(globex);

    const newPrimaryDomain = `${uuidv7().slice(-8)}-primary.swap.test`;
    const removableDomain = `${uuidv7().slice(-8)}-temp.swap.test`;
    const guardedDomain = `${uuidv7().slice(-8)}-used.swap.test`;

    const addPrimaryRes = await inject(devTrustApp, "POST", "/core/v1/organization/domains", swapOwnerToken, {
      domain: newPrimaryDomain,
    });
    expect(addPrimaryRes.statusCode).toBe(201);
    const newPrimaryId = addPrimaryRes.json().data.id as string;

    // Niezweryfikowana domena nie może zostać główną -> 409
    expect(
      (await inject(devTrustApp, "PUT", `/core/v1/organization/domains/${newPrimaryId}/primary`, swapOwnerToken))
        .statusCode,
    ).toBe(409);

    // Obca domena -> 404 nawet dla zwykłego pracownika; własna domena dla zwykłego -> 403
    expect(
      (
        await inject(
          devTrustApp,
          "PUT",
          `/core/v1/organization/domains/${globex.primaryDomainId}/primary`,
          swapRegularToken,
        )
      ).statusCode,
    ).toBe(404);
    expect(
      (await inject(devTrustApp, "DELETE", `/core/v1/organization/domains/${globex.primaryDomainId}`, swapRegularToken))
        .statusCode,
    ).toBe(404);
    expect(
      (await inject(devTrustApp, "PUT", `/core/v1/organization/domains/${newPrimaryId}/primary`, swapRegularToken))
        .statusCode,
    ).toBe(403);
    expect(
      (await inject(devTrustApp, "DELETE", `/core/v1/organization/domains/${newPrimaryId}`, swapRegularToken))
        .statusCode,
    ).toBe(403);

    // Weryfikacja i atomowa zamiana głównej domeny
    expect(
      (
        await inject(devTrustApp, "POST", `/core/v1/organization/domains/${newPrimaryId}/verify`, swapOwnerToken, {
          trustLocally: true,
        })
      ).statusCode,
    ).toBe(200);

    const swapRes = await inject(
      devTrustApp,
      "PUT",
      `/core/v1/organization/domains/${newPrimaryId}/primary`,
      swapOwnerToken,
    );
    expect(swapRes.statusCode).toBe(200);
    const swappedDomains = swapRes.json().data.domains as { id: string; isPrimary: boolean }[];
    expect(swappedDomains.find((d) => d.id === newPrimaryId)?.isPrimary).toBe(true);
    expect(swappedDomains.find((d) => d.id === swapCo.primaryDomainId)?.isPrimary).toBe(false);

    // Powtórne PUT jest idempotentne i nie dodaje drugiego wpisu audytu
    expect(
      (await inject(devTrustApp, "PUT", `/core/v1/organization/domains/${newPrimaryId}/primary`, swapOwnerToken))
        .statusCode,
    ).toBe(200);
    const primaryAudits = await withOrganization(db, swapCo.id, (tx) =>
      tx.auditLog.findMany({ where: { action: "organization.domain.primary_changed", resourceId: swapCo.id } }),
    );
    expect(primaryAudits).toHaveLength(1);
    expect(primaryAudits[0]?.metadata).toEqual({
      domainId: newPrimaryId,
      fromDomain: swapCo.domain,
      toDomain: newPrimaryDomain,
    });

    // Nie można usunąć aktualnej głównej domeny ani starej domeny używanej przez konta -> 409
    expect(
      (await inject(devTrustApp, "DELETE", `/core/v1/organization/domains/${newPrimaryId}`, swapOwnerToken)).statusCode,
    ).toBe(409);
    expect(
      (await inject(devTrustApp, "DELETE", `/core/v1/organization/domains/${swapCo.primaryDomainId}`, swapOwnerToken))
        .statusCode,
    ).toBe(409);

    // Domena używana przez workEmail pracownika bez konta albo zaproszenie PENDING -> 409
    const guardedAdd = await inject(devTrustApp, "POST", "/core/v1/organization/domains", swapOwnerToken, {
      domain: guardedDomain,
    });
    const guardedId = guardedAdd.json().data.id as string;
    await inject(devTrustApp, "POST", `/core/v1/organization/domains/${guardedId}/verify`, swapOwnerToken, {
      trustLocally: true,
    });

    const empRes = await inject(devTrustApp, "POST", "/core/v1/employees", swapOwnerToken, {
      firstName: "Marek",
      lastName: "Domena",
      workEmail: `marek@${guardedDomain}`,
    });
    expect(empRes.statusCode).toBe(201);
    const empId = empRes.json().data.id as string;

    expect(
      (await inject(devTrustApp, "DELETE", `/core/v1/organization/domains/${guardedId}`, swapOwnerToken)).statusCode,
    ).toBe(409);

    // Po wyczyszczeniu workEmail i zaproszeniu innego pracownika nadal blokuje zaproszenie PENDING / konto
    expect(
      (await inject(devTrustApp, "PATCH", `/core/v1/employees/${empId}`, swapOwnerToken, { workEmail: null }))
        .statusCode,
    ).toBe(200);
    expect(
      (
        await inject(devTrustApp, "POST", "/core/v1/invitations", swapOwnerToken, {
          email: `kasia@${guardedDomain}`,
          firstName: "Kasia",
          lastName: "Zaproszona",
        })
      ).statusCode,
    ).toBe(201);
    expect(
      (await inject(devTrustApp, "DELETE", `/core/v1/organization/domains/${guardedId}`, swapOwnerToken)).statusCode,
    ).toBe(409);

    // Nieużywana niegłówna domena -> 204, audyt i natychmiastowe zwolnienie UNIQUE(domain) dla innej firmy
    const removableAdd = await inject(devTrustApp, "POST", "/core/v1/organization/domains", swapOwnerToken, {
      domain: removableDomain,
    });
    const removableId = removableAdd.json().data.id as string;
    await inject(devTrustApp, "POST", `/core/v1/organization/domains/${removableId}/verify`, swapOwnerToken, {
      trustLocally: true,
    });

    const delRes = await inject(devTrustApp, "DELETE", `/core/v1/organization/domains/${removableId}`, swapOwnerToken);
    expect(delRes.statusCode).toBe(204);
    expect(delRes.body).toBe("");

    const removedAudit = await withOrganization(db, swapCo.id, (tx) =>
      tx.auditLog.findFirstOrThrow({
        where: { action: "organization.domain.removed", resourceId: removableId },
      }),
    );
    expect(removedAudit.metadata).toEqual({ domain: removableDomain });

    // Inna firma (Globex) może teraz dodać zwolnioną domenę
    const claimedByGlobex = await inject(devTrustApp, "POST", "/core/v1/organization/domains", globexOwnerToken, {
      domain: removableDomain,
    });
    expect(claimedByGlobex.statusCode).toBe(201);

    // Nie można usunąć ostatniej zweryfikowanej domeny (gdy główna jest PENDING)
    const pendingPrimaryCo = await createCompany("PendingPrimary", { primaryStatus: "PENDING" });
    const pendingPrimaryToken = await token(pendingPrimaryCo);
    const onlyVerifiedAdd = await inject(devTrustApp, "POST", "/core/v1/organization/domains", pendingPrimaryToken, {
      domain: `${uuidv7().slice(-8)}-only.verified.test`,
    });
    const onlyVerifiedId = onlyVerifiedAdd.json().data.id as string;
    await inject(devTrustApp, "POST", `/core/v1/organization/domains/${onlyVerifiedId}/verify`, pendingPrimaryToken, {
      trustLocally: true,
    });
    const deleteLastVerified = await inject(
      devTrustApp,
      "DELETE",
      `/core/v1/organization/domains/${onlyVerifiedId}`,
      pendingPrimaryToken,
    );
    expect(deleteLastVerified.statusCode).toBe(409);
    expect(deleteLastVerified.json().error.code).toBe("CONFLICT");

    // Limit 20 domen w firmie -> 21. odrzucona kodem 409
    const capCo = await createCompany("CapCo");
    const capToken = await token(capCo);
    await withOrganization(db, capCo.id, async (tx) => {
      const prefix = uuidv7().slice(-8);
      for (let i = 1; i < MAX_ORGANIZATION_DOMAINS; i++) {
        await tx.organizationDomain.create({
          data: {
            id: uuidv7(),
            organizationId: capCo.id,
            domain: `d${i}-${prefix}.cap.test`,
            status: "PENDING",
            verificationMethod: "DNS_TXT",
            isPrimary: false,
          },
        });
      }
    });
    const overLimit = await inject(devTrustApp, "POST", "/core/v1/organization/domains", capToken, {
      domain: `overflow-${uuidv7().slice(-8)}.cap.test`,
    });
    expect(overLimit.statusCode).toBe(409);
    expect(overLimit.json().error.code).toBe("CONFLICT");
  });
});
