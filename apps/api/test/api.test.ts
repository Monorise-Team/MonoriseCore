import {
  CORE_PERMISSIONS,
  CORE_ROLE_TEMPLATES,
  PERMISSIONS_READ_SCOPE,
  PERMISSIONS_REGISTER_SCOPE,
} from "@core/contracts";
import { createDb, uuidv7, withOrganization } from "@core/db";
import { coreEvents, fromOutboxRecord } from "@monorise-team/events";
import { can, permissionSnapshotSchema, scopeOf } from "@monorise-team/permissions";
import { createLocalJWKSet, exportJWK, generateKeyPair, SignJWT, type CryptoKey } from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { endEntitlement, grantEntitlement } from "../src/entitlements.js";
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

let signingKey: CryptoKey;
let otherKey: CryptoKey;
let app: ReturnType<typeof buildServer>;

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

async function createCompany(name: string): Promise<Company> {
  const id = uuidv7();
  const domain = `${id.slice(-8)}-${name}.test`;
  const employeeId = uuidv7();
  const accountId = uuidv7();
  const email = `anna@${domain}`;
  await db.authUser.create({ data: { id: accountId, name: "Anna", email, emailVerified: true } });
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

function token(identity: Identity, overrides: Record<string, unknown> = {}, key = signingKey, expiresIn = "5m") {
  return new SignJWT({
    org_id: identity.organizationId,
    employee_id: identity.employeeId,
    authz_rev: 0,
    amr: ["pwd"],
    ...overrides,
  })
    .setProtectedHeader({ alg: "EdDSA" })
    .setIssuer(ISSUER)
    .setAudience(AUDIENCE)
    .setSubject(identity.accountId)
    .setIssuedAt()
    .setExpirationTime(expiresIn)
    .sign(key);
}

function machineToken(
  clientId: string,
  scope = PERMISSIONS_REGISTER_SCOPE,
  overrides: Record<string, unknown> = {},
  key = signingKey,
  expiresIn = "5m",
) {
  return new SignJWT({
    client_id: clientId,
    azp: clientId,
    scope,
    ...overrides,
  })
    .setProtectedHeader({ alg: "EdDSA" })
    .setIssuer(ISSUER)
    .setAudience(AUDIENCE)
    .setSubject(clientId)
    .setIssuedAt()
    .setExpirationTime(expiresIn)
    .sign(key);
}

const request = (
  method: "GET" | "POST" | "PUT" | "PATCH" | "DELETE",
  url: string,
  bearer?: string,
  payload?: Record<string, unknown> | unknown[],
) =>
  app.inject({
    method,
    url,
    headers: bearer ? { authorization: `Bearer ${bearer}` } : {},
    ...(payload !== undefined ? { payload } : {}),
  });

const get = (url: string, bearer?: string) => request("GET", url, bearer);

let acme: Company;
let acmeMember: Identity;
let globex: Company;

beforeAll(async () => {
  const pair = await generateKeyPair("EdDSA", { crv: "Ed25519" });
  signingKey = pair.privateKey;
  otherKey = (await generateKeyPair("EdDSA", { crv: "Ed25519" })).privateKey;
  const jwk = { ...(await exportJWK(pair.publicKey)), alg: "EdDSA", kid: "test" };
  const tokenOptions = { keys: createLocalJWKSet({ keys: [jwk] }), issuer: ISSUER, audience: AUDIENCE };
  app = buildServer({
    db,
    verifyToken: createTokenVerifier(tokenOptions),
    verifyMachineToken: createMachineTokenVerifier(tokenOptions),
  });
  acme = await createCompany("acme");
  acmeMember = await createMember(acme, "Jan", "Kowalski");
  globex = await createCompany("globex");
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
  await db.$disconnect();
  await ownerDb.$disconnect();
});

describe("Core API", () => {
  it("działa bez logowania tylko dla /core/v1/health", async () => {
    const health = await get("/core/v1/health");
    expect(health.statusCode).toBe(200);
    expect(health.json()).toMatchObject({ data: { status: "ok" }, error: null });

    const me = await get("/core/v1/me");
    expect(me.statusCode).toBe(401);
    expect(me.json()).toMatchObject({ data: null, error: { code: "UNAUTHENTICATED" } });
  });

  it("zwraca dane zalogowanego pracownika, jego firmy i flagę isOwner", async () => {
    const ownerResponse = await get("/core/v1/me", await token(acme));
    expect(ownerResponse.statusCode).toBe(200);
    expect(ownerResponse.json().data).toMatchObject({
      account: { id: acme.accountId, status: "ACTIVE", isOwner: true },
      employee: { id: acme.employeeId, accountId: acme.accountId, firstName: "Anna", lastName: "acme" },
      organization: { id: acme.id, name: "acme", status: "ACTIVE" },
    });

    const memberResponse = await get("/core/v1/me", await token(acmeMember));
    expect(memberResponse.statusCode).toBe(200);
    expect(memberResponse.json().data.account).toMatchObject({
      id: acmeMember.accountId,
      status: "ACTIVE",
      isOwner: false,
    });

    const organization = await get("/core/v1/organization", await token(globex));
    expect(organization.json().data).toMatchObject({ id: globex.id, name: "globex" });
  });

  it("odrzuca obcy podpis, zły odbiorcę, wygasły token i podmienioną firmę", async () => {
    expect((await get("/core/v1/me", await token(acme, {}, otherKey))).statusCode).toBe(401);
    const wrongAudience = await new SignJWT({ org_id: acme.id, employee_id: acme.employeeId, authz_rev: 0 })
      .setProtectedHeader({ alg: "EdDSA" })
      .setIssuer(ISSUER)
      .setAudience("https://ktos-inny.test")
      .setSubject(acme.accountId)
      .setIssuedAt()
      .setExpirationTime("5m")
      .sign(signingKey);
    expect((await get("/core/v1/me", wrongAudience)).statusCode).toBe(401);
    expect((await get("/core/v1/me", await token(acme, {}, signingKey, "-1m"))).statusCode).toBe(401);
    // Token Anny z Acme z podmienioną firmą: konto nie istnieje w Globex, więc RLS nie zwraca wiersza
    expect((await get("/core/v1/me", await token(acme, { org_id: globex.id }))).statusCode).toBe(401);
  });

  it("zarządza pracownikami, drzewem jednostek i członkostwami z kontrolą Ownera i separacją firm", async () => {
    const ownerToken = await token(acme);
    const memberToken = await token(acmeMember);
    const globexToken = await token(globex);

    // Owner dodaje pracownika bez konta
    const createdEmployee = await request("POST", "/core/v1/employees", ownerToken, {
      firstName: "Marek",
      lastName: "Nowak",
      workEmail: `marek@${acme.domain}`,
      jobTitle: "Magazynier",
    });
    expect(createdEmployee.statusCode).toBe(201);
    const marek = createdEmployee.json().data;
    expect(marek).toMatchObject({
      accountId: null,
      firstName: "Marek",
      lastName: "Nowak",
      workEmail: `marek@${acme.domain}`,
      jobTitle: "Magazynier",
      status: "ACTIVE",
    });

    // Owner buduje drzewo: Kraków -> Magazyn oraz Warszawa
    const krakowRes = await request("POST", "/core/v1/units", ownerToken, { name: "Kraków", type: "BRANCH" });
    expect(krakowRes.statusCode).toBe(201);
    const krakow = krakowRes.json().data;
    expect(krakow).toMatchObject({ name: "Kraków", type: "BRANCH", parentId: null, status: "ACTIVE" });

    const magazynRes = await request("POST", "/core/v1/units", ownerToken, {
      name: "Magazyn",
      type: "TEAM",
      parentId: krakow.id,
    });
    expect(magazynRes.statusCode).toBe(201);
    const magazyn = magazynRes.json().data;
    expect(magazyn).toMatchObject({ name: "Magazyn", type: "TEAM", parentId: krakow.id, status: "ACTIVE" });

    const warszawaRes = await request("POST", "/core/v1/units", ownerToken, { name: "Warszawa", type: "BRANCH" });
    expect(warszawaRes.statusCode).toBe(201);
    const warszawa = warszawaRes.json().data;

    // Owner przypisuje Annę do Magazynu (idempotentnie: najpierw MEMBER, potem LEADER)
    const putMember = await request("PUT", `/core/v1/units/${magazyn.id}/members/${acme.employeeId}`, ownerToken, {
      role: "MEMBER",
    });
    expect(putMember.statusCode).toBe(200);
    expect(putMember.json().data).toMatchObject({
      unitId: magazyn.id,
      employeeId: acme.employeeId,
      role: "MEMBER",
      employee: { id: acme.employeeId, firstName: "Anna" },
    });
    const initialJoinedAt = putMember.json().data.joinedAt;

    const putLeader = await request("PUT", `/core/v1/units/${magazyn.id}/members/${acme.employeeId}`, ownerToken, {
      role: "LEADER",
    });
    expect(putLeader.statusCode).toBe(200);
    expect(putLeader.json().data).toMatchObject({ role: "LEADER", joinedAt: initialJoinedAt });

    // Drugie konto tej samej firmy (nie-Owner) może czytać, ale dostaje 403 przy zapisach
    const memberEmployees = await get("/core/v1/employees", memberToken);
    expect(memberEmployees.statusCode).toBe(200);
    expect(memberEmployees.json().data.map((e: { id: string }) => e.id)).toContain(marek.id);

    const memberUnits = await get("/core/v1/units", memberToken);
    expect(memberUnits.statusCode).toBe(200);
    expect(memberUnits.json().data.map((u: { id: string }) => u.id)).toEqual(
      expect.arrayContaining([krakow.id, magazyn.id, warszawa.id]),
    );

    const memberUnitMembers = await get(`/core/v1/units/${magazyn.id}/members`, memberToken);
    expect(memberUnitMembers.statusCode).toBe(200);
    expect(memberUnitMembers.json().data).toHaveLength(1);
    expect(memberUnitMembers.json().data[0]).toMatchObject({ employeeId: acme.employeeId, role: "LEADER" });

    for (const denied of [
      await request("POST", "/core/v1/employees", memberToken, { firstName: "Piotr", lastName: "Zły" }),
      await request("POST", "/core/v1/units", memberToken, { name: "Dział", type: "DEPARTMENT" }),
      await request("PATCH", `/core/v1/units/${krakow.id}`, memberToken, { name: "Zmiana" }),
      await request("PUT", `/core/v1/units/${magazyn.id}/members/${marek.id}`, memberToken, { role: "MEMBER" }),
      await request("DELETE", `/core/v1/units/${magazyn.id}/members/${acme.employeeId}`, memberToken),
    ]) {
      expect(denied.statusCode).toBe(403);
      expect(denied.json().error.code).toBe("PERMISSION_DENIED");
    }

    // Inna firma (Globex) nie widzi zasobów Acme na listach i dostaje 404 dla identyfikatorów Acme
    expect((await get("/core/v1/units", globexToken)).json().data).toEqual([]);
    expect((await get("/core/v1/employees", globexToken)).json().data.map((e: { id: string }) => e.id)).toEqual([
      globex.employeeId,
    ]);

    const globexUnitRes = await request("POST", "/core/v1/units", globexToken, { name: "Gdańsk", type: "BRANCH" });
    expect(globexUnitRes.statusCode).toBe(201);
    const globexUnit = globexUnitRes.json().data;

    for (const hidden of [
      await get(`/core/v1/units/${magazyn.id}/members`, globexToken),
      await request("POST", "/core/v1/units", globexToken, { name: "Obcy", type: "TEAM", parentId: krakow.id }),
      await request("PATCH", `/core/v1/units/${krakow.id}`, globexToken, { name: "Przejęty" }),
      await request("PUT", `/core/v1/units/${magazyn.id}/members/${globex.employeeId}`, globexToken, {
        role: "MEMBER",
      }),
      await request("PUT", `/core/v1/units/${globexUnit.id}/members/${acme.employeeId}`, globexToken, {
        role: "MEMBER",
      }),
      await request("DELETE", `/core/v1/units/${magazyn.id}/members/${acme.employeeId}`, globexToken),
    ]) {
      expect(hidden.statusCode).toBe(404);
      expect(hidden.json().error.code).toBe("NOT_FOUND");
    }

    // Cykl w drzewie -> 409 CONFLICT
    const selfCycle = await request("PATCH", `/core/v1/units/${krakow.id}`, ownerToken, { parentId: krakow.id });
    expect(selfCycle.statusCode).toBe(409);
    expect(selfCycle.json().error.code).toBe("CONFLICT");

    const ancestorCycle = await request("PATCH", `/core/v1/units/${krakow.id}`, ownerToken, { parentId: magazyn.id });
    expect(ancestorCycle.statusCode).toBe(409);
    expect(ancestorCycle.json().error.code).toBe("CONFLICT");

    // Archiwizacja rodzica z aktywnym dzieckiem -> 409 CONFLICT
    const archiveBlocked = await request("PATCH", `/core/v1/units/${krakow.id}`, ownerToken, { status: "ARCHIVED" });
    expect(archiveBlocked.statusCode).toBe(409);
    expect(archiveBlocked.json().error.code).toBe("CONFLICT");

    // Usunięcie członkostwa -> 204, powtórzenie -> 404
    const deleted = await request("DELETE", `/core/v1/units/${magazyn.id}/members/${acme.employeeId}`, ownerToken);
    expect(deleted.statusCode).toBe(204);
    expect(deleted.body).toBe("");
    const deletedAgain = await request("DELETE", `/core/v1/units/${magazyn.id}/members/${acme.employeeId}`, ownerToken);
    expect(deletedAgain.statusCode).toBe(404);

    // Archiwizacja od liścia w górę i filtrowanie po statusie
    expect(
      (await request("PATCH", `/core/v1/units/${magazyn.id}`, ownerToken, { status: "ARCHIVED" })).statusCode,
    ).toBe(200);
    expect((await request("PATCH", `/core/v1/units/${krakow.id}`, ownerToken, { status: "ARCHIVED" })).statusCode).toBe(
      200,
    );

    const activeUnits = await get("/core/v1/units?status=ACTIVE", ownerToken);
    expect(activeUnits.statusCode).toBe(200);
    expect(activeUnits.json().data.map((u: { id: string }) => u.id)).toEqual([warszawa.id]);

    const archivedUnits = await get("/core/v1/units?status=ARCHIVED", ownerToken);
    expect(archivedUnits.statusCode).toBe(200);
    expect(
      archivedUnits
        .json()
        .data.map((u: { id: string }) => u.id)
        .sort(),
    ).toEqual([krakow.id, magazyn.id].sort());

    // Zmiana nazwy i przeniesienie na poziom firmy (parentId: null)
    const renamed = await request("PATCH", `/core/v1/units/${warszawa.id}`, ownerToken, {
      name: "Oddział Warszawa",
      parentId: null,
    });
    expect(renamed.statusCode).toBe(200);
    expect(renamed.json().data).toMatchObject({ name: "Oddział Warszawa", parentId: null });

    // Walidacja -> 422 VALIDATION_FAILED ze szczegółami
    for (const invalid of [
      await request("POST", "/core/v1/employees", ownerToken, { firstName: "", lastName: "Nowak" }),
      await request("POST", "/core/v1/units", ownerToken, { name: "X", type: "WRONG" }),
      await request("PATCH", "/core/v1/units/not-a-uuid", ownerToken, { name: "X" }),
      await request("PATCH", `/core/v1/units/${warszawa.id}`, ownerToken, {}),
      await get("/core/v1/units?status=INVALID", ownerToken),
      await request("PUT", `/core/v1/units/${warszawa.id}/members/${acme.employeeId}`, ownerToken, { role: "BOSS" }),
    ]) {
      expect(invalid.statusCode).toBe(422);
      expect(invalid.json().error.code).toBe("VALIDATION_FAILED");
      expect(invalid.json().error.details.length).toBeGreaterThan(0);
    }
  });

  it("stronicuje listy pracowników, jednostek (także z filtrem statusu) i członków kursorami", async () => {
    const ownerToken = await token(acme);

    // Pracownicy: mamy co najmniej 3 (Anna, Jan, Marek); pobieramy po 2 aż do ostatniej strony
    const firstEmp = await get("/core/v1/employees?limit=2", ownerToken);
    expect(firstEmp.statusCode).toBe(200);
    const firstEmpBody = firstEmp.json();
    expect(firstEmpBody.data).toHaveLength(2);
    expect(firstEmpBody.meta.nextCursor).toEqual(expect.any(String));

    const secondEmp = await get(
      `/core/v1/employees?limit=2&cursor=${encodeURIComponent(firstEmpBody.meta.nextCursor)}`,
      ownerToken,
    );
    expect(secondEmp.statusCode).toBe(200);
    const secondEmpBody = secondEmp.json();
    expect(secondEmpBody.data).toHaveLength(1);
    expect(secondEmpBody.meta.nextCursor).toBeNull();

    const allEmpIds = [...firstEmpBody.data, ...secondEmpBody.data].map((e: { id: string }) => e.id);
    expect(new Set(allEmpIds).size).toBe(3);
    expect(allEmpIds).toEqual([...allEmpIds].sort());

    // Jednostki: dodajemy 2 aktywne (łącznie 3 ACTIVE i 2 ARCHIVED = 5) i sprawdzamy stronicowanie + filtr ?status=
    const poznanRes = await request("POST", "/core/v1/units", ownerToken, { name: "Poznań", type: "BRANCH" });
    expect(poznanRes.statusCode).toBe(201);
    const poznan = poznanRes.json().data;
    const wroclawRes = await request("POST", "/core/v1/units", ownerToken, { name: "Wrocław", type: "BRANCH" });
    expect(wroclawRes.statusCode).toBe(201);

    const activePage1 = await get("/core/v1/units?status=ACTIVE&limit=2", ownerToken);
    expect(activePage1.statusCode).toBe(200);
    const activePage1Body = activePage1.json();
    expect(activePage1Body.data).toHaveLength(2);
    expect(activePage1Body.data.every((u: { status: string }) => u.status === "ACTIVE")).toBe(true);
    expect(activePage1Body.meta.nextCursor).toEqual(expect.any(String));

    const activePage2 = await get(
      `/core/v1/units?status=ACTIVE&limit=2&cursor=${encodeURIComponent(activePage1Body.meta.nextCursor)}`,
      ownerToken,
    );
    expect(activePage2.statusCode).toBe(200);
    const activePage2Body = activePage2.json();
    expect(activePage2Body.data).toHaveLength(1);
    expect(activePage2Body.data[0].status).toBe("ACTIVE");
    expect(activePage2Body.meta.nextCursor).toBeNull();

    const activeIds = [...activePage1Body.data, ...activePage2Body.data].map((u: { id: string }) => u.id);
    expect(new Set(activeIds).size).toBe(3);

    // Członkowie jednostki: przypisujemy wszystkich 3 pracowników do Poznania i stronicujemy po 2
    for (const empId of allEmpIds) {
      const added = await request("PUT", `/core/v1/units/${poznan.id}/members/${empId}`, ownerToken, {
        role: "MEMBER",
      });
      expect(added.statusCode).toBe(200);
    }

    const membersPage1 = await get(`/core/v1/units/${poznan.id}/members?limit=2`, ownerToken);
    expect(membersPage1.statusCode).toBe(200);
    const membersPage1Body = membersPage1.json();
    expect(membersPage1Body.data).toHaveLength(2);
    expect(membersPage1Body.meta.nextCursor).toEqual(expect.any(String));

    const membersPage2 = await get(
      `/core/v1/units/${poznan.id}/members?limit=2&cursor=${encodeURIComponent(membersPage1Body.meta.nextCursor)}`,
      ownerToken,
    );
    expect(membersPage2.statusCode).toBe(200);
    const membersPage2Body = membersPage2.json();
    expect(membersPage2Body.data).toHaveLength(1);
    expect(membersPage2Body.meta.nextCursor).toBeNull();

    const memberEmpIds = [...membersPage1Body.data, ...membersPage2Body.data].map(
      (m: { employeeId: string }) => m.employeeId,
    );
    expect(new Set(memberEmpIds)).toEqual(new Set(allEmpIds));

    // Błędny limit (> 100, 0, nie-liczba) i błędny kursor -> 422 VALIDATION_FAILED
    const nonUuidCursor = Buffer.from("not-a-uuid", "utf8").toString("base64url");
    for (const invalid of [
      await get("/core/v1/employees?limit=101", ownerToken),
      await get("/core/v1/units?limit=0", ownerToken),
      await get("/core/v1/units?limit=abc", ownerToken),
      await get(`/core/v1/units/${poznan.id}/members?limit=101`, ownerToken),
      await get("/core/v1/employees?cursor=!!!bad!!!", ownerToken),
      await get(`/core/v1/units?cursor=${nonUuidCursor}`, ownerToken),
      await get(`/core/v1/units/${poznan.id}/members?cursor=${nonUuidCursor}`, ownerToken),
    ]) {
      expect(invalid.statusCode).toBe(422);
      expect(invalid.json().error.code).toBe("VALIDATION_FAILED");
      expect(invalid.json().error.details.length).toBeGreaterThan(0);
    }
  });

  it("odcina konto po dezaktywacji, nawet z ważnym tokenem", async () => {
    const bearer = await token(globex);
    expect((await get("/core/v1/me", bearer)).statusCode).toBe(200);
    await withOrganization(db, globex.id, (tx) =>
      tx.account.update({ where: { id: globex.accountId }, data: { status: "DEACTIVATED" } }),
    );
    const response = await get("/core/v1/me", bearer);
    expect(response.statusCode).toBe(401);
    expect(response.json().error.code).toBe("ACCOUNT_DEACTIVATED");
  });

  it("zapisuje wpisy dziennika dla zmian pracowników i struktury firmy, widoczne tylko dla tej firmy", async () => {
    const acmeAudit = await withOrganization(db, acme.id, (tx) =>
      tx.auditLog.findMany({ orderBy: { createdAt: "asc" } }),
    );
    const actions = acmeAudit.map((entry) => entry.action);
    expect(actions).toEqual(
      expect.arrayContaining([
        "employee.created",
        "unit.created",
        "unit.updated",
        "unit.member.set",
        "unit.member.removed",
      ]),
    );
    expect(acmeAudit.every((entry) => entry.organizationId === acme.id && entry.actorType === "ACCOUNT")).toBe(true);
    expect(acmeAudit.every((entry) => entry.actorAccountId === acme.accountId && entry.requestId !== null)).toBe(true);

    // Zmiana jednostki zapisuje zmienione pola (old -> new)
    const renamedEntry = acmeAudit.find(
      (entry) =>
        entry.action === "unit.updated" &&
        typeof entry.metadata === "object" &&
        entry.metadata !== null &&
        "changes" in entry.metadata &&
        typeof (entry.metadata as { changes?: Record<string, unknown> }).changes?.name === "object",
    );
    expect(renamedEntry).toBeDefined();
    expect((renamedEntry?.metadata as { changes: { name: { old: string; new: string } } }).changes.name).toEqual({
      old: "Warszawa",
      new: "Oddział Warszawa",
    });

    // employee.created nie zapisuje danych osobowych w metadata
    const empEntry = acmeAudit.find((entry) => entry.action === "employee.created");
    expect(empEntry?.metadata).toEqual({});

    // unit.member.set i unit.member.removed zapisują rolę bez danych osobowych
    const setEntry = acmeAudit.find((entry) => entry.action === "unit.member.set");
    expect(setEntry?.metadata).toMatchObject({ role: expect.stringMatching(/^(MEMBER|LEADER)$/) });
    const removedEntry = acmeAudit.find((entry) => entry.action === "unit.member.removed");
    expect(removedEntry?.metadata).toMatchObject({ role: "LEADER" });

    // Inna firma (Globex) nie widzi wpisów Acme
    const globexAudit = await withOrganization(db, globex.id, (tx) => tx.auditLog.findMany());
    const acmeIds = new Set(acmeAudit.map((entry) => entry.id));
    expect(globexAudit.every((entry) => !acmeIds.has(entry.id))).toBe(true);
  });

  it("rejestruje uprawnienia platformy core.* przy starcie i działa idempotentnie", async () => {
    const first = await registerCorePermissions(db);
    expect(first.added.length + first.updated.length + first.restored.length + first.unchanged).toBe(
      CORE_PERMISSIONS.manifest.length,
    );

    const beforeCount = await ownerDb.auditLog.count({
      where: { action: "product.permissions.registered", resourceId: "core" },
    });

    const second = await registerCorePermissions(db);
    expect(second).toEqual({
      added: [],
      updated: [],
      deprecated: [],
      restored: [],
      unchanged: CORE_PERMISSIONS.manifest.length,
    });

    const afterCount = await ownerDb.auditLog.count({
      where: { action: "product.permissions.registered", resourceId: "core" },
    });
    expect(afterCount).toBe(beforeCount);
  });

  it("rejestruje uprawnienia produktu tokenem maszynowym, rozdziela tokeny i udostępnia listę z filtrami oraz stronicowaniem", async () => {
    const suffix = uuidv7().replaceAll("-", "").slice(-6);
    const productKey = `app${suffix}`;
    const otherProductKey = `oth${suffix}`;
    const productClientId = `${productKey}-web`;
    const otherClientId = `${otherProductKey}-web`;
    const productId = uuidv7();
    const otherProductId = uuidv7();

    await db.product.create({
      data: { id: productId, key: productKey, name: "Aplikacja testowa", registrationClientId: productClientId },
    });
    await db.product.create({
      data: { id: otherProductId, key: otherProductKey, name: "Inna aplikacja", registrationClientId: otherClientId },
    });

    try {
      const ownerToken = await token(acme);
      const memberToken = await token(acmeMember);
      const prodToken = await machineToken(productClientId);
      const otherProdToken = await machineToken(otherClientId);
      const noScopeToken = await machineToken(productClientId, "other:scope");

      // Token maszynowy nie działa na endpointach użytkownika
      const meWithMachine = await get("/core/v1/me", prodToken);
      expect(meWithMachine.statusCode).toBe(401);
      expect(meWithMachine.json().error.code).toBe("UNAUTHENTICATED");

      // Token użytkownika nie działa na endpoincie maszynowym
      const registerWithUser = await request("PUT", `/core/v1/products/${productKey}/permissions`, ownerToken, [
        { key: `${productKey}.entries.read`, description: "Odczyt wpisów" },
      ]);
      expect(registerWithUser.statusCode).toBe(401);
      expect(registerWithUser.json().error.code).toBe("UNAUTHENTICATED");

      // Brak wymaganego zakresu -> 403 PERMISSION_DENIED
      const registerNoScope = await request("PUT", `/core/v1/products/${productKey}/permissions`, noScopeToken, [
        { key: `${productKey}.entries.read`, description: "Odczyt wpisów" },
      ]);
      expect(registerNoScope.statusCode).toBe(403);
      expect(registerNoScope.json().error.code).toBe("PERMISSION_DENIED");

      // Klient innego produktu -> 403 PERMISSION_DENIED
      const registerWrongClient = await request("PUT", `/core/v1/products/${productKey}/permissions`, otherProdToken, [
        { key: `${productKey}.entries.read`, description: "Odczyt wpisów" },
      ]);
      expect(registerWrongClient.statusCode).toBe(403);
      expect(registerWrongClient.json().error.code).toBe("PERMISSION_DENIED");

      // Nieznany produkt -> 404 NOT_FOUND
      const registerUnknown = await request("PUT", `/core/v1/products/unknown${suffix}/permissions`, prodToken, [
        { key: `unknown${suffix}.entries.read`, description: "Odczyt wpisów" },
      ]);
      expect(registerUnknown.statusCode).toBe(404);
      expect(registerUnknown.json().error.code).toBe("NOT_FOUND");

      // Zły prefiks (inny produkt lub core.) -> 422 VALIDATION_FAILED ze szczegółami
      for (const badManifest of [
        [{ key: `${otherProductKey}.entries.read`, description: "Inny produkt" }],
        [{ key: "core.roles.manage", description: "Platformowe" }],
      ]) {
        const badPrefix = await request("PUT", `/core/v1/products/${productKey}/permissions`, prodToken, badManifest);
        expect(badPrefix.statusCode).toBe(422);
        expect(badPrefix.json().error.code).toBe("VALIDATION_FAILED");
        expect(badPrefix.json().error.details.length).toBeGreaterThan(0);
      }

      // 1. Rejestracja początkowa (added)
      const initialManifest = [
        { key: `${productKey}.entries.read`, description: "Odczyt wpisów" },
        { key: `${productKey}.entries.approve`, description: "Zatwierdzanie wpisów" },
        { key: `${productKey}.reports.export`, description: "Eksport raportów" },
      ];
      const addedRes = await request("PUT", `/core/v1/products/${productKey}/permissions`, prodToken, initialManifest);
      expect(addedRes.statusCode).toBe(200);
      expect(addedRes.json().data).toEqual({
        added: [`${productKey}.entries.approve`, `${productKey}.entries.read`, `${productKey}.reports.export`],
        updated: [],
        deprecated: [],
        restored: [],
        unchanged: 0,
      });

      expect(
        await ownerDb.auditLog.count({
          where: { action: "product.permissions.registered", productId, actorType: "PRODUCT" },
        }),
      ).toBe(1);

      // 2. Ten sam manifest po raz drugi -> brak zmian, brak drugiego wpisu w dzienniku
      const repeatRes = await request("PUT", `/core/v1/products/${productKey}/permissions`, prodToken, initialManifest);
      expect(repeatRes.statusCode).toBe(200);
      expect(repeatRes.json().data).toEqual({
        added: [],
        updated: [],
        deprecated: [],
        restored: [],
        unchanged: 3,
      });
      expect(
        await ownerDb.auditLog.count({
          where: { action: "product.permissions.registered", productId, actorType: "PRODUCT" },
        }),
      ).toBe(1);

      // 3. Zmiana opisu (updated) i usunięcie klucza z manifestu (deprecated)
      const updatedManifest = [
        { key: `${productKey}.entries.read`, description: "Odczyt wpisów czasu pracy" },
        { key: `${productKey}.entries.approve`, description: "Zatwierdzanie wpisów" },
      ];
      const updateRes = await request("PUT", `/core/v1/products/${productKey}/permissions`, prodToken, updatedManifest);
      expect(updateRes.statusCode).toBe(200);
      expect(updateRes.json().data).toEqual({
        added: [],
        updated: [`${productKey}.entries.read`],
        deprecated: [`${productKey}.reports.export`],
        restored: [],
        unchanged: 1,
      });
      expect(
        await ownerDb.auditLog.count({
          where: { action: "product.permissions.registered", productId, actorType: "PRODUCT" },
        }),
      ).toBe(2);

      // GET /core/v1/permissions: domyślnie pomija wycofane, dostępne także dla konta nie-Ownera
      const activeOnly = await get(`/core/v1/permissions?product=${productKey}`, memberToken);
      expect(activeOnly.statusCode).toBe(200);
      expect(activeOnly.json().data).toEqual(
        expect.arrayContaining([
          {
            key: `${productKey}.entries.read`,
            product: productKey,
            description: "Odczyt wpisów czasu pracy",
            deprecated: false,
          },
          {
            key: `${productKey}.entries.approve`,
            product: productKey,
            description: "Zatwierdzanie wpisów",
            deprecated: false,
          },
        ]),
      );
      expect(activeOnly.json().data).toHaveLength(2);

      // ?includeDeprecated=false również pomija wycofane, ?includeDeprecated=true je dołącza
      const explicitFalse = await get(
        `/core/v1/permissions?product=${productKey}&includeDeprecated=false`,
        memberToken,
      );
      expect(explicitFalse.statusCode).toBe(200);
      expect(explicitFalse.json().data).toHaveLength(2);

      const withDeprecated = await get(
        `/core/v1/permissions?product=${productKey}&includeDeprecated=true`,
        memberToken,
      );
      expect(withDeprecated.statusCode).toBe(200);
      expect(withDeprecated.json().data).toHaveLength(3);
      expect(withDeprecated.json().data).toContainEqual({
        key: `${productKey}.reports.export`,
        product: productKey,
        description: "Eksport raportów",
        deprecated: true,
      });

      // Stronicowanie kursorowe listy uprawnień
      const page1 = await get(`/core/v1/permissions?product=${productKey}&includeDeprecated=true&limit=2`, memberToken);
      expect(page1.statusCode).toBe(200);
      const page1Body = page1.json();
      expect(page1Body.data).toHaveLength(2);
      expect(page1Body.meta.nextCursor).toEqual(expect.any(String));

      const page2 = await get(
        `/core/v1/permissions?product=${productKey}&includeDeprecated=true&limit=2&cursor=${encodeURIComponent(page1Body.meta.nextCursor)}`,
        memberToken,
      );
      expect(page2.statusCode).toBe(200);
      const page2Body = page2.json();
      expect(page2Body.data).toHaveLength(1);
      expect(page2Body.meta.nextCursor).toBeNull();
      expect(new Set([...page1Body.data, ...page2Body.data].map((item: { key: string }) => item.key)).size).toBe(3);

      // Filtr ?product=core zwraca uprawnienia platformy z product: null
      const corePerms = await get("/core/v1/permissions?product=core", ownerToken);
      expect(corePerms.statusCode).toBe(200);
      expect(corePerms.json().data.length).toBeGreaterThanOrEqual(CORE_PERMISSIONS.manifest.length);
      expect(corePerms.json().data.every((item: { product: string | null }) => item.product === null)).toBe(true);

      // Błędne parametry zapytania -> 422
      const badInclude = await get("/core/v1/permissions?includeDeprecated=maybe", ownerToken);
      expect(badInclude.statusCode).toBe(422);

      // 4. Przywrócenie wycofanego klucza (restored)
      const restoredRes = await request("PUT", `/core/v1/products/${productKey}/permissions`, prodToken, [
        ...updatedManifest,
        { key: `${productKey}.reports.export`, description: "Eksport raportów (przywrócony)" },
      ]);
      expect(restoredRes.statusCode).toBe(200);
      expect(restoredRes.json().data).toEqual({
        added: [],
        updated: [],
        deprecated: [],
        restored: [`${productKey}.reports.export`],
        unchanged: 2,
      });

      const afterRestore = await get(`/core/v1/permissions?product=${productKey}`, memberToken);
      expect(afterRestore.statusCode).toBe(200);
      expect(afterRestore.json().data).toHaveLength(3);
      expect(afterRestore.json().data).toContainEqual({
        key: `${productKey}.reports.export`,
        product: productKey,
        description: "Eksport raportów (przywrócony)",
        deprecated: false,
      });
    } finally {
      await ownerDb.auditLog.deleteMany({ where: { productId: { in: [productId, otherProductId] } } });
      await ownerDb.permission.deleteMany({ where: { productId: { in: [productId, otherProductId] } } });
      await ownerDb.product.deleteMany({ where: { id: { in: [productId, otherProductId] } } });
    }
  });

  it("rejestruje gotową rolę platformy core.company_admin przy starcie i działa idempotentnie", async () => {
    await registerCorePermissions(db);
    const first = await registerCoreRoleTemplates(db);
    expect(first.added.length + first.updated.length + first.restored.length + first.unchanged).toBe(
      CORE_ROLE_TEMPLATES.length,
    );

    const beforeCount = await ownerDb.auditLog.count({
      where: { action: "role_templates.registered", resourceId: "core" },
    });

    const second = await registerCoreRoleTemplates(db);
    expect(second).toEqual({
      added: [],
      updated: [],
      archived: [],
      restored: [],
      unchanged: CORE_ROLE_TEMPLATES.length,
    });

    const afterCount = await ownerDb.auditLog.count({
      where: { action: "role_templates.registered", resourceId: "core" },
    });
    expect(afterCount).toBe(beforeCount);

    const rolesRes = await get("/core/v1/roles?product=core", await token(acme));
    expect(rolesRes.statusCode).toBe(200);
    const companyAdmin = rolesRes.json().data.find((r: { key: string | null }) => r.key === "core.company_admin");
    expect(companyAdmin).toMatchObject({
      key: "core.company_admin",
      name: "Administrator firmy",
      product: null,
      isTemplate: true,
      archivedAt: null,
    });
    expect(companyAdmin.permissions).toEqual(CORE_PERMISSIONS.manifest.map((p) => p.key).sort());
  });

  it("rejestruje gotowe role produktu tokenem maszynowym z walidacją prefiksu i uprawnień oraz archiwizacją", async () => {
    const suffix = uuidv7().replaceAll("-", "").slice(-6);
    const productKey = `tpl${suffix}`;
    const otherProductKey = `otpl${suffix}`;
    const productClientId = `${productKey}-web`;
    const otherClientId = `${otherProductKey}-web`;
    const productId = uuidv7();
    const otherProductId = uuidv7();

    await db.product.create({
      data: { id: productId, key: productKey, name: "Produkt szablonów", registrationClientId: productClientId },
    });
    await db.product.create({
      data: { id: otherProductId, key: otherProductKey, name: "Inny produkt", registrationClientId: otherClientId },
    });

    try {
      const ownerToken = await token(acme);
      const prodToken = await machineToken(productClientId);
      const otherProdToken = await machineToken(otherClientId);
      const noScopeToken = await machineToken(productClientId, "other:scope");

      // Rejestrujemy 3 uprawnienia produktu, potem jedno wycofamy
      expect(
        (
          await request("PUT", `/core/v1/products/${productKey}/permissions`, prodToken, [
            { key: `${productKey}.entries.read`, description: "Odczyt wpisów" },
            { key: `${productKey}.entries.approve`, description: "Zatwierdzanie wpisów" },
            { key: `${productKey}.legacy.run`, description: "Stare uprawnienie" },
          ])
        ).statusCode,
      ).toBe(200);
      expect(
        (
          await request("PUT", `/core/v1/products/${productKey}/permissions`, prodToken, [
            { key: `${productKey}.entries.read`, description: "Odczyt wpisów" },
            { key: `${productKey}.entries.approve`, description: "Zatwierdzanie wpisów" },
          ])
        ).statusCode,
      ).toBe(200);

      // Ochrona tokenu i klienta
      expect(
        (
          await request("PUT", `/core/v1/products/${productKey}/role-templates`, ownerToken, [
            { key: `${productKey}.worker`, name: "Pracownik", permissions: [`${productKey}.entries.read`] },
          ])
        ).statusCode,
      ).toBe(401);
      expect(
        (
          await request("PUT", `/core/v1/products/${productKey}/role-templates`, noScopeToken, [
            { key: `${productKey}.worker`, name: "Pracownik", permissions: [`${productKey}.entries.read`] },
          ])
        ).statusCode,
      ).toBe(403);
      expect(
        (
          await request("PUT", `/core/v1/products/${productKey}/role-templates`, otherProdToken, [
            { key: `${productKey}.worker`, name: "Pracownik", permissions: [`${productKey}.entries.read`] },
          ])
        ).statusCode,
      ).toBe(403);
      expect(
        (
          await request("PUT", `/core/v1/products/unknown${suffix}/role-templates`, prodToken, [
            { key: `unknown${suffix}.worker`, name: "Pracownik", permissions: [`${productKey}.entries.read`] },
          ])
        ).statusCode,
      ).toBe(404);

      // Zły prefiks, nieznane uprawnienie, wycofane uprawnienie -> 422 ze szczegółami
      for (const badBody of [
        [{ key: `${otherProductKey}.worker`, name: "Zły prefiks", permissions: [`${productKey}.entries.read`] }],
        [{ key: `${productKey}.worker`, name: "Nieznane", permissions: [`${productKey}.missing.read`] }],
        [{ key: `${productKey}.worker`, name: "Wycofane", permissions: [`${productKey}.legacy.run`] }],
      ]) {
        const res = await request("PUT", `/core/v1/products/${productKey}/role-templates`, prodToken, badBody);
        expect(res.statusCode).toBe(422);
        expect(res.json().error.code).toBe("VALIDATION_FAILED");
        expect(res.json().error.details.length).toBeGreaterThan(0);
      }

      // 1. Dodanie szablonów
      const initial = [
        {
          key: `${productKey}.worker`,
          name: "Pracownik",
          description: "Podgląd wpisów",
          permissions: [`${productKey}.entries.read`],
        },
        {
          key: `${productKey}.manager`,
          name: "Kierownik",
          permissions: [`${productKey}.entries.read`, `${productKey}.entries.approve`],
        },
      ];
      const addedRes = await request("PUT", `/core/v1/products/${productKey}/role-templates`, prodToken, initial);
      expect(addedRes.statusCode).toBe(200);
      expect(addedRes.json().data).toEqual({
        added: [`${productKey}.manager`, `${productKey}.worker`],
        updated: [],
        archived: [],
        restored: [],
        unchanged: 0,
      });
      expect(
        await ownerDb.auditLog.count({
          where: { action: "product.role_templates.registered", productId, actorType: "PRODUCT" },
        }),
      ).toBe(1);

      // 2. Idempotentność (bez nowego wpisu audytu)
      const repeatRes = await request("PUT", `/core/v1/products/${productKey}/role-templates`, prodToken, initial);
      expect(repeatRes.statusCode).toBe(200);
      expect(repeatRes.json().data).toEqual({
        added: [],
        updated: [],
        archived: [],
        restored: [],
        unchanged: 2,
      });
      expect(
        await ownerDb.auditLog.count({
          where: { action: "product.role_templates.registered", productId, actorType: "PRODUCT" },
        }),
      ).toBe(1);

      // 3. Aktualizacja + archiwizacja brakującego szablonu
      const updateRes = await request("PUT", `/core/v1/products/${productKey}/role-templates`, prodToken, [
        {
          key: `${productKey}.worker`,
          name: "Pracownik (nowa nazwa)",
          description: "Podgląd wpisów",
          permissions: [`${productKey}.entries.read`],
        },
      ]);
      expect(updateRes.statusCode).toBe(200);
      expect(updateRes.json().data).toEqual({
        added: [],
        updated: [`${productKey}.worker`],
        archived: [`${productKey}.manager`],
        restored: [],
        unchanged: 0,
      });

      const activeTemplates = await get(`/core/v1/roles?product=${productKey}`, ownerToken);
      expect(activeTemplates.statusCode).toBe(200);
      expect(activeTemplates.json().data).toHaveLength(1);
      expect(activeTemplates.json().data[0].key).toBe(`${productKey}.worker`);

      const withArchived = await get(`/core/v1/roles?product=${productKey}&includeArchived=true`, ownerToken);
      expect(withArchived.statusCode).toBe(200);
      expect(withArchived.json().data).toHaveLength(2);

      // 4. Przywrócenie zarchiwizowanego szablonu
      const restoreRes = await request("PUT", `/core/v1/products/${productKey}/role-templates`, prodToken, [
        {
          key: `${productKey}.worker`,
          name: "Pracownik (nowa nazwa)",
          description: "Podgląd wpisów",
          permissions: [`${productKey}.entries.read`],
        },
        {
          key: `${productKey}.manager`,
          name: "Kierownik",
          permissions: [`${productKey}.entries.read`, `${productKey}.entries.approve`],
        },
      ]);
      expect(restoreRes.statusCode).toBe(200);
      expect(restoreRes.json().data).toEqual({
        added: [],
        updated: [],
        archived: [],
        restored: [`${productKey}.manager`],
        unchanged: 1,
      });
    } finally {
      await ownerDb.role.deleteMany({ where: { productId: { in: [productId, otherProductId] } } });
      await ownerDb.auditLog.deleteMany({ where: { productId: { in: [productId, otherProductId] } } });
      await ownerDb.permission.deleteMany({ where: { productId: { in: [productId, otherProductId] } } });
      await ownerDb.product.deleteMany({ where: { id: { in: [productId, otherProductId] } } });
    }
  });

  it("obsługuje role, kopiowanie szablonu, delegowanie z zakresem, role czasowe, strukturę, authzRevision, archiwizację i audyt", async () => {
    await registerCorePermissions(db);
    await registerCoreRoleTemplates(db);

    const suffix = uuidv7().replaceAll("-", "").slice(-6);
    const productKey = `tt${suffix}`;
    const productClientId = `${productKey}-web`;
    const productId = uuidv7();
    await db.product.create({
      data: { id: productId, key: productKey, name: "TimoTime test", registrationClientId: productClientId },
    });

    const company = await createCompany(`roles-${suffix}`);
    const otherCompany = await createCompany(`other-${suffix}`);
    const jan = await createMember(company, "Jan", "Kierownik");
    const piotr = await createMember(company, "Piotr", "Pracownik");
    const ewa = await createMember(company, "Ewa", "Wygasla");
    const deactivated = await createMember(company, "Tomasz", "Wylaczony");

    await withOrganization(db, company.id, (tx) =>
      tx.account.update({ where: { id: deactivated.accountId }, data: { status: "DEACTIVATED" } }),
    );

    const getAuthzRev = async (accountId: string) =>
      (
        await withOrganization(db, company.id, (tx) =>
          tx.account.findUniqueOrThrow({ where: { id: accountId }, select: { authzRevision: true } }),
        )
      ).authzRevision;

    try {
      const prodToken = await machineToken(productClientId);
      const ownerToken = await token(company);
      const janToken = await token(jan);
      const piotrToken = await token(piotr);
      const ewaToken = await token(ewa);
      const otherOwnerToken = await token(otherCompany);

      // Rejestrujemy uprawnienia i szablon produktu
      expect(
        (
          await request("PUT", `/core/v1/products/${productKey}/permissions`, prodToken, [
            { key: `${productKey}.entries.read`, description: "Odczyt godzin" },
            { key: `${productKey}.entries.approve`, description: "Zatwierdzanie godzin" },
            { key: `${productKey}.reports.export`, description: "Eksport raportów" },
          ])
        ).statusCode,
      ).toBe(200);
      expect(
        (
          await request("PUT", `/core/v1/products/${productKey}/role-templates`, prodToken, [
            {
              key: `${productKey}.manager`,
              name: "Kierownik szablon",
              description: "Zatwierdza godziny zespołu",
              permissions: [`${productKey}.entries.read`, `${productKey}.entries.approve`],
            },
          ])
        ).statusCode,
      ).toBe(200);

      // Jednostki: Kraków -> Magazyn oraz Warszawa
      const krakow = (
        await request("POST", "/core/v1/units", ownerToken, { name: "Oddział Kraków", type: "BRANCH" })
      ).json().data;
      const magazyn = (
        await request("POST", "/core/v1/units", ownerToken, {
          name: "Magazyn Kraków",
          type: "TEAM",
          parentId: krakow.id,
        })
      ).json().data;
      const warszawa = (
        await request("POST", "/core/v1/units", ownerToken, { name: "Oddział Warszawa", type: "BRANCH" })
      ).json().data;

      // Lista pracowników zawiera accountId (niepuste dla pracownika z kontem)
      const employeesRes = await get("/core/v1/employees", ownerToken);
      const janEmp = employeesRes.json().data.find((e: { id: string }) => e.id === jan.employeeId);
      expect(janEmp.accountId).toBe(jan.accountId);

      // Pobranie szablonu i próba jego edycji/archiwizacji -> 403
      const templateList = await get(`/core/v1/roles?product=${productKey}`, ownerToken);
      const templateRole = templateList
        .json()
        .data.find((r: { key: string | null }) => r.key === `${productKey}.manager`);
      expect(templateRole).toBeDefined();
      expect(
        (await request("PATCH", `/core/v1/roles/${templateRole.id}`, ownerToken, { name: "Zmiana" })).statusCode,
      ).toBe(403);
      expect((await request("DELETE", `/core/v1/roles/${templateRole.id}`, ownerToken)).statusCode).toBe(403);

      // Owner kopiuje szablon i tworzy własne role
      const copiedRes = await request("POST", "/core/v1/roles", ownerToken, {
        copyFromRoleId: templateRole.id,
        name: "Kierownik TimoTime",
      });
      expect(copiedRes.statusCode).toBe(201);
      const copiedRole = copiedRes.json().data;
      expect(copiedRole).toMatchObject({
        name: "Kierownik TimoTime",
        product: productKey,
        isTemplate: false,
        copiedFromRoleId: templateRole.id,
        permissions: [`${productKey}.entries.approve`, `${productKey}.entries.read`],
      });

      const exportRoleRes = await request("POST", "/core/v1/roles", ownerToken, {
        name: "Analityk raportów",
        product: productKey,
        permissions: [`${productKey}.entries.read`, `${productKey}.reports.export`],
      });
      expect(exportRoleRes.statusCode).toBe(201);
      const exportRole = exportRoleRes.json().data;

      const krakowAdminRoleRes = await request("POST", "/core/v1/roles", ownerToken, {
        name: "Administrator oddziału",
        product: null,
        permissions: [CORE_PERMISSIONS.keys["roles.assign"], CORE_PERMISSIONS.keys["structure.manage"]],
      });
      expect(krakowAdminRoleRes.statusCode).toBe(201);
      const krakowAdminRole = krakowAdminRoleRes.json().data;

      // GET /roles?includeTemplates=false nie zwraca szablonów; GET /roles/{id} zwraca szczegóły
      const companyOnlyRoles = await get("/core/v1/roles?includeTemplates=false", piotrToken);
      expect(companyOnlyRoles.statusCode).toBe(200);
      expect(companyOnlyRoles.json().data.every((r: { isTemplate: boolean }) => !r.isTemplate)).toBe(true);
      expect((await get(`/core/v1/roles/${copiedRole.id}`, piotrToken)).json().data.permissions).toEqual([
        `${productKey}.entries.approve`,
        `${productKey}.entries.read`,
      ]);
      // Inna firma nie widzi roli company
      expect((await get(`/core/v1/roles/${copiedRole.id}`, otherOwnerToken)).statusCode).toBe(404);

      // Konto bez uprawnień dostaje 403 na wszystkie zapisy
      for (const denied of [
        await request("POST", "/core/v1/employees", piotrToken, { firstName: "X", lastName: "Y" }),
        await request("POST", "/core/v1/units", piotrToken, { name: "X", type: "TEAM", parentId: krakow.id }),
        await request("PATCH", `/core/v1/units/${krakow.id}`, piotrToken, { name: "X" }),
        await request("PUT", `/core/v1/units/${krakow.id}/members/${piotr.employeeId}`, piotrToken, { role: "MEMBER" }),
        await request("DELETE", `/core/v1/units/${krakow.id}/members/${piotr.employeeId}`, piotrToken),
        await request("POST", "/core/v1/roles", piotrToken, {
          name: "Nielegalna",
          product: null,
          permissions: [CORE_PERMISSIONS.keys["audit.read"]],
        }),
        await request("PATCH", `/core/v1/roles/${copiedRole.id}`, piotrToken, { name: "Zmiana" }),
        await request("DELETE", `/core/v1/roles/${copiedRole.id}`, piotrToken),
        await request("POST", "/core/v1/role-assignments", piotrToken, {
          accountId: piotr.accountId,
          roleId: copiedRole.id,
          scopeType: "UNIT",
          scopeId: krakow.id,
        }),
        await request("PUT", "/core/v1/organization/owner", piotrToken, { accountId: piotr.accountId }),
      ]) {
        expect(denied.statusCode).toBe(403);
        expect(denied.json().error.code).toBe("PERMISSION_DENIED");
      }

      // Nadanie wyłączonemu kontu -> 409 CONFLICT
      const assignDeactivated = await request("POST", "/core/v1/role-assignments", ownerToken, {
        accountId: deactivated.accountId,
        roleId: copiedRole.id,
        scopeType: "ORGANIZATION",
      });
      expect(assignDeactivated.statusCode).toBe(409);

      // Owner nadaje Janowi obie role (Administrator oddziału + Kierownik TimoTime) na Kraków; sprawdzamy authzRevision
      const janRev0 = await getAuthzRev(jan.accountId);
      const janCoreAssignRes = await request("POST", "/core/v1/role-assignments", ownerToken, {
        accountId: jan.accountId,
        roleId: krakowAdminRole.id,
        scopeType: "UNIT",
        scopeId: krakow.id,
      });
      expect(janCoreAssignRes.statusCode).toBe(201);
      expect(await getAuthzRev(jan.accountId)).toBe(janRev0 + 1);

      const janProductAssignRes = await request("POST", "/core/v1/role-assignments", ownerToken, {
        accountId: jan.accountId,
        roleId: copiedRole.id,
        scopeType: "UNIT",
        scopeId: krakow.id,
      });
      expect(janProductAssignRes.statusCode).toBe(201);
      expect(await getAuthzRev(jan.accountId)).toBe(janRev0 + 2);

      // Jan z core.structure.manage w Krakowie tworzy zespół pod Krakowem, ale dostaje 403 dla Warszawy i root
      const krakowSubTeamRes = await request("POST", "/core/v1/units", janToken, {
        name: "Zmiana nocna",
        type: "TEAM",
        parentId: krakow.id,
      });
      expect(krakowSubTeamRes.statusCode).toBe(201);
      const krakowSubTeam = krakowSubTeamRes.json().data;

      expect(
        (
          await request("POST", "/core/v1/units", janToken, {
            name: "Zespół Wawa",
            type: "TEAM",
            parentId: warszawa.id,
          })
        ).statusCode,
      ).toBe(403);
      expect(
        (await request("POST", "/core/v1/units", janToken, { name: "Nowy oddział", type: "BRANCH" })).statusCode,
      ).toBe(403);
      expect(
        (await request("PATCH", `/core/v1/units/${krakowSubTeam.id}`, janToken, { parentId: warszawa.id })).statusCode,
      ).toBe(403);

      // Jan z core.roles.assign w Krakowie nadaje Piotrowi Kierownika w Krakowie i podjednostce Magazyn
      const piotrRev0 = await getAuthzRev(piotr.accountId);
      const piotrKrakowAssign = await request("POST", "/core/v1/role-assignments", janToken, {
        accountId: piotr.accountId,
        roleId: copiedRole.id,
        scopeType: "UNIT",
        scopeId: krakow.id,
      });
      expect(piotrKrakowAssign.statusCode).toBe(201);
      expect(await getAuthzRev(piotr.accountId)).toBe(piotrRev0 + 1);

      const piotrMagazynAssign = await request("POST", "/core/v1/role-assignments", janToken, {
        accountId: piotr.accountId,
        roleId: copiedRole.id,
        scopeType: "UNIT",
        scopeId: magazyn.id,
      });
      expect(piotrMagazynAssign.statusCode).toBe(201);

      // Jan dostaje 403 przy delegowaniu: Warszawa, ORGANIZATION, RESOURCE, oraz rola z brakującym uprawnieniem
      expect(
        (
          await request("POST", "/core/v1/role-assignments", janToken, {
            accountId: piotr.accountId,
            roleId: copiedRole.id,
            scopeType: "UNIT",
            scopeId: warszawa.id,
          })
        ).statusCode,
      ).toBe(403);
      expect(
        (
          await request("POST", "/core/v1/role-assignments", janToken, {
            accountId: piotr.accountId,
            roleId: copiedRole.id,
            scopeType: "ORGANIZATION",
          })
        ).statusCode,
      ).toBe(403);
      expect(
        (
          await request("POST", "/core/v1/role-assignments", janToken, {
            accountId: piotr.accountId,
            roleId: copiedRole.id,
            scopeType: "RESOURCE",
            scopeId: "proj_1",
          })
        ).statusCode,
      ).toBe(403);
      expect(
        (
          await request("POST", "/core/v1/role-assignments", janToken, {
            accountId: piotr.accountId,
            roleId: exportRole.id,
            scopeType: "UNIT",
            scopeId: krakow.id,
          })
        ).statusCode,
      ).toBe(403);

      // Widoczność listy przypisań: Owner i Jan widzą wszystkie; Piotr widzi tylko swoje
      const ownerAssignments = await get("/core/v1/role-assignments", ownerToken);
      expect(ownerAssignments.statusCode).toBe(200);
      expect(ownerAssignments.json().data.length).toBe(4);

      const janAssignments = await get("/core/v1/role-assignments", janToken);
      expect(janAssignments.statusCode).toBe(200);
      expect(janAssignments.json().data.length).toBe(4);

      const piotrAssignments = await get("/core/v1/role-assignments", piotrToken);
      expect(piotrAssignments.statusCode).toBe(200);
      expect(piotrAssignments.json().data).toHaveLength(2);
      expect(piotrAssignments.json().data.every((a: { accountId: string }) => a.accountId === piotr.accountId)).toBe(
        true,
      );
      // Piotr filtrujący po cudzym accountId dostaje pustą listę
      const piotrForJan = await get(`/core/v1/role-assignments?accountId=${jan.accountId}`, piotrToken);
      expect(piotrForJan.statusCode).toBe(200);
      expect(piotrForJan.json().data).toEqual([]);

      // Role czasowe (jeszcze nieważna i wygasła) nie dają żadnych uprawnień
      const pastStart = new Date(Date.now() - 120_000).toISOString();
      const pastEnd = new Date(Date.now() - 60_000).toISOString();
      const futureStart = new Date(Date.now() + 60_000).toISOString();
      const futureEnd = new Date(Date.now() + 120_000).toISOString();

      expect(
        (
          await request("POST", "/core/v1/role-assignments", ownerToken, {
            accountId: ewa.accountId,
            roleId: krakowAdminRole.id,
            scopeType: "UNIT",
            scopeId: krakow.id,
            validFrom: pastStart,
            validUntil: pastEnd,
          })
        ).statusCode,
      ).toBe(201);
      const ewaWarszawaAssign = await request("POST", "/core/v1/role-assignments", ownerToken, {
        accountId: ewa.accountId,
        roleId: krakowAdminRole.id,
        scopeType: "UNIT",
        scopeId: warszawa.id,
        validFrom: futureStart,
        validUntil: futureEnd,
      });
      expect(ewaWarszawaAssign.statusCode).toBe(201);

      expect(
        (await request("POST", "/core/v1/units", ewaToken, { name: "Próba Ewy", type: "TEAM", parentId: krakow.id }))
          .statusCode,
      ).toBe(403);
      expect(
        (
          await request("POST", "/core/v1/units", ewaToken, {
            name: "Próba Ewy 2",
            type: "TEAM",
            parentId: warszawa.id,
          })
        ).statusCode,
      ).toBe(403);
      // Wygasłe/przyszłe core.roles.assign nie daje też wglądu w cudze przypisania
      const ewaAssignments = await get("/core/v1/role-assignments", ewaToken);
      expect(ewaAssignments.json().data.every((a: { accountId: string }) => a.accountId === ewa.accountId)).toBe(true);

      // Aktualizacja uprawnień roli podbija authzRevision wszystkich przypisanych kont
      const janRevBeforePatch = await getAuthzRev(jan.accountId);
      const piotrRevBeforePatch = await getAuthzRev(piotr.accountId);
      const patchedRole = await request("PATCH", `/core/v1/roles/${copiedRole.id}`, ownerToken, {
        permissions: [`${productKey}.entries.read`],
      });
      expect(patchedRole.statusCode).toBe(200);
      expect(patchedRole.json().data.permissions).toEqual([`${productKey}.entries.read`]);
      expect(await getAuthzRev(jan.accountId)).toBe(janRevBeforePatch + 1);
      expect(await getAuthzRev(piotr.accountId)).toBe(piotrRevBeforePatch + 1);

      // Archiwizacja roli z przypisaniami -> 409 CONFLICT
      expect((await request("DELETE", `/core/v1/roles/${copiedRole.id}`, ownerToken)).statusCode).toBe(409);

      // Odbieranie przypisań: Jan nie może odebrać przypisania spoza Krakowa (403), ale odbiera w Krakowie/Magazynie
      expect(
        (await request("DELETE", `/core/v1/role-assignments/${ewaWarszawaAssign.json().data.id}`, janToken)).statusCode,
      ).toBe(403);
      const piotrRevBeforeRevoke = await getAuthzRev(piotr.accountId);
      expect(
        (await request("DELETE", `/core/v1/role-assignments/${piotrKrakowAssign.json().data.id}`, janToken)).statusCode,
      ).toBe(204);
      expect(await getAuthzRev(piotr.accountId)).toBe(piotrRevBeforeRevoke + 1);
      expect(
        (await request("DELETE", `/core/v1/role-assignments/${piotrMagazynAssign.json().data.id}`, janToken))
          .statusCode,
      ).toBe(204);

      // Owner odbiera Janowi rolę Kierownika, po czym archiwizuje rolę -> 204
      expect(
        (await request("DELETE", `/core/v1/role-assignments/${janProductAssignRes.json().data.id}`, ownerToken))
          .statusCode,
      ).toBe(204);
      expect((await request("DELETE", `/core/v1/roles/${copiedRole.id}`, ownerToken)).statusCode).toBe(204);

      // Zarchiwizowanej roli nie można edytować ani przypisać
      expect(
        (await request("PATCH", `/core/v1/roles/${copiedRole.id}`, ownerToken, { name: "Po archiwizacji" })).statusCode,
      ).toBe(409);
      expect(
        (
          await request("POST", "/core/v1/role-assignments", ownerToken, {
            accountId: piotr.accountId,
            roleId: copiedRole.id,
            scopeType: "ORGANIZATION",
          })
        ).statusCode,
      ).toBe(409);

      // Dziennik zdarzeń ma wpisy wszystkich operacji i jest widoczny wyłącznie dla tej firmy
      const companyAudit = await withOrganization(db, company.id, (tx) => tx.auditLog.findMany());
      const actions = companyAudit.map((entry) => entry.action);
      expect(actions).toEqual(
        expect.arrayContaining(["role.created", "role.updated", "role.archived", "role.assigned", "role.revoked"]),
      );
      const otherAudit = await withOrganization(db, otherCompany.id, (tx) => tx.auditLog.findMany());
      const companyAuditIds = new Set(companyAudit.map((entry) => entry.id));
      expect(otherAudit.every((entry) => !companyAuditIds.has(entry.id))).toBe(true);
    } finally {
      for (const c of [company, otherCompany]) {
        await withOrganization(db, c.id, (tx) => tx.organization.delete({ where: { id: c.id } }));
        for (const accountId of [c.accountId, ...c.extraAccountIds]) {
          await db.authUser.deleteMany({ where: { id: accountId } });
        }
      }
      await ownerDb.role.deleteMany({ where: { productId } });
      await ownerDb.auditLog.deleteMany({ where: { productId } });
      await ownerDb.permission.deleteMany({ where: { productId } });
      await ownerDb.product.deleteMany({ where: { id: productId } });
    }
  });

  it("przekazuje rolę Ownera: poprzedni Owner traci prawa Ownera, nowy zyskuje, authzRevision rośnie i trafia wpis do audytu", async () => {
    await registerCorePermissions(db);
    await registerCoreRoleTemplates(db);

    const suffix = uuidv7().replaceAll("-", "").slice(-6);
    const company = await createCompany(`owner-${suffix}`);
    const jan = await createMember(company, "Jan", "NowyOwner");
    const deactivated = await createMember(company, "Adam", "Wylaczony");

    await withOrganization(db, company.id, (tx) =>
      tx.account.update({ where: { id: deactivated.accountId }, data: { status: "DEACTIVATED" } }),
    );

    const getAuthzRev = async (accountId: string) =>
      (
        await withOrganization(db, company.id, (tx) =>
          tx.account.findUniqueOrThrow({ where: { id: accountId }, select: { authzRevision: true } }),
        )
      ).authzRevision;

    try {
      const annaToken = await token(company);
      const janToken = await token(jan);

      // Nawet Administrator firmy (szablon core.company_admin) nie może przekazać roli Ownera
      const rolesRes = await get("/core/v1/roles?product=core", annaToken);
      const companyAdminTemplate = rolesRes
        .json()
        .data.find((r: { key: string | null }) => r.key === "core.company_admin");
      const assignAdmin = await request("POST", "/core/v1/role-assignments", annaToken, {
        accountId: jan.accountId,
        roleId: companyAdminTemplate.id,
        scopeType: "ORGANIZATION",
      });
      expect(assignAdmin.statusCode).toBe(201);

      expect(
        (await request("PUT", "/core/v1/organization/owner", janToken, { accountId: jan.accountId })).statusCode,
      ).toBe(403);

      // Odbieramy rolę Janowi, żeby sprawdzić czyste przejście praw Ownera
      expect(
        (await request("DELETE", `/core/v1/role-assignments/${assignAdmin.json().data.id}`, annaToken)).statusCode,
      ).toBe(204);

      // Błędy walidacji / konfliktu / 404
      expect(
        (await request("PUT", "/core/v1/organization/owner", annaToken, { accountId: company.accountId })).statusCode,
      ).toBe(409);
      expect(
        (await request("PUT", "/core/v1/organization/owner", annaToken, { accountId: deactivated.accountId }))
          .statusCode,
      ).toBe(409);
      expect(
        (await request("PUT", "/core/v1/organization/owner", annaToken, { accountId: acme.accountId })).statusCode,
      ).toBe(404);

      const annaRevBefore = await getAuthzRev(company.accountId);
      const janRevBefore = await getAuthzRev(jan.accountId);

      // Przekazanie Ownera Annie -> Janowi
      const transferRes = await request("PUT", "/core/v1/organization/owner", annaToken, {
        accountId: jan.accountId,
      });
      expect(transferRes.statusCode).toBe(200);
      expect(transferRes.json().data).toEqual({ ownerAccountId: jan.accountId });

      // authzRevision podbite u obu kont
      expect(await getAuthzRev(company.accountId)).toBe(annaRevBefore + 1);
      expect(await getAuthzRev(jan.accountId)).toBe(janRevBefore + 1);

      // GET /me odzwierciedla zmianę isOwner
      expect((await get("/core/v1/me", annaToken)).json().data.account.isOwner).toBe(false);
      expect((await get("/core/v1/me", janToken)).json().data.account.isOwner).toBe(true);

      // Anna straciła prawa Ownera (nie ma żadnych ról -> 403)
      expect(
        (await request("POST", "/core/v1/employees", annaToken, { firstName: "X", lastName: "Y" })).statusCode,
      ).toBe(403);
      expect(
        (await request("PUT", "/core/v1/organization/owner", annaToken, { accountId: company.accountId })).statusCode,
      ).toBe(403);

      // Jan zyskał pełne prawa Ownera
      expect(
        (await request("POST", "/core/v1/employees", janToken, { firstName: "Nowy", lastName: "Pracownik" }))
          .statusCode,
      ).toBe(201);

      // Wpis w dzienniku zdarzeń z { from, to }
      const auditEntries = await withOrganization(db, company.id, (tx) =>
        tx.auditLog.findMany({ where: { action: "organization.owner.transferred" } }),
      );
      expect(auditEntries).toHaveLength(1);
      expect(auditEntries[0]?.metadata).toEqual({ from: company.accountId, to: jan.accountId });
    } finally {
      await withOrganization(db, company.id, (tx) => tx.organization.delete({ where: { id: company.id } }));
      for (const accountId of [company.accountId, ...company.extraAccountIds]) {
        await db.authUser.deleteMany({ where: { id: accountId } });
      }
    }
  });

  it("nieistniejąca jednostka daje 404 przed sprawdzeniem uprawnień, a zarchiwizowana gotowa rola nie daje uprawnień", async () => {
    await registerCorePermissions(db);
    await registerCoreRoleTemplates(db);

    const suffix = uuidv7().replaceAll("-", "").slice(-6);
    const company = await createCompany(`archived-${suffix}`);
    const jan = await createMember(company, "Jan", "Administrator");
    const missingUnitId = uuidv7();
    const companyAdmin = await db.role.findFirstOrThrow({ where: { key: "core.company_admin" } });

    try {
      const ownerToken = await token(company);
      const janToken = await token(jan);

      // Jan bez żadnej roli: nieistniejąca jednostka to 404, a nie 403
      expect(
        (await request("POST", "/core/v1/units", janToken, { name: "X", type: "TEAM", parentId: missingUnitId }))
          .statusCode,
      ).toBe(404);
      expect((await request("PATCH", `/core/v1/units/${missingUnitId}`, janToken, { name: "Y" })).statusCode).toBe(404);
      expect(
        (
          await request("PUT", `/core/v1/units/${missingUnitId}/members/${jan.employeeId}`, janToken, {
            role: "MEMBER",
          })
        ).statusCode,
      ).toBe(404);
      expect(
        (await request("DELETE", `/core/v1/units/${missingUnitId}/members/${jan.employeeId}`, janToken)).statusCode,
      ).toBe(404);
      // Istniejąca jednostka bez uprawnień: 403
      const unit = (await request("POST", "/core/v1/units", ownerToken, { name: "Oddział", type: "BRANCH" })).json()
        .data;
      expect((await request("PATCH", `/core/v1/units/${unit.id}`, janToken, { name: "Z" })).statusCode).toBe(403);

      // Gotowa rola „Administrator firmy” w całej firmie pozwala Janowi tworzyć jednostki
      expect(
        (
          await request("POST", "/core/v1/role-assignments", ownerToken, {
            accountId: jan.accountId,
            roleId: companyAdmin.id,
            scopeType: "ORGANIZATION",
          })
        ).statusCode,
      ).toBe(201);
      expect((await request("POST", "/core/v1/units", janToken, { name: "Zespół A", type: "TEAM" })).statusCode).toBe(
        201,
      );

      // Po archiwizacji gotowej roli (np. wycofanej przez produkt) przypisanie przestaje działać
      await db.role.update({ where: { id: companyAdmin.id }, data: { archivedAt: new Date() } });
      expect((await request("POST", "/core/v1/units", janToken, { name: "Zespół B", type: "TEAM" })).statusCode).toBe(
        403,
      );
    } finally {
      await db.role.update({ where: { id: companyAdmin.id }, data: { archivedAt: null } });
      await withOrganization(db, company.id, (tx) => tx.organization.delete({ where: { id: company.id } }));
      for (const accountId of [company.accountId, ...company.extraAccountIds]) {
        await db.authUser.deleteMany({ where: { id: accountId } });
      }
    }
  });

  it("aktualizuje istniejący szablon core.company_admin o nowe uprawnienie core.app_access.manage przy starcie", async () => {
    await registerCorePermissions(db);
    await registerCoreRoleTemplates(db);

    const companyAdmin = await db.role.findFirstOrThrow({
      where: { key: "core.company_admin" },
      include: { permissions: { select: { permission: { select: { id: true, key: true } } } } },
    });
    const appAccessPerm = companyAdmin.permissions.find(
      (rp) => rp.permission.key === CORE_PERMISSIONS.keys["app_access.manage"],
    );
    expect(appAccessPerm).toBeDefined();

    // Symulujemy bazę sprzed etapu 3 (brak core.app_access.manage w szablonie) i ponowną rejestrację przy starcie
    await db.rolePermission.delete({
      where: { roleId_permissionId: { roleId: companyAdmin.id, permissionId: appAccessPerm!.permission.id } },
    });
    const summary = await registerCoreRoleTemplates(db);
    expect(summary.updated).toContain("core.company_admin");

    const refreshed = await db.role.findFirstOrThrow({
      where: { key: "core.company_admin" },
      include: { permissions: { select: { permission: { select: { key: true } } } } },
    });
    expect(refreshed.permissions.map((rp) => rp.permission.key)).toContain(CORE_PERMISSIONS.keys["app_access.manage"]);
  });

  it("obsługuje Entitlement CLI, AppAccess, migawkę uprawnień produktu (can/scopeOf) oraz zdarzenia outbox", async () => {
    await registerCorePermissions(db);
    await registerCoreRoleTemplates(db);

    const suffix = uuidv7().replaceAll("-", "").slice(-6);
    const company = await createCompany(`snap-${suffix}`);
    const otherCompany = await createCompany(`snap-other-${suffix}`);
    const jan = await createMember(company, "Jan", "Kierownik");
    const piotr = await createMember(company, "Piotr", "Pracownik");
    const ewa = await createMember(company, "Ewa", "BezJednostek");
    const invited = await createMember(company, "Kasia", "Zaproszona");
    const deactivated = await createMember(company, "Adam", "Wylaczony");

    await withOrganization(db, company.id, async (tx) => {
      await tx.organizationDomain.create({
        data: {
          id: uuidv7(),
          organizationId: company.id,
          domain: company.domain,
          status: "VERIFIED",
          verificationMethod: "DNS_TXT",
          isPrimary: true,
        },
      });
      await tx.account.update({ where: { id: invited.accountId }, data: { status: "INVITED" } });
      await tx.account.update({
        where: { id: deactivated.accountId },
        data: { status: "DEACTIVATED", deactivatedAt: new Date() },
      });
    });

    const productKey = `timo${suffix}`;
    const otherProductKey = `aven${suffix}`;
    const clientId = `${productKey}-web`;
    const otherClientId = `${otherProductKey}-web`;
    const productId = uuidv7();
    const otherProductId = uuidv7();

    await db.product.create({
      data: { id: productId, key: productKey, name: "TimoTime Test", registrationClientId: clientId },
    });
    await db.product.create({
      data: { id: otherProductId, key: otherProductKey, name: "AvenMail Test", registrationClientId: otherClientId },
    });

    const getAuthzRev = async (accountId: string) =>
      (
        await withOrganization(db, company.id, (tx) =>
          tx.account.findUniqueOrThrow({ where: { id: accountId }, select: { authzRevision: true } }),
        )
      ).authzRevision;

    const getOutboxEvents = async (orgId: string, accountId?: string) =>
      withOrganization(db, orgId, (tx) =>
        tx.outboxEvent.findMany({
          ...(accountId ? { where: { resourceId: accountId } } : {}),
          orderBy: { id: "asc" },
        }),
      );

    try {
      const ownerToken = await token(company);
      const janToken = await token(jan);
      const piotrToken = await token(piotr);
      const otherOwnerToken = await token(otherCompany);
      const registerToken = await machineToken(clientId, PERMISSIONS_REGISTER_SCOPE);
      const readToken = await machineToken(clientId, PERMISSIONS_READ_SCOPE);
      const otherReadToken = await machineToken(otherClientId, PERMISSIONS_READ_SCOPE);

      // Rejestrujemy uprawnienia produktu: 2 aktywne + 1 później wycofane
      expect(
        (
          await request("PUT", `/core/v1/products/${productKey}/permissions`, registerToken, [
            { key: `${productKey}.entries.read`, description: "Odczyt wpisów" },
            { key: `${productKey}.entries.approve`, description: "Zatwierdzanie godzin" },
            { key: `${productKey}.legacy.use`, description: "Wycofane uprawnienie" },
          ])
        ).statusCode,
      ).toBe(200);

      // Drzewo jednostek: Kraków -> Magazyn, Warszawa, oraz Zarchiwizowany oddział
      const krakow = (
        await request("POST", "/core/v1/units", ownerToken, { name: "Oddział Kraków", type: "BRANCH" })
      ).json().data;
      const magazyn = (
        await request("POST", "/core/v1/units", ownerToken, {
          name: "Magazyn Kraków",
          type: "TEAM",
          parentId: krakow.id,
        })
      ).json().data;
      const warszawa = (
        await request("POST", "/core/v1/units", ownerToken, { name: "Oddział Warszawa", type: "BRANCH" })
      ).json().data;
      const archivedBranch = (
        await request("POST", "/core/v1/units", ownerToken, { name: "Stary Oddział", type: "BRANCH" })
      ).json().data;
      expect(
        (await request("PATCH", `/core/v1/units/${archivedBranch.id}`, ownerToken, { status: "ARCHIVED" })).statusCode,
      ).toBe(200);

      // Przypisujemy pracowników do jednostek (Ewa zostaje bez żadnej jednostki)
      expect(
        (await request("PUT", `/core/v1/units/${magazyn.id}/members/${jan.employeeId}`, ownerToken, { role: "LEADER" }))
          .statusCode,
      ).toBe(200);
      expect(
        (
          await request("PUT", `/core/v1/units/${warszawa.id}/members/${piotr.employeeId}`, ownerToken, {
            role: "MEMBER",
          })
        ).statusCode,
      ).toBe(200);

      // Role: Kierownik produktu (z wycofanym później kluczem), druga rola archiwizowana oraz rola core.*
      const managerRole = (
        await request("POST", "/core/v1/roles", ownerToken, {
          name: "Kierownik",
          product: productKey,
          permissions: [`${productKey}.entries.read`, `${productKey}.entries.approve`, `${productKey}.legacy.use`],
        })
      ).json().data;
      const tempRole = (
        await request("POST", "/core/v1/roles", ownerToken, {
          name: "Tymczasowa produktu",
          product: productKey,
          permissions: [`${productKey}.entries.read`],
        })
      ).json().data;
      const appAccessRole = (
        await request("POST", "/core/v1/roles", ownerToken, {
          name: "Administrator aplikacji",
          product: null,
          permissions: [CORE_PERMISSIONS.keys["app_access.manage"]],
        })
      ).json().data;

      // Nadajemy Janowi: Kierownika na Oddział Kraków, rolę Core app_access.manage na Kraków, oraz tempRole (którą zaraz zarchiwizujemy)
      const janManagerAssign = (
        await request("POST", "/core/v1/role-assignments", ownerToken, {
          accountId: jan.accountId,
          roleId: managerRole.id,
          scopeType: "UNIT",
          scopeId: krakow.id,
        })
      ).json().data;
      expect(janManagerAssign.id).toBeTruthy();
      expect(
        (
          await request("POST", "/core/v1/role-assignments", ownerToken, {
            accountId: jan.accountId,
            roleId: appAccessRole.id,
            scopeType: "UNIT",
            scopeId: krakow.id,
          })
        ).statusCode,
      ).toBe(201);
      expect(
        (
          await request("POST", "/core/v1/role-assignments", ownerToken, {
            accountId: jan.accountId,
            roleId: tempRole.id,
            scopeType: "ORGANIZATION",
          })
        ).statusCode,
      ).toBe(201);

      // Wycofujemy uprawnienie legacy.use oraz archiwizujemy tempRole bezpośrednio w bazie (jak wycofany szablon)
      expect(
        (
          await request("PUT", `/core/v1/products/${productKey}/permissions`, registerToken, [
            { key: `${productKey}.entries.read`, description: "Odczyt wpisów" },
            { key: `${productKey}.entries.approve`, description: "Zatwierdzanie godzin" },
          ])
        ).statusCode,
      ).toBe(200);
      await withOrganization(db, company.id, (tx) =>
        tx.role.update({ where: { id: tempRole.id }, data: { archivedAt: new Date() } }),
      );

      // 1. Firma BEZ Entitlement: migawka dla Ownera i Jana zwraca products: []
      const snapNoEntOwner = await get(
        `/core/v1/products/${productKey}/permission-snapshot?organizationId=${company.id}&accountId=${company.accountId}`,
        readToken,
      );
      expect(snapNoEntOwner.statusCode).toBe(200);
      expect(permissionSnapshotSchema.parse(snapNoEntOwner.json().data)).toMatchObject({
        accountId: company.accountId,
        organizationId: company.id,
        isOwner: true,
        products: [],
      });
      expect(can(snapNoEntOwner.json().data, `${productKey}.entries.read`)).toBe(false);

      // Bez Entitlement: POST /core/v1/app-access zwraca 409 i NIE zapisuje zdarzenia outbox
      const outboxBeforeFail = (await getOutboxEvents(company.id)).length;
      const noEntGrant = await request("POST", "/core/v1/app-access", ownerToken, {
        accountId: jan.accountId,
        product: productKey,
      });
      expect(noEntGrant.statusCode).toBe(409);
      expect((await getOutboxEvents(company.id)).length).toBe(outboxBeforeFail);

      // 2. CLI grantEntitlement po domenie firmy: przyznaje Entitlement, podbija authzRevision wszystkich kont i zapisuje outbox + audyt
      const ownerRevBeforeEnt = await getAuthzRev(company.accountId);
      const janRevBeforeEnt = await getAuthzRev(jan.accountId);
      const piotrRevBeforeEnt = await getAuthzRev(piotr.accountId);
      const futureEndsAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
      const grantResult = await grantEntitlement(db, {
        organization: company.domain,
        product: productKey,
        endsAt: futureEndsAt,
      });
      expect(grantResult).toMatchObject({
        organizationId: company.id,
        productKey,
        status: "ACTIVE",
        updated: false,
        affectedAccounts: 6,
      });
      expect(await getAuthzRev(company.accountId)).toBe(ownerRevBeforeEnt + 1);
      expect(await getAuthzRev(jan.accountId)).toBe(janRevBeforeEnt + 1);
      expect(await getAuthzRev(piotr.accountId)).toBe(piotrRevBeforeEnt + 1);

      const cliAudit = await withOrganization(db, company.id, (tx) =>
        tx.auditLog.findMany({ where: { action: "entitlement.granted" } }),
      );
      expect(cliAudit).toHaveLength(1);
      expect(cliAudit[0]?.actorType).toBe("SYSTEM");
      expect(cliAudit[0]?.metadata).toMatchObject({ source: "cli", productKey });

      // GET /core/v1/entitlements dostępne dla zwykłego konta firmy i odizolowane między firmami
      const entListRes = await get("/core/v1/entitlements", piotrToken);
      expect(entListRes.statusCode).toBe(200);
      expect(entListRes.json().data).toHaveLength(1);
      expect(entListRes.json().data[0]).toMatchObject({
        id: grantResult.entitlementId,
        product: productKey,
        sourceType: "MANUAL",
        status: "ACTIVE",
        isActive: true,
      });
      const otherEntList = await get("/core/v1/entitlements", otherOwnerToken);
      expect(otherEntList.json().data).toEqual([]);

      // 3. Z Entitlement, bez AppAccess: Owner ma [productKey], Jan ma []
      const snapOwnerWithEnt = await get(
        `/core/v1/products/${productKey}/permission-snapshot?organizationId=${company.id}&accountId=${company.accountId}`,
        readToken,
      );
      expect(snapOwnerWithEnt.statusCode).toBe(200);
      expect(snapOwnerWithEnt.json().data.products).toEqual([productKey]);
      expect(can(snapOwnerWithEnt.json().data, `${productKey}.entries.approve`, { unitIds: [warszawa.id] })).toBe(true);

      const snapJanNoAccess = await get(
        `/core/v1/products/${productKey}/permission-snapshot?organizationId=${company.id}&accountId=${jan.accountId}`,
        readToken,
      );
      expect(snapJanNoAccess.statusCode).toBe(200);
      expect(snapJanNoAccess.json().data.products).toEqual([]);
      expect(can(snapJanNoAccess.json().data, `${productKey}.entries.approve`, { unitIds: [krakow.id] })).toBe(false);

      // 4. AppAccess: uprawnienia po jednostkach pracownika, 409 dla INVITED/DEACTIVATED/duplikatu, widoczność
      // Jan ma core.app_access.manage na Kraków -> może włączyć sobie (Magazyn pod Krakowem), ale 403 dla Piotra (Warszawa) i Ewy (brak jednostek)
      expect(
        (await request("POST", "/core/v1/app-access", janToken, { accountId: piotr.accountId, product: productKey }))
          .statusCode,
      ).toBe(403);
      expect(
        (await request("POST", "/core/v1/app-access", janToken, { accountId: ewa.accountId, product: productKey }))
          .statusCode,
      ).toBe(403);
      // Piotr bez uprawnień dostaje 403
      expect(
        (await request("POST", "/core/v1/app-access", piotrToken, { accountId: piotr.accountId, product: productKey }))
          .statusCode,
      ).toBe(403);
      // Owner dostaje 409 dla INVITED i DEACTIVATED
      expect(
        (
          await request("POST", "/core/v1/app-access", ownerToken, {
            accountId: invited.accountId,
            product: productKey,
          })
        ).statusCode,
      ).toBe(409);
      expect(
        (
          await request("POST", "/core/v1/app-access", ownerToken, {
            accountId: deactivated.accountId,
            product: productKey,
          })
        ).statusCode,
      ).toBe(409);

      // Jan włącza TimoTime sobie (jest w Magazynie -> poddrzewo Krakowa) -> 201
      const janRevBeforeAccess = await getAuthzRev(jan.accountId);
      const janAccessRes = await request("POST", "/core/v1/app-access", janToken, {
        accountId: jan.accountId,
        product: productKey,
      });
      expect(janAccessRes.statusCode).toBe(201);
      const janAccess = janAccessRes.json().data;
      expect(janAccess).toMatchObject({
        accountId: jan.accountId,
        product: productKey,
        status: "ACTIVE",
        grantedByAccountId: jan.accountId,
        revokedAt: null,
      });
      expect(await getAuthzRev(jan.accountId)).toBe(janRevBeforeAccess + 1);

      // Ponowne włączenie tego samego aktywnego produktu -> 409
      expect(
        (await request("POST", "/core/v1/app-access", ownerToken, { accountId: jan.accountId, product: productKey }))
          .statusCode,
      ).toBe(409);

      // Owner włącza aplikację Piotrowi i Ewie (bez jednostek)
      const piotrAccess = (
        await request("POST", "/core/v1/app-access", ownerToken, { accountId: piotr.accountId, product: productKey })
      ).json().data;
      expect(
        (await request("POST", "/core/v1/app-access", ownerToken, { accountId: ewa.accountId, product: productKey }))
          .statusCode,
      ).toBe(201);

      // Widoczność GET /core/v1/app-access: Owner i Jan (core.app_access.manage) widzą wszystkie; Piotr tylko swoje
      expect((await get("/core/v1/app-access", ownerToken)).json().data).toHaveLength(3);
      expect((await get("/core/v1/app-access", janToken)).json().data).toHaveLength(3);
      const piotrVisible = await get("/core/v1/app-access", piotrToken);
      expect(piotrVisible.json().data.map((a: { id: string }) => a.id)).toEqual([piotrAccess.id]);
      expect((await get(`/core/v1/app-access?accountId=${jan.accountId}`, piotrToken)).json().data).toEqual([]);

      // Jan nie może wyłączyć dostępu Piotra (Warszawa poza zakresem Krakowa -> 403)
      expect((await request("DELETE", `/core/v1/app-access/${piotrAccess.id}`, janToken)).statusCode).toBe(403);

      // 5. Migawka uprawnień Jana z AppAccess + rolą Kierownik na Kraków: can() i scopeOf()
      const snapJanRes = await get(
        `/core/v1/products/${productKey}/permission-snapshot?organizationId=${company.id}&accountId=${jan.accountId}`,
        readToken,
      );
      expect(snapJanRes.statusCode).toBe(200);
      const snapJan = permissionSnapshotSchema.parse(snapJanRes.json().data);
      expect(snapJan.products).toEqual([productKey]);
      expect(snapJan.authzRevision).toBe(janRevBeforeAccess + 1);
      // Tylko aktywne uprawnienia tego produktu (bez core.*, bez legacy.use, bez zarchiwizowanej tempRole)
      expect(snapJan.grants.map((g) => g.permission).sort()).toEqual([
        `${productKey}.entries.approve`,
        `${productKey}.entries.read`,
      ]);
      expect(snapJan.grants.every((g) => g.scope.type === "UNIT" && g.scope.unitId === krakow.id)).toBe(true);
      // Zarchiwizowany oddział obecny w units
      expect(snapJan.units.map((u) => u.id)).toContain(archivedBranch.id);

      // Biblioteka @monorise-team/permissions rozstrzyga dostęp Jana: Kraków i Magazyn TAK, Warszawa NIE
      expect(can(snapJan, `${productKey}.entries.approve`, { unitIds: [krakow.id] })).toBe(true);
      expect(can(snapJan, `${productKey}.entries.approve`, { unitIds: [magazyn.id] })).toBe(true);
      expect(can(snapJan, `${productKey}.entries.approve`, { unitIds: [warszawa.id] })).toBe(false);
      expect(scopeOf(snapJan, `${productKey}.entries.approve`)).toEqual({
        type: "LIMITED",
        unitIds: [krakow.id, magazyn.id].sort(),
        resourceIds: [],
      });

      // 6. Kontrola błędów i przypadków brzegowych migawki produktu
      // Token innego produktu -> 403; token ze złym zakresem (register zamiast read) -> 403; token użytkownika -> 401
      expect(
        (
          await get(
            `/core/v1/products/${productKey}/permission-snapshot?organizationId=${company.id}&accountId=${jan.accountId}`,
            otherReadToken,
          )
        ).statusCode,
      ).toBe(403);
      expect(
        (
          await get(
            `/core/v1/products/${productKey}/permission-snapshot?organizationId=${company.id}&accountId=${jan.accountId}`,
            registerToken,
          )
        ).statusCode,
      ).toBe(403);
      expect(
        (
          await get(
            `/core/v1/products/${productKey}/permission-snapshot?organizationId=${company.id}&accountId=${jan.accountId}`,
            ownerToken,
          )
        ).statusCode,
      ).toBe(401);
      // Nieznane konto / konto innej firmy / nieznana firma -> 404
      expect(
        (
          await get(
            `/core/v1/products/${productKey}/permission-snapshot?organizationId=${company.id}&accountId=${otherCompany.accountId}`,
            readToken,
          )
        ).statusCode,
      ).toBe(404);
      expect(
        (
          await get(
            `/core/v1/products/${productKey}/permission-snapshot?organizationId=${uuidv7()}&accountId=${jan.accountId}`,
            readToken,
          )
        ).statusCode,
      ).toBe(404);
      // INVITED i DEACTIVATED -> migawka z pustymi products i grants
      for (const inactiveId of [invited.accountId, deactivated.accountId]) {
        const res = await get(
          `/core/v1/products/${productKey}/permission-snapshot?organizationId=${company.id}&accountId=${inactiveId}`,
          readToken,
        );
        expect(res.statusCode).toBe(200);
        const parsed = permissionSnapshotSchema.parse(res.json().data);
        expect(parsed.products).toEqual([]);
        expect(parsed.grants).toEqual([]);
        expect(parsed.units.length).toBeGreaterThan(0);
      }

      // 7. Cofnięcie i ponowne włączenie AppAccess (historia zachowana, nowy wiersz przy ponownym włączeniu)
      const janRevBeforeRevoke = await getAuthzRev(jan.accountId);
      expect((await request("DELETE", `/core/v1/app-access/${janAccess.id}`, ownerToken)).statusCode).toBe(204);
      expect(await getAuthzRev(jan.accountId)).toBe(janRevBeforeRevoke + 1);
      // Ponowne DELETE tego samego wiersza -> 409
      expect((await request("DELETE", `/core/v1/app-access/${janAccess.id}`, ownerToken)).statusCode).toBe(409);

      // Ponowne włączenie tworzy nowy wiersz; ?includeRevoked=true pokazuje historię obu
      const janRegrantRes = await request("POST", "/core/v1/app-access", ownerToken, {
        accountId: jan.accountId,
        product: productKey,
      });
      expect(janRegrantRes.statusCode).toBe(201);
      expect(janRegrantRes.json().data.id).not.toBe(janAccess.id);

      const janHistory = await get(`/core/v1/app-access?accountId=${jan.accountId}&includeRevoked=true`, ownerToken);
      expect(janHistory.json().data).toHaveLength(2);
      expect(
        janHistory
          .json()
          .data.map((a: { status: string }) => a.status)
          .sort(),
      ).toEqual(["ACTIVE", "REVOKED"]);

      // 8. Zmiana uprawnień roli firmowej, odebranie przypisania oraz przekazanie Ownera zapisują zdarzenia outbox w tej samej transakcji
      expect(
        (
          await request("PATCH", `/core/v1/roles/${managerRole.id}`, ownerToken, {
            permissions: [`${productKey}.entries.read`],
          })
        ).statusCode,
      ).toBe(200);
      expect((await request("DELETE", `/core/v1/role-assignments/${janManagerAssign.id}`, ownerToken)).statusCode).toBe(
        204,
      );
      expect(
        (await request("PUT", "/core/v1/organization/owner", ownerToken, { accountId: jan.accountId })).statusCode,
      ).toBe(200);

      // 9. CLI endEntitlement kończy dostęp, podbija authzRevision wszystkich kont i wyłącza produkt w migawce
      const endResult = await endEntitlement(db, { organization: company.id, product: productKey });
      expect(endResult).toMatchObject({
        entitlementId: grantResult.entitlementId,
        organizationId: company.id,
        productKey,
        previousStatus: "ACTIVE",
        affectedAccounts: 6,
      });
      const snapAfterEnd = await get(
        `/core/v1/products/${productKey}/permission-snapshot?organizationId=${company.id}&accountId=${jan.accountId}`,
        readToken,
      );
      expect(snapAfterEnd.json().data.products).toEqual([]);

      // 10. Weryfikujemy zapisane zdarzenia outbox dla Jana: rosnące authzRevision, poprawny format koperty @monorise-team/events
      const janEvents = await getOutboxEvents(company.id, jan.accountId);
      expect(janEvents.length).toBeGreaterThanOrEqual(8);
      const finalJanRev = await getAuthzRev(jan.accountId);
      expect(janEvents[janEvents.length - 1]?.resourceVersion).toBe(finalJanRev);
      for (const row of janEvents) {
        expect(row.type).toBe("organization.permissions.changed");
        expect(row.version).toBe(1);
        expect(row.resourceType).toBe("account");
        expect(row.resourceId).toBe(jan.accountId);
        expect(row.publishedAt).toBeNull();
        expect(row.payload).toEqual({ authzRevision: row.resourceVersion });

        const parsed = coreEvents.parse(
          fromOutboxRecord(
            {
              ...row,
              payload: row.payload as Record<string, unknown>,
            },
            { source: "core" },
          ),
        );
        expect(parsed.status).toBe("known");
      }
      // Zdarzenia są odizolowane między firmami
      expect(await getOutboxEvents(otherCompany.id)).toEqual([]);
    } finally {
      for (const c of [company, otherCompany]) {
        await withOrganization(db, c.id, (tx) => tx.organization.delete({ where: { id: c.id } }));
        for (const accountId of [c.accountId, ...c.extraAccountIds]) {
          await db.authUser.deleteMany({ where: { id: accountId } });
        }
      }
      await ownerDb.role.deleteMany({ where: { productId: { in: [productId, otherProductId] } } });
      await ownerDb.auditLog.deleteMany({ where: { productId: { in: [productId, otherProductId] } } });
      await ownerDb.permission.deleteMany({ where: { productId: { in: [productId, otherProductId] } } });
      await ownerDb.product.deleteMany({ where: { id: { in: [productId, otherProductId] } } });
    }
  });
});
