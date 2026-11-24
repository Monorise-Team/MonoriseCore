import { CORE_PERMISSIONS, PERMISSIONS_REGISTER_SCOPE } from "@core/contracts";
import { createDb, uuidv7, withOrganization } from "@core/db";
import { createLocalJWKSet, exportJWK, generateKeyPair, SignJWT, type CryptoKey } from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { registerCorePermissions } from "../src/permissions-registry.js";
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
      employee: { id: acme.employeeId, firstName: "Anna", lastName: "acme" },
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
});
