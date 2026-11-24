import { createDb, uuidv7, withOrganization } from "@core/db";
import { createLocalJWKSet, exportJWK, generateKeyPair, SignJWT, type CryptoKey } from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { buildServer } from "../src/server.js";
import { createTokenVerifier } from "../src/tokens.js";

const ISSUER = "http://localhost:3100";
const AUDIENCE = "http://localhost:3200";
const db = createDb(
  process.env.CORE_TEST_APP_DATABASE_URL ?? "postgresql://core_app:core_app@localhost:5433/monorise_core_test",
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

const get = (url: string, bearer?: string) => request("GET", url, bearer);

let acme: Company;
let acmeMember: Identity;
let globex: Company;

beforeAll(async () => {
  const pair = await generateKeyPair("EdDSA", { crv: "Ed25519" });
  signingKey = pair.privateKey;
  otherKey = (await generateKeyPair("EdDSA", { crv: "Ed25519" })).privateKey;
  const jwk = { ...(await exportJWK(pair.publicKey)), alg: "EdDSA", kid: "test" };
  app = buildServer({
    db,
    verifyToken: createTokenVerifier({ keys: createLocalJWKSet({ keys: [jwk] }), issuer: ISSUER, audience: AUDIENCE }),
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
});
