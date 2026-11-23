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

interface Company {
  id: string;
  employeeId: string;
  accountId: string;
}

async function createCompany(name: string): Promise<Company> {
  const id = uuidv7();
  const employeeId = uuidv7();
  const accountId = uuidv7();
  const email = `anna@${id.slice(-8)}-${name}.test`;
  await db.authUser.create({ data: { id: accountId, name: "Anna", email, emailVerified: true } });
  await withOrganization(db, id, async (tx) => {
    await tx.organization.create({ data: { id, name, createdVia: "SELF_SIGNUP", status: "ACTIVE" } });
    await tx.employee.create({ data: { id: employeeId, organizationId: id, firstName: "Anna", lastName: name } });
    await tx.account.create({
      data: { id: accountId, organizationId: id, employeeId, email, normalizedEmail: email, status: "ACTIVE" },
    });
  });
  return { id, employeeId, accountId };
}

function token(company: Company, overrides: Record<string, unknown> = {}, key = signingKey, expiresIn = "5m") {
  return new SignJWT({ org_id: company.id, employee_id: company.employeeId, authz_rev: 0, amr: ["pwd"], ...overrides })
    .setProtectedHeader({ alg: "EdDSA" })
    .setIssuer(ISSUER)
    .setAudience(AUDIENCE)
    .setSubject(company.accountId)
    .setIssuedAt()
    .setExpirationTime(expiresIn)
    .sign(key);
}

const get = (url: string, bearer?: string) =>
  app.inject({ method: "GET", url, headers: bearer ? { authorization: `Bearer ${bearer}` } : {} });

let acme: Company;
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
  globex = await createCompany("globex");
});

afterAll(async () => {
  await app?.close();
  for (const company of [acme, globex]) {
    if (!company) continue;
    await withOrganization(db, company.id, (tx) => tx.organization.delete({ where: { id: company.id } }));
    await db.authUser.delete({ where: { id: company.accountId } });
  }
  await db.$disconnect();
});

describe("Core API", () => {
  it("działa bez logowania tylko dla /v1/health", async () => {
    const health = await get("/v1/health");
    expect(health.statusCode).toBe(200);
    expect(health.json()).toMatchObject({ data: { status: "ok" }, error: null });

    const me = await get("/v1/me");
    expect(me.statusCode).toBe(401);
    expect(me.json()).toMatchObject({ data: null, error: { code: "UNAUTHENTICATED" } });
  });

  it("zwraca dane zalogowanego pracownika i jego firmy", async () => {
    const response = await get("/v1/me", await token(acme));
    expect(response.statusCode).toBe(200);
    expect(response.json().data).toMatchObject({
      account: { id: acme.accountId, status: "ACTIVE" },
      employee: { id: acme.employeeId, firstName: "Anna", lastName: "acme" },
      organization: { id: acme.id, name: "acme", status: "ACTIVE" },
    });
    const organization = await get("/v1/organization", await token(globex));
    expect(organization.json().data).toMatchObject({ id: globex.id, name: "globex" });
  });

  it("odrzuca obcy podpis, zły odbiorcę, wygasły token i podmienioną firmę", async () => {
    expect((await get("/v1/me", await token(acme, {}, otherKey))).statusCode).toBe(401);
    const wrongAudience = await new SignJWT({ org_id: acme.id, employee_id: acme.employeeId, authz_rev: 0 })
      .setProtectedHeader({ alg: "EdDSA" })
      .setIssuer(ISSUER)
      .setAudience("https://ktos-inny.test")
      .setSubject(acme.accountId)
      .setIssuedAt()
      .setExpirationTime("5m")
      .sign(signingKey);
    expect((await get("/v1/me", wrongAudience)).statusCode).toBe(401);
    expect((await get("/v1/me", await token(acme, {}, signingKey, "-1m"))).statusCode).toBe(401);
    // Token Anny z Acme z podmienioną firmą: konto nie istnieje w Globex, więc RLS nie zwraca wiersza
    expect((await get("/v1/me", await token(acme, { org_id: globex.id }))).statusCode).toBe(401);
  });

  it("odcina konto po dezaktywacji, nawet z ważnym tokenem", async () => {
    const bearer = await token(globex);
    expect((await get("/v1/me", bearer)).statusCode).toBe(200);
    await withOrganization(db, globex.id, (tx) =>
      tx.account.update({ where: { id: globex.accountId }, data: { status: "DEACTIVATED" } }),
    );
    const response = await get("/v1/me", bearer);
    expect(response.statusCode).toBe(401);
    expect(response.json().error.code).toBe("ACCOUNT_DEACTIVATED");
  });
});
