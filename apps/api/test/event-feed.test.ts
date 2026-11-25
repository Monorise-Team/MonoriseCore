import { DIRECTORY_READ_SCOPE, EVENTS_READ_SCOPE, ProductEvent } from "@core/contracts";
import { createDb, uuidv7, withOrganization } from "@core/db";
import { coreEvents } from "@monorise-team/events";
import { createLocalJWKSet, exportJWK, generateKeyPair, SignJWT, type CryptoKey } from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { endEntitlement, grantEntitlement } from "../src/entitlements.js";
import { publishAllPendingEvents, publishPendingEvents } from "../src/event-feed.js";
import { buildPermissionsChangedRecord, emitPermissionsChanged } from "../src/outbox.js";
import { buildServer } from "../src/server.js";
import { createMachineTokenVerifier, createTokenVerifier } from "../src/tokens.js";

const ISSUER = "http://localhost:3100";
const AUDIENCE = "http://localhost:3200";

const db = createDb(
  process.env.CORE_TEST_APP_DATABASE_URL ?? "postgresql://core_app:core_app@localhost:5433/monorise_core_test",
);

interface Company {
  id: string;
  accountId: string;
  employeeId: string;
}

let signingKey: CryptoKey;
let app: ReturnType<typeof buildServer>;
let acme: Company;
let globex: Company;

const suffix = uuidv7()
  .slice(-6)
  .replace(/[^a-z0-9]/g, "a");
const productKey = `feed${suffix}`;
const otherProductKey = `other${suffix}`;
const clientId = `${productKey}-web`;
const otherClientId = `${otherProductKey}-web`;

async function createCompany(name: string): Promise<Company> {
  const id = uuidv7();
  const employeeId = uuidv7();
  const accountId = uuidv7();
  const email = `anna@${id.slice(-8)}-${name.toLowerCase()}.test`;
  await db.authUser.create({ data: { id: accountId, name: `Anna ${name}`, email, emailVerified: true } });
  await withOrganization(db, id, async (tx) => {
    await tx.organization.create({ data: { id, name, createdVia: "SELF_SIGNUP", status: "ACTIVE" } });
    await tx.employee.create({ data: { id: employeeId, organizationId: id, firstName: "Anna", lastName: name } });
    await tx.account.create({
      data: { id: accountId, organizationId: id, employeeId, email, normalizedEmail: email, status: "ACTIVE" },
    });
    await tx.organization.update({ where: { id }, data: { ownerAccountId: accountId } });
  });
  return { id, accountId, employeeId };
}

function machineToken(client: string, scope = EVENTS_READ_SCOPE) {
  return new SignJWT({ client_id: client, azp: client, scope })
    .setProtectedHeader({ alg: "EdDSA" })
    .setIssuer(ISSUER)
    .setAudience(AUDIENCE)
    .setSubject(client)
    .setIssuedAt()
    .setExpirationTime("5m")
    .sign(signingKey);
}

function userToken(company: Company) {
  return new SignJWT({ org_id: company.id, employee_id: company.employeeId, authz_rev: 0, amr: ["pwd"] })
    .setProtectedHeader({ alg: "EdDSA" })
    .setIssuer(ISSUER)
    .setAudience(AUDIENCE)
    .setSubject(company.accountId)
    .setIssuedAt()
    .setExpirationTime("5m")
    .sign(signingKey);
}

async function feed(query = "", bearer?: string, product = productKey) {
  const response = await app.inject({
    method: "GET",
    url: `/core/v1/products/${product}/events${query}`,
    headers: { authorization: `Bearer ${bearer ?? (await machineToken(clientId))}` },
  });
  return response;
}

async function feedItems(query = ""): Promise<{ items: ProductEvent[]; nextCursor: string | null }> {
  const response = await feed(query);
  expect(response.statusCode).toBe(200);
  const body = response.json();
  return { items: body.data.map((item: unknown) => ProductEvent.parse(item)), nextCursor: body.meta.nextCursor };
}

/** Zdarzenie zmiany uprawnień konta zapisane w outboxie firmy (jak przy zmianie roli). */
async function emitFor(company: Company, authzRevision: number, occurredAt?: Date) {
  await withOrganization(db, company.id, async (tx) => {
    if (occurredAt) {
      await tx.outboxEvent.create({
        data: {
          ...buildPermissionsChangedRecord({ organizationId: company.id, accountId: company.accountId, authzRevision }),
          occurredAt,
        },
      });
    } else {
      await emitPermissionsChanged(tx, { organizationId: company.id, accountId: company.accountId, authzRevision });
    }
  });
}

beforeAll(async () => {
  const pair = await generateKeyPair("EdDSA", { crv: "Ed25519" });
  signingKey = pair.privateKey;
  const jwk = { ...(await exportJWK(pair.publicKey)), alg: "EdDSA", kid: "test-feed" };
  const tokenOptions = { keys: createLocalJWKSet({ keys: [jwk] }), issuer: ISSUER, audience: AUDIENCE };
  app = buildServer({
    db,
    verifyToken: createTokenVerifier(tokenOptions),
    verifyMachineToken: createMachineTokenVerifier(tokenOptions),
    authUrl: ISSUER,
  });

  await db.product.create({
    data: { id: uuidv7(), key: productKey, name: "Produkt kanału", registrationClientId: clientId },
  });
  await db.product.create({
    data: { id: uuidv7(), key: otherProductKey, name: "Inny produkt", registrationClientId: otherClientId },
  });
  acme = await createCompany("Acme");
  globex = await createCompany("Globex");
  // Acme ma produkt, Globex nie ma
  await grantEntitlement(db, { organization: acme.id, product: productKey });
  // Wcześniejsze zdarzenia innych testów i firm nie przeszkadzają: kanał zaczynamy od bieżącego stanu
  await publishAllPendingEvents(db);
});

afterAll(async () => {
  await app?.close();
  for (const company of [acme, globex]) {
    if (!company) continue;
    await withOrganization(db, company.id, (tx) => tx.organization.delete({ where: { id: company.id } }));
    await db.authUser.deleteMany({ where: { id: company.accountId } });
  }
  await db.$disconnect();
});

describe("Kanał zdarzeń dla produktów (MonoriseCore#53)", () => {
  it("daje zdarzeniu numer dopiero przy wysyłce i pokazuje tylko firmy z dostępem do produktu", async () => {
    const start = await feedItems();
    const before = start.items.at(-1)?.sequence ?? "0";

    await emitFor(acme, 101);
    await emitFor(globex, 201);

    // Przed wysyłką zdarzenie nie ma numeru, więc nie ma go w kanale
    expect((await feedItems(`?cursor=${before}`)).items).toEqual([]);

    expect(await publishAllPendingEvents(db)).toBeGreaterThanOrEqual(2);

    const { items, nextCursor } = await feedItems(`?cursor=${before}`);
    expect(items).toHaveLength(1);
    expect(nextCursor).toBeNull();
    const [event] = items;
    expect(event).toMatchObject({
      type: "organization.permissions.changed",
      version: 1,
      source: "core",
      organizationId: acme.id,
      resourceType: "account",
      resourceId: acme.accountId,
      resourceVersion: 101,
      data: { authzRevision: 101 },
    });
    expect(BigInt(event!.sequence)).toBeGreaterThan(BigInt(before));

    // Koperta (bez numeru) przechodzi katalog zdarzeń produktu z @monorise-team/events
    const { sequence: _sequence, ...envelope } = event!;
    expect(coreEvents.parse(envelope)).toMatchObject({ status: "known" });
  });

  it("stronicuje po numerze i zwraca nextCursor tylko przy pełnej stronie", async () => {
    const start = (await feedItems()).items.at(-1)?.sequence ?? "0";
    await emitFor(acme, 102);
    await emitFor(acme, 103);
    await emitFor(acme, 104);
    await publishAllPendingEvents(db);

    const first = await feedItems(`?cursor=${start}&limit=2`);
    expect(first.items.map((item) => item.resourceVersion)).toEqual([102, 103]);
    expect(first.nextCursor).toBe(first.items[1]!.sequence);

    const second = await feedItems(`?cursor=${first.nextCursor}&limit=2`);
    expect(second.items.map((item) => item.resourceVersion)).toEqual([104]);
    expect(second.nextCursor).toBeNull();

    const sequences = [...first.items, ...second.items].map((item) => BigInt(item.sequence));
    expect(sequences).toEqual([...sequences].sort((a, b) => (a < b ? -1 : 1)));
  });

  it("nie gubi zdarzenia zapisanego później ze starszą datą (numer nadaje wysyłka, nie zapis)", async () => {
    const last = (await feedItems()).items.at(-1)!.sequence;
    // Jak transakcja, która zaczęła się dawno, ale zatwierdziła się po poprzedniej wysyłce
    await emitFor(acme, 105, new Date(Date.now() - 60 * 60 * 1000));
    await publishAllPendingEvents(db);

    const { items } = await feedItems(`?cursor=${last}`);
    expect(items.map((item) => item.resourceVersion)).toEqual([105]);
  });

  it("równoległe wysyłki nadają każdemu zdarzeniu jeden, różny numer", async () => {
    const last = (await feedItems()).items.at(-1)!.sequence;
    for (let revision = 110; revision < 130; revision += 1) await emitFor(acme, revision);

    await Promise.all(Array.from({ length: 5 }, () => publishPendingEvents(db, 7)));
    await publishAllPendingEvents(db);

    const { items } = await feedItems(`?cursor=${last}&limit=100`);
    expect(items.map((item) => item.resourceVersion).sort((a, b) => a - b)).toEqual(
      Array.from({ length: 20 }, (_, index) => 110 + index),
    );
    expect(new Set(items.map((item) => item.sequence)).size).toBe(20);
  });

  it("odmawia bez zakresu core:events.read, cudzemu klientowi, tokenowi osoby i przy złym kursorze", async () => {
    expect((await feed("", await machineToken(clientId, DIRECTORY_READ_SCOPE))).statusCode).toBe(403);
    expect((await feed("", await machineToken(otherClientId))).statusCode).toBe(403);
    expect((await feed("", await userToken(acme))).statusCode).toBe(401);
    expect((await feed("", await machineToken(clientId), `brak${suffix}`)).statusCode).toBe(404);
    expect((await feed("?cursor=01")).statusCode).toBe(422);
    expect((await feed("?cursor=-1")).statusCode).toBe(422);
    expect((await feed("?limit=501")).statusCode).toBe(422);
  });

  it("po zakończeniu umowy produkt nie widzi już zdarzeń tej firmy", async () => {
    await endEntitlement(db, { organization: acme.id, product: productKey });
    await publishAllPendingEvents(db);
    expect((await feedItems()).items.filter((item) => item.organizationId === acme.id)).toEqual([]);
  });
});
