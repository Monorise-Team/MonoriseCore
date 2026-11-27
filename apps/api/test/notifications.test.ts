import {
  DIRECTORY_READ_SCOPE,
  IDEMPOTENCY_KEY_HEADER,
  IDEMPOTENCY_REPLAYED_HEADER,
  NOTIFICATIONS_SEND_SCOPE,
} from "@core/contracts";
import { createDb, uuidv7, withOrganization } from "@core/db";
import { createLocalJWKSet, exportJWK, generateKeyPair, SignJWT, type CryptoKey } from "jose";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { grantEntitlement } from "../src/entitlements.js";
import { clearSentMails, clearSentNotificationMails, type OutgoingMail } from "../src/mail.js";
import { deliverPendingMail, MAIL_MAX_ATTEMPTS } from "../src/mail-outbox.js";
import { createUnsubscribeToken, UNSUBSCRIBE_HTML_HEADERS } from "../src/notifications.js";
import { registerCorePermissions } from "../src/permissions-registry.js";
import { buildServer } from "../src/server.js";
import { createMachineTokenVerifier, createTokenVerifier } from "../src/tokens.js";

const ISSUER = "http://localhost:3100";
const AUDIENCE = "http://localhost:3200";
const API_URL = "https://api.monorise.test";
const UNSUBSCRIBE_SECRET = "test-notifications-unsubscribe-secret-0123456789";

const TIMOTIME_CLIENT_ID = "timotime-web";
const TIMOTIME_URI = "http://timo-time.localhost:3300/app";
const KIVOTASKS_CLIENT_ID = "kivotasks-web";
const KIVOTASKS_URI = "http://kivotasks.localhost:3500/";

const appUrl =
  process.env.CORE_TEST_APP_DATABASE_URL ?? "postgresql://core_app:core_app@localhost:5433/monorise_core_test";
const ownerUrl =
  process.env.CORE_TEST_DATABASE_URL ?? "postgresql://core_owner:core_owner@localhost:5433/monorise_core_test";
const db = createDb(appUrl);
const ownerDb = createDb(ownerUrl);

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

let signingKey: CryptoKey;
let app: ReturnType<typeof buildServer>;
let acme: Company;
let globex: Company;
let acmeMember: Identity;
let acmeNoAccess: Identity;
let acmeDeactivated: Identity;
let acmeFormer: Identity;
let timotimeProductId: string;
let timotimeClientId = TIMOTIME_CLIENT_ID;
let timotimeOrigin = new URL(TIMOTIME_URI).origin;
let kivotasksClientId = KIVOTASKS_CLIENT_ID;

const createdProductIds: string[] = [];
const createdOAuthClientIds: string[] = [];

async function ensureProductAndClient(
  key: string,
  name: string,
  defaultClientId: string,
  defaultUri: string,
): Promise<{ productId: string; clientId: string; origin: string }> {
  let product = await ownerDb.product.findUnique({ where: { key } });
  let clientId = product?.registrationClientId ?? defaultClientId;

  if (!product) {
    const id = uuidv7();
    product = await ownerDb.product.create({
      data: { id, key, name, registrationClientId: clientId },
    });
    createdProductIds.push(id);
  } else if (!product.registrationClientId) {
    product = await ownerDb.product.update({
      where: { id: product.id },
      data: { registrationClientId: clientId },
    });
  }

  let client = await ownerDb.authOAuthClient.findUnique({ where: { clientId } });
  if (!client) {
    client = await ownerDb.authOAuthClient.create({
      data: {
        id: uuidv7(),
        clientId,
        name,
        uri: defaultUri,
        redirectUris: [`${new URL(defaultUri).origin}/api/auth/callback`],
        grantTypes: ["authorization_code", "refresh_token", "client_credentials"],
        clientCredentialsScopes: [NOTIFICATIONS_SEND_SCOPE],
      },
    });
    createdOAuthClientIds.push(clientId);
  } else if (!client.uri) {
    client = await ownerDb.authOAuthClient.update({ where: { clientId }, data: { uri: defaultUri } });
  }

  const effectiveUri = client.uri ?? defaultUri;
  clientId = client.clientId;
  return { productId: product.id, clientId, origin: new URL(effectiveUri).origin };
}

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
        verifiedAt: new Date("2026-01-01T00:00:00.000Z"),
        isPrimary: true,
      },
    });
    await tx.employee.create({ data: { id: employeeId, organizationId: id, firstName: "Anna", lastName: name } });
    await tx.account.create({
      data: { id: accountId, organizationId: id, employeeId, email, normalizedEmail: email, status: "ACTIVE" },
    });
    await tx.organization.update({ where: { id }, data: { ownerAccountId: accountId } });
  });

  return { id, organizationId: id, domain, employeeId, accountId, email, extraAccountIds: [] };
}

async function createMember(
  company: Company,
  firstName: string,
  lastName: string,
  options: { accountStatus?: "ACTIVE" | "DEACTIVATED"; employeeStatus?: "ACTIVE" | "FORMER" } = {},
): Promise<Identity> {
  const employeeId = uuidv7();
  const accountId = uuidv7();
  const email = `${firstName.toLowerCase()}-${accountId.slice(-6)}@${company.domain}`;

  await db.authUser.create({ data: { id: accountId, name: `${firstName} ${lastName}`, email, emailVerified: true } });
  await withOrganization(db, company.id, async (tx) => {
    await tx.employee.create({
      data: {
        id: employeeId,
        organizationId: company.id,
        firstName,
        lastName,
        status: options.employeeStatus ?? "ACTIVE",
      },
    });
    await tx.account.create({
      data: {
        id: accountId,
        organizationId: company.id,
        employeeId,
        email,
        normalizedEmail: email,
        status: options.accountStatus ?? "ACTIVE",
      },
    });
  });

  company.extraAccountIds.push(accountId);
  return { organizationId: company.id, employeeId, accountId, email };
}

function userToken(identity: Identity) {
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

function machineToken(clientId: string, scope = NOTIFICATIONS_SEND_SCOPE) {
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

async function makeJobDueNow(orgId: string, jobId: string): Promise<void> {
  await withOrganization(
    ownerDb,
    orgId,
    (tx) =>
      tx.$executeRaw`
      UPDATE "public"."mail_outbox"
      SET "nextAttemptAt" = now() - interval '1 second',
          "lockedUntil" = NULL
      WHERE "id" = ${jobId}::uuid`,
  );
}

beforeAll(async () => {
  process.env.CORE_SMTP_URL = "memory";
  process.env.CORE_NOTIFICATIONS_SMTP_URL = "memory";
  await registerCorePermissions(db);

  const timotime = await ensureProductAndClient("timotime", "TimoTime", TIMOTIME_CLIENT_ID, TIMOTIME_URI);
  timotimeProductId = timotime.productId;
  timotimeClientId = timotime.clientId;
  timotimeOrigin = timotime.origin;
  const kivotasks = await ensureProductAndClient("kivotasks", "KivoTasks", KIVOTASKS_CLIENT_ID, KIVOTASKS_URI);
  kivotasksClientId = kivotasks.clientId;

  const pair = await generateKeyPair("EdDSA", { crv: "Ed25519" });
  signingKey = pair.privateKey;
  const jwk = { ...(await exportJWK(pair.publicKey)), alg: "EdDSA", kid: "test-notifications" };
  const tokenOptions = { keys: createLocalJWKSet({ keys: [jwk] }), issuer: ISSUER, audience: AUDIENCE };

  app = buildServer({
    db,
    verifyToken: createTokenVerifier(tokenOptions),
    verifyMachineToken: createMachineTokenVerifier(tokenOptions),
    notificationsUnsubscribeSecret: UNSUBSCRIBE_SECRET,
  });

  acme = await createCompany("Acme");
  globex = await createCompany("Globex");
  acmeMember = await createMember(acme, "Jan", "Kowalski");
  acmeNoAccess = await createMember(acme, "Marek", "BezDostepu");
  acmeDeactivated = await createMember(acme, "Ewa", "Wylaczona", { accountStatus: "DEACTIVATED" });
  acmeFormer = await createMember(acme, "Piotr", "Byly", { employeeStatus: "FORMER" });

  // Acme ma Entitlement dla timotime (brak dla kivotasks); Globex nie ma żadnych Entitlements
  await grantEntitlement(db, { organization: acme.id, product: "timotime" });

  // Jan ma AppAccess do timotime; Marek nie ma; Ewa i Piotr mają AppAccess ale są nieaktywni
  await withOrganization(db, acme.id, async (tx) => {
    for (const acc of [acmeMember, acmeDeactivated, acmeFormer]) {
      await tx.appAccess.create({
        data: {
          id: uuidv7(),
          organizationId: acme.id,
          accountId: acc.accountId,
          productId: timotimeProductId,
          status: "ACTIVE",
          grantedByAccountId: acme.accountId,
        },
      });
    }
  });
});

beforeEach(async () => {
  clearSentMails();
  clearSentNotificationMails();
  for (const company of [acme, globex]) {
    await withOrganization(ownerDb, company.id, async (tx) => {
      await tx.mailOutbox.deleteMany({});
      await tx.notification.deleteMany({});
      await tx.notificationPreference.deleteMany({});
      await tx.idempotencyKey.deleteMany({});
    });
  }
});

afterAll(async () => {
  await app?.close();
  for (const company of [acme, globex]) {
    if (!company) continue;
    const allAccounts = await withOrganization(db, company.id, (tx) => tx.account.findMany({ select: { id: true } }));
    const ids = [...new Set([company.accountId, ...company.extraAccountIds, ...allAccounts.map((a) => a.id)])];
    await withOrganization(ownerDb, company.id, async (tx) => {
      await tx.mailOutbox.deleteMany({});
      await tx.notification.deleteMany({});
      await tx.notificationPreference.deleteMany({});
      await tx.roleAssignment.deleteMany({});
      await tx.organization.delete({ where: { id: company.id } });
    });
    await db.authUser.deleteMany({ where: { id: { in: ids } } });
  }
  if (createdProductIds.length > 0) {
    await ownerDb.product.deleteMany({ where: { id: { in: createdProductIds } } });
  }
  if (createdOAuthClientIds.length > 0) {
    await ownerDb.authOAuthClient.deleteMany({ where: { clientId: { in: createdOAuthClientIds } } });
  }
  await db.$disconnect();
  await ownerDb.$disconnect();
});

describe("Moduł powiadomień Core (MonoriseCore#86, ADR-0048)", () => {
  it("przyjmuje powiadomienie produktu, kolejkuje w mail_outbox i dostarcza przez kanał powiadomień z nagłówkami RFC 8058 i escape HTML", async () => {
    const token = await machineToken(timotimeClientId);
    const validActionUrl = `${timotimeOrigin}/app/timesheets?week=48`;
    const res = await app.inject({
      method: "POST",
      url: `/core/v1/organizations/${acme.id}/notifications`,
      headers: { authorization: `Bearer ${token}` },
      payload: {
        recipientAccountId: acmeMember.accountId,
        category: "timotime.reminders",
        title: `Uzupełnij czas pracy <script>alert("x")</script>`,
        body: "Brakuje wpisu za piątek.\nSprawdź <b>grafik</b> w TimoTime.",
        actionUrl: validActionUrl,
      },
    });

    expect(res.statusCode).toBe(202);
    const body = res.json().data as { id: string; status: string; skipReason: string | null };
    expect(body).toEqual({ id: expect.any(String), status: "QUEUED", skipReason: null });

    const delivered: OutgoingMail[] = [];
    const summary = await deliverPendingMail(db, {
      apiUrl: API_URL,
      notificationsUnsubscribeSecret: UNSUBSCRIBE_SECRET,
      notificationsMailer: async (mail) => {
        delivered.push(mail);
      },
    });
    expect(summary).toEqual({ claimed: 1, sent: 1, retried: 0, failed: 0, cancelled: 0, skipped: 0 });
    expect(delivered).toHaveLength(1);

    const mail = delivered[0]!;
    expect(mail.to).toBe(acmeMember.email);
    expect(mail.subject).toContain("TimoTime");
    expect(mail.headers?.["List-Unsubscribe-Post"]).toBe("List-Unsubscribe=One-Click");
    expect(mail.headers?.["List-Unsubscribe"]).toMatch(
      /^<https:\/\/api\.monorise\.test\/core\/v1\/notifications\/unsubscribe\/[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+>$/,
    );
    expect(mail.html).not.toContain("<script>");
    expect(mail.html).not.toContain("<b>grafik</b>");
    expect(mail.html).toContain("&lt;script&gt;");
    expect(mail.html).toContain(validActionUrl);

    const [notificationRow, outboxRow] = await withOrganization(db, acme.id, (tx) =>
      Promise.all([
        tx.notification.findUniqueOrThrow({ where: { id: body.id } }),
        tx.mailOutbox.findFirstOrThrow({ where: { notificationId: body.id } }),
      ]),
    );
    expect(notificationRow.status).toBe("SENT");
    expect(notificationRow.sentAt).not.toBeNull();
    expect(notificationRow.skipReason).toBeNull();
    expect(outboxRow.status).toBe("SENT");
    expect(outboxRow.sentAt).not.toBeNull();

    // Owner ma domyślny dostęp do produktu firmy bez wpisu AppAccess
    const ownerRes = await app.inject({
      method: "POST",
      url: `/core/v1/organizations/${acme.id}/notifications`,
      headers: { authorization: `Bearer ${token}` },
      payload: {
        recipientAccountId: acme.accountId,
        category: "timotime.reminders",
        title: "Przypomnienie dla Ownera",
        body: "Treść dla Ownera.",
      },
    });
    expect(ownerRes.statusCode).toBe(202);
    expect(ownerRes.json().data.status).toBe("QUEUED");
  });

  it("pomija powiadomienie (PREFERENCE_OFF) gdy kategoria jest wyłączona przed zleceniem oraz gdy wyłączona między zleceniem a wysyłką", async () => {
    const memberBearer = await userToken(acmeMember);
    const timoToken = await machineToken(timotimeClientId);

    // 1. Wyłączenie kategorii przed zleceniem -> 202 SKIPPED/PREFERENCE_OFF bez mail_outbox
    const putOff = await app.inject({
      method: "PUT",
      url: "/core/v1/me/notification-preferences/timotime.reminders",
      headers: { authorization: `Bearer ${memberBearer}` },
      payload: { enabled: false },
    });
    expect(putOff.statusCode).toBe(200);

    const skippedBefore = await app.inject({
      method: "POST",
      url: `/core/v1/organizations/${acme.id}/notifications`,
      headers: { authorization: `Bearer ${timoToken}` },
      payload: {
        recipientAccountId: acmeMember.accountId,
        category: "timotime.reminders",
        title: "Nie wyjdzie",
        body: "Preferencja jest wyłączona.",
      },
    });
    expect(skippedBefore.statusCode).toBe(202);
    expect(skippedBefore.json().data).toMatchObject({ status: "SKIPPED", skipReason: "PREFERENCE_OFF" });
    const outboxBefore = await withOrganization(db, acme.id, (tx) =>
      tx.mailOutbox.findMany({ where: { notificationId: skippedBefore.json().data.id as string } }),
    );
    expect(outboxBefore).toHaveLength(0);

    // 2. Włączamy ponownie, zlecamy powiadomienie (QUEUED), a potem wyłączamy PRZED uruchomieniem workera
    await app.inject({
      method: "PUT",
      url: "/core/v1/me/notification-preferences/timotime.reminders",
      headers: { authorization: `Bearer ${memberBearer}` },
      payload: { enabled: true },
    });

    const queuedRes = await app.inject({
      method: "POST",
      url: `/core/v1/organizations/${acme.id}/notifications`,
      headers: { authorization: `Bearer ${timoToken}` },
      payload: {
        recipientAccountId: acmeMember.accountId,
        category: "timotime.reminders",
        title: "Wyłączone przed wysyłką",
        body: "Treść.",
      },
    });
    expect(queuedRes.statusCode).toBe(202);
    const queuedId = queuedRes.json().data.id as string;

    await app.inject({
      method: "PUT",
      url: "/core/v1/me/notification-preferences/timotime.reminders",
      headers: { authorization: `Bearer ${memberBearer}` },
      payload: { enabled: false },
    });

    const delivered: OutgoingMail[] = [];
    const summary = await deliverPendingMail(db, {
      apiUrl: API_URL,
      notificationsUnsubscribeSecret: UNSUBSCRIBE_SECRET,
      notificationsMailer: async (mail) => {
        delivered.push(mail);
      },
    });
    expect(summary).toEqual({ claimed: 1, sent: 0, retried: 0, failed: 0, cancelled: 1, skipped: 0 });
    expect(delivered).toHaveLength(0);

    const [notifAfter, outboxAfter] = await withOrganization(db, acme.id, (tx) =>
      Promise.all([
        tx.notification.findUniqueOrThrow({ where: { id: queuedId } }),
        tx.mailOutbox.findFirstOrThrow({ where: { notificationId: queuedId } }),
      ]),
    );
    expect(notifAfter.status).toBe("SKIPPED");
    expect(notifAfter.skipReason).toBe("PREFERENCE_OFF");
    expect(notifAfter.sentAt).toBeNull();
    expect(outboxAfter.status).toBe("CANCELLED");
  });

  it("odrzuca cudzą kategorię, kategorie logowania, brak zakresu, brak Entitlement, obcy actionUrl i nieistniejącą firmę", async () => {
    const timoToken = await machineToken(timotimeClientId);
    const kivoToken = await machineToken(kivotasksClientId);
    const wrongScopeToken = await machineToken(timotimeClientId, DIRECTORY_READ_SCOPE);
    const memberBearer = await userToken(acmeMember);

    // Token użytkownika zamiast maszynowego -> 401
    const userAsMachine = await app.inject({
      method: "POST",
      url: `/core/v1/organizations/${acme.id}/notifications`,
      headers: { authorization: `Bearer ${memberBearer}` },
      payload: {
        recipientAccountId: acmeMember.accountId,
        category: "timotime.reminders",
        title: "Tytuł",
        body: "Treść",
      },
    });
    expect(userAsMachine.statusCode).toBe(401);

    // Brak wymaganego zakresu -> 403
    const badScope = await app.inject({
      method: "POST",
      url: `/core/v1/organizations/${acme.id}/notifications`,
      headers: { authorization: `Bearer ${wrongScopeToken}` },
      payload: {
        recipientAccountId: acmeMember.accountId,
        category: "timotime.reminders",
        title: "Tytuł",
        body: "Treść",
      },
    });
    expect(badScope.statusCode).toBe(403);

    // Kategoria innego produktu i kategorie kanału logowania -> 403 PERMISSION_DENIED
    for (const category of ["kivotasks.assignments", "security", "account"]) {
      const res = await app.inject({
        method: "POST",
        url: `/core/v1/organizations/${acme.id}/notifications`,
        headers: { authorization: `Bearer ${timoToken}` },
        payload: {
          recipientAccountId: acmeMember.accountId,
          category,
          title: "Tytuł",
          body: "Treść",
        },
      });
      expect(res.statusCode).toBe(403);
      expect(res.json().error.code).toBe("PERMISSION_DENIED");
    }

    // Firma bez Entitlement do kivotasks -> 403; Globex bez Entitlement do timotime -> 403
    const noKivoEnt = await app.inject({
      method: "POST",
      url: `/core/v1/organizations/${acme.id}/notifications`,
      headers: { authorization: `Bearer ${kivoToken}` },
      payload: {
        recipientAccountId: acmeMember.accountId,
        category: "kivotasks.assignments",
        title: "Zadanie",
        body: "Treść",
      },
    });
    expect(noKivoEnt.statusCode).toBe(403);

    const globexNoEnt = await app.inject({
      method: "POST",
      url: `/core/v1/organizations/${globex.id}/notifications`,
      headers: { authorization: `Bearer ${timoToken}` },
      payload: {
        recipientAccountId: globex.accountId,
        category: "timotime.reminders",
        title: "Przypomnienie",
        body: "Treść",
      },
    });
    expect(globexNoEnt.statusCode).toBe(403);

    // Nieistniejąca firma -> 404
    const missingOrg = await app.inject({
      method: "POST",
      url: `/core/v1/organizations/${uuidv7()}/notifications`,
      headers: { authorization: `Bearer ${timoToken}` },
      payload: {
        recipientAccountId: acmeMember.accountId,
        category: "timotime.reminders",
        title: "Przypomnienie",
        body: "Treść",
      },
    });
    expect(missingOrg.statusCode).toBe(404);
    expect(missingOrg.json().error.code).toBe("NOT_FOUND");

    // Obcy actionUrl -> 422 VALIDATION_FAILED
    const foreignAction = await app.inject({
      method: "POST",
      url: `/core/v1/organizations/${acme.id}/notifications`,
      headers: { authorization: `Bearer ${timoToken}` },
      payload: {
        recipientAccountId: acmeMember.accountId,
        category: "timotime.reminders",
        title: "Przypomnienie",
        body: "Treść",
        actionUrl: "https://phishing.test/login",
      },
    });
    expect(foreignAction.statusCode).toBe(422);
    expect(foreignAction.json().error.code).toBe("VALIDATION_FAILED");
  });

  it("zwraca 202 SKIPPED/NO_ACCESS bez zdradzania szczegółów dla braku AppAccess, konta DEACTIVATED, pracownika FORMER i konta innej firmy", async () => {
    const timoToken = await machineToken(timotimeClientId);

    for (const recipientAccountId of [
      acmeNoAccess.accountId,
      acmeDeactivated.accountId,
      acmeFormer.accountId,
      globex.accountId,
      uuidv7(),
    ]) {
      const res = await app.inject({
        method: "POST",
        url: `/core/v1/organizations/${acme.id}/notifications`,
        headers: { authorization: `Bearer ${timoToken}` },
        payload: {
          recipientAccountId,
          category: "timotime.reminders",
          title: "Przypomnienie",
          body: "Treść",
        },
      });
      expect(res.statusCode).toBe(202);
      expect(res.json().data).toEqual({
        id: expect.any(String),
        status: "SKIPPED",
        skipReason: "NO_ACCESS",
      });
    }

    const outboxRows = await withOrganization(db, acme.id, (tx) => tx.mailOutbox.findMany());
    expect(outboxRows).toHaveLength(0);
  });

  it("obsługuje Idempotency-Key bez duplikowania powiadomienia ani zadania w mail_outbox i zwraca 409 przy innej treści", async () => {
    const timoToken = await machineToken(timotimeClientId);
    const key = `notif-idem-${uuidv7()}`;
    const payload = {
      recipientAccountId: acmeMember.accountId,
      category: "timotime.reminders",
      title: "Powtarzalne przypomnienie",
      body: "Treść przypomnienia.",
    };

    const first = await app.inject({
      method: "POST",
      url: `/core/v1/organizations/${acme.id}/notifications`,
      headers: { authorization: `Bearer ${timoToken}`, [IDEMPOTENCY_KEY_HEADER]: key },
      payload,
    });
    expect(first.statusCode).toBe(202);
    expect(first.headers[IDEMPOTENCY_REPLAYED_HEADER.toLowerCase()]).toBeUndefined();

    const replay = await app.inject({
      method: "POST",
      url: `/core/v1/organizations/${acme.id}/notifications`,
      headers: { authorization: `Bearer ${timoToken}`, [IDEMPOTENCY_KEY_HEADER]: key },
      payload: {
        body: payload.body,
        title: payload.title,
        category: payload.category,
        recipientAccountId: payload.recipientAccountId,
      },
    });
    expect(replay.statusCode).toBe(202);
    expect(replay.headers[IDEMPOTENCY_REPLAYED_HEADER.toLowerCase()]).toBe("true");
    expect(replay.json()).toEqual(first.json());

    const conflict = await app.inject({
      method: "POST",
      url: `/core/v1/organizations/${acme.id}/notifications`,
      headers: { authorization: `Bearer ${timoToken}`, [IDEMPOTENCY_KEY_HEADER]: key },
      payload: { ...payload, title: "Zmieniony tytuł" },
    });
    expect(conflict.statusCode).toBe(409);
    expect(conflict.json().error.code).toBe("CONFLICT");

    const [notifs, jobs] = await withOrganization(db, acme.id, (tx) =>
      Promise.all([tx.notification.findMany(), tx.mailOutbox.findMany()]),
    );
    expect(notifs).toHaveLength(1);
    expect(jobs).toHaveLength(1);
  });

  it("obsługuje GET/PUT /me/notification-preferences (w tym 422 dla security i audyt) oraz jednoklikowe wypisanie RFC 8058", async () => {
    const memberBearer = await userToken(acmeMember);
    const globexBearer = await userToken(globex);
    const timoToken = await machineToken(timotimeClientId);

    // 1. Acme ma tylko timotime -> GET zwraca security, account (always on, optional: false) i timotime.reminders (enabled: true)
    const acmeList = await app.inject({
      method: "GET",
      url: "/core/v1/me/notification-preferences",
      headers: { authorization: `Bearer ${memberBearer}` },
    });
    expect(acmeList.statusCode).toBe(200);
    expect(
      acmeList.json().data.map((p: { category: string; enabled: boolean; optional: boolean }) => ({
        category: p.category,
        enabled: p.enabled,
        optional: p.optional,
      })),
    ).toEqual([
      { category: "security", enabled: true, optional: false },
      { category: "account", enabled: true, optional: false },
      { category: "timotime.reminders", enabled: true, optional: true },
    ]);

    // Globex bez produktów widzi wyłącznie kategorie kanału logowania
    const globexList = await app.inject({
      method: "GET",
      url: "/core/v1/me/notification-preferences",
      headers: { authorization: `Bearer ${globexBearer}` },
    });
    expect(globexList.statusCode).toBe(200);
    expect(globexList.json().data.map((p: { category: string }) => p.category)).toEqual(["security", "account"]);

    // 2. PUT dla security, account oraz nieznanej kategorii -> 422
    for (const bad of ["security", "account", "nonexistent.cat"]) {
      const res = await app.inject({
        method: "PUT",
        url: `/core/v1/me/notification-preferences/${bad}`,
        headers: { authorization: `Bearer ${memberBearer}` },
        payload: { enabled: false },
      });
      expect(res.statusCode).toBe(422);
      expect(res.json().error.code).toBe("VALIDATION_FAILED");
    }

    // 3. PUT dla timotime.reminders zapisuje preferencję i wpis audytu notification.preference_changed
    const putOff = await app.inject({
      method: "PUT",
      url: "/core/v1/me/notification-preferences/timotime.reminders",
      headers: { authorization: `Bearer ${memberBearer}` },
      payload: { enabled: false },
    });
    expect(putOff.statusCode).toBe(200);
    expect(putOff.json().data).toMatchObject({ category: "timotime.reminders", enabled: false });

    const putOn = await app.inject({
      method: "PUT",
      url: "/core/v1/me/notification-preferences/timotime.reminders",
      headers: { authorization: `Bearer ${memberBearer}` },
      payload: { enabled: true },
    });
    expect(putOn.statusCode).toBe(200);
    expect(putOn.json().data).toMatchObject({ category: "timotime.reminders", enabled: true });

    // 4. Wysyłamy powiadomienie, pobieramy prawdziwy link wypisania z List-Unsubscribe i wywołujemy POST bez logowania
    const sendRes = await app.inject({
      method: "POST",
      url: `/core/v1/organizations/${acme.id}/notifications`,
      headers: { authorization: `Bearer ${timoToken}` },
      payload: {
        recipientAccountId: acmeMember.accountId,
        category: "timotime.reminders",
        title: "Test linku wypisania",
        body: "Sprawdź nagłówek List-Unsubscribe.",
      },
    });
    expect(sendRes.statusCode).toBe(202);

    const delivered: OutgoingMail[] = [];
    await deliverPendingMail(db, {
      apiUrl: API_URL,
      notificationsUnsubscribeSecret: UNSUBSCRIBE_SECRET,
      notificationsMailer: async (mail) => {
        delivered.push(mail);
      },
    });
    expect(delivered).toHaveLength(1);
    const unsubHeader = delivered[0]!.headers?.["List-Unsubscribe"] ?? "";
    const match = /^<https:\/\/api\.monorise\.test(\/core\/v1\/notifications\/unsubscribe\/[^>]+)>$/.exec(unsubHeader);
    expect(match).not.toBeNull();

    const unsubRes = await app.inject({
      method: "POST",
      url: match![1]!,
      headers: { "content-type": "application/x-www-form-urlencoded" },
      payload: "List-Unsubscribe=One-Click",
    });
    expect(unsubRes.statusCode).toBe(200);
    expect(unsubRes.json().data).toEqual({ category: "timotime.reminders", enabled: false });

    // Zmanipulowany token oraz token konta z niewłaściwej firmy -> 404
    const tamperedRes = await app.inject({
      method: "POST",
      url: `${match![1]!}X`,
    });
    expect(tamperedRes.statusCode).toBe(404);
    expect(tamperedRes.json().error.code).toBe("NOT_FOUND");

    const wrongCompanyToken = createUnsubscribeToken(
      { organizationId: globex.id, accountId: acmeMember.accountId, category: "timotime.reminders" },
      UNSUBSCRIBE_SECRET,
    );
    const wrongCompanyRes = await app.inject({
      method: "POST",
      url: `/core/v1/notifications/unsubscribe/${wrongCompanyToken}`,
    });
    expect(wrongCompanyRes.statusCode).toBe(404);

    // Audyt zawiera wpisy notification.preference_changed z PUT i z linku wypisania
    const audits = await withOrganization(db, acme.id, (tx) =>
      tx.auditLog.findMany({
        where: { action: "notification.preference_changed", actorAccountId: acmeMember.accountId },
        orderBy: { createdAt: "asc" },
      }),
    );
    expect(audits.length).toBeGreaterThanOrEqual(3);
    expect(audits.at(-1)?.metadata).toMatchObject({
      category: "timotime.reminders",
      enabled: false,
      source: "unsubscribe_link",
    });
  });

  it("ponawia wysyłkę powiadomienia przy chwilowych błędach SMTP i oznacza FAILED po ostatniej (8.) próbie", async () => {
    const timoToken = await machineToken(timotimeClientId);
    const res = await app.inject({
      method: "POST",
      url: `/core/v1/organizations/${acme.id}/notifications`,
      headers: { authorization: `Bearer ${timoToken}` },
      payload: {
        recipientAccountId: acmeMember.accountId,
        category: "timotime.reminders",
        title: "Test ponowień",
        body: "Treść.",
      },
    });
    expect(res.statusCode).toBe(202);
    const notifId = res.json().data.id as string;
    const jobRow = await withOrganization(db, acme.id, (tx) =>
      tx.mailOutbox.findFirstOrThrow({ where: { notificationId: notifId } }),
    );

    for (let attempt = 1; attempt <= MAIL_MAX_ATTEMPTS; attempt += 1) {
      if (attempt > 1) {
        await makeJobDueNow(acme.id, jobRow.id);
      }
      const summary = await deliverPendingMail(db, {
        apiUrl: API_URL,
        notificationsUnsubscribeSecret: UNSUBSCRIBE_SECRET,
        notificationsMailer: async () => {
          throw new Error(`SMTP error attempt ${attempt}`);
        },
      });

      const [notif, job] = await withOrganization(db, acme.id, (tx) =>
        Promise.all([
          tx.notification.findUniqueOrThrow({ where: { id: notifId } }),
          tx.mailOutbox.findUniqueOrThrow({ where: { id: jobRow.id } }),
        ]),
      );

      if (attempt < MAIL_MAX_ATTEMPTS) {
        expect(summary.retried).toBe(1);
        expect(notif.status).toBe("QUEUED");
        expect(job.status).toBe("PENDING");
        expect(job.attempts).toBe(attempt);
      } else {
        expect(summary.failed).toBe(1);
        expect(notif.status).toBe("FAILED");
        expect(notif.sentAt).toBeNull();
        expect(job.status).toBe("FAILED");
        expect(job.failedAt).not.toBeNull();
        expect(job.attempts).toBe(MAIL_MAX_ATTEMPTS);
      }
    }
  });

  it("obsługuje stronę HTML GET wypisania bez zmiany stanu, POST HTML i multipart/form-data, wyścig kliknięć, audyt tylko przy zmianie i odrzuca konta nieaktywne", async () => {
    const memberBearer = await userToken(acmeMember);
    const validToken = createUnsubscribeToken(
      { organizationId: acme.id, accountId: acmeMember.accountId, category: "timotime.reminders" },
      UNSUBSCRIBE_SECRET,
    );
    const deactivatedToken = createUnsubscribeToken(
      { organizationId: acme.id, accountId: acmeDeactivated.accountId, category: "timotime.reminders" },
      UNSUBSCRIBE_SECRET,
    );

    const auditsBefore = await withOrganization(db, acme.id, (tx) =>
      tx.auditLog.count({ where: { action: "notification.preference_changed", actorAccountId: acmeMember.accountId } }),
    );

    // 1. GET zwraca polską stronę potwierdzenia HTML bez jakiejkolwiek zmiany w bazie
    const getRes = await app.inject({
      method: "GET",
      url: `/core/v1/notifications/unsubscribe/${validToken}`,
    });
    expect(getRes.statusCode).toBe(200);
    expect(getRes.headers["content-type"]).toBe(UNSUBSCRIBE_HTML_HEADERS["Content-Type"]);
    expect(getRes.headers["content-security-policy"]).toBe(UNSUBSCRIBE_HTML_HEADERS["Content-Security-Policy"]);
    expect(getRes.headers["x-content-type-options"]).toBe(UNSUBSCRIBE_HTML_HEADERS["X-Content-Type-Options"]);
    expect(getRes.headers["referrer-policy"]).toBe(UNSUBSCRIBE_HTML_HEADERS["Referrer-Policy"]);
    expect(getRes.headers["cache-control"]).toBe(UNSUBSCRIBE_HTML_HEADERS["Cache-Control"]);
    expect(getRes.body).toContain("Przypomnienia TimoTime");
    expect(getRes.body).toContain("Acme");
    expect(getRes.body).toContain("Wyłącz powiadomienia");
    expect(getRes.body).toContain('name="List-Unsubscribe" value="One-Click"');

    const prefsAfterGet = await withOrganization(db, acme.id, (tx) =>
      tx.notificationPreference.findMany({ where: { accountId: acmeMember.accountId } }),
    );
    expect(prefsAfterGet).toHaveLength(0);

    // 2. Dwa równoległe pierwsze kliknięcia POST (Accept: text/html) -> oba 200 HTML, brak 500, dokładnie 1 wiersz i 1 wpis audytu
    const [click1, click2] = await Promise.all([
      app.inject({
        method: "POST",
        url: `/core/v1/notifications/unsubscribe/${validToken}`,
        headers: {
          "content-type": "application/x-www-form-urlencoded",
          accept: "text/html,application/xhtml+xml",
        },
        payload: "List-Unsubscribe=One-Click",
      }),
      app.inject({
        method: "POST",
        url: `/core/v1/notifications/unsubscribe/${validToken}`,
        headers: {
          "content-type": "application/x-www-form-urlencoded",
          accept: "text/html,application/xhtml+xml",
        },
        payload: "List-Unsubscribe=One-Click",
      }),
    ]);
    expect(click1.statusCode).toBe(200);
    expect(click2.statusCode).toBe(200);
    expect(click1.headers["content-type"]).toBe(UNSUBSCRIBE_HTML_HEADERS["Content-Type"]);
    expect(click1.body).toContain("Powiadomienia z kategorii Przypomnienia TimoTime są wyłączone.");

    const [prefsAfterRace, auditsAfterRace] = await withOrganization(db, acme.id, (tx) =>
      Promise.all([
        tx.notificationPreference.findMany({ where: { accountId: acmeMember.accountId } }),
        tx.auditLog.count({
          where: { action: "notification.preference_changed", actorAccountId: acmeMember.accountId },
        }),
      ]),
    );
    expect(prefsAfterRace).toHaveLength(1);
    expect(prefsAfterRace[0]?.enabled).toBe(false);
    expect(auditsAfterRace).toBe(auditsBefore + 1);

    // 3. Ponowny PUT z enabled=false nie dopisuje wpisu audytu; multipart/form-data działa; application/xml -> 422
    const noopPut = await app.inject({
      method: "PUT",
      url: "/core/v1/me/notification-preferences/timotime.reminders",
      headers: { authorization: `Bearer ${memberBearer}` },
      payload: { enabled: false },
    });
    expect(noopPut.statusCode).toBe(200);

    await app.inject({
      method: "PUT",
      url: "/core/v1/me/notification-preferences/timotime.reminders",
      headers: { authorization: `Bearer ${memberBearer}` },
      payload: { enabled: true },
    });

    const multipartRes = await app.inject({
      method: "POST",
      url: `/core/v1/notifications/unsubscribe/${validToken}`,
      headers: { "content-type": "multipart/form-data; boundary=---core86" },
      payload:
        '-----core86\r\nContent-Disposition: form-data; name="List-Unsubscribe"\r\n\r\nOne-Click\r\n-----core86--\r\n',
    });
    expect(multipartRes.statusCode).toBe(200);
    expect(multipartRes.json().data).toEqual({ category: "timotime.reminders", enabled: false });

    const unsupportedRes = await app.inject({
      method: "POST",
      url: `/core/v1/notifications/unsubscribe/${validToken}`,
      headers: { "content-type": "application/xml" },
      payload: "<unsubscribe/>",
    });
    expect(unsupportedRes.statusCode).toBe(422);
    expect(unsupportedRes.json().error.code).toBe("VALIDATION_FAILED");

    const auditsAfterMultipart = await withOrganization(db, acme.id, (tx) =>
      tx.auditLog.count({ where: { action: "notification.preference_changed", actorAccountId: acmeMember.accountId } }),
    );
    // +1 za race (true->false), +0 za noopPut, +1 za PUT true, +1 za multipart (true->false) = +3
    expect(auditsAfterMultipart).toBe(auditsBefore + 3);

    // 4. Token nieaktywnego konta (DEACTIVATED) i zmanipulowany token -> neutralne 404 na GET i POST
    for (const badToken of [deactivatedToken, `${validToken}tampered`]) {
      const get404 = await app.inject({
        method: "GET",
        url: `/core/v1/notifications/unsubscribe/${badToken}`,
      });
      expect(get404.statusCode).toBe(404);
      expect(get404.headers["content-security-policy"]).toBe(UNSUBSCRIBE_HTML_HEADERS["Content-Security-Policy"]);
      expect(get404.body).toContain("Ten link jest nieaktualny.");

      const post404Html = await app.inject({
        method: "POST",
        url: `/core/v1/notifications/unsubscribe/${badToken}`,
        headers: { accept: "text/html" },
      });
      expect(post404Html.statusCode).toBe(404);
      expect(post404Html.body).toContain("Ten link jest nieaktualny.");

      const post404Json = await app.inject({
        method: "POST",
        url: `/core/v1/notifications/unsubscribe/${badToken}`,
      });
      expect(post404Json.statusCode).toBe(404);
      expect(post404Json.json().error.code).toBe("NOT_FOUND");
    }
  });

  it("odrzuca (403) zlecenia dla firm SUSPENDED i DELETED oraz pomija (SKIPPED/NO_ACCESS) ich zakolejkowane powiadomienia przy wysyłce", async () => {
    const timoToken = await machineToken(timotimeClientId);

    for (const blockedStatus of ["SUSPENDED", "DELETED"] as const) {
      // Najpierw zlecenie w stanie ACTIVE (z niekanonicznym actionUrl z segmentem `..`), potem zmiana statusu firmy
      const queuedRes = await app.inject({
        method: "POST",
        url: `/core/v1/organizations/${acme.id}/notifications`,
        headers: { authorization: `Bearer ${timoToken}` },
        payload: {
          recipientAccountId: acmeMember.accountId,
          category: "timotime.reminders",
          title: `Test ${blockedStatus}`,
          body: "Treść powiadomienia.",
          actionUrl: `${timotimeOrigin}/app/../app/timesheets`,
        },
      });
      expect(queuedRes.statusCode).toBe(202);
      const queuedId = queuedRes.json().data.id as string;

      const storedBefore = await withOrganization(db, acme.id, (tx) =>
        tx.notification.findUniqueOrThrow({ where: { id: queuedId } }),
      );
      expect(storedBefore.actionUrl).toBe(`${timotimeOrigin}/app/timesheets`);

      try {
        await withOrganization(ownerDb, acme.id, (tx) =>
          tx.organization.update({ where: { id: acme.id }, data: { status: blockedStatus } }),
        );

        // Nowe zlecenie dla zablokowanej firmy -> 403 PERMISSION_DENIED
        const rejectedPost = await app.inject({
          method: "POST",
          url: `/core/v1/organizations/${acme.id}/notifications`,
          headers: { authorization: `Bearer ${timoToken}` },
          payload: {
            recipientAccountId: acmeMember.accountId,
            category: "timotime.reminders",
            title: "Odrzucone",
            body: "Firma zablokowana.",
          },
        });
        expect(rejectedPost.statusCode).toBe(403);
        expect(rejectedPost.json().error.code).toBe("PERMISSION_DENIED");

        // Zakolejkowane wcześniej powiadomienie nie wychodzi -> SKIPPED/NO_ACCESS i CANCELLED
        const delivered: OutgoingMail[] = [];
        const summary = await deliverPendingMail(db, {
          apiUrl: API_URL,
          notificationsUnsubscribeSecret: UNSUBSCRIBE_SECRET,
          notificationsMailer: async (mail) => {
            delivered.push(mail);
          },
        });
        expect(summary).toEqual({ claimed: 1, sent: 0, retried: 0, failed: 0, cancelled: 1, skipped: 0 });
        expect(delivered).toHaveLength(0);

        const [notifAfter, outboxAfter] = await withOrganization(db, acme.id, (tx) =>
          Promise.all([
            tx.notification.findUniqueOrThrow({ where: { id: queuedId } }),
            tx.mailOutbox.findFirstOrThrow({ where: { notificationId: queuedId } }),
          ]),
        );
        expect(notifAfter.status).toBe("SKIPPED");
        expect(notifAfter.skipReason).toBe("NO_ACCESS");
        expect(notifAfter.sentAt).toBeNull();
        expect(outboxAfter.status).toBe("CANCELLED");
      } finally {
        await withOrganization(ownerDb, acme.id, (tx) =>
          tx.organization.update({ where: { id: acme.id }, data: { status: "ACTIVE" } }),
        );
      }
    }
  });
});
