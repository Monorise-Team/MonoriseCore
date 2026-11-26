import { createDb, hashToken, invitationByTokenHash, uuidv7, withOrganization } from "@core/db";
import { createLocalJWKSet, exportJWK, generateKeyPair, SignJWT, type CryptoKey } from "jose";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { createInvitation } from "../src/invitations.js";
import { clearSentMails, sentMails, type OutgoingMail } from "../src/mail.js";
import {
  claimMailJobs,
  cleanupOldMailJobs,
  computeMailBackoffMs,
  deliverPendingMail,
  MAIL_CLEANUP_RETENTION_MS,
  MAIL_LAST_ERROR_MAX_LENGTH,
  MAIL_MAX_ATTEMPTS,
} from "../src/mail-outbox.js";
import { registerCorePermissions } from "../src/permissions-registry.js";
import { buildServer } from "../src/server.js";
import { createMachineTokenVerifier, createTokenVerifier } from "../src/tokens.js";

const ISSUER = "http://localhost:3100";
const AUDIENCE = "http://localhost:3200";
const AUTH_URL = "http://localhost:3100";

const appUrl =
  process.env.CORE_TEST_APP_DATABASE_URL ?? "postgresql://core_app:core_app@localhost:5433/monorise_core_test";
const ownerUrl =
  process.env.CORE_TEST_DATABASE_URL ?? "postgresql://core_owner:core_owner@localhost:5433/monorise_core_test";
const db = createDb(appUrl);
const ownerDb = createDb(ownerUrl);

interface Company {
  id: string;
  domain: string;
  employeeId: string;
  accountId: string;
}

let signingKey: CryptoKey;
let currentNow = new Date("2026-11-26T10:00:00.000Z");
let app: ReturnType<typeof buildServer>;
let acme: Company;
let globex: Company;

function deferred<T = void>() {
  let resolve!: (value: T | PromiseLike<T>) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
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

  return { id, domain, employeeId, accountId };
}

function token(company: Company) {
  return new SignJWT({
    org_id: company.id,
    employee_id: company.employeeId,
    authz_rev: 0,
    amr: ["pwd"],
  })
    .setProtectedHeader({ alg: "EdDSA" })
    .setIssuer(ISSUER)
    .setAudience(AUDIENCE)
    .setSubject(company.accountId)
    .setIssuedAt()
    .setExpirationTime("5m")
    .sign(signingKey);
}

function request(method: "GET" | "POST" | "DELETE", url: string, bearer: string, payload?: Record<string, unknown>) {
  return app.inject({
    method,
    url,
    headers: { authorization: `Bearer ${bearer}` },
    ...(payload !== undefined ? { payload } : {}),
  });
}

function extractTokenFromMail(mail: OutgoingMail): string {
  const match = /https?:\/\/\S+/.exec(mail.text);
  expect(match).not.toBeNull();
  const parsed = new URL(match![0]);
  expect(parsed.pathname).toBe("/invite");
  const rawToken = parsed.searchParams.get("token");
  expect(rawToken).toBeTruthy();
  return rawToken!;
}

beforeAll(async () => {
  process.env.CORE_SMTP_URL = "memory";
  await registerCorePermissions(db);

  const pair = await generateKeyPair("EdDSA", { crv: "Ed25519" });
  signingKey = pair.privateKey;
  const jwk = { ...(await exportJWK(pair.publicKey)), alg: "EdDSA", kid: "test-mail-outbox" };
  const tokenOptions = { keys: createLocalJWKSet({ keys: [jwk] }), issuer: ISSUER, audience: AUDIENCE };

  app = buildServer({
    db,
    verifyToken: createTokenVerifier(tokenOptions),
    verifyMachineToken: createMachineTokenVerifier(tokenOptions),
    now: () => currentNow,
  });

  acme = await createCompany("Acme");
  globex = await createCompany("Globex");
});

beforeEach(async () => {
  clearSentMails();
  currentNow = new Date("2026-11-26T10:00:00.000Z");
  // core_owner też podlega RLS (FORCE), a core_app nie ma DELETE na mail_outbox: kasujemy w kontekście firmy
  for (const company of [acme, globex]) {
    await withOrganization(ownerDb, company.id, (tx) => tx.mailOutbox.deleteMany({}));
  }
});

afterAll(async () => {
  await app?.close();
  for (const company of [acme, globex]) {
    if (!company) continue;
    const allAccounts = await withOrganization(db, company.id, (tx) => tx.account.findMany({ select: { id: true } }));
    const ids = [...new Set([company.accountId, ...allAccounts.map((a) => a.id)])];
    await withOrganization(db, company.id, async (tx) => {
      await tx.roleAssignment.deleteMany({});
      await tx.organization.delete({ where: { id: company.id } });
    });
    await db.authUser.deleteMany({ where: { id: { in: ids } } });
  }
  await db.$disconnect();
  await ownerDb.$disconnect();
});

describe("Transakcyjna kolejka poczty mail_outbox (MonoriseCore#60)", () => {
  it("nie wysyła żadnego e-maila przed COMMIT — wycofanie transakcji po createInvitation nie zostawia zadania ani maila", async () => {
    const email = `rollback-${uuidv7().slice(-6)}@${acme.domain}`;

    await expect(
      withOrganization(db, acme.id, async (tx) => {
        await createInvitation(tx, {
          organizationId: acme.id,
          email,
          firstName: "Jan",
          lastName: "Wycofany",
          invitedBy: acme.accountId,
          actor: { type: "ACCOUNT", accountId: acme.accountId },
          now: currentNow,
        });
        throw new Error("celowe wycofanie przed COMMIT");
      }),
    ).rejects.toThrow("celowe wycofanie przed COMMIT");

    const [invitations, jobs] = await withOrganization(db, acme.id, (tx) =>
      Promise.all([tx.invitation.findMany({ where: { normalizedEmail: email } }), tx.mailOutbox.findMany()]),
    );
    expect(invitations).toHaveLength(0);
    expect(jobs).toHaveLength(0);

    const summary = await deliverPendingMail(db, { authUrl: AUTH_URL, now: currentNow });
    expect(summary.claimed).toBe(0);
    expect(sentMails()).toHaveLength(0);
  });

  it("błąd mailera nie wycofuje zaproszenia, planuje ponowienie z wykładniczym backoffem i przycina lastError do 500 znaków", async () => {
    const ownerToken = await token(acme);
    const email = `retry-${uuidv7().slice(-6)}@${acme.domain}`;

    const createRes = await request("POST", "/core/v1/invitations", ownerToken, {
      email,
      firstName: "Anna",
      lastName: "Ponowienie",
    });
    expect(createRes.statusCode).toBe(201);
    const invId = createRes.json().data.id as string;

    // Próba 1: chwilowy błąd SMTP -> zaproszenie zostaje PENDING, zadanie dostaje backoff 30 s
    const firstSummary = await deliverPendingMail(db, {
      authUrl: AUTH_URL,
      now: currentNow,
      mailer: async () => {
        throw new Error("421 SMTP connection refused");
      },
    });
    expect(firstSummary).toEqual({ claimed: 1, sent: 0, retried: 1, failed: 0, cancelled: 0 });

    const [invAfter1, jobAfter1] = await withOrganization(db, acme.id, (tx) =>
      Promise.all([
        tx.invitation.findUniqueOrThrow({ where: { id: invId } }),
        tx.mailOutbox.findFirstOrThrow({ where: { invitationId: invId } }),
      ]),
    );
    expect(invAfter1.status).toBe("PENDING");
    expect(jobAfter1.status).toBe("PENDING");
    expect(jobAfter1.attempts).toBe(1);
    expect(jobAfter1.lockedUntil).toBeNull();
    expect(jobAfter1.lastAttemptAt?.getTime()).toBe(currentNow.getTime());
    expect(jobAfter1.nextAttemptAt.getTime()).toBe(currentNow.getTime() + computeMailBackoffMs(1));
    expect(jobAfter1.lastError).toBe("421 SMTP connection refused");
    expect(jobAfter1.sentAt).toBeNull();
    expect(jobAfter1.failedAt).toBeNull();

    // Milisekundę przed terminem ponowienia worker nie pobiera zadania
    const tooEarly = await deliverPendingMail(db, {
      authUrl: AUTH_URL,
      now: new Date(jobAfter1.nextAttemptAt.getTime() - 1),
    });
    expect(tooEarly.claimed).toBe(0);

    // Próba 2 w terminie ponowienia: długi błąd (>500 znaków) zostaje przycięty, backoff rośnie do 60 s
    const t2 = jobAfter1.nextAttemptAt;
    const secondSummary = await deliverPendingMail(db, {
      authUrl: AUTH_URL,
      now: t2,
      mailer: async () => {
        throw new Error(`SMTP: ${"x".repeat(700)}`);
      },
    });
    expect(secondSummary).toEqual({ claimed: 1, sent: 0, retried: 1, failed: 0, cancelled: 0 });

    const jobAfter2 = await withOrganization(db, acme.id, (tx) =>
      tx.mailOutbox.findFirstOrThrow({ where: { invitationId: invId } }),
    );
    expect(jobAfter2.status).toBe("PENDING");
    expect(jobAfter2.attempts).toBe(2);
    expect(jobAfter2.nextAttemptAt.getTime()).toBe(t2.getTime() + computeMailBackoffMs(2));
    expect(jobAfter2.lastError?.length).toBe(MAIL_LAST_ERROR_MAX_LENGTH);

    // Próba 3 kończy się sukcesem -> status SENT, wyczyszczony lastError
    const t3 = jobAfter2.nextAttemptAt;
    const thirdSummary = await deliverPendingMail(db, { authUrl: AUTH_URL, now: t3 });
    expect(thirdSummary).toEqual({ claimed: 1, sent: 1, retried: 0, failed: 0, cancelled: 0 });

    const jobAfter3 = await withOrganization(db, acme.id, (tx) =>
      tx.mailOutbox.findFirstOrThrow({ where: { invitationId: invId } }),
    );
    expect(jobAfter3.status).toBe("SENT");
    expect(jobAfter3.attempts).toBe(3);
    expect(jobAfter3.sentAt?.getTime()).toBe(t3.getTime());
    expect(jobAfter3.lockedUntil).toBeNull();
    expect(jobAfter3.lastError).toBeNull();
  });

  it("oznacza zadanie jako FAILED po osiągnięciu MAIL_MAX_ATTEMPTS (8) i nie ujawnia lastError w API", async () => {
    const ownerToken = await token(acme);
    const email = `failed-${uuidv7().slice(-6)}@${acme.domain}`;

    const createRes = await request("POST", "/core/v1/invitations", ownerToken, {
      email,
      firstName: "Jan",
      lastName: "Awaria",
    });
    expect(createRes.statusCode).toBe(201);
    const invId = createRes.json().data.id as string;

    let clock = new Date(currentNow.getTime());
    const alwaysFail = async () => {
      throw new Error("550 Mailbox unavailable (internal SMTP detail)");
    };

    for (let attempt = 1; attempt <= MAIL_MAX_ATTEMPTS; attempt += 1) {
      const summary = await deliverPendingMail(db, {
        authUrl: AUTH_URL,
        now: clock,
        mailer: alwaysFail,
      });

      const job = await withOrganization(db, acme.id, (tx) =>
        tx.mailOutbox.findFirstOrThrow({ where: { invitationId: invId } }),
      );
      expect(job.attempts).toBe(attempt);
      expect(job.lockedUntil).toBeNull();
      expect(job.lastAttemptAt?.getTime()).toBe(clock.getTime());
      expect(job.lastError).toBe("550 Mailbox unavailable (internal SMTP detail)");

      if (attempt < MAIL_MAX_ATTEMPTS) {
        expect(summary).toEqual({ claimed: 1, sent: 0, retried: 1, failed: 0, cancelled: 0 });
        expect(job.status).toBe("PENDING");
        expect(job.failedAt).toBeNull();
        expect(job.nextAttemptAt.getTime()).toBe(clock.getTime() + computeMailBackoffMs(attempt));
        clock = job.nextAttemptAt;
      } else {
        expect(summary).toEqual({ claimed: 1, sent: 0, retried: 0, failed: 1, cancelled: 0 });
        expect(job.status).toBe("FAILED");
        expect(job.failedAt?.getTime()).toBe(clock.getTime());
      }
    }

    // Po osiągnięciu limitu prób kolejne przebiegi nie pobierają już zadania FAILED
    const later = await deliverPendingMail(db, {
      authUrl: AUTH_URL,
      now: new Date(clock.getTime() + 2 * 60 * 60 * 1000),
      mailer: alwaysFail,
    });
    expect(later.claimed).toBe(0);

    // API zwraca delivery.status = FAILED, attempts = 8 i nigdy nie zawiera lastError
    const listRes = await request("GET", "/core/v1/invitations", ownerToken);
    expect(listRes.statusCode).toBe(200);
    const row = (listRes.json().data as Array<{ id: string; delivery: Record<string, unknown> }>).find(
      (item) => item.id === invId,
    );
    expect(row?.delivery).toEqual({
      status: "FAILED",
      attempts: MAIL_MAX_ATTEMPTS,
      lastAttemptAt: clock.toISOString(),
      sentAt: null,
    });
    expect("lastError" in (row?.delivery ?? {})).toBe(false);
    expect(JSON.stringify(row)).not.toContain("Mailbox unavailable");
  });

  it("generuje token dopiero przy wysyłce, zapisuje jego skrót bez zmiany expiresAt i link działa do akceptacji", async () => {
    const ownerToken = await token(acme);
    const email = `accept-${uuidv7().slice(-6)}@${acme.domain}`;

    const createRes = await request("POST", "/core/v1/invitations", ownerToken, {
      email,
      firstName: "Katarzyna",
      lastName: "Akceptacja",
    });
    expect(createRes.statusCode).toBe(201);
    const inv = createRes.json().data;

    const beforeDelivery = await withOrganization(db, acme.id, (tx) =>
      tx.invitation.findUniqueOrThrow({ where: { id: inv.id } }),
    );
    expect(beforeDelivery.tokenHash).toMatch(/^[0-9a-f]{64}$/);
    expect(sentMails()).toHaveLength(0);

    const deliveryTime = new Date(currentNow.getTime() + 5_000);
    const summary = await deliverPendingMail(db, { authUrl: AUTH_URL, now: deliveryTime });
    expect(summary).toEqual({ claimed: 1, sent: 1, retried: 0, failed: 0, cancelled: 0 });

    const mail = sentMails().find((m) => m.to === email)!;
    expect(mail).toBeDefined();
    const rawToken = extractTokenFromMail(mail);
    const expectedHash = hashToken(rawToken);

    const afterDelivery = await withOrganization(db, acme.id, (tx) =>
      tx.invitation.findUniqueOrThrow({ where: { id: inv.id }, include: { account: true } }),
    );
    expect(afterDelivery.tokenHash).toBe(expectedHash);
    expect(afterDelivery.tokenHash).not.toBe(beforeDelivery.tokenHash);
    expect(afterDelivery.expiresAt.getTime()).toBe(beforeDelivery.expiresAt.getTime());

    // Link z e-maila przechodzi wyszukiwanie i pełną ścieżkę akceptacji konta INVITED -> ACTIVE
    const lookup = await invitationByTokenHash(db, expectedHash);
    expect(lookup).toEqual({ organizationId: acme.id, invitationId: inv.id });

    await withOrganization(db, lookup!.organizationId, async (tx) => {
      const loaded = await tx.invitation.findUniqueOrThrow({
        where: { id: lookup!.invitationId },
        include: { account: { select: { status: true } } },
      });
      expect(loaded.tokenHash).toBe(expectedHash);
      expect(loaded.status).toBe("PENDING");
      expect(loaded.expiresAt.getTime()).toBeGreaterThan(deliveryTime.getTime());
      expect(loaded.account.status).toBe("INVITED");

      await tx.invitation.update({
        where: { id: loaded.id },
        data: { status: "ACCEPTED", acceptedAt: deliveryTime },
      });
      await tx.account.update({
        where: { id: loaded.accountId },
        data: { status: "ACTIVE" },
      });
      await tx.authUser.update({
        where: { id: loaded.accountId },
        data: { emailVerified: true },
      });
    });

    // Dodatkowe zadanie dla już zaakceptowanego zaproszenia zostaje anulowane bez wysyłki
    clearSentMails();
    const strayJobId = uuidv7();
    await withOrganization(db, acme.id, (tx) =>
      tx.mailOutbox.create({
        data: {
          id: strayJobId,
          organizationId: acme.id,
          kind: "INVITATION",
          invitationId: inv.id,
          status: "PENDING",
          nextAttemptAt: deliveryTime,
          createdAt: deliveryTime,
          updatedAt: deliveryTime,
        },
      }),
    );
    const straySummary = await deliverPendingMail(db, { authUrl: AUTH_URL, now: deliveryTime });
    expect(straySummary).toEqual({ claimed: 1, sent: 0, retried: 0, failed: 0, cancelled: 1 });
    expect(sentMails()).toHaveLength(0);
    const strayJob = await withOrganization(db, acme.id, (tx) =>
      tx.mailOutbox.findUniqueOrThrow({ where: { id: strayJobId } }),
    );
    expect(strayJob.status).toBe("CANCELLED");
    expect(strayJob.lockedUntil).toBeNull();
  });

  it("resend anuluje poprzednie oczekujące zadanie i natychmiast unieważnia stary link", async () => {
    const ownerToken = await token(acme);
    const email = `resend-${uuidv7().slice(-6)}@${acme.domain}`;

    const createRes = await request("POST", "/core/v1/invitations", ownerToken, {
      email,
      firstName: "Marek",
      lastName: "Ponowiony",
    });
    expect(createRes.statusCode).toBe(201);
    const invId = createRes.json().data.id as string;

    // Resend PRZED wysyłką pierwszego zadania -> pierwsze zadanie staje się CANCELLED, wychodzi tylko 1 mail
    const firstJob = await withOrganization(db, acme.id, (tx) =>
      tx.mailOutbox.findFirstOrThrow({ where: { invitationId: invId } }),
    );
    const resendBeforeSend = await request("POST", `/core/v1/invitations/${invId}/resend`, ownerToken);
    expect(resendBeforeSend.statusCode).toBe(200);

    const jobsAfterFirstResend = await withOrganization(db, acme.id, (tx) =>
      tx.mailOutbox.findMany({ where: { invitationId: invId }, orderBy: { createdAt: "asc" } }),
    );
    expect(jobsAfterFirstResend).toHaveLength(2);
    expect(jobsAfterFirstResend[0]?.id).toBe(firstJob.id);
    expect(jobsAfterFirstResend[0]?.status).toBe("CANCELLED");
    expect(jobsAfterFirstResend[1]?.status).toBe("PENDING");

    const pass1 = await deliverPendingMail(db, { authUrl: AUTH_URL, now: currentNow });
    expect(pass1).toEqual({ claimed: 1, sent: 1, retried: 0, failed: 0, cancelled: 0 });
    expect(sentMails()).toHaveLength(1);
    const token1 = extractTokenFromMail(sentMails()[0]!);
    expect(await invitationByTokenHash(db, hashToken(token1))).toEqual({
      organizationId: acme.id,
      invitationId: invId,
    });

    // Resend PO wysyłce -> stary link przestaje działać NATYCHMIAST (jeszcze przed uruchomieniem workera)
    const resendAfterSend = await request("POST", `/core/v1/invitations/${invId}/resend`, ownerToken);
    expect(resendAfterSend.statusCode).toBe(200);
    expect(await invitationByTokenHash(db, hashToken(token1))).toBeNull();

    // Worker dostarcza nowy link, który działa
    clearSentMails();
    const pass2 = await deliverPendingMail(db, { authUrl: AUTH_URL, now: currentNow });
    expect(pass2).toEqual({ claimed: 1, sent: 1, retried: 0, failed: 0, cancelled: 0 });
    const token2 = extractTokenFromMail(sentMails()[0]!);
    expect(token2).not.toBe(token1);
    expect(await invitationByTokenHash(db, hashToken(token2))).toEqual({
      organizationId: acme.id,
      invitationId: invId,
    });
  });

  it("cofnięcie zaproszenia (revoke) anuluje oczekujące zadanie i nic nie zostaje wysłane", async () => {
    const ownerToken = await token(acme);
    const email = `revoke-${uuidv7().slice(-6)}@${acme.domain}`;

    const createRes = await request("POST", "/core/v1/invitations", ownerToken, {
      email,
      firstName: "Piotr",
      lastName: "Cofniety",
    });
    expect(createRes.statusCode).toBe(201);
    const invId = createRes.json().data.id as string;

    const revokeRes = await request("DELETE", `/core/v1/invitations/${invId}`, ownerToken);
    expect(revokeRes.statusCode).toBe(204);

    const job = await withOrganization(db, acme.id, (tx) =>
      tx.mailOutbox.findFirstOrThrow({ where: { invitationId: invId } }),
    );
    expect(job.status).toBe("CANCELLED");
    expect(job.lockedUntil).toBeNull();

    const summary = await deliverPendingMail(db, { authUrl: AUTH_URL, now: currentNow });
    expect(summary.claimed).toBe(0);
    expect(sentMails()).toHaveLength(0);

    const listRes = await request("GET", "/core/v1/invitations", ownerToken);
    const listed = (
      listRes.json().data as Array<{ id: string; status: string; delivery: { status: string | null } }>
    ).find((item) => item.id === invId);
    expect(listed?.status).toBe("REVOKED");
    expect(listed?.delivery.status).toBe("CANCELLED");
  });

  it("dwa równoległe przebiegi deliverPendingMail nigdy nie wysyłają tego samego zadania dwa razy (SKIP LOCKED i dzierżawa)", async () => {
    const ownerToken = await token(acme);
    const db2 = createDb(appUrl);

    try {
      // 1. Pojedyncze zadanie i dwa równoległe przebiegi na dwóch połączeniach z barierą w mailerze
      const singleEmail = `concurrent-one-${uuidv7().slice(-6)}@${acme.domain}`;
      const createOne = await request("POST", "/core/v1/invitations", ownerToken, {
        email: singleEmail,
        firstName: "Jan",
        lastName: "Rownolegly",
      });
      expect(createOne.statusCode).toBe(201);

      const sentSingle: OutgoingMail[] = [];
      const firstMailerEntered = deferred();
      const releaseMailer = deferred();

      const p1 = deliverPendingMail(db, {
        authUrl: AUTH_URL,
        now: currentNow,
        mailer: async (mail) => {
          sentSingle.push(mail);
          firstMailerEntered.resolve();
          await releaseMailer.promise;
        },
      });
      await firstMailerEntered.promise;

      const p2 = deliverPendingMail(db2, {
        authUrl: AUTH_URL,
        now: currentNow,
        mailer: async (mail) => {
          sentSingle.push(mail);
        },
      });
      const r2 = await p2;
      releaseMailer.resolve();
      const r1 = await p1;

      expect(r1.sent + r2.sent).toBe(1);
      expect(r1.claimed + r2.claimed).toBe(1);
      expect(sentSingle).toHaveLength(1);

      // 2. Sześć zadań i trzy jednoczesne przebiegi z limit=3 -> każde zaproszenie dostaje dokładnie 1 e-mail
      const batchEmails: string[] = [];
      for (let i = 0; i < 6; i += 1) {
        const email = `batch-${i}-${uuidv7().slice(-6)}@${acme.domain}`;
        batchEmails.push(email);
        const res = await request("POST", "/core/v1/invitations", ownerToken, {
          email,
          firstName: "Osoba",
          lastName: `Numer${i}`,
        });
        expect(res.statusCode).toBe(201);
      }

      const deliveredTo: string[] = [];
      const batchMailer = async (mail: OutgoingMail) => {
        await new Promise((resolve) => setTimeout(resolve, 10));
        deliveredTo.push(mail.to);
      };

      await Promise.all([
        deliverPendingMail(db, { limit: 3, authUrl: AUTH_URL, now: currentNow, mailer: batchMailer }),
        deliverPendingMail(db2, { limit: 3, authUrl: AUTH_URL, now: currentNow, mailer: batchMailer }),
        deliverPendingMail(db, { limit: 3, authUrl: AUTH_URL, now: currentNow, mailer: batchMailer }),
      ]);
      // Drenaż reszty na wypadek, gdyby wyścig ominął któryś wiersz w pierwszej rundzie
      await deliverPendingMail(db, { limit: 20, authUrl: AUTH_URL, now: currentNow, mailer: batchMailer });

      expect(deliveredTo.sort()).toEqual([...batchEmails].sort());
      expect(new Set(deliveredTo).size).toBe(batchEmails.length);

      // 3. Wygaśnięcie dzierżawy (semantyka at-least-once): porzucona dzierżawa pozwala kolejnej próbie wysłać nowy link
      const leaseEmail = `lease-${uuidv7().slice(-6)}@${acme.domain}`;
      const createLease = await request("POST", "/core/v1/invitations", ownerToken, {
        email: leaseEmail,
        firstName: "Ewa",
        lastName: "Dzierzawa",
      });
      expect(createLease.statusCode).toBe(201);

      const claimedOnly = await claimMailJobs(db, { limit: 10, leaseMs: 5_000, now: currentNow });
      expect(claimedOnly).toHaveLength(1);
      expect(claimedOnly[0]?.attempts).toBe(1);

      // Przed wygaśnięciem dzierżawy drugie claim nic nie zwraca
      expect(
        await claimMailJobs(db2, { limit: 10, leaseMs: 5_000, now: new Date(currentNow.getTime() + 4_000) }),
      ).toEqual([]);

      // Po wygaśnięciu dzierżawy kolejna próba przejmuje zadanie (attempts = 2) i kończy wysyłkę
      const recoveredAt = new Date(currentNow.getTime() + 6_000);
      const recovered = await deliverPendingMail(db2, { authUrl: AUTH_URL, now: recoveredAt });
      expect(recovered).toEqual({ claimed: 1, sent: 1, retried: 0, failed: 0, cancelled: 0 });
      const leaseJob = await withOrganization(db, acme.id, (tx) =>
        tx.mailOutbox.findFirstOrThrow({ where: { id: claimedOnly[0]!.id } }),
      );
      expect(leaseJob.status).toBe("SENT");
      expect(leaseJob.attempts).toBe(2);
    } finally {
      await db2.$disconnect();
    }
  });

  it("zwraca pole delivery w odpowiedziach API (create, list, resend) oraz null dla starszych zaproszeń bez wiersza mail_outbox", async () => {
    const ownerToken = await token(acme);
    const email = `api-delivery-${uuidv7().slice(-6)}@${acme.domain}`;

    const createRes = await request("POST", "/core/v1/invitations", ownerToken, {
      email,
      firstName: "Tomasz",
      lastName: "Dostawa",
    });
    expect(createRes.statusCode).toBe(201);
    const invId = createRes.json().data.id as string;
    expect(createRes.json().data.delivery).toEqual({
      status: "PENDING",
      attempts: 0,
      lastAttemptAt: null,
      sentAt: null,
    });

    await deliverPendingMail(db, { authUrl: AUTH_URL, now: currentNow });

    const listAfterSend = await request("GET", "/core/v1/invitations", ownerToken);
    expect(listAfterSend.statusCode).toBe(200);
    const sentRow = (listAfterSend.json().data as Array<{ id: string; delivery: Record<string, unknown> }>).find(
      (item) => item.id === invId,
    );
    expect(sentRow?.delivery).toEqual({
      status: "SENT",
      attempts: 1,
      lastAttemptAt: currentNow.toISOString(),
      sentAt: currentNow.toISOString(),
    });

    // Resend przy tym samym currentNow -> najnowszy wiersz w API to nowe zadanie PENDING (attempts=0)
    const resendRes = await request("POST", `/core/v1/invitations/${invId}/resend`, ownerToken);
    expect(resendRes.statusCode).toBe(200);
    expect(resendRes.json().data.delivery).toEqual({
      status: "PENDING",
      attempts: 0,
      lastAttemptAt: null,
      sentAt: null,
    });

    const listAfterResend = await request("GET", "/core/v1/invitations", ownerToken);
    const resentRow = (listAfterResend.json().data as Array<{ id: string; delivery: Record<string, unknown> }>).find(
      (item) => item.id === invId,
    );
    expect(resentRow?.delivery).toEqual({
      status: "PENDING",
      attempts: 0,
      lastAttemptAt: null,
      sentAt: null,
    });

    // Starsze zaproszenie bez żadnego wiersza mail_outbox -> delivery.status === null
    await withOrganization(ownerDb, acme.id, (tx) => tx.mailOutbox.deleteMany({ where: { invitationId: invId } }));
    const listWithoutJob = await request("GET", "/core/v1/invitations", ownerToken);
    const legacyRow = (listWithoutJob.json().data as Array<{ id: string; delivery: Record<string, unknown> }>).find(
      (item) => item.id === invId,
    );
    expect(legacyRow?.delivery).toEqual({
      status: null,
      attempts: 0,
      lastAttemptAt: null,
      sentAt: null,
    });
  });

  it("egzekwuje RLS: inna firma nie widzi ani nie zmienia wierszy mail_outbox, a core_app nie ma DELETE", async () => {
    const acmeToken = await token(acme);
    const email = `rls-${uuidv7().slice(-6)}@${acme.domain}`;

    const createRes = await request("POST", "/core/v1/invitations", acmeToken, {
      email,
      firstName: "Izolacja",
      lastName: "Acme",
    });
    expect(createRes.statusCode).toBe(201);
    const invId = createRes.json().data.id as string;

    const acmeJobs = await withOrganization(db, acme.id, (tx) =>
      tx.mailOutbox.findMany({ where: { invitationId: invId } }),
    );
    expect(acmeJobs).toHaveLength(1);
    const acmeJobId = acmeJobs[0]!.id;

    // Globex nie widzi wiersza Acme i nie może go zmienić
    const globexJobs = await withOrganization(db, globex.id, (tx) => tx.mailOutbox.findMany());
    expect(globexJobs).toEqual([]);
    expect(
      await withOrganization(db, globex.id, (tx) => tx.mailOutbox.findUnique({ where: { id: acmeJobId } })),
    ).toBeNull();
    const crossUpdate = await withOrganization(db, globex.id, (tx) =>
      tx.mailOutbox.updateMany({ where: { id: acmeJobId }, data: { status: "CANCELLED" } }),
    );
    expect(crossUpdate.count).toBe(0);

    // Bez kontekstu firmy brak widoczności
    expect(await db.mailOutbox.findMany()).toEqual([]);

    // Próba zapisu w cudzej firmie -> RLS blokuje
    await expect(
      withOrganization(db, globex.id, (tx) =>
        tx.mailOutbox.create({
          data: {
            id: uuidv7(),
            organizationId: acme.id,
            kind: "INVITATION",
            invitationId: invId,
            status: "PENDING",
          },
        }),
      ),
    ).rejects.toThrow(/row-level security|violates/i);

    // core_app nie może usuwać wierszy bezpośrednio (tylko mail_outbox_cleanup)
    await expect(
      withOrganization(db, acme.id, (tx) => tx.mailOutbox.delete({ where: { id: acmeJobId } })),
    ).rejects.toThrow(/permission denied/i);
  });

  it("mail_outbox_cleanup usuwa wyłącznie stare wiersze SENT i CANCELLED, zachowując nowsze oraz PENDING i FAILED", async () => {
    const ownerToken = await token(acme);
    const email = `cleanup-${uuidv7().slice(-6)}@${acme.domain}`;

    const createRes = await request("POST", "/core/v1/invitations", ownerToken, {
      email,
      firstName: "Sprzatanie",
      lastName: "Kolejki",
    });
    expect(createRes.statusCode).toBe(201);
    const invId = createRes.json().data.id as string;

    // Usuwamy początkowy wiersz z create, żeby dokładnie sterować sześcioma wierszami testowymi
    await withOrganization(ownerDb, acme.id, (tx) => tx.mailOutbox.deleteMany({ where: { invitationId: invId } }));

    const cutoff = new Date(currentNow.getTime() - MAIL_CLEANUP_RETENTION_MS);
    const oldTime = new Date(cutoff.getTime() - 24 * 60 * 60 * 1000); // 31 dni temu
    const recentTime = new Date(currentNow.getTime() - 5 * 24 * 60 * 60 * 1000); // 5 dni temu

    const oldSentId = uuidv7();
    const recentSentId = uuidv7();
    const oldCancelledId = uuidv7();
    const recentCancelledId = uuidv7();
    const oldPendingId = uuidv7();
    const oldFailedId = uuidv7();

    await withOrganization(db, acme.id, async (tx) => {
      await tx.mailOutbox.createMany({
        data: [
          {
            id: oldSentId,
            organizationId: acme.id,
            kind: "INVITATION",
            invitationId: invId,
            status: "SENT",
            attempts: 1,
            sentAt: oldTime,
            lastAttemptAt: oldTime,
            createdAt: oldTime,
            updatedAt: oldTime,
          },
          {
            id: recentSentId,
            organizationId: acme.id,
            kind: "INVITATION",
            invitationId: invId,
            status: "SENT",
            attempts: 1,
            sentAt: recentTime,
            lastAttemptAt: recentTime,
            createdAt: recentTime,
            updatedAt: recentTime,
          },
          {
            id: oldCancelledId,
            organizationId: acme.id,
            kind: "INVITATION",
            invitationId: invId,
            status: "CANCELLED",
            attempts: 0,
            createdAt: oldTime,
            updatedAt: oldTime,
          },
          {
            id: recentCancelledId,
            organizationId: acme.id,
            kind: "INVITATION",
            invitationId: invId,
            status: "CANCELLED",
            attempts: 0,
            createdAt: recentTime,
            updatedAt: recentTime,
          },
          {
            id: oldPendingId,
            organizationId: acme.id,
            kind: "INVITATION",
            invitationId: invId,
            status: "PENDING",
            attempts: 0,
            nextAttemptAt: oldTime,
            createdAt: oldTime,
            updatedAt: oldTime,
          },
          {
            id: oldFailedId,
            organizationId: acme.id,
            kind: "INVITATION",
            invitationId: invId,
            status: "FAILED",
            attempts: MAIL_MAX_ATTEMPTS,
            lastAttemptAt: oldTime,
            failedAt: oldTime,
            lastError: "550 permanent error",
            createdAt: oldTime,
            updatedAt: oldTime,
          },
        ],
      });
    });

    const deleted = await cleanupOldMailJobs(db, cutoff);
    expect(deleted).toBeGreaterThanOrEqual(2);

    const remaining = await withOrganization(db, acme.id, (tx) =>
      tx.mailOutbox.findMany({ where: { invitationId: invId }, select: { id: true } }),
    );
    expect(remaining.map((row) => row.id).sort()).toEqual(
      [recentSentId, recentCancelledId, oldPendingId, oldFailedId].sort(),
    );
  });
});
