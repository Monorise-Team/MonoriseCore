import { createDb, hashToken, invitationByTokenHash, uuidv7, withOrganization } from "@core/db";
import { createLocalJWKSet, exportJWK, generateKeyPair, SignJWT, type CryptoKey } from "jose";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { createInvitation, createInvitationByOrganization } from "../src/invitations.js";
import { clearSentMails, sentMails, type OutgoingMail } from "../src/mail.js";
import {
  claimMailJobById,
  claimMailJobs,
  cleanupOldMailJobs,
  computeMailBackoffMs,
  deliverMailJob,
  deliverPendingMail,
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

/** Cofa `nextAttemptAt` wskazanego zadania w przeszłość (względem `now()` bazy), symulując upływ backoffu. */
async function makeJobDueNow(orgId: string, jobId: string): Promise<void> {
  await withOrganization(
    ownerDb,
    orgId,
    (tx) =>
      tx.$executeRaw`
      UPDATE "public"."mail_outbox"
      SET "nextAttemptAt" = now() - interval '1 second'
      WHERE "id" = ${jobId}::uuid`,
  );
}

/** Cofa `lockedUntil` i `nextAttemptAt` wskazanego zadania w przeszłość, symulując wygaśnięcie dzierżawy. */
async function expireJobLease(orgId: string, jobId: string): Promise<void> {
  await withOrganization(
    ownerDb,
    orgId,
    (tx) =>
      tx.$executeRaw`
      UPDATE "public"."mail_outbox"
      SET "lockedUntil" = now() - interval '1 second',
          "nextAttemptAt" = now() - interval '1 second'
      WHERE "id" = ${jobId}::uuid`,
  );
}

beforeAll(async () => {
  process.env.CORE_SMTP_URL = "memory";
  await registerCorePermissions(db);

  const pair = await generateKeyPair("EdDSA", { crv: "Ed25519" });
  signingKey = pair.privateKey;
  const jwk = { ...(await exportJWK(pair.publicKey)), alg: "EdDSA", kid: "test-mail-outbox" };
  const tokenOptions = { keys: createLocalJWKSet({ keys: [jwk] }), issuer: ISSUER, audience: AUDIENCE };

  // Brak jawnego `now`: serwer korzysta z rzeczywistego zegara bazy PostgreSQL (jak na produkcji).
  app = buildServer({
    db,
    verifyToken: createTokenVerifier(tokenOptions),
    verifyMachineToken: createMachineTokenVerifier(tokenOptions),
  });

  acme = await createCompany("Acme");
  globex = await createCompany("Globex");
});

beforeEach(async () => {
  clearSentMails();
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
        });
        throw new Error("celowe wycofanie przed COMMIT");
      }),
    ).rejects.toThrow("celowe wycofanie przed COMMIT");

    const [invitations, jobs] = await withOrganization(db, acme.id, (tx) =>
      Promise.all([tx.invitation.findMany({ where: { normalizedEmail: email } }), tx.mailOutbox.findMany()]),
    );
    expect(invitations).toHaveLength(0);
    expect(jobs).toHaveLength(0);

    const summary = await deliverPendingMail(db, { authUrl: AUTH_URL });
    expect(summary.claimed).toBe(0);
    expect(sentMails()).toHaveLength(0);
  });

  it("deliverPendingMail(db) bez jawnego now używa wyłącznie zegara PostgreSQL now() od kolejkowania po zapis SENT", async () => {
    const ownerToken = await token(acme);
    const email = `real-clock-${uuidv7().slice(-6)}@${acme.domain}`;

    const createRes = await request("POST", "/core/v1/invitations", ownerToken, {
      email,
      firstName: "Anna",
      lastName: "ZegarBazy",
    });
    expect(createRes.statusCode).toBe(201);
    const invId = createRes.json().data.id as string;

    const summary = await deliverPendingMail(db);
    expect(summary).toEqual({ claimed: 1, sent: 1, retried: 0, failed: 0, cancelled: 0, skipped: 0 });

    const job = await withOrganization(db, acme.id, (tx) =>
      tx.mailOutbox.findFirstOrThrow({ where: { invitationId: invId } }),
    );
    expect(job.status).toBe("SENT");
    expect(job.attempts).toBe(1);
    expect(job.lockedUntil).toBeNull();
    expect(job.lastAttemptAt).not.toBeNull();
    expect(job.sentAt).not.toBeNull();
    expect(job.sentAt!.getTime()).toBeGreaterThanOrEqual(job.lastAttemptAt!.getTime());

    const mail = sentMails().find((m) => m.to === email);
    expect(mail).toBeDefined();
    const rawToken = extractTokenFromMail(mail!);
    expect(await invitationByTokenHash(db, hashToken(rawToken))).toEqual({
      organizationId: acme.id,
      invitationId: invId,
    });
  });

  it("błąd mailera nie wycofuje zaproszenia, planuje ponowienie z wykładniczym backoffem oraz cenzuruje i przycina lastError", async () => {
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
      mailer: async () => {
        throw new Error("421 SMTP connection refused via smtps://bot:tajne@smtp.acme.test:465");
      },
    });
    expect(firstSummary).toEqual({ claimed: 1, sent: 0, retried: 1, failed: 0, cancelled: 0, skipped: 0 });

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
    expect(jobAfter1.lastAttemptAt).not.toBeNull();
    expect(jobAfter1.nextAttemptAt.getTime() - jobAfter1.lastAttemptAt!.getTime()).toBeGreaterThanOrEqual(
      computeMailBackoffMs(1),
    );
    expect(jobAfter1.lastError).toBe("421 SMTP connection refused via smtps://[redacted]@smtp.acme.test:465");
    expect(jobAfter1.sentAt).toBeNull();
    expect(jobAfter1.failedAt).toBeNull();

    // Przed upływem 30 s backoffu worker nie pobiera zadania
    const tooEarly = await deliverPendingMail(db, { authUrl: AUTH_URL });
    expect(tooEarly.claimed).toBe(0);

    // Próba 2 po upływie backoffu: długi błąd (>500 znaków) zostaje przycięty, backoff rośnie do 60 s
    await makeJobDueNow(acme.id, jobAfter1.id);
    const secondSummary = await deliverPendingMail(db, {
      authUrl: AUTH_URL,
      mailer: async () => {
        throw new Error(`SMTP ?token=secret123: ${"x".repeat(700)}`);
      },
    });
    expect(secondSummary).toEqual({ claimed: 1, sent: 0, retried: 1, failed: 0, cancelled: 0, skipped: 0 });

    const jobAfter2 = await withOrganization(db, acme.id, (tx) =>
      tx.mailOutbox.findFirstOrThrow({ where: { invitationId: invId } }),
    );
    expect(jobAfter2.status).toBe("PENDING");
    expect(jobAfter2.attempts).toBe(2);
    expect(jobAfter2.nextAttemptAt.getTime() - jobAfter2.lastAttemptAt!.getTime()).toBeGreaterThanOrEqual(
      computeMailBackoffMs(2),
    );
    expect(jobAfter2.lastError?.length).toBe(MAIL_LAST_ERROR_MAX_LENGTH);
    expect(jobAfter2.lastError).toContain("token=[redacted]");
    expect(jobAfter2.lastError).not.toContain("secret123");

    // Próba 3 kończy się sukcesem -> status SENT, wyczyszczony lastError
    await makeJobDueNow(acme.id, jobAfter2.id);
    const thirdSummary = await deliverPendingMail(db, { authUrl: AUTH_URL });
    expect(thirdSummary).toEqual({ claimed: 1, sent: 1, retried: 0, failed: 0, cancelled: 0, skipped: 0 });

    const jobAfter3 = await withOrganization(db, acme.id, (tx) =>
      tx.mailOutbox.findFirstOrThrow({ where: { invitationId: invId } }),
    );
    expect(jobAfter3.status).toBe("SENT");
    expect(jobAfter3.attempts).toBe(3);
    expect(jobAfter3.sentAt).not.toBeNull();
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
    const jobRow = await withOrganization(db, acme.id, (tx) =>
      tx.mailOutbox.findFirstOrThrow({ where: { invitationId: invId } }),
    );

    const alwaysFail = async () => {
      throw new Error("550 Mailbox unavailable (internal SMTP detail)");
    };

    for (let attempt = 1; attempt <= MAIL_MAX_ATTEMPTS; attempt += 1) {
      if (attempt > 1) {
        await makeJobDueNow(acme.id, jobRow.id);
      }
      const summary = await deliverPendingMail(db, {
        authUrl: AUTH_URL,
        mailer: alwaysFail,
      });

      const job = await withOrganization(db, acme.id, (tx) =>
        tx.mailOutbox.findUniqueOrThrow({ where: { id: jobRow.id } }),
      );
      expect(job.attempts).toBe(attempt);
      expect(job.lockedUntil).toBeNull();
      expect(job.lastAttemptAt).not.toBeNull();
      expect(job.lastError).toBe("550 Mailbox unavailable (internal SMTP detail)");

      if (attempt < MAIL_MAX_ATTEMPTS) {
        expect(summary).toEqual({ claimed: 1, sent: 0, retried: 1, failed: 0, cancelled: 0, skipped: 0 });
        expect(job.status).toBe("PENDING");
        expect(job.failedAt).toBeNull();
        expect(job.nextAttemptAt.getTime() - job.lastAttemptAt!.getTime()).toBeGreaterThanOrEqual(
          computeMailBackoffMs(attempt),
        );
      } else {
        expect(summary).toEqual({ claimed: 1, sent: 0, retried: 0, failed: 1, cancelled: 0, skipped: 0 });
        expect(job.status).toBe("FAILED");
        expect(job.failedAt).not.toBeNull();
      }
    }

    // Po osiągnięciu limitu prób kolejne przebiegi nie pobierają już zadania FAILED (nawet po cofnięciu nextAttemptAt)
    await makeJobDueNow(acme.id, jobRow.id);
    const later = await deliverPendingMail(db, { authUrl: AUTH_URL, mailer: alwaysFail });
    expect(later.claimed).toBe(0);

    // API zwraca delivery.status = FAILED, attempts = 8 i nigdy nie zawiera lastError
    const listRes = await request("GET", "/core/v1/invitations", ownerToken);
    expect(listRes.statusCode).toBe(200);
    const row = (listRes.json().data as Array<{ id: string; delivery: Record<string, unknown> }>).find(
      (item) => item.id === invId,
    );
    expect(row?.delivery).toMatchObject({
      status: "FAILED",
      attempts: MAIL_MAX_ATTEMPTS,
      sentAt: null,
    });
    expect(typeof row?.delivery.lastAttemptAt).toBe("string");
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

    const summary = await deliverPendingMail(db, { authUrl: AUTH_URL });
    expect(summary).toEqual({ claimed: 1, sent: 1, retried: 0, failed: 0, cancelled: 0, skipped: 0 });

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
      expect(loaded.account.status).toBe("INVITED");

      await tx.invitation.update({
        where: { id: loaded.id },
        data: { status: "ACCEPTED", acceptedAt: new Date() },
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
        },
      }),
    );
    const straySummary = await deliverPendingMail(db, { authUrl: AUTH_URL });
    expect(straySummary).toEqual({ claimed: 1, sent: 0, retried: 0, failed: 0, cancelled: 1, skipped: 0 });
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
      tx.mailOutbox.findMany({ where: { invitationId: invId }, orderBy: [{ createdAt: "asc" }, { id: "asc" }] }),
    );
    expect(jobsAfterFirstResend).toHaveLength(2);
    expect(jobsAfterFirstResend[0]?.id).toBe(firstJob.id);
    expect(jobsAfterFirstResend[0]?.status).toBe("CANCELLED");
    expect(jobsAfterFirstResend[1]?.status).toBe("PENDING");

    const pass1 = await deliverPendingMail(db, { authUrl: AUTH_URL });
    expect(pass1).toEqual({ claimed: 1, sent: 1, retried: 0, failed: 0, cancelled: 0, skipped: 0 });
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
    const pass2 = await deliverPendingMail(db, { authUrl: AUTH_URL });
    expect(pass2).toEqual({ claimed: 1, sent: 1, retried: 0, failed: 0, cancelled: 0, skipped: 0 });
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

    const summary = await deliverPendingMail(db, { authUrl: AUTH_URL });
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
        mailer: async (mail) => {
          sentSingle.push(mail);
          firstMailerEntered.resolve();
          await releaseMailer.promise;
        },
      });
      await firstMailerEntered.promise;

      const p2 = deliverPendingMail(db2, {
        authUrl: AUTH_URL,
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
        deliverPendingMail(db, { limit: 3, authUrl: AUTH_URL, mailer: batchMailer }),
        deliverPendingMail(db2, { limit: 3, authUrl: AUTH_URL, mailer: batchMailer }),
        deliverPendingMail(db, { limit: 3, authUrl: AUTH_URL, mailer: batchMailer }),
      ]);
      await deliverPendingMail(db, { limit: 20, authUrl: AUTH_URL, mailer: batchMailer });

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

      const claimedOnly = await claimMailJobs(db, { limit: 10, leaseMs: 60_000 });
      expect(claimedOnly).toHaveLength(1);
      expect(claimedOnly[0]?.attempts).toBe(1);

      // Przed wygaśnięciem dzierżawy drugie claim nic nie zwraca
      expect(await claimMailJobs(db2, { limit: 10, leaseMs: 60_000 })).toEqual([]);

      // Po wygaśnięciu dzierżawy kolejna próba przejmuje zadanie (attempts = 2) i kończy wysyłkę
      await expireJobLease(acme.id, claimedOnly[0]!.id);
      const recovered = await deliverPendingMail(db2, { authUrl: AUTH_URL });
      expect(recovered).toEqual({ claimed: 1, sent: 1, retried: 0, failed: 0, cancelled: 0, skipped: 0 });
      const leaseJob = await withOrganization(db, acme.id, (tx) =>
        tx.mailOutbox.findFirstOrThrow({ where: { id: claimedOnly[0]!.id } }),
      );
      expect(leaseJob.status).toBe("SENT");
      expect(leaseJob.attempts).toBe(2);
    } finally {
      await db2.$disconnect();
    }
  });

  it("wyścig dzierżawy (ogrodzenie po attempts): spóźniony worker 1 nigdy nie nadpisuje ani nie psuje próby workera 2", async () => {
    const ownerToken = await token(acme);
    const db2 = createDb(appUrl);

    try {
      // Scenariusz A: worker 1 wisi w mailerze, dzierżawa wygasa, worker 2 wysyła i oznacza SENT,
      // a potem worker 1 kończy sukcesem -> zostaje pominięty (skipped: 1), wygrywa link workera 2
      const emailA = `fence-a-${uuidv7().slice(-6)}@${acme.domain}`;
      const invAId = (
        await request("POST", "/core/v1/invitations", ownerToken, {
          email: emailA,
          firstName: "Jan",
          lastName: "OgrodzenieA",
        })
      ).json().data.id as string;
      const jobA = await withOrganization(db, acme.id, (tx) =>
        tx.mailOutbox.findFirstOrThrow({ where: { invitationId: invAId } }),
      );

      const w1PausedA = deferred();
      const w1ReleaseA = deferred();
      let tokenW1A = "";
      let tokenW2A = "";

      const worker1A = deliverPendingMail(db, {
        authUrl: AUTH_URL,
        mailer: async (mail) => {
          tokenW1A = extractTokenFromMail(mail);
          w1PausedA.resolve();
          await w1ReleaseA.promise;
        },
      });
      await w1PausedA.promise;

      await expireJobLease(acme.id, jobA.id);
      const worker2A = await deliverPendingMail(db2, {
        authUrl: AUTH_URL,
        mailer: async (mail) => {
          tokenW2A = extractTokenFromMail(mail);
        },
      });
      expect(worker2A).toEqual({ claimed: 1, sent: 1, retried: 0, failed: 0, cancelled: 0, skipped: 0 });

      w1ReleaseA.resolve();
      const summaryW1A = await worker1A;
      expect(summaryW1A).toEqual({ claimed: 1, sent: 0, retried: 0, failed: 0, cancelled: 0, skipped: 1 });

      const finalJobA = await withOrganization(db, acme.id, (tx) =>
        tx.mailOutbox.findUniqueOrThrow({ where: { id: jobA.id } }),
      );
      expect(finalJobA.status).toBe("SENT");
      expect(finalJobA.attempts).toBe(2);
      expect(tokenW2A).not.toBe(tokenW1A);
      expect(await invitationByTokenHash(db, hashToken(tokenW1A))).toBeNull();
      expect(await invitationByTokenHash(db, hashToken(tokenW2A))).toEqual({
        organizationId: acme.id,
        invitationId: invAId,
      });

      // Scenariusz B (krytyczny z przeglądu): worker 1 wisi w mailerze, dzierżawa wygasa, worker 2 pobiera próbę 2
      // i wisi w mailerze; worker 1 kończy sukcesem PRZED workerem 2, a worker 2 kończy błędem ->
      // worker 1 MUSI zostać pominięty (nie oznacza SENT!), a worker 2 planuje ponowienie (próba 3 dostarcza link)
      const emailB = `fence-b-${uuidv7().slice(-6)}@${acme.domain}`;
      const invBId = (
        await request("POST", "/core/v1/invitations", ownerToken, {
          email: emailB,
          firstName: "Anna",
          lastName: "OgrodzenieB",
        })
      ).json().data.id as string;
      const jobB = await withOrganization(db, acme.id, (tx) =>
        tx.mailOutbox.findFirstOrThrow({ where: { invitationId: invBId } }),
      );

      const w1PausedB = deferred();
      const w1ReleaseB = deferred();
      const w2PausedB = deferred();
      const w2ReleaseB = deferred();

      const worker1B = deliverPendingMail(db, {
        authUrl: AUTH_URL,
        mailer: async () => {
          w1PausedB.resolve();
          await w1ReleaseB.promise;
        },
      });
      await w1PausedB.promise;

      await expireJobLease(acme.id, jobB.id);
      const worker2B = deliverPendingMail(db2, {
        authUrl: AUTH_URL,
        mailer: async () => {
          w2PausedB.resolve();
          await w2ReleaseB.promise;
          throw new Error("421 temporary failure on attempt 2");
        },
      });
      await w2PausedB.promise;

      // Worker 1 kończy sukcesem jako pierwszy -> ogrodzenie po attempts=1 blokuje jego zapis SENT!
      w1ReleaseB.resolve();
      const summaryW1B = await worker1B;
      expect(summaryW1B).toEqual({ claimed: 1, sent: 0, retried: 0, failed: 0, cancelled: 0, skipped: 1 });

      // Worker 2 kończy błędem -> jego zapis ponowienia (attempts=2) przechodzi i zadanie wraca do kolejki
      w2ReleaseB.resolve();
      const summaryW2B = await worker2B;
      expect(summaryW2B).toEqual({ claimed: 1, sent: 0, retried: 1, failed: 0, cancelled: 0, skipped: 0 });

      const midJobB = await withOrganization(db, acme.id, (tx) =>
        tx.mailOutbox.findUniqueOrThrow({ where: { id: jobB.id } }),
      );
      expect(midJobB.status).toBe("PENDING");
      expect(midJobB.attempts).toBe(2);

      // Próba 3 kończy się sukcesem i link z próby 3 działa
      await makeJobDueNow(acme.id, jobB.id);
      let tokenW3B = "";
      const summaryW3B = await deliverPendingMail(db, {
        authUrl: AUTH_URL,
        mailer: async (mail) => {
          tokenW3B = extractTokenFromMail(mail);
        },
      });
      expect(summaryW3B).toEqual({ claimed: 1, sent: 1, retried: 0, failed: 0, cancelled: 0, skipped: 0 });
      expect(await invitationByTokenHash(db, hashToken(tokenW3B))).toEqual({
        organizationId: acme.id,
        invitationId: invBId,
      });

      // Scenariusz C: worker 1 kończy BŁĘDEM po tym, jak worker 2 oznaczył SENT -> worker 1 pominięty, SENT nienaruszone
      const emailC = `fence-c-${uuidv7().slice(-6)}@${acme.domain}`;
      const invCId = (
        await request("POST", "/core/v1/invitations", ownerToken, {
          email: emailC,
          firstName: "Ewa",
          lastName: "OgrodzenieC",
        })
      ).json().data.id as string;
      const jobC = await withOrganization(db, acme.id, (tx) =>
        tx.mailOutbox.findFirstOrThrow({ where: { invitationId: invCId } }),
      );

      const w1PausedC = deferred();
      const w1ReleaseC = deferred();
      let tokenW2C = "";

      const worker1C = deliverPendingMail(db, {
        authUrl: AUTH_URL,
        mailer: async () => {
          w1PausedC.resolve();
          await w1ReleaseC.promise;
          throw new Error("late timeout from worker 1");
        },
      });
      await w1PausedC.promise;

      await expireJobLease(acme.id, jobC.id);
      const worker2C = await deliverPendingMail(db2, {
        authUrl: AUTH_URL,
        mailer: async (mail) => {
          tokenW2C = extractTokenFromMail(mail);
        },
      });
      expect(worker2C).toEqual({ claimed: 1, sent: 1, retried: 0, failed: 0, cancelled: 0, skipped: 0 });

      w1ReleaseC.resolve();
      const summaryW1C = await worker1C;
      expect(summaryW1C).toEqual({ claimed: 1, sent: 0, retried: 0, failed: 0, cancelled: 0, skipped: 1 });

      const finalJobC = await withOrganization(db, acme.id, (tx) =>
        tx.mailOutbox.findUniqueOrThrow({ where: { id: jobC.id } }),
      );
      expect(finalJobC.status).toBe("SENT");
      expect(finalJobC.attempts).toBe(2);
      expect(finalJobC.lastError).toBeNull();
      expect(await invitationByTokenHash(db, hashToken(tokenW2C))).toEqual({
        organizationId: acme.id,
        invitationId: invCId,
      });
    } finally {
      await db2.$disconnect();
    }
  });

  it("wyścigi podczas pauzy w mailerze: resend, revoke oraz accept (sukces i błąd mailera)", async () => {
    const ownerToken = await token(acme);

    // 1. Resend podczas pauzy w mailerze -> job1 zostaje CANCELLED, worker 1 zwraca skipped, stary link nie działa, job2 działa
    const resendEmail = `race-resend-${uuidv7().slice(-6)}@${acme.domain}`;
    const resendInvId = (
      await request("POST", "/core/v1/invitations", ownerToken, {
        email: resendEmail,
        firstName: "Karol",
        lastName: "WyscigResend",
      })
    ).json().data.id as string;
    const jobResend1 = await withOrganization(db, acme.id, (tx) =>
      tx.mailOutbox.findFirstOrThrow({ where: { invitationId: resendInvId } }),
    );

    const pausedResend = deferred();
    const releaseResend = deferred();
    let staleToken = "";
    const inFlightResend = deliverPendingMail(db, {
      authUrl: AUTH_URL,
      mailer: async (mail) => {
        staleToken = extractTokenFromMail(mail);
        pausedResend.resolve();
        await releaseResend.promise;
      },
    });
    await pausedResend.promise;

    expect((await request("POST", `/core/v1/invitations/${resendInvId}/resend`, ownerToken)).statusCode).toBe(200);
    releaseResend.resolve();
    expect(await inFlightResend).toEqual({ claimed: 1, sent: 0, retried: 0, failed: 0, cancelled: 0, skipped: 1 });

    expect(
      (await withOrganization(db, acme.id, (tx) => tx.mailOutbox.findUniqueOrThrow({ where: { id: jobResend1.id } })))
        .status,
    ).toBe("CANCELLED");
    expect(await invitationByTokenHash(db, hashToken(staleToken))).toBeNull();

    // Nowe zadanie z resend dostarcza działający link
    let freshToken = "";
    const afterResend = await deliverPendingMail(db, {
      authUrl: AUTH_URL,
      mailer: async (mail) => {
        freshToken = extractTokenFromMail(mail);
      },
    });
    expect(afterResend).toEqual({ claimed: 1, sent: 1, retried: 0, failed: 0, cancelled: 0, skipped: 0 });
    expect(await invitationByTokenHash(db, hashToken(freshToken))).toEqual({
      organizationId: acme.id,
      invitationId: resendInvId,
    });

    // 2. Revoke podczas pauzy w mailerze -> job zostaje CANCELLED, worker zwraca skipped, zaproszenie zostaje REVOKED
    const revokeEmail = `race-revoke-${uuidv7().slice(-6)}@${acme.domain}`;
    const revokeInvId = (
      await request("POST", "/core/v1/invitations", ownerToken, {
        email: revokeEmail,
        firstName: "Piotr",
        lastName: "WyscigRevoke",
      })
    ).json().data.id as string;
    const jobRevoke = await withOrganization(db, acme.id, (tx) =>
      tx.mailOutbox.findFirstOrThrow({ where: { invitationId: revokeInvId } }),
    );

    const pausedRevoke = deferred();
    const releaseRevoke = deferred();
    const inFlightRevoke = deliverPendingMail(db, {
      authUrl: AUTH_URL,
      mailer: async () => {
        pausedRevoke.resolve();
        await releaseRevoke.promise;
      },
    });
    await pausedRevoke.promise;

    expect((await request("DELETE", `/core/v1/invitations/${revokeInvId}`, ownerToken)).statusCode).toBe(204);
    releaseRevoke.resolve();
    expect(await inFlightRevoke).toEqual({ claimed: 1, sent: 0, retried: 0, failed: 0, cancelled: 0, skipped: 1 });

    const [revokedInv, cancelledJob] = await withOrganization(db, acme.id, (tx) =>
      Promise.all([
        tx.invitation.findUniqueOrThrow({ where: { id: revokeInvId } }),
        tx.mailOutbox.findUniqueOrThrow({ where: { id: jobRevoke.id } }),
      ]),
    );
    expect(revokedInv.status).toBe("REVOKED");
    expect(cancelledJob.status).toBe("CANCELLED");

    // 3a. Accept podczas pauzy w mailerze (mailer kończy sukcesem) -> zadanie SENT, zaproszenie pozostaje ACCEPTED
    const acceptOkEmail = `race-accept-ok-${uuidv7().slice(-6)}@${acme.domain}`;
    const acceptOkInv = (
      await request("POST", "/core/v1/invitations", ownerToken, {
        email: acceptOkEmail,
        firstName: "Alicja",
        lastName: "AkceptOk",
      })
    ).json().data as { id: string; accountId: string };
    const jobAcceptOk = await withOrganization(db, acme.id, (tx) =>
      tx.mailOutbox.findFirstOrThrow({ where: { invitationId: acceptOkInv.id } }),
    );

    const pausedAcceptOk = deferred();
    const releaseAcceptOk = deferred();
    const inFlightAcceptOk = deliverPendingMail(db, {
      authUrl: AUTH_URL,
      mailer: async () => {
        pausedAcceptOk.resolve();
        await releaseAcceptOk.promise;
      },
    });
    await pausedAcceptOk.promise;

    await withOrganization(db, acme.id, async (tx) => {
      await tx.invitation.update({
        where: { id: acceptOkInv.id },
        data: { status: "ACCEPTED", acceptedAt: new Date() },
      });
      await tx.account.update({ where: { id: acceptOkInv.accountId }, data: { status: "ACTIVE" } });
    });
    releaseAcceptOk.resolve();
    expect(await inFlightAcceptOk).toEqual({ claimed: 1, sent: 1, retried: 0, failed: 0, cancelled: 0, skipped: 0 });
    expect(
      (await withOrganization(db, acme.id, (tx) => tx.mailOutbox.findUniqueOrThrow({ where: { id: jobAcceptOk.id } })))
        .status,
    ).toBe("SENT");

    // 3b. Accept podczas pauzy w mailerze (mailer rzuca błąd) -> zadanie CANCELLED bez ponowień, zaproszenie ACCEPTED
    const acceptFailEmail = `race-accept-fail-${uuidv7().slice(-6)}@${acme.domain}`;
    const acceptFailInv = (
      await request("POST", "/core/v1/invitations", ownerToken, {
        email: acceptFailEmail,
        firstName: "Beata",
        lastName: "AkceptBlad",
      })
    ).json().data as { id: string; accountId: string };
    const jobAcceptFail = await withOrganization(db, acme.id, (tx) =>
      tx.mailOutbox.findFirstOrThrow({ where: { invitationId: acceptFailInv.id } }),
    );

    const pausedAcceptFail = deferred();
    const releaseAcceptFail = deferred();
    const inFlightAcceptFail = deliverPendingMail(db, {
      authUrl: AUTH_URL,
      mailer: async () => {
        pausedAcceptFail.resolve();
        await releaseAcceptFail.promise;
        throw new Error("451 delayed SMTP failure");
      },
    });
    await pausedAcceptFail.promise;

    await withOrganization(db, acme.id, async (tx) => {
      await tx.invitation.update({
        where: { id: acceptFailInv.id },
        data: { status: "ACCEPTED", acceptedAt: new Date() },
      });
      await tx.account.update({ where: { id: acceptFailInv.accountId }, data: { status: "ACTIVE" } });
    });
    releaseAcceptFail.resolve();
    expect(await inFlightAcceptFail).toEqual({ claimed: 1, sent: 0, retried: 0, failed: 0, cancelled: 1, skipped: 0 });
    expect(
      (
        await withOrganization(db, acme.id, (tx) =>
          tx.mailOutbox.findUniqueOrThrow({ where: { id: jobAcceptFail.id } }),
        )
      ).status,
    ).toBe("CANCELLED");
  });

  it("wyścig CLI claimMailJobById kontra deliverPendingMail na tym samym zadaniu wysyła dokładnie 1 wiadomość", async () => {
    const db2 = createDb(appUrl);
    try {
      const cliEmail = `cli-race-${uuidv7().slice(-6)}@${acme.domain}`;
      const created = await createInvitationByOrganization(db, {
        organization: acme.id,
        email: cliEmail,
        firstName: "Marek",
        lastName: "CliWyscig",
      });

      const delivered: OutgoingMail[] = [];
      const sharedMailer = async (mail: OutgoingMail) => {
        delivered.push(mail);
      };

      const cliAttempt = async () => {
        const claimed = await claimMailJobById(db, created.organizationId, created.mailJobId);
        if (!claimed) return null;
        return deliverMailJob(db, claimed, { authUrl: AUTH_URL, mailer: sharedMailer });
      };

      const [cliOutcome, workerOutcome] = await Promise.all([
        cliAttempt(),
        deliverPendingMail(db2, { authUrl: AUTH_URL, mailer: sharedMailer }),
      ]);

      const cliSent = cliOutcome?.status === "SENT" ? 1 : 0;
      expect(cliSent + workerOutcome.sent).toBe(1);
      expect(delivered).toHaveLength(1);
      expect(delivered[0]?.to).toBe(cliEmail);
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

    await deliverPendingMail(db, { authUrl: AUTH_URL });

    const listAfterSend = await request("GET", "/core/v1/invitations", ownerToken);
    expect(listAfterSend.statusCode).toBe(200);
    const sentRow = (listAfterSend.json().data as Array<{ id: string; delivery: Record<string, unknown> }>).find(
      (item) => item.id === invId,
    );
    expect(sentRow?.delivery).toMatchObject({
      status: "SENT",
      attempts: 1,
    });
    expect(typeof sentRow?.delivery.lastAttemptAt).toBe("string");
    expect(typeof sentRow?.delivery.sentAt).toBe("string");

    // Resend natychmiast tworzy nowszy wiersz PENDING (attempts=0) widoczny w odpowiedzi i na liście
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

  it("mail_outbox_cleanup usuwa stare SENT/CANCELLED oraz zastąpione FAILED, więc delivery nigdy nie cofa się z SENT do FAILED", async () => {
    const ownerToken = await token(acme);

    // Zaproszenie 1: zestaw podstawowych wierszy (stare i świeże SENT/CANCELLED, stary PENDING, jedyny stary FAILED)
    const invBaseId = (
      await request("POST", "/core/v1/invitations", ownerToken, {
        email: `cleanup-base-${uuidv7().slice(-6)}@${acme.domain}`,
        firstName: "Sprzatanie",
        lastName: "Podstawowe",
      })
    ).json().data.id as string;

    // Zaproszenie 2: stary FAILED (35 dni) + świeży SENT (5 dni) -> po cleanup zostaje SENT (stary FAILED usunięty)
    const invKeepSentId = (
      await request("POST", "/core/v1/invitations", ownerToken, {
        email: `cleanup-keep-sent-${uuidv7().slice(-6)}@${acme.domain}`,
        firstName: "Sprzatanie",
        lastName: "ZostawSent",
      })
    ).json().data.id as string;

    // Zaproszenie 3: stary FAILED (35 dni) + stary SENT (31 dni) -> nawet przy porcji=1 znikają oba (FAILED najpierw)
    const invBothOldId = (
      await request("POST", "/core/v1/invitations", ownerToken, {
        email: `cleanup-both-old-${uuidv7().slice(-6)}@${acme.domain}`,
        firstName: "Sprzatanie",
        lastName: "ObaStare",
      })
    ).json().data.id as string;

    // Zaproszenie 4: jedyny wiersz to stary FAILED (35 dni, brak nowszego) -> zostaje zachowany do diagnostyki
    const invSoleFailedId = (
      await request("POST", "/core/v1/invitations", ownerToken, {
        email: `cleanup-sole-fail-${uuidv7().slice(-6)}@${acme.domain}`,
        firstName: "Sprzatanie",
        lastName: "JedynyFailed",
      })
    ).json().data.id as string;

    await withOrganization(ownerDb, acme.id, (tx) => tx.mailOutbox.deleteMany({}));

    const oldSentId = uuidv7();
    const recentSentId = uuidv7();
    const oldCancelledId = uuidv7();
    const recentCancelledId = uuidv7();
    const oldPendingId = uuidv7();
    const soleOldFailedId = uuidv7();
    const supersededOldFailedKeepId = uuidv7();
    const newerRecentSentId = uuidv7();
    const supersededOldFailedBothId = uuidv7();
    const newerOldSentId = uuidv7();

    // Wstawiamy wiersze z datami liczonymi względem now() PostgreSQL
    await withOrganization(ownerDb, acme.id, async (tx) => {
      await tx.$executeRaw`
        INSERT INTO "public"."mail_outbox"
          ("id", "organizationId", "kind", "invitationId", "status", "attempts", "nextAttemptAt", "lastAttemptAt", "sentAt", "failedAt", "lastError", "createdAt", "updatedAt")
        VALUES
          (${oldSentId}::uuid, ${acme.id}::uuid, 'INVITATION', ${invBaseId}::uuid, 'SENT', 1, now() - interval '31 days', now() - interval '31 days', now() - interval '31 days', NULL, NULL, now() - interval '31 days', now() - interval '31 days'),
          (${recentSentId}::uuid, ${acme.id}::uuid, 'INVITATION', ${invBaseId}::uuid, 'SENT', 1, now() - interval '5 days', now() - interval '5 days', now() - interval '5 days', NULL, NULL, now() - interval '5 days', now() - interval '5 days'),
          (${oldCancelledId}::uuid, ${acme.id}::uuid, 'INVITATION', ${invBaseId}::uuid, 'CANCELLED', 0, now() - interval '31 days', NULL, NULL, NULL, NULL, now() - interval '31 days', now() - interval '31 days'),
          (${recentCancelledId}::uuid, ${acme.id}::uuid, 'INVITATION', ${invBaseId}::uuid, 'CANCELLED', 0, now() - interval '5 days', NULL, NULL, NULL, NULL, now() - interval '5 days', now() - interval '5 days'),
          (${oldPendingId}::uuid, ${acme.id}::uuid, 'INVITATION', ${invBaseId}::uuid, 'PENDING', 0, now() - interval '31 days', NULL, NULL, NULL, NULL, now() - interval '31 days', now() - interval '31 days'),
          (${soleOldFailedId}::uuid, ${acme.id}::uuid, 'INVITATION', ${invSoleFailedId}::uuid, 'FAILED', ${MAIL_MAX_ATTEMPTS}::integer, now() - interval '35 days', now() - interval '35 days', NULL, now() - interval '35 days', '550 permanent error', now() - interval '35 days', now() - interval '35 days'),
          (${supersededOldFailedKeepId}::uuid, ${acme.id}::uuid, 'INVITATION', ${invKeepSentId}::uuid, 'FAILED', ${MAIL_MAX_ATTEMPTS}::integer, now() - interval '35 days', now() - interval '35 days', NULL, now() - interval '35 days', '550 old error', now() - interval '35 days', now() - interval '35 days'),
          (${newerRecentSentId}::uuid, ${acme.id}::uuid, 'INVITATION', ${invKeepSentId}::uuid, 'SENT', 1, now() - interval '5 days', now() - interval '5 days', now() - interval '5 days', NULL, NULL, now() - interval '5 days', now() - interval '5 days'),
          (${supersededOldFailedBothId}::uuid, ${acme.id}::uuid, 'INVITATION', ${invBothOldId}::uuid, 'FAILED', ${MAIL_MAX_ATTEMPTS}::integer, now() - interval '35 days', now() - interval '35 days', NULL, now() - interval '35 days', '550 old error', now() - interval '35 days', now() - interval '35 days'),
          (${newerOldSentId}::uuid, ${acme.id}::uuid, 'INVITATION', ${invBothOldId}::uuid, 'SENT', 1, now() - interval '31 days', now() - interval '31 days', now() - interval '31 days', NULL, NULL, now() - interval '31 days', now() - interval '31 days')`;
    });

    // Uruchamiamy sprzątanie z porcjami po 1 wierszu, żeby zweryfikować kolejność usuwania i brak cofnięcia delivery
    const deleted = await cleanupOldMailJobs(db, 1);
    expect(deleted).toBeGreaterThanOrEqual(5);

    const remainingIds = (
      await withOrganization(db, acme.id, (tx) => tx.mailOutbox.findMany({ select: { id: true } }))
    ).map((row) => row.id);
    expect(remainingIds.sort()).toEqual(
      [recentSentId, recentCancelledId, oldPendingId, soleOldFailedId, newerRecentSentId].sort(),
    );

    const listRes = await request("GET", "/core/v1/invitations?limit=100", ownerToken);
    expect(listRes.statusCode).toBe(200);
    const byId = new Map(
      (listRes.json().data as Array<{ id: string; delivery: { status: string | null } }>).map((row) => [
        row.id,
        row.delivery.status,
      ]),
    );
    expect(byId.get(invKeepSentId)).toBe("SENT");
    expect(byId.get(invBothOldId)).toBeNull();
    expect(byId.get(invSoleFailedId)).toBe("FAILED");
  });
});
