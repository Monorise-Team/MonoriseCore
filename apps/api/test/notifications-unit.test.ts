import {
  DIRECTORY_READ_SCOPE,
  IDEMPOTENCY_KEY_HEADER,
  IDEMPOTENCY_REPLAYED_HEADER,
  NOTIFICATIONS_SEND_SCOPE,
} from "@core/contracts";
import type { PrismaClient } from "@core/db";
import { afterEach, describe, expect, it } from "vitest";
import {
  clearSentMails,
  clearSentNotificationMails,
  escapeHtml,
  notificationMail,
  resolveNotificationsMailConfig,
  sendNotificationMail,
  sentMails,
  sentNotificationMails,
  type OutgoingMail,
} from "../src/mail.js";
import { deliverMailJob, MAIL_MAX_ATTEMPTS, type ClaimedMailJob } from "../src/mail-outbox.js";
import {
  buildUnsubscribeUrl,
  createUnsubscribeToken,
  MIN_NOTIFICATIONS_UNSUBSCRIBE_SECRET_LENGTH,
  NotificationError,
  resolveApiUrl,
  resolveNotificationsUnsubscribeSecret,
  validateActionUrlOrigin,
  verifyUnsubscribeToken,
} from "../src/notifications.js";
import { buildServer } from "../src/server.js";

const ORG_ID = "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6a01";
const OTHER_ORG_ID = "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6a02";
const OWNER_ACC_ID = "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6a11";
const OWNER_EMP_ID = "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6a12";
const MEMBER_ACC_ID = "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6a21";
const MEMBER_EMP_ID = "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6a22";
const NO_ACCESS_ACC_ID = "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6a31";
const NO_ACCESS_EMP_ID = "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6a32";
const TIMOTIME_PROD_ID = "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6a41";
const KIVOTASKS_PROD_ID = "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6a42";
const NOTIF_ID = "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6a51";
const JOB_ID = "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6a52";

const TEST_UNSUBSCRIBE_SECRET = "test-unsubscribe-secret-0123456789abcdef";

const ORIGINAL_ENV = {
  NODE_ENV: process.env.NODE_ENV,
  CORE_SMTP_URL: process.env.CORE_SMTP_URL,
  CORE_MAIL_FROM: process.env.CORE_MAIL_FROM,
  CORE_NOTIFICATIONS_SMTP_URL: process.env.CORE_NOTIFICATIONS_SMTP_URL,
  CORE_NOTIFICATIONS_FROM: process.env.CORE_NOTIFICATIONS_FROM,
  CORE_NOTIFICATIONS_UNSUBSCRIBE_SECRET: process.env.CORE_NOTIFICATIONS_UNSUBSCRIBE_SECRET,
};

function restoreEnv(): void {
  for (const [key, value] of Object.entries(ORIGINAL_ENV)) {
    if (value === undefined) {
      delete process.env[key];
    } else {
      process.env[key] = value;
    }
  }
}

afterEach(() => {
  restoreEnv();
  clearSentMails();
  clearSentNotificationMails();
});

describe("Moduł powiadomień — testy jednostkowe bez bazy (MonoriseCore#86)", () => {
  it("podpisuje i weryfikuje token wypisania HMAC-SHA256 w stałym czasie, odrzucając zmanipulowane i nieopcjonalne tokeny", () => {
    const token = createUnsubscribeToken(
      { organizationId: ORG_ID, accountId: MEMBER_ACC_ID, category: "timotime.reminders" },
      TEST_UNSUBSCRIBE_SECRET,
    );
    expect(token).toMatch(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
    expect(verifyUnsubscribeToken(token, TEST_UNSUBSCRIBE_SECRET)).toEqual({
      organizationId: ORG_ID,
      accountId: MEMBER_ACC_ID,
      category: "timotime.reminders",
    });

    const [payloadPart, sigPart] = token.split(".");
    const flippedSig = `${sigPart![0] === "A" ? "B" : "A"}${sigPart!.slice(1)}`;
    const tamperedPayload = Buffer.from(
      JSON.stringify({ organizationId: OTHER_ORG_ID, accountId: MEMBER_ACC_ID, category: "timotime.reminders" }),
      "utf8",
    ).toString("base64url");

    // Manipulacja podpisem, ładunkiem, inny sekret, zły format i kategorie obowiązkowe (security/account)
    expect(verifyUnsubscribeToken(`${payloadPart}.${flippedSig}`, TEST_UNSUBSCRIBE_SECRET)).toBeNull();
    expect(verifyUnsubscribeToken(`${tamperedPayload}.${sigPart}`, TEST_UNSUBSCRIBE_SECRET)).toBeNull();
    expect(verifyUnsubscribeToken(token, "inny-sekret-0123456789abcdef01234567")).toBeNull();
    expect(verifyUnsubscribeToken("", TEST_UNSUBSCRIBE_SECRET)).toBeNull();
    expect(verifyUnsubscribeToken("bez-kropki", TEST_UNSUBSCRIBE_SECRET)).toBeNull();
    expect(verifyUnsubscribeToken(`${payloadPart}.${sigPart}.extra`, TEST_UNSUBSCRIBE_SECRET)).toBeNull();
    expect(verifyUnsubscribeToken("not+base64.abc", TEST_UNSUBSCRIBE_SECRET)).toBeNull();
    expect(verifyUnsubscribeToken("a".repeat(1025), TEST_UNSUBSCRIBE_SECRET)).toBeNull();

    // Nawet podpisany token z kategorią obowiązkową `security` lub `account` musi zostać odrzucony
    const securityToken = createUnsubscribeToken(
      { organizationId: ORG_ID, accountId: MEMBER_ACC_ID, category: "security" },
      TEST_UNSUBSCRIBE_SECRET,
    );
    expect(verifyUnsubscribeToken(securityToken, TEST_UNSUBSCRIBE_SECRET)).toBeNull();

    const accountToken = createUnsubscribeToken(
      { organizationId: ORG_ID, accountId: MEMBER_ACC_ID, category: "account" },
      TEST_UNSUBSCRIBE_SECRET,
    );
    expect(verifyUnsubscribeToken(accountToken, TEST_UNSUBSCRIBE_SECRET)).toBeNull();
  });

  it("wymaga CORE_NOTIFICATIONS_UNSUBSCRIBE_SECRET (>= 32 znaki) na produkcji, a poza produkcją wyprowadza go z sekretu dev", () => {
    expect(() =>
      resolveNotificationsUnsubscribeSecret({
        env: { NODE_ENV: "production", CORE_DOMAIN_VERIFICATION_SECRET: "d".repeat(40) },
        fallbackSecret: "f".repeat(40),
      }),
    ).toThrow(/CORE_NOTIFICATIONS_UNSUBSCRIBE_SECRET/);

    expect(() =>
      resolveNotificationsUnsubscribeSecret({
        env: {
          NODE_ENV: "production",
          CORE_NOTIFICATIONS_UNSUBSCRIBE_SECRET: `  ${"x".repeat(MIN_NOTIFICATIONS_UNSUBSCRIBE_SECRET_LENGTH - 1)}  `,
        },
      }),
    ).toThrow(/CORE_NOTIFICATIONS_UNSUBSCRIBE_SECRET/);

    expect(
      resolveNotificationsUnsubscribeSecret({
        env: {
          NODE_ENV: "production",
          CORE_NOTIFICATIONS_UNSUBSCRIBE_SECRET: `  ${"x".repeat(MIN_NOTIFICATIONS_UNSUBSCRIBE_SECRET_LENGTH)}  `,
        },
      }),
    ).toBe("x".repeat(MIN_NOTIFICATIONS_UNSUBSCRIBE_SECRET_LENGTH));

    // W development bez jawnego sekretu wyprowadza deterministyczny sekret z CORE_DOMAIN_VERIFICATION_SECRET (różny od niego)
    const devBase = "local-domain-secret-0123456789abcdef";
    const derived1 = resolveNotificationsUnsubscribeSecret({
      env: { NODE_ENV: "development", CORE_DOMAIN_VERIFICATION_SECRET: devBase },
    });
    const derived2 = resolveNotificationsUnsubscribeSecret({
      env: { NODE_ENV: "development", CORE_DOMAIN_VERIFICATION_SECRET: devBase },
    });
    expect(derived1).toBe(derived2);
    expect(derived1).not.toBe(devBase);
    expect(derived1.length).toBeGreaterThanOrEqual(32);

    // W development jawna wartość wygrywa nad fallbackiem
    expect(
      resolveNotificationsUnsubscribeSecret({
        env: {
          NODE_ENV: "development",
          CORE_NOTIFICATIONS_UNSUBSCRIBE_SECRET: "  explicit-dev-secret  ",
          CORE_DOMAIN_VERIFICATION_SECRET: devBase,
        },
      }),
    ).toBe("explicit-dev-secret");

    // Brak obu sekretów w development rzuca błąd
    expect(() => resolveNotificationsUnsubscribeSecret({ env: { NODE_ENV: "development" } })).toThrow(
      /CORE_NOTIFICATIONS_UNSUBSCRIBE_SECRET/,
    );
  });

  it("wymaga CORE_NOTIFICATIONS_SMTP_URL i CORE_NOTIFICATIONS_FROM na produkcji, a poza produkcją wraca do kanału logowania", async () => {
    expect(() =>
      resolveNotificationsMailConfig({
        NODE_ENV: "production",
        CORE_SMTP_URL: "smtp://login.example:587",
        CORE_MAIL_FROM: "Monorise <no-reply@monorise.studio>",
      }),
    ).toThrow(/CORE_NOTIFICATIONS_SMTP_URL/);

    expect(() =>
      resolveNotificationsMailConfig({
        NODE_ENV: "production",
        CORE_NOTIFICATIONS_SMTP_URL: "smtp://notify.example:587",
      }),
    ).toThrow(/CORE_NOTIFICATIONS_FROM/);

    expect(
      resolveNotificationsMailConfig({
        NODE_ENV: "production",
        CORE_NOTIFICATIONS_SMTP_URL: "  smtp://notify.example:587  ",
        CORE_NOTIFICATIONS_FROM: "  Monorise Powiadomienia <notifications@monorise.studio>  ",
      }),
    ).toEqual({
      smtpUrl: "smtp://notify.example:587",
      from: "Monorise Powiadomienia <notifications@monorise.studio>",
    });

    expect(
      resolveNotificationsMailConfig({
        NODE_ENV: "development",
        CORE_SMTP_URL: "smtp://localhost:1125",
        CORE_MAIL_FROM: "Monorise <no-reply@monorise.studio>",
      }),
    ).toEqual({
      smtpUrl: "smtp://localhost:1125",
      from: "Monorise <no-reply@monorise.studio>",
    });

    // W trybie memory sendNotificationMail trafia do osobnego bufora powiadomień (kanał logowania pozostaje czysty)
    process.env.NODE_ENV = "test";
    process.env.CORE_NOTIFICATIONS_SMTP_URL = "memory";
    process.env.CORE_NOTIFICATIONS_FROM = "Powiadomienia <notify@monorise.studio>";
    await sendNotificationMail({
      to: "anna@acme.test",
      subject: "Test",
      text: "Treść",
      html: "<p>Treść</p>",
      headers: { "List-Unsubscribe-Post": "List-Unsubscribe=One-Click" },
    });
    expect(sentMails()).toHaveLength(0);
    expect(sentNotificationMails()).toHaveLength(1);
    expect(sentNotificationMails()[0]?.from).toBe("Powiadomienia <notify@monorise.studio>");
  });

  it("renderuje wspólny układ e-maila powiadomienia z nagłówkami RFC 8058 i koduje cały tekst produktu w HTML", () => {
    expect(escapeHtml(`<script>alert("x" & 'y')</script>`)).toBe(
      "&lt;script&gt;alert(&quot;x&quot; &amp; &#39;y&#39;)&lt;/script&gt;",
    );

    const apiUrl = resolveApiUrl("https://api.monorise.studio/");
    expect(apiUrl).toBe("https://api.monorise.studio");
    const unsubscribeUrl = buildUnsubscribeUrl("tok.sig", apiUrl);
    expect(unsubscribeUrl).toBe("https://api.monorise.studio/core/v1/notifications/unsubscribe/tok.sig");

    const mail = notificationMail({
      to: "jan@acme.test",
      productName: `KivoTasks <"Beta">`,
      organizationName: "Acme & Synowie",
      categoryName: "Przypisane zadania KivoTasks",
      title: `Zadanie <img src=x onerror=alert(1)> "KT-7"\nnowa linia`,
      body: "Linia 1 <b>nie-html</b>\nLinia 2 'cytat' & znak",
      actionUrl: `https://kivotasks.monorise.studio/issues/KT-7?a=1&b="2"`,
      unsubscribeUrl,
    });

    expect(mail.to).toBe("jan@acme.test");
    expect(mail.subject).not.toMatch(/[\r\n]/);
    expect(mail.subject).toContain("KT-7");
    expect(mail.headers).toEqual({
      "List-Unsubscribe": `<${unsubscribeUrl}>`,
      "List-Unsubscribe-Post": "List-Unsubscribe=One-Click",
    });

    // Tekst zawiera nazwę produktu, tytuł, treść, link akcji i stopkę z linkiem wypisania
    expect(mail.text).toContain("KivoTasks");
    expect(mail.text).toContain("Acme & Synowie");
    expect(mail.text).toContain("Linia 1 <b>nie-html</b>\nLinia 2 'cytat' & znak");
    expect(mail.text).toContain(`https://kivotasks.monorise.studio/issues/KT-7?a=1&b="2"`);
    expect(mail.text).toContain(unsubscribeUrl);

    // HTML bezpiecznie koduje wszystkie dane produktu i zachowuje łamanie linii jako <br>
    expect(mail.html).not.toContain("<img ");
    expect(mail.html).not.toContain("<b>nie-html</b>");
    expect(mail.html).toContain("&lt;img src=x onerror=alert(1)&gt;");
    expect(mail.html).toContain("&lt;b&gt;nie-html&lt;/b&gt;<br>Linia 2 &#39;cytat&#39; &amp; znak");
    expect(mail.html).toContain("Acme &amp; Synowie");
    expect(mail.html).toContain(`href="https://kivotasks.monorise.studio/issues/KT-7?a=1&amp;b=&quot;2&quot;"`);
    expect(mail.html).toContain(`href="${unsubscribeUrl}"`);

    // Brak actionUrl nie renderuje przycisku akcji
    const withoutAction = notificationMail({
      to: "jan@acme.test",
      productName: "TimoTime",
      organizationName: "Acme",
      categoryName: "Przypomnienia TimoTime",
      title: "Przypomnienie",
      body: "Uzupełnij godziny.",
      actionUrl: null,
      unsubscribeUrl,
    });
    expect(withoutAction.text).not.toContain("Otwórz w TimoTime:");
    expect(withoutAction.html).not.toContain("Otwórz w TimoTime");
    expect(withoutAction.html).toContain(unsubscribeUrl);
  });

  it("waliduje origin actionUrl względem uri klienta OAuth produktu", () => {
    expect(() =>
      validateActionUrlOrigin(
        "http://timo-time.localhost:3300/app/entries?week=48#top",
        "http://timo-time.localhost:3300/app",
      ),
    ).not.toThrow();
    expect(() =>
      validateActionUrlOrigin("https://kivotasks.monorise.studio/issues/KT-1", "https://kivotasks.monorise.studio/"),
    ).not.toThrow();

    for (const [actionUrl, clientUri] of [
      ["https://evil.example/phish", "https://kivotasks.monorise.studio/"],
      ["https://sub.kivotasks.monorise.studio/x", "https://kivotasks.monorise.studio/"],
      ["http://kivotasks.monorise.studio/issues/KT-1", "https://kivotasks.monorise.studio/"],
      ["http://timo-time.localhost:3301/app", "http://timo-time.localhost:3300/app"],
      ["https://user:pass@kivotasks.monorise.studio/issues/KT-1", "https://kivotasks.monorise.studio/"],
      ["javascript:alert(1)", "https://kivotasks.monorise.studio/"],
      ["https://kivotasks.monorise.studio/issues/KT-1", null],
    ] as const) {
      let caught: unknown;
      try {
        validateActionUrlOrigin(actionUrl, clientUri);
      } catch (error) {
        caught = error;
      }
      expect(caught, `Powinno odrzucić ${actionUrl}`).toBeInstanceOf(NotificationError);
      expect(caught).toMatchObject({ status: 422, code: "VALIDATION_FAILED" });
    }
  });

  it("deliverMailJob obsługuje NOTIFICATION: wysyłkę, pominięcie po wyłączeniu preferencji, ponowienie, FAILED po 8. próbie i fencing", async () => {
    const now = new Date("2026-11-27T10:00:00.000Z");

    const buildJobFixture = (opts: {
      attempts?: number;
      jobAttemptsInDb?: number;
      prefEnabled?: boolean;
      hasAppAccess?: boolean;
    }) => {
      const state = {
        notificationStatus: "QUEUED" as string,
        notificationSkipReason: null as string | null,
        notificationSentAt: null as Date | null,
        outboxStatus: "PENDING" as string,
      };
      const job: ClaimedMailJob = {
        id: JOB_ID,
        organizationId: ORG_ID,
        kind: "NOTIFICATION",
        invitationId: null,
        notificationId: NOTIF_ID,
        attempts: opts.attempts ?? 1,
      };

      const fakeDb = {
        $transaction: async <T>(fn: (tx: unknown) => Promise<T>): Promise<T> => {
          const tx = {
            $executeRaw: async (strings: TemplateStringsArray) => {
              const sql = strings.join(" ");
              if (sql.includes('UPDATE "public"."mail_outbox"')) {
                if ((opts.jobAttemptsInDb ?? job.attempts) !== job.attempts) return 0;
                if (sql.includes("'CANCELLED'")) state.outboxStatus = "CANCELLED";
                if (sql.includes("'FAILED'")) state.outboxStatus = "FAILED";
              }
              return 1;
            },
            $queryRaw: async (strings: TemplateStringsArray) => {
              const sql = strings.join(" ");
              if (sql.includes('RETURNING "sentAt"')) {
                if ((opts.jobAttemptsInDb ?? job.attempts) !== job.attempts) return [];
                state.outboxStatus = "SENT";
                return [{ sentAt: now }];
              }
              return [{ now }];
            },
            mailOutbox: {
              findUnique: async () => ({
                status: state.outboxStatus,
                attempts: opts.jobAttemptsInDb ?? job.attempts,
              }),
            },
            notification: {
              findUnique: async () => ({
                id: NOTIF_ID,
                product: "timotime",
                category: "timotime.reminders",
                recipientAccountId: MEMBER_ACC_ID,
                title: "Uzupełnij czas pracy",
                body: "Brakuje wpisu za piątek.",
                actionUrl: "http://timo-time.localhost:3300/app",
                status: state.notificationStatus,
                organization: { name: "Acme" },
              }),
              updateMany: async ({
                data,
              }: {
                data: { status?: string; skipReason?: string | null; sentAt?: Date | null };
              }) => {
                if (data.status !== undefined) state.notificationStatus = data.status;
                if (data.skipReason !== undefined) state.notificationSkipReason = data.skipReason;
                if (data.sentAt !== undefined) state.notificationSentAt = data.sentAt;
                return { count: 1 };
              },
            },
            product: {
              findUnique: async () => ({ id: TIMOTIME_PROD_ID, key: "timotime", name: "TimoTime" }),
            },
            entitlement: {
              findFirst: async () => ({ id: "ent-1" }),
            },
            account: {
              findUnique: async () => ({
                id: MEMBER_ACC_ID,
                email: "jan@acme.test",
                status: "ACTIVE",
                employee: { status: "ACTIVE" },
                organization: { ownerAccountId: OWNER_ACC_ID },
              }),
            },
            appAccess: {
              findFirst: async () => (opts.hasAppAccess === false ? null : { id: "aa-1" }),
            },
            notificationPreference: {
              findUnique: async () => (opts.prefEnabled === false ? { enabled: false } : null),
            },
          };
          return fn(tx);
        },
      } as unknown as PrismaClient;

      return { job, fakeDb, state };
    };

    // 1. Sukces: wysyła przez notificationsMailer (nie mailer), oznacza SENT z sentAt, zawiera poprawny token RFC 8058
    const sent: OutgoingMail[] = [];
    let loginMailerCalled = false;
    const okFixture = buildJobFixture({});
    const okOutcome = await deliverMailJob(okFixture.fakeDb, okFixture.job, {
      apiUrl: "https://api.monorise.studio",
      notificationsUnsubscribeSecret: TEST_UNSUBSCRIBE_SECRET,
      mailer: async () => {
        loginMailerCalled = true;
      },
      notificationsMailer: async (mail) => {
        sent.push(mail);
      },
      now,
    });
    expect(okOutcome).toEqual({ status: "SENT" });
    expect(loginMailerCalled).toBe(false);
    expect(sent).toHaveLength(1);
    expect(okFixture.state).toEqual({
      notificationStatus: "SENT",
      notificationSkipReason: null,
      notificationSentAt: now,
      outboxStatus: "SENT",
    });
    expect(sent[0]?.headers?.["List-Unsubscribe-Post"]).toBe("List-Unsubscribe=One-Click");
    const listUnsub = sent[0]?.headers?.["List-Unsubscribe"] ?? "";
    const tokenMatch = /^<https:\/\/api\.monorise\.studio\/core\/v1\/notifications\/unsubscribe\/([^>]+)>$/.exec(
      listUnsub,
    );
    expect(tokenMatch).not.toBeNull();
    expect(verifyUnsubscribeToken(decodeURIComponent(tokenMatch![1]!), TEST_UNSUBSCRIBE_SECRET)).toEqual({
      organizationId: ORG_ID,
      accountId: MEMBER_ACC_ID,
      category: "timotime.reminders",
    });

    // 2. Preferencja wyłączona między zleceniem a wysyłką -> SKIPPED/PREFERENCE_OFF i CANCELLED bez wysyłki
    let sentWhenOff = 0;
    const offFixture = buildJobFixture({ prefEnabled: false });
    const offOutcome = await deliverMailJob(offFixture.fakeDb, offFixture.job, {
      notificationsUnsubscribeSecret: TEST_UNSUBSCRIBE_SECRET,
      notificationsMailer: async () => {
        sentWhenOff += 1;
      },
      now,
    });
    expect(offOutcome).toEqual({ status: "CANCELLED" });
    expect(sentWhenOff).toBe(0);
    expect(offFixture.state).toMatchObject({
      notificationStatus: "SKIPPED",
      notificationSkipReason: "PREFERENCE_OFF",
      outboxStatus: "CANCELLED",
    });

    // 3. Brak dostępu w chwili wysyłki -> SKIPPED/NO_ACCESS i CANCELLED bez wysyłki
    const noAccessFixture = buildJobFixture({ hasAppAccess: false });
    const noAccessOutcome = await deliverMailJob(noAccessFixture.fakeDb, noAccessFixture.job, {
      notificationsUnsubscribeSecret: TEST_UNSUBSCRIBE_SECRET,
      notificationsMailer: async () => {
        sentWhenOff += 1;
      },
      now,
    });
    expect(noAccessOutcome).toEqual({ status: "CANCELLED" });
    expect(sentWhenOff).toBe(0);
    expect(noAccessFixture.state).toMatchObject({
      notificationStatus: "SKIPPED",
      notificationSkipReason: "NO_ACCESS",
      outboxStatus: "CANCELLED",
    });

    // 4. Błąd SMTP przed limitem prób -> PENDING (powiadomienie zostaje QUEUED)
    const retryFixture = buildJobFixture({ attempts: 1 });
    const retryOutcome = await deliverMailJob(retryFixture.fakeDb, retryFixture.job, {
      notificationsUnsubscribeSecret: TEST_UNSUBSCRIBE_SECRET,
      notificationsMailer: async () => {
        throw new Error("421 Try again later");
      },
      now,
    });
    expect(retryOutcome).toEqual({ status: "PENDING" });
    expect(retryFixture.state.notificationStatus).toBe("QUEUED");

    // 5. Ostatnia (8.) nieudana próba -> FAILED na mail_outbox i FAILED na notifications
    const failFixture = buildJobFixture({ attempts: MAIL_MAX_ATTEMPTS });
    const failOutcome = await deliverMailJob(failFixture.fakeDb, failFixture.job, {
      notificationsUnsubscribeSecret: TEST_UNSUBSCRIBE_SECRET,
      notificationsMailer: async () => {
        throw new Error("550 Permanent failure");
      },
      now,
    });
    expect(failOutcome).toEqual({ status: "FAILED" });
    expect(failFixture.state).toMatchObject({
      notificationStatus: "FAILED",
      outboxStatus: "FAILED",
    });

    // 6. Spóźniony worker (fencing: attempts w bazie > job.attempts) -> SKIPPED bez wysyłki
    const staleFixture = buildJobFixture({ attempts: 1, jobAttemptsInDb: 2 });
    const staleOutcome = await deliverMailJob(staleFixture.fakeDb, staleFixture.job, {
      notificationsUnsubscribeSecret: TEST_UNSUBSCRIBE_SECRET,
      notificationsMailer: async () => {
        throw new Error("Nie powinien wysyłać");
      },
      now,
    });
    expect(staleOutcome).toEqual({ status: "SKIPPED" });
    expect(staleFixture.state.notificationStatus).toBe("QUEUED");
  });

  it("obsługuje wszystkie 4 ścieżki HTTP powiadomień (zlecenie, idempotencja, preferencje, wypisanie RFC 8058) z izolacją i audytem", async () => {
    const now = new Date("2026-11-27T10:00:00.000Z");
    const notifications: Record<string, unknown>[] = [];
    const mailOutboxRows: Record<string, unknown>[] = [];
    const auditLogs: Record<string, unknown>[] = [];
    const preferences = new Map<string, { id: string; enabled: boolean }>();
    const idempotencyStore = new Map<
      string,
      { requestHash: string; responseStatus: number; responseBody: unknown; expiresAt: Date }
    >();
    let wakeCount = 0;

    const prefKey = (orgId: string, accId: string, category: string, channel: string) =>
      `${orgId}|${accId}|${category}|${channel}`;
    const idemKey = (orgId: string, principal: string, key: string) => `${orgId}|${principal}|${key}`;

    const accounts = new Map([
      [
        OWNER_ACC_ID,
        {
          id: OWNER_ACC_ID,
          organizationId: ORG_ID,
          employeeId: OWNER_EMP_ID,
          email: "anna@acme.test",
          status: "ACTIVE" as const,
          employee: { status: "ACTIVE" as const },
          organization: { ownerAccountId: OWNER_ACC_ID },
        },
      ],
      [
        MEMBER_ACC_ID,
        {
          id: MEMBER_ACC_ID,
          organizationId: ORG_ID,
          employeeId: MEMBER_EMP_ID,
          email: "jan@acme.test",
          status: "ACTIVE" as const,
          employee: { status: "ACTIVE" as const },
          organization: { ownerAccountId: OWNER_ACC_ID },
        },
      ],
      [
        NO_ACCESS_ACC_ID,
        {
          id: NO_ACCESS_ACC_ID,
          organizationId: ORG_ID,
          employeeId: NO_ACCESS_EMP_ID,
          email: "marek@acme.test",
          status: "ACTIVE" as const,
          employee: { status: "ACTIVE" as const },
          organization: { ownerAccountId: OWNER_ACC_ID },
        },
      ],
    ]);

    const products = new Map([
      [
        "timotime-web",
        { id: TIMOTIME_PROD_ID, key: "timotime", name: "TimoTime", uri: "http://timo-time.localhost:3300/app" },
      ],
      [
        "kivotasks-web",
        { id: KIVOTASKS_PROD_ID, key: "kivotasks", name: "KivoTasks", uri: "http://kivotasks.localhost:3500/" },
      ],
    ]);

    // Firma ma aktywny Entitlement wyłącznie dla timotime (brak dla kivotasks)
    const activeOrgEntitlements = new Map([[ORG_ID, new Set([TIMOTIME_PROD_ID])]]);
    const activeAppAccess = new Set([`${ORG_ID}|${MEMBER_ACC_ID}|${TIMOTIME_PROD_ID}`]);

    const db = {
      product: {
        findUnique: async ({ where }: { where: { registrationClientId?: string } }) =>
          where.registrationClientId ? (products.get(where.registrationClientId) ?? null) : null,
      },
      $transaction: async <T>(fn: (tx: unknown) => Promise<T>): Promise<T> => {
        let currentOrgId = "";
        const tx = {
          $executeRaw: async (strings: TemplateStringsArray, ...values: unknown[]) => {
            if (strings.join(" ").includes("set_config")) {
              currentOrgId = String(values[0] ?? "");
            }
            return 1;
          },
          organization: {
            findUnique: async ({ where }: { where: { id: string } }) =>
              where.id === ORG_ID && currentOrgId === ORG_ID ? { id: ORG_ID } : null,
          },
          authOAuthClient: {
            findUnique: async ({ where }: { where: { clientId: string } }) => {
              const p = products.get(where.clientId);
              return p ? { uri: p.uri } : null;
            },
          },
          entitlement: {
            findFirst: async ({ where }: { where: { productId: string } }) => {
              const set = activeOrgEntitlements.get(currentOrgId);
              return set?.has(where.productId) ? { id: `ent-${where.productId}` } : null;
            },
            findMany: async () => {
              const set = activeOrgEntitlements.get(currentOrgId);
              if (!set) return [];
              const res: { product: { key: string } }[] = [];
              if (set.has(TIMOTIME_PROD_ID)) res.push({ product: { key: "timotime" } });
              if (set.has(KIVOTASKS_PROD_ID)) res.push({ product: { key: "kivotasks" } });
              return res;
            },
          },
          account: {
            findUnique: async ({ where }: { where: { id: string } }) => {
              const acc = accounts.get(where.id);
              if (!acc || acc.organizationId !== currentOrgId) return null;
              return { ...acc, authzRevision: 0 };
            },
          },
          appAccess: {
            findFirst: async ({ where }: { where: { accountId: string; productId: string } }) =>
              activeAppAccess.has(`${currentOrgId}|${where.accountId}|${where.productId}`) ? { id: "aa-1" } : null,
          },
          notificationPreference: {
            findUnique: async ({
              where,
            }: {
              where: {
                organizationId_accountId_category_channel: {
                  organizationId: string;
                  accountId: string;
                  category: string;
                  channel: string;
                };
              };
            }) => {
              const k = where.organizationId_accountId_category_channel;
              if (k.organizationId !== currentOrgId) return null;
              return preferences.get(prefKey(k.organizationId, k.accountId, k.category, k.channel)) ?? null;
            },
            findMany: async ({ where }: { where: { accountId: string; channel: string } }) => {
              const rows: { category: string; enabled: boolean }[] = [];
              for (const [k, value] of preferences) {
                const [orgId, accId, category, channel] = k.split("|");
                if (orgId === currentOrgId && accId === where.accountId && channel === where.channel) {
                  rows.push({ category: category!, enabled: value.enabled });
                }
              }
              return rows;
            },
            upsert: async ({
              where,
              create,
              update,
            }: {
              where: {
                organizationId_accountId_category_channel: {
                  organizationId: string;
                  accountId: string;
                  category: string;
                  channel: string;
                };
              };
              create: { id: string; enabled: boolean };
              update: { enabled: boolean };
            }) => {
              const k = where.organizationId_accountId_category_channel;
              const mapKey = prefKey(k.organizationId, k.accountId, k.category, k.channel);
              const existing = preferences.get(mapKey);
              const saved = existing
                ? { id: existing.id, enabled: update.enabled }
                : { id: create.id, enabled: create.enabled };
              preferences.set(mapKey, saved);
              return saved;
            },
          },
          notification: {
            create: async ({ data }: { data: Record<string, unknown> }) => {
              notifications.push(data);
              return data;
            },
          },
          mailOutbox: {
            create: async ({ data }: { data: { id: string } & Record<string, unknown> }) => {
              mailOutboxRows.push(data);
              return { id: data.id };
            },
          },
          auditLog: {
            create: async ({ data }: { data: Record<string, unknown> }) => {
              auditLogs.push(data);
              return data;
            },
          },
          idempotencyKey: {
            findUnique: async ({
              where,
            }: {
              where: { organizationId_principal_key: { organizationId: string; principal: string; key: string } };
            }) => {
              const k = where.organizationId_principal_key;
              return idempotencyStore.get(idemKey(k.organizationId, k.principal, k.key)) ?? null;
            },
            upsert: async ({
              where,
              create,
              update,
            }: {
              where: { organizationId_principal_key: { organizationId: string; principal: string; key: string } };
              create: { requestHash: string; responseStatus: number; responseBody: unknown; expiresAt: Date };
              update: { requestHash: string; responseStatus: number; responseBody: unknown; expiresAt: Date };
            }) => {
              const k = where.organizationId_principal_key;
              const mapKey = idemKey(k.organizationId, k.principal, k.key);
              const next = idempotencyStore.has(mapKey) ? update : create;
              idempotencyStore.set(mapKey, next);
              return next;
            },
          },
        };
        return fn(tx);
      },
    } as unknown as PrismaClient;

    const app = buildServer({
      db,
      now: () => now,
      notificationsUnsubscribeSecret: TEST_UNSUBSCRIBE_SECRET,
      mailOutboxWorker: {
        wake: () => {
          wakeCount += 1;
        },
      },
      verifyToken: async (tok) => {
        const acc = accounts.get(tok);
        if (!acc) throw new Error("invalid user token");
        return {
          iss: "http://localhost:3100",
          sub: acc.id,
          aud: "http://localhost:3200",
          org_id: acc.organizationId,
          employee_id: acc.employeeId,
          amr: ["pwd"],
          authz_rev: 0,
          iat: 1,
          exp: 9_999_999_999,
        };
      },
      verifyMachineToken: async (tok) => {
        const sep = tok.indexOf(":");
        if (sep === -1) throw new Error("invalid machine token");
        const clientId = tok.slice(0, sep);
        const scope = tok.slice(sep + 1);
        if (!clientId || !scope) throw new Error("invalid machine token");
        return {
          iss: "http://localhost:3100",
          sub: clientId,
          aud: "http://localhost:3200",
          client_id: clientId,
          scope,
          iat: 1,
          exp: 9_999_999_999,
        };
      },
    });

    try {
      // 1. Zły zakres tokenu maszynowego -> 403
      const wrongScope = await app.inject({
        method: "POST",
        url: `/core/v1/organizations/${ORG_ID}/notifications`,
        headers: { authorization: `Bearer timotime-web:${DIRECTORY_READ_SCOPE}` },
        payload: {
          recipientAccountId: MEMBER_ACC_ID,
          category: "timotime.reminders",
          title: "Tytuł",
          body: "Treść",
        },
      });
      expect(wrongScope.statusCode).toBe(403);

      // 2. Kategoria innego produktu i kategorie logowania -> 403
      for (const forbiddenCat of ["kivotasks.assignments", "security", "account"]) {
        const res = await app.inject({
          method: "POST",
          url: `/core/v1/organizations/${ORG_ID}/notifications`,
          headers: { authorization: `Bearer timotime-web:${NOTIFICATIONS_SEND_SCOPE}` },
          payload: {
            recipientAccountId: MEMBER_ACC_ID,
            category: forbiddenCat,
            title: "Tytuł",
            body: "Treść",
          },
        });
        expect(res.statusCode).toBe(403);
        expect(res.json().error.code).toBe("PERMISSION_DENIED");
      }

      // 3. Obcy actionUrl -> 422
      const foreignUrl = await app.inject({
        method: "POST",
        url: `/core/v1/organizations/${ORG_ID}/notifications`,
        headers: { authorization: `Bearer timotime-web:${NOTIFICATIONS_SEND_SCOPE}` },
        payload: {
          recipientAccountId: MEMBER_ACC_ID,
          category: "timotime.reminders",
          title: "Tytuł",
          body: "Treść",
          actionUrl: "https://evil.test/steal",
        },
      });
      expect(foreignUrl.statusCode).toBe(422);
      expect(foreignUrl.json().error.code).toBe("VALIDATION_FAILED");

      // 4. Firma bez Entitlement (kivotasks) -> 403; nieznana firma -> 404
      const noEntitlement = await app.inject({
        method: "POST",
        url: `/core/v1/organizations/${ORG_ID}/notifications`,
        headers: { authorization: `Bearer kivotasks-web:${NOTIFICATIONS_SEND_SCOPE}` },
        payload: {
          recipientAccountId: MEMBER_ACC_ID,
          category: "kivotasks.assignments",
          title: "Zadanie",
          body: "Treść",
        },
      });
      expect(noEntitlement.statusCode).toBe(403);

      const unknownOrg = await app.inject({
        method: "POST",
        url: `/core/v1/organizations/${OTHER_ORG_ID}/notifications`,
        headers: { authorization: `Bearer timotime-web:${NOTIFICATIONS_SEND_SCOPE}` },
        payload: {
          recipientAccountId: MEMBER_ACC_ID,
          category: "timotime.reminders",
          title: "Tytuł",
          body: "Treść",
        },
      });
      expect(unknownOrg.statusCode).toBe(404);

      // 5. Odbiorca bez AppAccess -> 202 SKIPPED/NO_ACCESS (bez mail_outbox i bez wake)
      const noAccess = await app.inject({
        method: "POST",
        url: `/core/v1/organizations/${ORG_ID}/notifications`,
        headers: { authorization: `Bearer timotime-web:${NOTIFICATIONS_SEND_SCOPE}` },
        payload: {
          recipientAccountId: NO_ACCESS_ACC_ID,
          category: "timotime.reminders",
          title: "Przypomnienie",
          body: "Treść",
        },
      });
      expect(noAccess.statusCode).toBe(202);
      expect(noAccess.json().data).toMatchObject({ status: "SKIPPED", skipReason: "NO_ACCESS" });
      expect(mailOutboxRows).toHaveLength(0);
      expect(wakeCount).toBe(0);

      // 6. Poprawne zlecenie z Idempotency-Key -> 202 QUEUED, 1 mail_outbox, 1 wake; powtórka bez drugiego wpisu i bez wake; inna treść -> 409
      const validPayload = {
        recipientAccountId: MEMBER_ACC_ID,
        category: "timotime.reminders",
        title: "Uzupełnij czas pracy",
        body: "Brakuje wpisu za piątek.",
        actionUrl: "http://timo-time.localhost:3300/app/entries",
      };
      const queued = await app.inject({
        method: "POST",
        url: `/core/v1/organizations/${ORG_ID}/notifications`,
        headers: {
          authorization: `Bearer timotime-web:${NOTIFICATIONS_SEND_SCOPE}`,
          [IDEMPOTENCY_KEY_HEADER]: "notif-key-1",
        },
        payload: validPayload,
      });
      expect(queued.statusCode).toBe(202);
      expect(queued.json().data).toMatchObject({ id: expect.any(String), status: "QUEUED", skipReason: null });
      expect(mailOutboxRows).toHaveLength(1);
      expect(wakeCount).toBe(1);

      const replayed = await app.inject({
        method: "POST",
        url: `/core/v1/organizations/${ORG_ID}/notifications`,
        headers: {
          authorization: `Bearer timotime-web:${NOTIFICATIONS_SEND_SCOPE}`,
          [IDEMPOTENCY_KEY_HEADER]: "notif-key-1",
        },
        payload: validPayload,
      });
      expect(replayed.statusCode).toBe(202);
      expect(replayed.headers[IDEMPOTENCY_REPLAYED_HEADER.toLowerCase()]).toBe("true");
      expect(replayed.json()).toEqual(queued.json());
      expect(mailOutboxRows).toHaveLength(1);
      expect(wakeCount).toBe(1);

      const conflict = await app.inject({
        method: "POST",
        url: `/core/v1/organizations/${ORG_ID}/notifications`,
        headers: {
          authorization: `Bearer timotime-web:${NOTIFICATIONS_SEND_SCOPE}`,
          [IDEMPOTENCY_KEY_HEADER]: "notif-key-1",
        },
        payload: { ...validPayload, title: "Inny tytuł" },
      });
      expect(conflict.statusCode).toBe(409);

      // 7. GET /me/notification-preferences: security + account + tylko produkty firmy (timotime, bez kivotasks)
      const listRes = await app.inject({
        method: "GET",
        url: "/core/v1/me/notification-preferences",
        headers: { authorization: `Bearer ${MEMBER_ACC_ID}` },
      });
      expect(listRes.statusCode).toBe(200);
      expect(
        listRes.json().data.map((item: { category: string; enabled: boolean; optional: boolean }) => ({
          category: item.category,
          enabled: item.enabled,
          optional: item.optional,
        })),
      ).toEqual([
        { category: "security", enabled: true, optional: false },
        { category: "account", enabled: true, optional: false },
        { category: "timotime.reminders", enabled: true, optional: true },
      ]);

      // 8. PUT /me/notification-preferences: 422 dla security, account i nieznanej; 200 + audyt dla timotime.reminders
      for (const badCat of ["security", "account", "unknown.cat"]) {
        const res = await app.inject({
          method: "PUT",
          url: `/core/v1/me/notification-preferences/${badCat}`,
          headers: { authorization: `Bearer ${MEMBER_ACC_ID}` },
          payload: { enabled: false },
        });
        expect(res.statusCode).toBe(422);
        expect(res.json().error.code).toBe("VALIDATION_FAILED");
      }

      const disableRes = await app.inject({
        method: "PUT",
        url: "/core/v1/me/notification-preferences/timotime.reminders",
        headers: { authorization: `Bearer ${MEMBER_ACC_ID}` },
        payload: { enabled: false },
      });
      expect(disableRes.statusCode).toBe(200);
      expect(disableRes.json().data).toMatchObject({ category: "timotime.reminders", enabled: false });
      expect(auditLogs).toHaveLength(1);
      expect(auditLogs[0]).toMatchObject({
        action: "notification.preference_changed",
        actorType: "ACCOUNT",
        actorAccountId: MEMBER_ACC_ID,
        metadata: expect.objectContaining({ category: "timotime.reminders", enabled: false, source: "api" }),
      });

      // Po wyłączeniu kategorii kolejne zlecenie -> 202 SKIPPED/PREFERENCE_OFF
      const skippedPref = await app.inject({
        method: "POST",
        url: `/core/v1/organizations/${ORG_ID}/notifications`,
        headers: { authorization: `Bearer timotime-web:${NOTIFICATIONS_SEND_SCOPE}` },
        payload: validPayload,
      });
      expect(skippedPref.statusCode).toBe(202);
      expect(skippedPref.json().data).toMatchObject({ status: "SKIPPED", skipReason: "PREFERENCE_OFF" });
      expect(mailOutboxRows).toHaveLength(1);

      // Włączamy ponownie i wypisujemy się jednoklikowo (RFC 8058 form-urlencoded bez tokenu)
      await app.inject({
        method: "PUT",
        url: "/core/v1/me/notification-preferences/timotime.reminders",
        headers: { authorization: `Bearer ${MEMBER_ACC_ID}` },
        payload: { enabled: true },
      });

      const unsubToken = createUnsubscribeToken(
        { organizationId: ORG_ID, accountId: MEMBER_ACC_ID, category: "timotime.reminders" },
        TEST_UNSUBSCRIBE_SECRET,
      );
      const unsubOk = await app.inject({
        method: "POST",
        url: `/core/v1/notifications/unsubscribe/${unsubToken}`,
        headers: { "content-type": "application/x-www-form-urlencoded" },
        payload: "List-Unsubscribe=One-Click",
      });
      expect(unsubOk.statusCode).toBe(200);
      expect(unsubOk.json().data).toEqual({ category: "timotime.reminders", enabled: false });
      expect(auditLogs.at(-1)).toMatchObject({
        action: "notification.preference_changed",
        actorAccountId: MEMBER_ACC_ID,
        metadata: expect.objectContaining({ enabled: false, source: "unsubscribe_link" }),
      });

      // Zmanipulowany token i token konta z innej firmy -> 404
      const unsubTampered = await app.inject({
        method: "POST",
        url: `/core/v1/notifications/unsubscribe/${unsubToken}tampered`,
      });
      expect(unsubTampered.statusCode).toBe(404);
      expect(unsubTampered.json().error.code).toBe("NOT_FOUND");

      const wrongCompanyToken = createUnsubscribeToken(
        { organizationId: OTHER_ORG_ID, accountId: MEMBER_ACC_ID, category: "timotime.reminders" },
        TEST_UNSUBSCRIBE_SECRET,
      );
      const unsubWrongCompany = await app.inject({
        method: "POST",
        url: `/core/v1/notifications/unsubscribe/${wrongCompanyToken}`,
      });
      expect(unsubWrongCompany.statusCode).toBe(404);
    } finally {
      await app.close();
    }
  });
});
