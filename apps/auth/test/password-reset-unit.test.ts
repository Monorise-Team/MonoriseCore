import type * as CoreDb from "@core/db";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  clearSentMails,
  MAIL_RETRY_DELAYS_MS,
  MAIL_SEND_DEADLINE_MS,
  passwordResetMail,
  sanitizeMailError,
  sendMailInBackground,
  sendMailWithDeadline,
  sendMailWithRetry,
  SMTP_TIMEOUTS,
  type ClosableMailTransport,
  type OutgoingMail,
} from "@/server/mail";

const ORG_ID = "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f7a01";
const USER_ID = "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f7a11";
const EMP_ID = "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f7a12";

interface MockState {
  claims: CoreDb.AccountClaims | null;
  revokedCalls: string[];
  revokedResult: CoreDb.RevokedUserAuthTokens;
  audits: {
    organizationId: string;
    actorType: string;
    actorAccountId: string;
    action: string;
    resourceType: string;
    resourceId: string;
    metadata: unknown;
    ipAddress: string | null;
    userAgent: string | null;
    requestId: string | null;
  }[];
  transactionCalls: number;
}

const state: MockState = {
  claims: {
    organizationId: ORG_ID,
    employeeId: EMP_ID,
    authzRevision: 0,
    accountStatus: "ACTIVE",
    organizationStatus: "ACTIVE",
  },
  revokedCalls: [],
  revokedResult: { accessTokens: 2, refreshTokens: 1, sessions: 0 },
  audits: [],
  transactionCalls: 0,
};

vi.mock("@core/db", async (importOriginal) => {
  const actual = await importOriginal<typeof CoreDb>();
  return {
    ...actual,
    accountClaims: vi.fn(async () => state.claims),
    revokeUserAuthTokens: vi.fn(async (_tx: unknown, userId: string) => {
      state.revokedCalls.push(userId);
      return state.revokedResult;
    }),
    withOrganization: vi.fn(async (_db: unknown, _orgId: string, fn: (tx: unknown) => Promise<unknown>) => {
      const tx = {
        auditLog: {
          create: async ({ data }: { data: MockState["audits"][number] }) => {
            state.audits.push(data);
            return data;
          },
        },
      };
      return fn(tx);
    }),
  };
});

vi.mock("@/server/db", () => ({
  db: {
    $transaction: vi.fn(async (fn: (tx: unknown) => Promise<unknown>) => {
      state.transactionCalls += 1;
      return fn({});
    }),
  },
}));

const sampleMail: OutgoingMail = passwordResetMail("anna@acme.test", "http://localhost:3100/reset-password?token=abc");

beforeEach(() => {
  clearSentMails();
  state.claims = {
    organizationId: ORG_ID,
    employeeId: EMP_ID,
    authzRevision: 0,
    accountStatus: "ACTIVE",
    organizationStatus: "ACTIVE",
  };
  state.revokedCalls = [];
  state.revokedResult = { accessTokens: 2, refreshTokens: 1, sessions: 0 };
  state.audits = [];
  state.transactionCalls = 0;
});

afterEach(() => {
  vi.useRealTimers();
});

describe("wysyłka maili logowania z ponowieniami (apps/auth/src/server/mail.ts)", () => {
  it("tworzy wiadomość resetu hasła z tematem, informacją o 30 minutach i notatką o zignorowaniu", () => {
    const mail = passwordResetMail("anna@acme.test", "http://localhost:3100/reset-password?token=sekret-123");
    expect(mail.to).toBe("anna@acme.test");
    expect(mail.subject).toBe("Zmiana hasła w Monorise");
    expect(mail.text).toContain("30 minut");
    expect(mail.text).toContain("http://localhost:3100/reset-password?token=sekret-123");
    expect(mail.text).toContain("zignoruj");
    expect(mail.html).toContain("30 minut");
    expect(mail.html).toContain("http://localhost:3100/reset-password?token=sekret-123");
    expect(mail.html).toContain("zignoruj");
  });

  it("ma ustawione limity czasu SMTP i 3 opóźnienia ponowień (0 s, 2 s, 5 s)", () => {
    expect(SMTP_TIMEOUTS).toEqual({
      connectionTimeout: 10_000,
      greetingTimeout: 10_000,
      socketTimeout: 20_000,
    });
    expect(MAIL_SEND_DEADLINE_MS).toBe(30_000);
    expect(MAIL_RETRY_DELAYS_MS).toEqual([0, 2_000, 5_000]);
  });

  it("wysyła w pierwszej próbie bez czekania, a przy chwilowym błędzie ponawia z opóźnieniami", async () => {
    const slept: number[] = [];
    const sleep = async (ms: number) => {
      slept.push(ms);
    };

    const okSender = vi.fn(async () => undefined);
    await sendMailWithRetry(sampleMail, { sender: okSender, sleep });
    expect(okSender).toHaveBeenCalledTimes(1);
    expect(slept).toEqual([]);

    // Sukces w 3. próbie po 2 błędach -> opóźnienia 2000 ms i 5000 ms
    let attempt = 0;
    const flakySender = vi.fn(async () => {
      attempt += 1;
      if (attempt < 3) throw new Error(`SMTP temporary error #${attempt}`);
    });
    await sendMailWithRetry(sampleMail, { sender: flakySender, sleep });
    expect(flakySender).toHaveBeenCalledTimes(3);
    expect(slept).toEqual([2_000, 5_000]);
  });

  it("poddaje się po 3 nieudanych próbach i rzuca ostatni błąd", async () => {
    const slept: number[] = [];
    const attempts: number[] = [];
    const failingSender = vi.fn(async () => {
      throw new Error(`SMTP failure #${attempts.length + 1}`);
    });

    await expect(
      sendMailWithRetry(sampleMail, {
        sender: failingSender,
        sleep: async (ms) => {
          slept.push(ms);
        },
        onAttemptError: (n) => {
          attempts.push(n);
        },
      }),
    ).rejects.toThrow("SMTP failure #3");

    expect(failingSender).toHaveBeenCalledTimes(3);
    expect(attempts).toEqual([1, 2, 3]);
    expect(slept).toEqual([2_000, 5_000]);
  });

  it("przerywa zawieszone połączenie SMTP po twardym limicie czasu i zamyka transport", async () => {
    vi.useFakeTimers();
    const close = vi.fn();
    const hangingTransport: ClosableMailTransport = {
      sendMail: () => new Promise(() => undefined),
      close,
    };

    const pending = sendMailWithDeadline(
      hangingTransport,
      { from: "Monorise <no-reply@monorise.studio>", ...sampleMail },
      1_000,
    );
    const assertion = expect(pending).rejects.toThrow(/Przekroczono limit czasu wysyłki SMTP/);
    await vi.advanceTimersByTimeAsync(1_050);
    await assertion;
    expect(close).toHaveBeenCalled();
  });

  it("sendMailInBackground nie rzuca błędu po wyczerpaniu prób i anonimizuje tokeny oraz hasła SMTP w logu", async () => {
    const logs: string[] = [];
    const failingSender = vi.fn(async () => {
      throw new Error("Connection failed to smtps://user:supersecret@smtp.example/send?token=tajny-token-999");
    });

    await expect(
      sendMailInBackground(sampleMail, "password-reset", {
        sender: failingSender,
        sleep: async () => undefined,
        logger: (message) => logs.push(message),
      }),
    ).resolves.toBeUndefined();

    expect(failingSender).toHaveBeenCalledTimes(3);
    expect(logs).toHaveLength(1);
    expect(logs[0]).toContain("[auth:mail:password-reset]");
    expect(logs[0]).not.toContain("supersecret");
    expect(logs[0]).not.toContain("tajny-token-999");
    expect(sanitizeMailError(new Error("smtp://admin:pass@mail.test?token=xyz"))).toBe(
      "Error: smtp://***@mail.test?token=***",
    );
  });
});

describe("pomocniki resetu hasła (apps/auth/src/server/password-reset.ts)", () => {
  it("ustawia 30-minutową ważność tokenu i weryfikuje token bez jego zużycia", async () => {
    const { isPasswordResetTokenValid, PASSWORD_RESET_TOKEN_EXPIRES_IN_SECONDS } =
      await import("@/server/password-reset");
    expect(PASSWORD_RESET_TOKEN_EXPIRES_IN_SECONDS).toBe(1800);

    const now = new Date("2026-11-26T18:00:00.000Z");
    const lookup = {
      findVerificationValue: vi.fn(async (identifier: string) => {
        if (identifier === "reset-password:valid-token") {
          return { expiresAt: new Date(now.getTime() + 60_000) };
        }
        if (identifier === "reset-password:expired-token") {
          return { expiresAt: new Date(now.getTime() - 1_000) };
        }
        return null;
      }),
    };

    expect(await isPasswordResetTokenValid(lookup, "valid-token", now)).toBe(true);
    expect(await isPasswordResetTokenValid(lookup, "expired-token", now)).toBe(false);
    expect(await isPasswordResetTokenValid(lookup, "unknown-token", now)).toBe(false);
    expect(await isPasswordResetTokenValid(lookup, "   ", now)).toBe(false);
  });

  it("odmawia wysłania resetu kontom INVITED, DEACTIVATED oraz firmom SUSPENDED i DELETED", async () => {
    const { canRequestPasswordReset } = await import("@/server/password-reset");

    state.claims = {
      organizationId: ORG_ID,
      employeeId: EMP_ID,
      authzRevision: 0,
      accountStatus: "ACTIVE",
      organizationStatus: "ACTIVE",
    };
    expect(await canRequestPasswordReset(USER_ID)).toBe(true);

    state.claims.organizationStatus = "PENDING_VERIFICATION";
    expect(await canRequestPasswordReset(USER_ID)).toBe(true);

    state.claims.accountStatus = "INVITED";
    expect(await canRequestPasswordReset(USER_ID)).toBe(false);

    state.claims.accountStatus = "DEACTIVATED";
    expect(await canRequestPasswordReset(USER_ID)).toBe(false);

    state.claims.accountStatus = "ACTIVE";
    state.claims.organizationStatus = "SUSPENDED";
    expect(await canRequestPasswordReset(USER_ID)).toBe(false);

    state.claims.organizationStatus = "DELETED";
    expect(await canRequestPasswordReset(USER_ID)).toBe(false);

    state.claims = null;
    expect(await canRequestPasswordReset(USER_ID)).toBe(true);
  });

  it("handlePasswordReset unieważnia tokeny OAuth i zapisuje wpis audytu account.password_reset", async () => {
    const { handlePasswordReset } = await import("@/server/password-reset");

    await handlePasswordReset(USER_ID, {
      ipAddress: "127.0.0.1, 10.0.0.5",
      userAgent: "MonoriseTest/1.0",
    });

    expect(state.revokedCalls).toEqual([USER_ID]);
    expect(state.audits).toEqual([
      expect.objectContaining({
        organizationId: ORG_ID,
        actorType: "ACCOUNT",
        actorAccountId: USER_ID,
        action: "account.password_reset",
        resourceType: "account",
        resourceId: USER_ID,
        metadata: {
          revokedOAuthRefreshes: 1,
          revokedOAuthAccesses: 2,
        },
        ipAddress: "127.0.0.1",
        userAgent: "MonoriseTest/1.0",
        requestId: null,
      }),
    ]);
  });

  it("handlePasswordReset dla konta bez organizacji unieważnia tokeny OAuth i pomija wpis audytu", async () => {
    const { handlePasswordReset } = await import("@/server/password-reset");
    state.claims = null;

    await handlePasswordReset(USER_ID);

    expect(state.transactionCalls).toBe(1);
    expect(state.revokedCalls).toEqual([USER_ID]);
    expect(state.audits).toHaveLength(0);
  });
});
