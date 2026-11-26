import { createHash, randomBytes } from "node:crypto";
import { uuidv7, withOrganization } from "@core/db";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { auth } from "@/server/auth";
import { db } from "@/server/db";
import { clearSentMails, sentMails } from "@/server/mail";
import { ensureFirstPartyClients } from "@/server/oauth-clients";
import { isPasswordResetTokenValid, PASSWORD_RESET_TOKEN_EXPIRES_IN_SECONDS } from "@/server/password-reset";
import { signUpOrganization } from "@/server/signup";

const BASE = "http://localhost:3100";
const RESOURCE = `http://timo-${crypto.randomUUID().slice(0, 8)}.localhost:3300`;
const REDIRECT = "http://timo-time.localhost:3300/api/auth/callback";
const CLIENT_ID = `timotime-reset-test-${crypto.randomUUID().slice(0, 8)}`;

const INITIAL_PASSWORD = "pierwsze-dlugie-haslo-76";
const NEW_PASSWORD = "drugie-nowe-dlugie-haslo-76";

const createdOrgs: { organizationId: string; email: string }[] = [];
const createdUserIds: string[] = [];
let client: { client_id: string; client_secret: string };

const base64url = (buffer: Buffer) => buffer.toString("base64url");

async function call(path: string, init: RequestInit & { form?: Record<string, string> } = {}) {
  const headers = new Headers(init.headers);
  headers.set("Origin", BASE);
  let body = init.body;
  if (init.form) {
    headers.set("Content-Type", "application/x-www-form-urlencoded");
    body = new URLSearchParams(init.form).toString();
  }
  return auth.handler(new Request(`${BASE}${path}`, { ...init, headers, body, redirect: "manual" }));
}

async function createVerifiedAccount(label: string) {
  const email = `anna@${crypto.randomUUID().slice(0, 8)}-${label}.test`;
  const { organizationId } = await signUpOrganization({
    organizationName: `Acme ${label}`,
    firstName: "Anna",
    lastName: "Kowalska",
    email,
    password: INITIAL_PASSWORD,
  });
  createdOrgs.push({ organizationId, email });
  const verifyMail = [...sentMails()].reverse().find((m) => m.to === email && /Potwierdź adres e-mail/.test(m.subject));
  expect(verifyMail).toBeDefined();
  const verifyUrl = new URL(/https?:\/\/\S+/.exec(verifyMail!.text)![0]);
  await auth.api.verifyEmail({ query: { token: verifyUrl.searchParams.get("token")! } });
  const user = await db.authUser.findUniqueOrThrow({ where: { email } });
  return { organizationId, email, userId: user.id };
}

async function signInForOAuthTokens(email: string, password: string) {
  const verifier = base64url(randomBytes(32));
  const challenge = base64url(createHash("sha256").update(verifier).digest());
  const authorize = new URLSearchParams({
    response_type: "code",
    client_id: client.client_id,
    redirect_uri: REDIRECT,
    scope: "openid profile email offline_access",
    state: "reset-test",
    code_challenge: challenge,
    code_challenge_method: "S256",
    resource: RESOURCE,
  });
  const first = await call(`/api/auth/oauth2/authorize?${authorize}`);
  const login = new URL(first.headers.get("location")!, BASE);
  const signIn = await call("/api/auth/sign-in/email", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password, oauth_query: login.search.slice(1) }),
  });
  const signInBody = (await signIn.json().catch(() => ({}))) as { url?: string };
  const code = new URL(signIn.headers.get("location") ?? signInBody.url!).searchParams.get("code")!;
  const exchange = await call("/api/auth/oauth2/token", {
    method: "POST",
    form: {
      grant_type: "authorization_code",
      code,
      redirect_uri: REDIRECT,
      client_id: client.client_id,
      client_secret: client.client_secret,
      code_verifier: verifier,
      resource: RESOURCE,
    },
  });
  expect(exchange.status).toBe(200);
  return (await exchange.json()) as { access_token: string; refresh_token: string };
}

async function refreshOAuthToken(refreshToken: string) {
  return call("/api/auth/oauth2/token", {
    method: "POST",
    form: {
      grant_type: "refresh_token",
      refresh_token: refreshToken,
      client_id: client.client_id,
      client_secret: client.client_secret,
      resource: RESOURCE,
    },
  });
}

function extractResetToken(email: string): string {
  const mail = [...sentMails()].reverse().find((m) => m.to === email && m.subject === "Zmiana hasła w Monorise");
  expect(mail).toBeDefined();
  expect(mail!.text).toContain("30 minut");
  expect(mail!.text).toContain("zignoruj");
  const linkMatch = /https?:\/\/\S+/.exec(mail!.text);
  expect(linkMatch).not.toBeNull();
  const url = new URL(linkMatch![0]);
  expect(url.pathname).toBe("/reset-password");
  const token = url.searchParams.get("token");
  expect(token).toBeTruthy();
  return token!;
}

beforeAll(async () => {
  const secrets = await ensureFirstPartyClients({
    resources: [{ identifier: RESOURCE, name: "TimoTime API (test)" }],
    clients: [
      {
        clientId: CLIENT_ID,
        name: "TimoTime (test)",
        redirectUris: [REDIRECT],
        confidential: true,
        resources: [RESOURCE],
      },
    ],
  });
  client = { client_id: CLIENT_ID, client_secret: secrets[CLIENT_ID]! };
});

afterAll(async () => {
  for (const { organizationId, email } of createdOrgs) {
    await withOrganization(db, organizationId, (tx) => tx.organization.deleteMany({ where: { id: organizationId } }));
    await db.authUser.deleteMany({ where: { email } });
  }
  if (createdUserIds.length > 0) {
    await db.authUser.deleteMany({ where: { id: { in: createdUserIds } } });
  }
  await db.authOAuthClient.deleteMany({ where: { clientId: CLIENT_ID } });
  await db.authOAuthResource.deleteMany({ where: { identifier: RESOURCE } });
  await db.$disconnect();
});

describe("reset hasła w apps/auth (MonoriseCore#76)", () => {
  it("zwraca identyczną odpowiedź dla istniejącego i nieistniejącego adresu, a mail z tokenem wysyła wyłącznie dla istniejącego konta", async () => {
    const account = await createVerifiedAccount("same-response");
    clearSentMails();

    const missingEmail = `brak-${crypto.randomUUID().slice(0, 8)}@nieistnieje.test`;
    const missingRes = await call("/api/auth/request-password-reset", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: missingEmail, redirectTo: "/reset-password" }),
    });
    const existingRes = await call("/api/auth/request-password-reset", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: account.email, redirectTo: "/reset-password" }),
    });

    expect(missingRes.status).toBe(200);
    expect(existingRes.status).toBe(200);
    expect(await missingRes.json()).toEqual(await existingRes.json());

    // Brak maila dla nieistniejącego konta
    expect(sentMails().filter((m) => m.to === missingEmail)).toHaveLength(0);

    // Mail z tokenem ważnym ~30 minut dla istniejącego konta
    const token = extractResetToken(account.email);
    const verification = await db.authVerification.findFirst({
      where: { identifier: `reset-password:${token}` },
    });
    expect(verification).not.toBeNull();
    const ttlSeconds = Math.round((verification!.expiresAt.getTime() - Date.now()) / 1000);
    expect(ttlSeconds).toBeGreaterThan(PASSWORD_RESET_TOKEN_EXPIRES_IN_SECONDS - 30);
    expect(ttlSeconds).toBeLessThanOrEqual(PASSWORD_RESET_TOKEN_EXPIRES_IN_SECONDS + 5);
  });

  it("zmienia hasło poprawnym tokenem, unieważnia sesje i tokeny OAuth, zapisuje audyt account.password_reset i odrzuca ponowne użycie tokenu", async () => {
    const account = await createVerifiedAccount("full-flow");

    // 1. Aktywna sesja Better Auth + tokeny OAuth (w tym obrócony token w 20-sekundowym oknie powtórki)
    const signInResponse = await auth.api.signInEmail({
      body: { email: account.email, password: INITIAL_PASSWORD },
      asResponse: true,
    });
    expect(signInResponse.status).toBe(200);
    const sessionCookie = signInResponse.headers
      .getSetCookie()
      .map((c) => c.split(";")[0])
      .join("; ");
    expect(await auth.api.getSession({ headers: new Headers({ cookie: sessionCookie }) })).not.toBeNull();

    const oauthTokens = await signInForOAuthTokens(account.email, INITIAL_PASSWORD);
    const rotatedRes = await refreshOAuthToken(oauthTokens.refresh_token);
    expect(rotatedRes.status).toBe(200);
    const rotatedTokens = (await rotatedRes.json()) as { access_token: string; refresh_token: string };

    // 2. Żądanie resetu hasła
    clearSentMails();
    const requestRes = await call("/api/auth/request-password-reset", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: account.email, redirectTo: "/reset-password" }),
    });
    expect(requestRes.status).toBe(200);
    const token = extractResetToken(account.email);

    const authCtx = await auth.$context;
    expect(await isPasswordResetTokenValid(authCtx.internalAdapter, token)).toBe(true);

    // 3. Zbyt krótkie hasło (< 12 znaków) jest odrzucane i nie zużywa tokenu
    const shortRes = await call("/api/auth/reset-password", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token, newPassword: "za-krotkie" }),
    });
    expect(shortRes.status).toBe(400);
    expect(await isPasswordResetTokenValid(authCtx.internalAdapter, token)).toBe(true);

    // 4. Zmiana hasła poprawnym tokenem
    const resetRes = await call("/api/auth/reset-password", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-forwarded-for": "127.0.0.1",
        "user-agent": "vitest-reset-agent",
      },
      body: JSON.stringify({ token, newPassword: NEW_PASSWORD }),
    });
    expect(resetRes.status).toBe(200);
    expect(await resetRes.json()).toEqual({ status: true });

    // 5. Poprzednie sesje Better Auth i wszystkie tokeny OAuth (także z okna powtórki) są unieważnione
    expect(await auth.api.getSession({ headers: new Headers({ cookie: sessionCookie }) })).toBeNull();
    expect(await db.authSession.count({ where: { userId: account.userId } })).toBe(0);
    expect(await db.authOAuthAccessToken.count({ where: { userId: account.userId } })).toBe(0);
    expect(await db.authOAuthRefreshToken.count({ where: { userId: account.userId } })).toBe(0);

    const replayRefresh = await refreshOAuthToken(oauthTokens.refresh_token);
    expect(replayRefresh.status).toBe(400);
    expect(((await replayRefresh.json()) as { error?: string }).error).toBe("invalid_grant");

    const currentRefresh = await refreshOAuthToken(rotatedTokens.refresh_token);
    expect(currentRefresh.status).toBe(400);
    expect(((await currentRefresh.json()) as { error?: string }).error).toBe("invalid_grant");

    // 6. Wpis audytu account.password_reset w firmie konta (bez haseł ani tokenów)
    const audits = await withOrganization(db, account.organizationId, (tx) =>
      tx.auditLog.findMany({ where: { action: "account.password_reset", resourceId: account.userId } }),
    );
    expect(audits).toHaveLength(1);
    expect(audits[0]).toMatchObject({
      organizationId: account.organizationId,
      actorType: "ACCOUNT",
      actorAccountId: account.userId,
      action: "account.password_reset",
      resourceType: "account",
      resourceId: account.userId,
      ipAddress: "127.0.0.1",
      userAgent: "vitest-reset-agent",
    });
    const serializedAudit = JSON.stringify(audits[0]);
    expect(serializedAudit).not.toContain(token);
    expect(serializedAudit).not.toContain(NEW_PASSWORD);
    expect(serializedAudit).not.toContain(INITIAL_PASSWORD);

    // 7. Stare hasło nie działa, nowe hasło loguje
    await expect(
      auth.api.signInEmail({ body: { email: account.email, password: INITIAL_PASSWORD } }),
    ).rejects.toThrow();
    const newSignIn = await auth.api.signInEmail({
      body: { email: account.email, password: NEW_PASSWORD },
      asResponse: true,
    });
    expect(newSignIn.status).toBe(200);

    // 8. Ponowne użycie tego samego tokenu kończy się błędem
    expect(await isPasswordResetTokenValid(authCtx.internalAdapter, token)).toBe(false);
    const secondUse = await call("/api/auth/reset-password", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token, newPassword: "trzecie-haslo-nie-powinno-zadzialac" }),
    });
    expect(secondUse.status).toBe(400);
    expect(((await secondUse.json()) as { code?: string }).code).toBe("INVALID_TOKEN");
  });

  it("odrzuca wygasły token resetu hasła", async () => {
    const account = await createVerifiedAccount("expired");
    clearSentMails();

    const requestRes = await call("/api/auth/request-password-reset", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: account.email, redirectTo: "/reset-password" }),
    });
    expect(requestRes.status).toBe(200);
    const token = extractResetToken(account.email);

    await db.authVerification.updateMany({
      where: { identifier: `reset-password:${token}` },
      data: { expiresAt: new Date(Date.now() - 1_000) },
    });

    const authCtx = await auth.$context;
    expect(await isPasswordResetTokenValid(authCtx.internalAdapter, token)).toBe(false);

    const expiredRes = await call("/api/auth/reset-password", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token, newPassword: NEW_PASSWORD }),
    });
    expect(expiredRes.status).toBe(400);
    expect(((await expiredRes.json()) as { code?: string }).code).toBe("INVALID_TOKEN");

    // Stare hasło nadal działa
    const stillOld = await auth.api.signInEmail({
      body: { email: account.email, password: INITIAL_PASSWORD },
      asResponse: true,
    });
    expect(stillOld.status).toBe(200);
  });

  it("dla konta bez organizacji zmienia hasło i pomija wpis audytu, a dla konta DEACTIVATED nie wysyła maila", async () => {
    // Konto bez organizacji
    const orphanId = uuidv7();
    const orphanEmail = `orphan-${orphanId.slice(-6)}@noorg.test`;
    const authCtx = await auth.$context;
    const passwordHash = await authCtx.password.hash(INITIAL_PASSWORD);
    await db.authUser.create({
      data: { id: orphanId, name: "Konto Bez Firmy", email: orphanEmail, emailVerified: true },
    });
    createdUserIds.push(orphanId);
    await db.authCredential.create({
      data: {
        id: uuidv7(),
        userId: orphanId,
        accountId: orphanId,
        providerId: "credential",
        password: passwordHash,
      },
    });

    clearSentMails();
    const orphanReq = await call("/api/auth/request-password-reset", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: orphanEmail, redirectTo: "/reset-password" }),
    });
    expect(orphanReq.status).toBe(200);
    const orphanToken = extractResetToken(orphanEmail);

    const orphanReset = await call("/api/auth/reset-password", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token: orphanToken, newPassword: NEW_PASSWORD }),
    });
    expect(orphanReset.status).toBe(200);

    // Konto DEACTIVATED -> taka sama odpowiedź 200, brak wysłanego maila
    const deactivated = await createVerifiedAccount("deactivated");
    await withOrganization(db, deactivated.organizationId, (tx) =>
      tx.account.update({
        where: { id: deactivated.userId },
        data: { status: "DEACTIVATED", deactivatedAt: new Date() },
      }),
    );
    clearSentMails();
    const deactivatedReq = await call("/api/auth/request-password-reset", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: deactivated.email, redirectTo: "/reset-password" }),
    });
    expect(deactivatedReq.status).toBe(200);
    expect(sentMails().filter((m) => m.to === deactivated.email)).toHaveLength(0);
  });
});
