import { createHash, randomBytes } from "node:crypto";
import { AccessTokenClaims } from "@core/contracts";
import { withOrganization } from "@core/db";
import { createLocalJWKSet, jwtVerify } from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { auth } from "@/server/auth";
import { ensureFirstPartyClients } from "@/server/oauth-clients";
import { db } from "@/server/db";
import { sentMails } from "@/server/mail";
import { signUpOrganization } from "@/server/signup";

const BASE = "http://localhost:3100";
const RESOURCE = `http://aven-${crypto.randomUUID().slice(0, 8)}.localhost:3000`;
const REDIRECT = "http://aven-mail.localhost:3000/api/auth/callback";
const PASSWORD = "bardzo-dlugie-haslo-1";

const CLIENT_ID = `avenmail-web-test-${crypto.randomUUID().slice(0, 8)}`;
let client: { client_id: string; client_secret: string };
let email: string;
let organizationId: string;

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

beforeAll(async () => {
  const secrets = await ensureFirstPartyClients({
    resources: [{ identifier: RESOURCE, name: "AvenMail API (test)" }],
    clients: [
      {
        clientId: CLIENT_ID,
        name: "AvenMail (test)",
        redirectUris: [REDIRECT],
        confidential: true,
        resources: [RESOURCE],
      },
    ],
  });
  client = { client_id: CLIENT_ID, client_secret: secrets[CLIENT_ID]! };

  email = `anna@${crypto.randomUUID().slice(0, 8)}-oauth.test`;
  ({ organizationId } = await signUpOrganization({
    organizationName: "Acme",
    firstName: "Anna",
    lastName: "Kowalska",
    email,
    password: PASSWORD,
  }));
  const mail = [...sentMails()].reverse().find((m) => m.to === email)!;
  const token = new URL(/https?:\/\/\S+/.exec(mail.text)![0]).searchParams.get("token")!;
  await auth.api.verifyEmail({ query: { token } });
});

afterAll(async () => {
  await withOrganization(db, organizationId, (tx) => tx.organization.deleteMany({ where: { id: organizationId } }));
  await db.authUser.deleteMany({ where: { email } });
  await db.authOAuthClient.deleteMany({ where: { clientId: client.client_id } });
  await db.authOAuthResource.deleteMany({ where: { identifier: RESOURCE } });
  await db.$disconnect();
});

describe("logowanie produktu przez Core (OAuth 2.1 z PKCE)", () => {
  it("przekierowuje, loguje, wydaje token dla API produktu i go odświeża", async () => {
    const verifier = base64url(randomBytes(32));
    const challenge = base64url(createHash("sha256").update(verifier).digest());
    const authorize = new URLSearchParams({
      response_type: "code",
      client_id: client.client_id,
      redirect_uri: REDIRECT,
      scope: "openid profile email offline_access",
      state: "stan-123",
      code_challenge: challenge,
      code_challenge_method: "S256",
      resource: RESOURCE,
    });

    // 1. Niezalogowana Anna trafia na ekran logowania z podpisanymi parametrami
    const first = await call(`/api/auth/oauth2/authorize?${authorize}`);
    expect(first.status).toBe(302);
    const login = new URL(first.headers.get("location")!, BASE);
    expect(login.pathname).toBe("/sign-in");
    expect(login.searchParams.get("sig")).toBeTruthy();

    // 2. Logowanie z ekranu (wtyczka klienta dokleja oauth_query) wraca do produktu z kodem
    const signIn = await call("/api/auth/sign-in/email", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password: PASSWORD, oauth_query: login.search.slice(1) }),
    });
    const signInBody = (await signIn.json().catch(() => ({}))) as { url?: string };
    const back = new URL(signIn.headers.get("location") ?? signInBody.url!);
    expect(`${back.origin}${back.pathname}`).toBe(REDIRECT);
    expect(back.searchParams.get("state")).toBe("stan-123");
    const code = back.searchParams.get("code")!;
    expect(code).toBeTruthy();

    // 3. Serwer produktu wymienia kod na token (z weryfikatorem PKCE i sekretem klienta)
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
    const tokens = (await exchange.json()) as { access_token: string; refresh_token: string; expires_in: number };
    expect(tokens.expires_in).toBe(300);
    expect(tokens.refresh_token).toBeTruthy();

    const jwks = createLocalJWKSet(await auth.api.getJwks());
    const { payload, protectedHeader } = await jwtVerify(tokens.access_token, jwks, {
      audience: RESOURCE,
      issuer: BASE,
      algorithms: ["EdDSA"],
    });
    expect(protectedHeader.alg).toBe("EdDSA");
    expect(payload.org_id).toBe(organizationId);
    expect(payload.employee_id).toEqual(expect.any(String));
    expect(payload.authz_rev).toBe(0);
    // sid dokłada sam serwer OAuth; amr jest polem zastrzeżonym i na razie go nie ma (kontrakt przyjmuje [])
    expect(payload.sid).toEqual(expect.any(String));
    expect(payload.client_id).toBe(client.client_id);
    expect(AccessTokenClaims.parse(payload).amr).toEqual([]);

    // 4. Odświeżenie tokenu bez ponownego logowania
    const refresh = await call("/api/auth/oauth2/token", {
      method: "POST",
      form: {
        grant_type: "refresh_token",
        refresh_token: tokens.refresh_token,
        client_id: client.client_id,
        client_secret: client.client_secret,
        resource: RESOURCE,
      },
    });
    expect(refresh.status).toBe(200);
    const refreshed = (await refresh.json()) as { access_token: string };
    const again = await jwtVerify(refreshed.access_token, jwks, { audience: RESOURCE });
    expect(again.payload.org_id).toBe(organizationId);
  });

  it("nie pozwala zalogowanej osobie zarejestrować własnej aplikacji", async () => {
    const signIn = await call("/api/auth/sign-in/email", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password: PASSWORD }),
    });
    const cookie = signIn.headers
      .getSetCookie()
      .map((c) => c.split(";")[0])
      .join("; ");
    const create = await call("/api/auth/oauth2/create-client", {
      method: "POST",
      headers: { "Content-Type": "application/json", cookie },
      body: JSON.stringify({ redirect_uris: ["https://zly.example/callback"], client_name: "Obca aplikacja" }),
    });
    expect([401, 403]).toContain(create.status);
    expect(await db.authOAuthClient.count({ where: { name: "Obca aplikacja" } })).toBe(0);
  });

  it("odrzuca kod bez właściwego weryfikatora PKCE", async () => {
    const challenge = base64url(createHash("sha256").update("prawdziwy-weryfikator-0123456789abcdef").digest());
    const authorize = new URLSearchParams({
      response_type: "code",
      client_id: client.client_id,
      redirect_uri: REDIRECT,
      scope: "openid",
      code_challenge: challenge,
      code_challenge_method: "S256",
      resource: RESOURCE,
    });
    const first = await call(`/api/auth/oauth2/authorize?${authorize}`);
    const login = new URL(first.headers.get("location")!, BASE);
    const signIn = await call("/api/auth/sign-in/email", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password: PASSWORD, oauth_query: login.search.slice(1) }),
    });
    const body = (await signIn.json().catch(() => ({}))) as { url?: string };
    const code = new URL(signIn.headers.get("location") ?? body.url!).searchParams.get("code")!;
    const exchange = await call("/api/auth/oauth2/token", {
      method: "POST",
      form: {
        grant_type: "authorization_code",
        code,
        redirect_uri: REDIRECT,
        client_id: client.client_id,
        client_secret: client.client_secret,
        code_verifier: "zly-weryfikator-0123456789abcdefghijklmnopqrstuv",
        resource: RESOURCE,
      },
    });
    expect(exchange.status).toBe(400);
  });
});
