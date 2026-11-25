import { createHash, randomBytes } from "node:crypto";
import {
  AccessTokenClaims,
  DIRECTORY_READ_SCOPE,
  MachineTokenClaims,
  PERMISSIONS_READ_SCOPE,
  PERMISSIONS_REGISTER_SCOPE,
} from "@core/contracts";
import { withOrganization } from "@core/db";
import { createLocalJWKSet, jwtVerify } from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { auth } from "@/server/auth";
import { ensureFirstPartyClients, PRODUCT_MACHINE_SCOPES, PRODUCT_SCOPES } from "@/server/oauth-clients";
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

async function refreshWith(refreshToken: string) {
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

/** Udaje, że minęło okno powtórki (20 s) dla obróconych tokenów Anny w tej aplikacji. */
async function expireRotationReplays() {
  const user = await db.authUser.findUniqueOrThrow({ where: { email } });
  await db.authOAuthRefreshToken.updateMany({
    where: { userId: user.id, clientId: client.client_id, rotatedAt: { not: null } },
    data: { rotationReplayExpiresAt: new Date(Date.now() - 1000) },
  });
}

/** Pełne logowanie Anny w produkcie (PKCE) i wymiana kodu na tokeny. */
async function signInForTokens(): Promise<{ access_token: string; refresh_token: string }> {
  const verifier = base64url(randomBytes(32));
  const challenge = base64url(createHash("sha256").update(verifier).digest());
  const authorize = new URLSearchParams({
    response_type: "code",
    client_id: client.client_id,
    redirect_uri: REDIRECT,
    scope: "openid profile email offline_access",
    state: "stan-456",
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
    const refreshed = (await refresh.json()) as { access_token: string; refresh_token: string };
    const again = await jwtVerify(refreshed.access_token, jwks, { audience: RESOURCE });
    expect(again.payload.org_id).toBe(organizationId);

    // 5. Token odświeżania jest jednorazowy: dostajemy nowy
    expect(refreshed.refresh_token).toBeTruthy();
    expect(refreshed.refresh_token).not.toBe(tokens.refresh_token);

    // 6. Przez 20 s stary token dostaje tę samą odpowiedź (dwa żądania przeglądarki naraz, ADR-0098)
    const replay = await refreshWith(tokens.refresh_token);
    expect(replay.status).toBe(200);
    const replayed = (await replay.json()) as { access_token: string; refresh_token: string };
    expect(replayed.refresh_token).toBe(refreshed.refresh_token);

    // 7. Po tym czasie ponowne użycie wygląda na kradzież i unieważnia też nowy token (RFC 9700, ADR-0023)
    await expireRotationReplays();
    const reuse = await refreshWith(tokens.refresh_token);
    expect(reuse.status).toBe(400);
    expect(((await reuse.json()) as { error?: string }).error).toBe("invalid_grant");
    const afterReuse = await refreshWith(refreshed.refresh_token);
    expect(afterReuse.status).toBe(400);
  });

  it("odmawia odświeżenia nieaktywnemu kontu zwykłym invalid_grant, a nie błędem serwera", async () => {
    const tokens = await signInForTokens();
    const user = await db.authUser.findUniqueOrThrow({ where: { email } });
    await withOrganization(db, organizationId, (tx) =>
      tx.account.update({ where: { id: user.id }, data: { status: "DEACTIVATED" } }),
    );
    try {
      const refresh = await refreshWith(tokens.refresh_token);
      expect(refresh.status).toBe(400);
      expect(((await refresh.json()) as { error?: string }).error).toBe("invalid_grant");
    } finally {
      await withOrganization(db, organizationId, (tx) =>
        tx.account.update({ where: { id: user.id }, data: { status: "ACTIVE" } }),
      );
    }
  });

  it("aplikacja na komputer loguje się przez 127.0.0.1 z dowolnym portem, bez sekretu (RFC 8252)", async () => {
    const desktopId = `avenmail-desktop-test-${crypto.randomUUID().slice(0, 8)}`;
    await ensureFirstPartyClients({
      resources: [{ identifier: RESOURCE, name: "AvenMail API (test)" }],
      clients: [
        {
          clientId: desktopId,
          name: "AvenMail na komputer (test)",
          redirectUris: ["http://127.0.0.1/oauth/callback"],
          confidential: false,
          resources: [RESOURCE],
        },
      ],
    });
    try {
      const verifier = base64url(randomBytes(32));
      const challenge = base64url(createHash("sha256").update(verifier).digest());
      const loopback = "http://127.0.0.1:53682/oauth/callback";
      const query = (redirectUri: string) =>
        new URLSearchParams({
          response_type: "code",
          client_id: desktopId,
          redirect_uri: redirectUri,
          scope: "openid offline_access",
          state: "stan-komputer",
          code_challenge: challenge,
          code_challenge_method: "S256",
          resource: RESOURCE,
        });

      // Inna ścieżka niż zarejestrowana nie prowadzi do logowania
      const wrong = await call(`/api/auth/oauth2/authorize?${query("http://127.0.0.1:53682/inna")}`);
      expect(new URL(wrong.headers.get("location") ?? "/", BASE).pathname).not.toBe("/sign-in");

      const first = await call(`/api/auth/oauth2/authorize?${query(loopback)}`);
      const login = new URL(first.headers.get("location")!, BASE);
      expect(login.pathname).toBe("/sign-in");
      const signIn = await call("/api/auth/sign-in/email", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password: PASSWORD, oauth_query: login.search.slice(1) }),
      });
      const body = (await signIn.json().catch(() => ({}))) as { url?: string };
      const back = new URL(signIn.headers.get("location") ?? body.url!);
      expect(`${back.origin}${back.pathname}`).toBe(loopback);

      const exchange = await call("/api/auth/oauth2/token", {
        method: "POST",
        form: {
          grant_type: "authorization_code",
          code: back.searchParams.get("code")!,
          redirect_uri: loopback,
          client_id: desktopId,
          code_verifier: verifier,
          resource: RESOURCE,
        },
      });
      expect(exchange.status).toBe(200);
      expect(((await exchange.json()) as { refresh_token?: string }).refresh_token).toBeTruthy();
    } finally {
      await db.authOAuthClient.deleteMany({ where: { clientId: desktopId } });
    }
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

  it("wydaje token maszynowy client_credentials tylko uprawnionemu klientowi poufnemu i blokuje ten zakres w logowaniu użytkownika", async () => {
    const suffix = crypto.randomUUID().slice(0, 8);
    const coreResource = `http://core-${suffix}.localhost:3200`;
    const m2mClientId = `timotime-web-test-${suffix}`;
    const publicClientId = `timotime-mobile-test-${suffix}`;

    const secrets = await ensureFirstPartyClients({
      resources: [
        { identifier: RESOURCE, name: "AvenMail API (test)" },
        {
          identifier: coreResource,
          name: "Core API (test)",
          allowedScopes: [...PRODUCT_SCOPES, ...PRODUCT_MACHINE_SCOPES],
        },
      ],
      clients: [
        {
          clientId: m2mClientId,
          name: "TimoTime (test)",
          redirectUris: [REDIRECT],
          confidential: true,
          resources: [RESOURCE, coreResource],
          clientCredentialsScopes: [...PRODUCT_MACHINE_SCOPES],
        },
        {
          clientId: publicClientId,
          name: "TimoTime na telefon (test)",
          redirectUris: ["timotime://oauth/callback"],
          confidential: false,
          resources: [RESOURCE, coreResource],
        },
      ],
    });
    const m2mSecret = secrets[m2mClientId]!;

    try {
      // 1. Poufny klient z grantem client_credentials dostaje token JWT dla Core API
      const issued = await call("/api/auth/oauth2/token", {
        method: "POST",
        form: {
          grant_type: "client_credentials",
          client_id: m2mClientId,
          client_secret: m2mSecret,
          scope: PERMISSIONS_REGISTER_SCOPE,
          resource: coreResource,
        },
      });
      expect(issued.status).toBe(200);
      const tokenBody = (await issued.json()) as {
        access_token: string;
        expires_in: number;
        scope: string;
        refresh_token?: string;
      };
      expect(tokenBody.expires_in).toBe(300);
      expect(tokenBody.scope).toBe(PERMISSIONS_REGISTER_SCOPE);
      expect(tokenBody.refresh_token).toBeUndefined();

      const jwks = createLocalJWKSet(await auth.api.getJwks());
      const { payload, protectedHeader } = await jwtVerify(tokenBody.access_token, jwks, {
        audience: coreResource,
        issuer: BASE,
        algorithms: ["EdDSA"],
      });
      expect(protectedHeader.alg).toBe("EdDSA");
      expect(payload.client_id).toBe(m2mClientId);
      expect(payload.azp).toBe(m2mClientId);
      expect(payload.scope).toBe(PERMISSIONS_REGISTER_SCOPE);
      expect(payload.org_id).toBeUndefined();
      expect(payload.employee_id).toBeUndefined();
      expect(payload.authz_rev).toBeUndefined();
      expect(MachineTokenClaims.parse(payload).client_id).toBe(m2mClientId);
      expect(AccessTokenClaims.safeParse(payload).success).toBe(false);

      // 1b. Poufny klient może też pobrać token maszynowy z zakresami core:permissions.read i core:directory.read
      for (const readScope of [PERMISSIONS_READ_SCOPE, DIRECTORY_READ_SCOPE]) {
        const issuedRead = await call("/api/auth/oauth2/token", {
          method: "POST",
          form: {
            grant_type: "client_credentials",
            client_id: m2mClientId,
            client_secret: m2mSecret,
            scope: readScope,
            resource: coreResource,
          },
        });
        expect(issuedRead.status).toBe(200);
        const readTokenBody = (await issuedRead.json()) as { access_token: string; scope: string };
        expect(readTokenBody.scope).toBe(readScope);
        const { payload: readPayload } = await jwtVerify(readTokenBody.access_token, jwks, {
          audience: coreResource,
          issuer: BASE,
          algorithms: ["EdDSA"],
        });
        expect(MachineTokenClaims.parse(readPayload).scope).toBe(readScope);
        expect(readPayload.org_id).toBeUndefined();
      }

      // 2. Dla zasobu produktu (bez core:permissions.register w allowedScopes) token maszynowy nie jest wydawany
      const wrongResource = await call("/api/auth/oauth2/token", {
        method: "POST",
        form: {
          grant_type: "client_credentials",
          client_id: m2mClientId,
          client_secret: m2mSecret,
          scope: PERMISSIONS_REGISTER_SCOPE,
          resource: RESOURCE,
        },
      });
      expect(wrongResource.status).toBe(400);

      // 3. Klient poufny bez grantu client_credentials dostaje odmowę
      const noGrant = await call("/api/auth/oauth2/token", {
        method: "POST",
        form: {
          grant_type: "client_credentials",
          client_id: client.client_id,
          client_secret: client.client_secret,
          scope: PERMISSIONS_REGISTER_SCOPE,
          resource: coreResource,
        },
      });
      expect(noGrant.status).toBe(400);

      // 4. Klient publiczny dostaje odmowę
      const publicDenied = await call("/api/auth/oauth2/token", {
        method: "POST",
        form: {
          grant_type: "client_credentials",
          client_id: publicClientId,
          scope: PERMISSIONS_REGISTER_SCOPE,
          resource: coreResource,
        },
      });
      expect(publicDenied.status).toBe(400);

      // 5. Przepływ przeglądarkowy użytkownika nie może poprosić o zakresy maszynowe (permissions.* ani directory.read)
      const challenge = base64url(createHash("sha256").update("weryfikator-user-scope-test-0123456789abcdef").digest());
      for (const machineScope of [PERMISSIONS_REGISTER_SCOPE, PERMISSIONS_READ_SCOPE, DIRECTORY_READ_SCOPE]) {
        const authorize = new URLSearchParams({
          response_type: "code",
          client_id: m2mClientId,
          redirect_uri: REDIRECT,
          scope: `openid ${machineScope}`,
          state: "stan-m2m-scope",
          code_challenge: challenge,
          code_challenge_method: "S256",
          resource: coreResource,
        });
        const deniedAuthorize = await call(`/api/auth/oauth2/authorize?${authorize}`);
        expect(deniedAuthorize.status).toBe(302);
        const location = new URL(deniedAuthorize.headers.get("location")!, BASE);
        expect(location.pathname).not.toBe("/sign-in");
        expect(location.searchParams.get("error")).toBe("invalid_scope");
      }
    } finally {
      await db.authOAuthClient.deleteMany({ where: { clientId: { in: [m2mClientId, publicClientId] } } });
      await db.authOAuthResource.deleteMany({ where: { identifier: coreResource } });
    }
  });
});
