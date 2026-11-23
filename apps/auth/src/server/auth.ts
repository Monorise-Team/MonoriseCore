import "server-only";
import { oauthProvider } from "@better-auth/oauth-provider";
import { accountClaims, uuidv7, withOrganization } from "@core/db";
import { betterAuth } from "better-auth";
import { prismaAdapter } from "better-auth/adapters/prisma";
import { nextCookies } from "better-auth/next-js";
import { jwt } from "better-auth/plugins";
import { config } from "./config";
import { db } from "./db";
import { linkMail, sendMail } from "./mail";
import { hashClientSecret } from "./oauth-clients";

/** Firmy w tych stanach nie logują się (wstrzymanie, usunięcie). */
const BLOCKED_ORGANIZATIONS = new Set(["SUSPENDED", "DELETED"]);

/**
 * Logowanie Monorise (ADR-0017): Better Auth z bazą monorise_core. Tabele biblioteki są w schemacie
 * „auth”, a konto firmy (Account) ma ten sam identyfikator co konto logowania (sub w tokenie).
 */
export const auth = betterAuth({
  appName: "Monorise",
  baseURL: config.authUrl,
  secret: config.secret,
  database: prismaAdapter(db, { provider: "postgresql" }),
  telemetry: { enabled: false },
  user: { modelName: "authUser" },
  session: { modelName: "authSession" },
  account: { modelName: "authCredential" },
  verification: { modelName: "authVerification" },
  advanced: {
    cookiePrefix: "monorise",
    database: { generateId: () => uuidv7() },
  },
  emailAndPassword: {
    enabled: true,
    requireEmailVerification: true,
    minPasswordLength: 12,
    maxPasswordLength: 128,
    autoSignIn: false,
  },
  emailVerification: {
    sendOnSignUp: true,
    autoSignInAfterVerification: true,
    sendVerificationEmail: async ({ user, url }) => {
      await sendMail(
        linkMail(
          user.email,
          "Potwierdź adres e-mail w Monorise",
          "Potwierdź, że ten adres należy do Ciebie, żeby zalogować się do Monorise.",
          "Potwierdź adres",
          url,
        ),
      );
    },
  },
  databaseHooks: {
    session: {
      create: {
        // Konto dezaktywowane albo firma wstrzymana: bez nowej sesji (spec §11)
        before: async (session) => {
          const claims = await accountClaims(db, session.userId);
          if (!claims || claims.accountStatus === "DEACTIVATED") return false;
          if (BLOCKED_ORGANIZATIONS.has(claims.organizationStatus)) return false;
          return { data: session };
        },
        after: async (session) => {
          const claims = await accountClaims(db, session.userId);
          if (!claims) return;
          await withOrganization(db, claims.organizationId, (tx) =>
            tx.account.update({ where: { id: session.userId }, data: { lastLoginAt: new Date() } }),
          );
        },
      },
    },
  },
  plugins: [
    jwt({
      jwks: { keyPairConfig: { alg: "EdDSA", crv: "Ed25519" } },
      jwt: {
        issuer: config.authUrl,
        audience: config.tokenAudience,
        // Token dostępu ważny 5 minut (ADR-0023)
        expirationTime: "5m",
        definePayload: async ({ user, session }) => {
          const claims = await accountClaims(db, user.id);
          if (!claims) throw new Error("Konto logowania bez konta firmy");
          return {
            org_id: claims.organizationId,
            employee_id: claims.employeeId,
            authz_rev: claims.authzRevision,
            sid: session.id,
            amr: ["pwd"],
          };
        },
      },
      schema: { jwks: { modelName: "authJwks" } },
    }),
    // Logowanie produktów (OAuth 2.1 z PKCE): produkt dostaje token dla swojego API (aud = zasób, RFC 8707)
    oauthProvider({
      loginPage: "/sign-in",
      consentPage: "/consent",
      scopes: ["openid", "profile", "email", "offline_access"],
      // Token dostępu ważny 5 minut (ADR-0023), odświeżanie do 30 dni
      accessTokenExpiresIn: 300,
      refreshTokenExpiresIn: 30 * 24 * 60 * 60,
      // Aplikacje rejestruje tylko Core (skrypt oauth:seed). Żadne działanie na klientach i zasobach przez
      // HTTP nie jest dozwolone, także dla zalogowanych (domyślnie wtyczka pozwala na nie każdej sesji).
      allowDynamicClientRegistration: false,
      clientPrivileges: async () => false,
      resourcePrivileges: async () => false,
      storeClientSecret: { hash: async (secret: string) => hashClientSecret(secret) },
      // Na produkcji tylko HTTPS; lokalnie także http://localhost i http://*.localhost
      allowInsecureRedirectUri: (url: URL) =>
        config.allowLocalHttpRedirects && (url.hostname === "localhost" || url.hostname.endsWith(".localhost")),
      customAccessTokenClaims: async ({ user }) => {
        if (!user) return {};
        const claims = await accountClaims(db, user.id);
        if (!claims || claims.accountStatus === "DEACTIVATED") throw new Error("Konto nie może się logować");
        // amr i acr ustala sam serwer OAuth (pola zastrzeżone), dlatego ich tu nie ma
        return { org_id: claims.organizationId, employee_id: claims.employeeId, authz_rev: claims.authzRevision };
      },
      schema: {
        oauthClient: { modelName: "authOAuthClient" },
        oauthResource: { modelName: "authOAuthResource" },
        oauthClientResource: { modelName: "authOAuthClientResource" },
        oauthRefreshToken: { modelName: "authOAuthRefreshToken" },
        oauthAccessToken: { modelName: "authOAuthAccessToken" },
        oauthConsent: { modelName: "authOAuthConsent" },
        oauthClientAssertion: { modelName: "authOAuthClientAssertion" },
      },
    }),
    // Ciasteczka sesji z akcji serwera Next.js
    nextCookies(),
  ],
});
