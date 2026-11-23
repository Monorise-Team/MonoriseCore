import "server-only";
import { accountClaims, uuidv7, withOrganization } from "@core/db";
import { betterAuth } from "better-auth";
import { prismaAdapter } from "better-auth/adapters/prisma";
import { nextCookies } from "better-auth/next-js";
import { jwt } from "better-auth/plugins";
import { config } from "./config";
import { db } from "./db";
import { linkMail, sendMail } from "./mail";

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
    // Ciasteczka sesji z akcji serwera Next.js
    nextCookies(),
  ],
});
