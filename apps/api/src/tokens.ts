import { AccessTokenClaims, MachineTokenClaims } from "@core/contracts";
import { createRemoteJWKSet, jwtVerify, type JWTVerifyGetKey } from "jose";

export interface TokenVerifierOptions {
  /** Klucze publiczne serwera logowania (JWKS); w testach zestaw lokalny. */
  keys: JWTVerifyGetKey;
  issuer: string;
  audience: string;
}

export type TokenVerifier = (token: string) => Promise<AccessTokenClaims>;
export type MachineTokenVerifier = (token: string) => Promise<MachineTokenClaims>;

/**
 * Weryfikacja tokenu dostępu lokalnie, bez pytania serwera logowania przy każdym żądaniu (ADR-0023):
 * podpis kluczem z JWKS, wystawca, odbiorca, ważność i komplet pól firmy.
 */
export function createTokenVerifier({ keys, issuer, audience }: TokenVerifierOptions): TokenVerifier {
  return async (token) => {
    const { payload } = await jwtVerify(token, keys, { issuer, audience, algorithms: ["EdDSA"] });
    return AccessTokenClaims.parse(payload);
  };
}

/**
 * Weryfikacja tokenu maszynowego (OAuth 2.1 `client_credentials`) tym samym JWKS, wystawcą i odbiorcą,
 * ale osobnym schematem bez `org_id` i z wymaganym `client_id`.
 */
export function createMachineTokenVerifier({ keys, issuer, audience }: TokenVerifierOptions): MachineTokenVerifier {
  return async (token) => {
    const { payload } = await jwtVerify(token, keys, { issuer, audience, algorithms: ["EdDSA"] });
    return MachineTokenClaims.parse(payload);
  };
}

export function remoteKeys(jwksUrl: string): JWTVerifyGetKey {
  return createRemoteJWKSet(new URL(jwksUrl), { cooldownDuration: 30_000, cacheMaxAge: 10 * 60_000 });
}
