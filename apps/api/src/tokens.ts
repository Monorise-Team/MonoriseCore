import { AccessTokenClaims } from "@core/contracts";
import { createRemoteJWKSet, jwtVerify, type JWTVerifyGetKey } from "jose";

export interface TokenVerifierOptions {
  /** Klucze publiczne serwera logowania (JWKS); w testach zestaw lokalny. */
  keys: JWTVerifyGetKey;
  issuer: string;
  audience: string;
}

export type TokenVerifier = (token: string) => Promise<AccessTokenClaims>;

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

export function remoteKeys(jwksUrl: string): JWTVerifyGetKey {
  return createRemoteJWKSet(new URL(jwksUrl), { cooldownDuration: 30_000, cacheMaxAge: 10 * 60_000 });
}
