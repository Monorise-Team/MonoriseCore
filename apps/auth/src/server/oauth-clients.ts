import "server-only";
import { createHash, randomBytes } from "node:crypto";
import { uuidv7 } from "@core/db";
import { db } from "./db";

export const PRODUCT_SCOPES = ["openid", "profile", "email", "offline_access"];

/** Skrót sekretu klienta (ten sam w konfiguracji wtyczki OAuth i przy rejestracji aplikacji). */
export function hashClientSecret(secret: string): string {
  return createHash("sha256").update(secret).digest("base64url");
}

export interface FirstPartyResource {
  /** Adres API produktu, a zarazem odbiorca tokenu (aud), np. https://aven.monorise.studio */
  identifier: string;
  name: string;
}

export interface FirstPartyClient {
  /** Stały identyfikator, np. avenmail-web */
  clientId: string;
  name: string;
  redirectUris: string[];
  /** Serwer produktu (BFF) z sekretem; aplikacje na komputer i telefon są publiczne (tylko PKCE). */
  confidential: boolean;
  resources: string[];
}

/**
 * Rejestruje aplikacje Monorise jako klientów OAuth (bez ekranu zgody, z obowiązkowym PKCE) i ich API jako
 * zasoby. Działa wielokrotnie: istniejące wpisy aktualizuje. Zwraca sekrety nowych klientów poufnych;
 * w bazie zostaje tylko ich skrót, więc trzeba je zapisać od razu.
 */
export async function ensureFirstPartyClients({
  resources,
  clients,
}: {
  resources: FirstPartyResource[];
  clients: FirstPartyClient[];
}): Promise<Record<string, string>> {
  for (const resource of resources) {
    await db.authOAuthResource.upsert({
      where: { identifier: resource.identifier },
      create: { id: uuidv7(), identifier: resource.identifier, name: resource.name, allowedScopes: PRODUCT_SCOPES },
      update: { name: resource.name, disabled: false, allowedScopes: PRODUCT_SCOPES },
    });
  }
  const secrets: Record<string, string> = {};
  for (const client of clients) {
    const data = {
      name: client.name,
      redirectUris: client.redirectUris,
      skipConsent: true,
      requirePKCE: true,
      disabled: false,
      enableEndSession: true,
      scopes: PRODUCT_SCOPES,
      grantTypes: ["authorization_code", "refresh_token"],
      responseTypes: ["code"],
      tokenEndpointAuthMethod: client.confidential ? "client_secret_post" : "none",
      applicationType: client.confidential ? "web" : "native",
    };
    const existing = await db.authOAuthClient.findUnique({ where: { clientId: client.clientId } });
    if (existing) {
      await db.authOAuthClient.update({ where: { clientId: client.clientId }, data });
    } else {
      const secret = client.confidential ? randomBytes(32).toString("base64url") : undefined;
      await db.authOAuthClient.create({
        data: {
          id: uuidv7(),
          clientId: client.clientId,
          clientSecret: secret ? hashClientSecret(secret) : null,
          ...data,
        },
      });
      if (secret) secrets[client.clientId] = secret;
    }
    for (const identifier of client.resources) {
      const linked = await db.authOAuthClientResource.findFirst({
        where: { clientId: client.clientId, resourceId: identifier },
      });
      if (!linked) {
        await db.authOAuthClientResource.create({
          data: { id: uuidv7(), clientId: client.clientId, resourceId: identifier },
        });
      }
    }
  }
  return secrets;
}
