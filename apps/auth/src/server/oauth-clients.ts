import "server-only";
import { createHash, randomBytes } from "node:crypto";
import {
  DIRECTORY_READ_SCOPE,
  EVENTS_READ_SCOPE,
  PERMISSIONS_READ_SCOPE,
  PERMISSIONS_REGISTER_SCOPE,
} from "@core/contracts";
import { uuidv7 } from "@core/db";
import { db } from "./db";

export const PRODUCT_SCOPES = ["openid", "profile", "email", "offline_access"];
/** Zakresy maszynowe (client_credentials) dla poufnych serwerów produktów w Core API. */
export const PRODUCT_MACHINE_SCOPES = [
  PERMISSIONS_REGISTER_SCOPE,
  PERMISSIONS_READ_SCOPE,
  DIRECTORY_READ_SCOPE,
  EVENTS_READ_SCOPE,
];

/** Skrót sekretu klienta (ten sam w konfiguracji wtyczki OAuth i przy rejestracji aplikacji). */
export function hashClientSecret(secret: string): string {
  return createHash("sha256").update(secret).digest("base64url");
}

export interface FirstPartyResource {
  /** Adres API produktu, a zarazem odbiorca tokenu (aud), np. https://aven.monorise.studio */
  identifier: string;
  name: string;
  /** Zakresy dopuszczone dla zasobu (domyślnie PRODUCT_SCOPES). */
  allowedScopes?: string[];
}

export interface FirstPartyClient {
  /** Stały identyfikator, np. avenmail-web */
  clientId: string;
  name: string;
  redirectUris: string[];
  /** Serwer produktu (BFF) z sekretem; aplikacje na komputer i telefon są publiczne (tylko PKCE). */
  confidential: boolean;
  resources: string[];
  /** Zakresy maszynowe (grant `client_credentials`), dozwolone wyłącznie dla klientów poufnych. */
  clientCredentialsScopes?: string[];
}

export interface FirstPartyProduct {
  /** Stały klucz produktu, np. `timotime` (zgodny z prefiksem kluczy uprawnień). */
  key: string;
  name: string;
  /** Identyfikator poufnego klienta OAuth uprawnionego do rejestracji uprawnień produktu. */
  registrationClientId: string;
}

/**
 * Rejestruje aplikacje Monorise jako klientów OAuth (bez ekranu zgody, z obowiązkowym PKCE), ich API jako
 * zasoby oraz opcjonalnie wpisy produktów w tabeli `products`. Działa wielokrotnie: istniejące wpisy aktualizuje.
 * Zwraca sekrety nowych klientów poufnych; w bazie zostaje tylko ich skrót, więc trzeba je zapisać od razu.
 */
export async function ensureFirstPartyClients({
  resources,
  clients,
  products = [],
}: {
  resources: FirstPartyResource[];
  clients: FirstPartyClient[];
  products?: FirstPartyProduct[];
}): Promise<Record<string, string>> {
  for (const resource of resources) {
    const allowedScopes = resource.allowedScopes ?? PRODUCT_SCOPES;
    await db.authOAuthResource.upsert({
      where: { identifier: resource.identifier },
      create: { id: uuidv7(), identifier: resource.identifier, name: resource.name, allowedScopes },
      update: { name: resource.name, disabled: false, allowedScopes },
    });
  }
  const secrets: Record<string, string> = {};
  for (const client of clients) {
    const m2mScopes = client.clientCredentialsScopes ?? [];
    if (m2mScopes.length > 0 && !client.confidential) {
      throw new Error(`Klient publiczny ${client.clientId} nie może mieć zakresów client_credentials`);
    }
    const grantTypes =
      m2mScopes.length > 0
        ? ["authorization_code", "refresh_token", "client_credentials"]
        : ["authorization_code", "refresh_token"];
    const data = {
      name: client.name,
      redirectUris: client.redirectUris,
      skipConsent: true,
      requirePKCE: true,
      disabled: false,
      enableEndSession: true,
      scopes: PRODUCT_SCOPES,
      clientCredentialsScopes: m2mScopes,
      grantTypes,
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
  for (const product of products) {
    await db.product.upsert({
      where: { key: product.key },
      create: {
        id: uuidv7(),
        key: product.key,
        name: product.name,
        registrationClientId: product.registrationClientId,
      },
      update: {
        name: product.name,
        registrationClientId: product.registrationClientId,
      },
    });
  }
  return secrets;
}
