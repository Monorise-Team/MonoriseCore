import "server-only";
import type { NextResponse } from "next/server";
import { config } from "./config";
import { db } from "./db";

export const RETURN_CLIENT_COOKIE = "monorise-return-client";
export const RETURN_CLIENT_MAX_AGE_SECONDS = 7 * 24 * 60 * 60;
export const RETURN_TO_PRODUCT_PATH = "/api/return-to-product";

const CLIENT_ID_PATTERN = /^[a-zA-Z0-9._-]{1,128}$/;

export interface ReturnClient {
  clientId: string;
  name: string;
  uri: string;
}

export interface ReturnButtonState {
  href: string;
  label: string;
  clientName: string;
}

/**
 * Akceptuje wyłącznie identyfikator klienta OAuth (nigdy adresu URL ani ścieżki).
 */
export function parseClientId(raw: unknown): string | null {
  if (typeof raw !== "string") return null;
  const trimmed = raw.trim();
  if (!CLIENT_ID_PATTERN.test(trimmed)) return null;
  return trimmed;
}

/**
 * Ciasteczko jest `Secure` poza lokalnym HTTP (`localhost`, `*.localhost`, `127.0.0.1`), tak jak
 * pozostałe ciasteczka `apps/auth`.
 */
export function isSecureReturnCookie(authUrl: string = config.authUrl): boolean {
  try {
    const url = new URL(authUrl);
    if (url.protocol === "https:") return true;
    return url.hostname !== "localhost" && !url.hostname.endsWith(".localhost") && url.hostname !== "127.0.0.1";
  } catch {
    return true;
  }
}

export function returnClientCookieOptions(maxAge = RETURN_CLIENT_MAX_AGE_SECONDS) {
  return {
    httpOnly: true,
    sameSite: "lax" as const,
    secure: isSecureReturnCookie(),
    path: "/",
    maxAge,
  };
}

export function setReturnClientCookie(response: NextResponse, clientId: string): void {
  response.cookies.set(RETURN_CLIENT_COOKIE, clientId, returnClientCookieOptions());
}

export function clearReturnClientCookie(response: NextResponse): void {
  response.cookies.set(RETURN_CLIENT_COOKIE, "", returnClientCookieOptions(0));
}

function parseProductUri(raw: string | null | undefined): string | null {
  const trimmed = raw?.trim();
  if (!trimmed) return null;
  try {
    const url = new URL(trimmed);
    if (url.protocol !== "https:" && url.protocol !== "http:") return null;
    return url.toString();
  } catch {
    return null;
  }
}

/**
 * Wyszukuje w bazie aktywnego klienta OAuth, który ma adres powrotu (`uri`).
 * Nieznane, wyłączone lub pozbawione adresu `uri` (np. aplikacje mobilne) zwracają `null`.
 */
export async function findReturnClient(rawClientId: unknown): Promise<ReturnClient | null> {
  const clientId = parseClientId(rawClientId);
  if (!clientId) return null;
  const client = await db.authOAuthClient.findUnique({
    where: { clientId },
    select: { clientId: true, name: true, uri: true, disabled: true },
  });
  if (!client || client.disabled) return null;
  const uri = parseProductUri(client.uri);
  const name = client.name?.trim();
  if (!uri || !name) return null;
  return { clientId: client.clientId, name, uri };
}

/**
 * Decyduje, czy na `/account` pokazać przycisk powrotu do produktu: dopiero gdy firma jest aktywna
 * (adres e-mail i główna domena potwierdzone) oraz istnieje zarejestrowany klient z adresem `uri`.
 */
export function resolveAccountReturnButton(params: {
  organizationStatus: string;
  hasPendingPrimaryDomain: boolean;
  emailVerified?: boolean;
  client: ReturnClient | null;
}): ReturnButtonState | null {
  if (!params.client) return null;
  if (params.emailVerified === false) return null;
  if (params.organizationStatus !== "ACTIVE" || params.hasPendingPrimaryDomain) return null;
  return {
    href: RETURN_TO_PRODUCT_PATH,
    label: `Wróć do ${params.client.name}`,
    clientName: params.client.name,
  };
}
