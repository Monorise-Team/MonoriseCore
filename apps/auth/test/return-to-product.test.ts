import { withOrganization } from "@core/db";
import { NextRequest } from "next/server";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { GET as returnToProductRoute } from "@/app/api/return-to-product/route";
import { POST as signUpRoute } from "@/app/api/signup/route";
import { db } from "@/server/db";
import { ensureFirstPartyClients } from "@/server/oauth-clients";
import { RETURN_CLIENT_COOKIE, RETURN_CLIENT_MAX_AGE_SECONDS } from "@/server/return-to-product";

const BASE = "http://localhost:3100";
const PASSWORD = "bardzo-dlugie-haslo-32";
const SUFFIX = crypto.randomUUID().slice(0, 8);
const RESOURCE = `http://time-${SUFFIX}.localhost:3300`;
const REDIRECT = "http://timo-time.localhost:3300/api/auth/callback";
const WEB_CLIENT_ID = `timotime-web-return-${SUFFIX}`;
const NO_URI_CLIENT_ID = `timotime-mobile-return-${SUFFIX}`;
const DISABLED_CLIENT_ID = `timotime-disabled-return-${SUFFIX}`;
const PRODUCT_URI = "http://timo-time.localhost:3300/app";

const createdOrgs: { organizationId: string; email: string }[] = [];
const createdClientIds = [WEB_CLIENT_ID, NO_URI_CLIENT_ID, DISABLED_CLIENT_ID];

function uniqueEmail(label: string) {
  return `anna@${crypto.randomUUID().slice(0, 8)}-${label}.test`;
}

function findSetCookie(response: Response, name: string): string | undefined {
  return response.headers.getSetCookie().find((header) => header.startsWith(`${name}=`));
}

async function postSignUp(payload: Record<string, unknown>) {
  const request = new NextRequest(`${BASE}/api/signup`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(payload),
  });
  const response = await signUpRoute(request);
  const body = (await response.json()) as { data: { organizationId: string; domain: string } | null; error: unknown };
  if (response.status === 201 && body.data) {
    createdOrgs.push({ organizationId: body.data.organizationId, email: String(payload.email) });
  }
  return { response, body };
}

beforeAll(async () => {
  await ensureFirstPartyClients({
    resources: [{ identifier: RESOURCE, name: "TimoTime API (return test)" }],
    clients: [
      {
        clientId: WEB_CLIENT_ID,
        name: "TimoTime",
        uri: PRODUCT_URI,
        redirectUris: [REDIRECT],
        confidential: true,
        resources: [RESOURCE],
      },
      {
        clientId: NO_URI_CLIENT_ID,
        name: "TimoTime na telefon",
        redirectUris: ["timotime://oauth/callback"],
        confidential: false,
        resources: [RESOURCE],
      },
      {
        clientId: DISABLED_CLIENT_ID,
        name: "Wyłączony produkt",
        uri: "http://disabled.localhost:3300/",
        redirectUris: [REDIRECT],
        confidential: true,
        resources: [RESOURCE],
      },
    ],
  });
  await db.authOAuthClient.update({
    where: { clientId: DISABLED_CLIENT_ID },
    data: { disabled: true },
  });
});

afterAll(async () => {
  for (const { organizationId, email } of createdOrgs) {
    await withOrganization(db, organizationId, (tx) => tx.organization.deleteMany({ where: { id: organizationId } }));
    await db.authUser.deleteMany({ where: { email } });
  }
  await db.authOAuthClient.deleteMany({ where: { clientId: { in: createdClientIds } } });
  await db.authOAuthResource.deleteMany({ where: { identifier: RESOURCE } });
  await db.$disconnect();
});

describe("powrót do produktu po założeniu firmy", () => {
  it("ensureFirstPartyClients zapisuje i aktualizuje pole uri klienta OAuth", async () => {
    const updateClientId = `timotime-uri-update-${SUFFIX}`;
    const initialUri = "http://timo-time.localhost:3300/start";
    const updatedUri = "http://timo-time.localhost:3300/app";
    try {
      await ensureFirstPartyClients({
        resources: [{ identifier: RESOURCE, name: "TimoTime API (return test)" }],
        clients: [
          {
            clientId: updateClientId,
            name: "TimoTime",
            uri: initialUri,
            redirectUris: [REDIRECT],
            confidential: true,
            resources: [RESOURCE],
          },
        ],
      });

      const created = await db.authOAuthClient.findUniqueOrThrow({ where: { clientId: updateClientId } });
      const mobile = await db.authOAuthClient.findUniqueOrThrow({ where: { clientId: NO_URI_CLIENT_ID } });
      expect(created.uri).toBe(initialUri);
      expect(mobile.uri).toBeNull();

      await ensureFirstPartyClients({
        resources: [{ identifier: RESOURCE, name: "TimoTime API (return test)" }],
        clients: [
          {
            clientId: updateClientId,
            name: "TimoTime",
            uri: updatedUri,
            redirectUris: [REDIRECT],
            confidential: true,
            resources: [RESOURCE],
          },
        ],
      });

      const updated = await db.authOAuthClient.findUniqueOrThrow({ where: { clientId: updateClientId } });
      expect(updated.uri).toBe(updatedUri);
    } finally {
      await db.authOAuthClient.deleteMany({ where: { clientId: updateClientId } });
    }
  });

  it("POST /api/signup ustawia ciasteczko HttpOnly wyłącznie dla zarejestrowanego, aktywnego klienta z uri", async () => {
    // 1. Zarejestrowany klient z uri: ustawia ciasteczko z samym client_id
    const registered = await postSignUp({
      organizationName: "Acme Return",
      firstName: "Anna",
      lastName: "Kowalska",
      email: uniqueEmail("registered"),
      password: PASSWORD,
      client_id: WEB_CLIENT_ID,
    });
    expect(registered.response.status).toBe(201);
    const cookieHeader = findSetCookie(registered.response, RETURN_CLIENT_COOKIE);
    expect(cookieHeader).toBeDefined();
    expect(cookieHeader).toContain(`${RETURN_CLIENT_COOKIE}=${WEB_CLIENT_ID}`);
    expect(cookieHeader).toContain("HttpOnly");
    expect(cookieHeader).toContain("Path=/");
    expect(cookieHeader?.toLowerCase()).toContain("samesite=lax");
    expect(cookieHeader).toContain(`Max-Age=${RETURN_CLIENT_MAX_AGE_SECONDS}`);
    expect(cookieHeader).not.toContain("Secure");

    // 2. Nieznany client_id: firma powstaje, bez ciasteczka
    const unknown = await postSignUp({
      organizationName: "Acme Unknown",
      firstName: "Anna",
      lastName: "Kowalska",
      email: uniqueEmail("unknown"),
      password: PASSWORD,
      client_id: "nieistniejacy-klient",
    });
    expect(unknown.response.status).toBe(201);
    expect(findSetCookie(unknown.response, RETURN_CLIENT_COOKIE)).toBeUndefined();

    // 3. Adres URL zamiast client_id: firma powstaje, bez ciasteczka
    const withUrl = await postSignUp({
      organizationName: "Acme Url",
      firstName: "Anna",
      lastName: "Kowalska",
      email: uniqueEmail("url"),
      password: PASSWORD,
      client_id: "https://zly.example/phish",
    });
    expect(withUrl.response.status).toBe(201);
    expect(findSetCookie(withUrl.response, RETURN_CLIENT_COOKIE)).toBeUndefined();

    // 4. Klient bez uri (mobilny) oraz klient wyłączony: firma powstaje, bez ciasteczka
    for (const [label, clientId] of [
      ["mobile", NO_URI_CLIENT_ID],
      ["disabled", DISABLED_CLIENT_ID],
    ] as const) {
      const result = await postSignUp({
        organizationName: `Acme ${label}`,
        firstName: "Anna",
        lastName: "Kowalska",
        email: uniqueEmail(label),
        password: PASSWORD,
        client_id: clientId,
      });
      expect(result.response.status).toBe(201);
      expect(findSetCookie(result.response, RETURN_CLIENT_COOKIE)).toBeUndefined();
    }
  });

  it("GET /api/return-to-product przekierowuje 303 do uri z bazy i czyści ciasteczko, a dla innych przypadków wraca na /account", async () => {
    // 1. Zarejestrowany klient z uri
    const validRequest = new NextRequest(`${BASE}/api/return-to-product`, {
      headers: { cookie: `${RETURN_CLIENT_COOKIE}=${WEB_CLIENT_ID}` },
    });
    const validResponse = await returnToProductRoute(validRequest);
    expect(validResponse.status).toBe(303);
    expect(validResponse.headers.get("location")).toBe(PRODUCT_URI);
    expect(validResponse.headers.get("cache-control")).toBe("no-store");
    const cleared = findSetCookie(validResponse, RETURN_CLIENT_COOKIE);
    expect(cleared).toContain(`${RETURN_CLIENT_COOKIE}=;`);
    expect(cleared).toContain("Max-Age=0");
    expect(cleared).toContain("HttpOnly");

    // 2. Podmienione ciasteczko (nieznany identyfikator) -> 303 na /account
    const unknownRequest = new NextRequest(`${BASE}/api/return-to-product`, {
      headers: { cookie: `${RETURN_CLIENT_COOKIE}=obcy-klient` },
    });
    const unknownResponse = await returnToProductRoute(unknownRequest);
    expect(unknownResponse.status).toBe(303);
    expect(unknownResponse.headers.get("location")).toBe(`${BASE}/account`);
    expect(findSetCookie(unknownResponse, RETURN_CLIENT_COOKIE)).toContain("Max-Age=0");

    // 3. Podmienione ciasteczko z adresem URL i złośliwymi parametrami w żądaniu -> nigdy nie trafia do odpowiedzi
    const evilUrl = "https://zly.example/kradziez";
    const tamperedRequest = new NextRequest(
      `${BASE}/api/return-to-product?redirect=${encodeURIComponent(evilUrl)}&client_id=${WEB_CLIENT_ID}`,
      {
        headers: {
          cookie: `${RETURN_CLIENT_COOKIE}=${encodeURIComponent(evilUrl)}`,
          host: "zly.example",
        },
      },
    );
    const tamperedResponse = await returnToProductRoute(tamperedRequest);
    expect(tamperedResponse.status).toBe(303);
    const tamperedLocation = tamperedResponse.headers.get("location") ?? "";
    expect(tamperedLocation).toBe(`${BASE}/account`);
    expect(tamperedLocation).not.toContain("zly.example");
    expect(findSetCookie(tamperedResponse, RETURN_CLIENT_COOKIE)).toContain("Max-Age=0");

    // 4. Brak ciasteczka -> 303 na /account
    const missingRequest = new NextRequest(`${BASE}/api/return-to-product`);
    const missingResponse = await returnToProductRoute(missingRequest);
    expect(missingResponse.status).toBe(303);
    expect(missingResponse.headers.get("location")).toBe(`${BASE}/account`);

    // 5. Wyłączony klient albo klient bez uri -> 303 na /account i wyczyszczenie ciasteczka
    for (const clientId of [DISABLED_CLIENT_ID, NO_URI_CLIENT_ID]) {
      const response = await returnToProductRoute(
        new NextRequest(`${BASE}/api/return-to-product`, {
          headers: { cookie: `${RETURN_CLIENT_COOKIE}=${clientId}` },
        }),
      );
      expect(response.status).toBe(303);
      expect(response.headers.get("location")).toBe(`${BASE}/account`);
      expect(findSetCookie(response, RETURN_CLIENT_COOKIE)).toContain("Max-Age=0");
    }
  });
});
