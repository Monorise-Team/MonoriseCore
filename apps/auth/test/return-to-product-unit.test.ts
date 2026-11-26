import { NextRequest, NextResponse } from "next/server";
import { describe, expect, it } from "vitest";
import { GET as returnToProductRoute } from "@/app/api/return-to-product/route";
import {
  clearReturnClientCookie,
  isSecureReturnCookie,
  parseClientId,
  resolveAccountReturnButton,
  RETURN_CLIENT_COOKIE,
  RETURN_CLIENT_MAX_AGE_SECONDS,
  RETURN_TO_PRODUCT_PATH,
  setReturnClientCookie,
} from "@/server/return-to-product";

const BASE = "http://localhost:3100";
const PRODUCT_URI = "http://timo-time.localhost:3300/app";

function findSetCookie(response: Response, name: string): string | undefined {
  return response.headers.getSetCookie().find((header) => header.startsWith(`${name}=`));
}

describe("pomocniki powrotu do produktu (testy jednostkowe)", () => {
  it("pokazuje przycisk powrotu na /account wyłącznie dla aktywnej firmy z potwierdzonym e-mailem i domeną", () => {
    const client = { clientId: "timotime-web", name: "TimoTime", uri: PRODUCT_URI };

    // Przed aktywacją firmy: brak przycisku
    expect(
      resolveAccountReturnButton({
        organizationStatus: "PENDING_VERIFICATION",
        hasPendingPrimaryDomain: true,
        emailVerified: true,
        client,
      }),
    ).toBeNull();

    // Główna domena nadal niepotwierdzona: brak przycisku
    expect(
      resolveAccountReturnButton({
        organizationStatus: "ACTIVE",
        hasPendingPrimaryDomain: true,
        emailVerified: true,
        client,
      }),
    ).toBeNull();

    // Niepotwierdzony e-mail: brak przycisku
    expect(
      resolveAccountReturnButton({
        organizationStatus: "ACTIVE",
        hasPendingPrimaryDomain: false,
        emailVerified: false,
        client,
      }),
    ).toBeNull();

    // Firma wstrzymana, kończąca współpracę, usunięta albo bez zapamiętanego klienta: brak przycisku
    for (const organizationStatus of ["SUSPENDED", "OFFBOARDING", "DELETED"] as const) {
      expect(
        resolveAccountReturnButton({
          organizationStatus,
          hasPendingPrimaryDomain: false,
          emailVerified: true,
          client,
        }),
      ).toBeNull();
    }
    expect(
      resolveAccountReturnButton({
        organizationStatus: "ACTIVE",
        hasPendingPrimaryDomain: false,
        emailVerified: true,
        client: null,
      }),
    ).toBeNull();

    // Firma aktywna (e-mail i domena potwierdzone): przycisk z nazwą klienta
    expect(
      resolveAccountReturnButton({
        organizationStatus: "ACTIVE",
        hasPendingPrimaryDomain: false,
        emailVerified: true,
        client,
      }),
    ).toEqual({
      href: RETURN_TO_PRODUCT_PATH,
      label: "Wróć do TimoTime",
      clientName: "TimoTime",
    });
  });

  it("akceptuje tylko identyfikator klienta (nigdy URL ani ścieżkę) i wyznacza flagę Secure poza localhost", () => {
    expect(parseClientId("timotime-web")).toBe("timotime-web");
    expect(parseClientId("  avenmail-web  ")).toBe("avenmail-web");
    expect(parseClientId("")).toBeNull();
    expect(parseClientId("   ")).toBeNull();
    expect(parseClientId(null)).toBeNull();
    expect(parseClientId(123)).toBeNull();
    expect(parseClientId("https://zly.example/")).toBeNull();
    expect(parseClientId("http://timo-time.localhost:3300/app")).toBeNull();
    expect(parseClientId("//zly.example")).toBeNull();
    expect(parseClientId("/account")).toBeNull();
    expect(parseClientId("a".repeat(129))).toBeNull();

    expect(isSecureReturnCookie("http://localhost:3100")).toBe(false);
    expect(isSecureReturnCookie("http://auth.localhost:3100")).toBe(false);
    expect(isSecureReturnCookie("http://127.0.0.1:3100")).toBe(false);
    expect(isSecureReturnCookie("https://localhost:3100")).toBe(true);
    expect(isSecureReturnCookie("https://auth.monorise.studio")).toBe(true);
    expect(isSecureReturnCookie("http://auth.monorise.studio")).toBe(true);
  });

  it("ustawia i czyści ciasteczko HttpOnly z oczekiwanymi atrybutami", () => {
    const response = NextResponse.json({ ok: true });
    setReturnClientCookie(response, "timotime-web");
    const setHeader = findSetCookie(response, RETURN_CLIENT_COOKIE);
    expect(setHeader).toBeDefined();
    expect(setHeader).toContain(`${RETURN_CLIENT_COOKIE}=timotime-web`);
    expect(setHeader).toContain("HttpOnly");
    expect(setHeader).toContain("Path=/");
    expect(setHeader?.toLowerCase()).toContain("samesite=lax");
    expect(setHeader).toContain(`Max-Age=${RETURN_CLIENT_MAX_AGE_SECONDS}`);
    expect(setHeader).not.toContain("Secure");

    const redirectResponse = NextResponse.redirect(PRODUCT_URI, { status: 303 });
    clearReturnClientCookie(redirectResponse);
    const clearHeader = findSetCookie(redirectResponse, RETURN_CLIENT_COOKIE);
    expect(clearHeader).toBeDefined();
    expect(clearHeader).toContain(`${RETURN_CLIENT_COOKIE}=;`);
    expect(clearHeader).toContain("Max-Age=0");
    expect(clearHeader).toContain("HttpOnly");
    expect(clearHeader).toContain("Path=/");
    expect(clearHeader?.toLowerCase()).toContain("samesite=lax");
  });

  it("GET /api/return-to-product bez ciasteczka lub z URL w ciasteczku zwraca 303 na /account bez adresu z żądania", async () => {
    const missing = await returnToProductRoute(new NextRequest(`${BASE}/api/return-to-product`));
    expect(missing.status).toBe(303);
    expect(missing.headers.get("location")).toBe(`${BASE}/account`);
    expect(missing.headers.get("cache-control")).toBe("no-store");

    const evilUrl = "https://zly.example/kradziez";
    const tampered = await returnToProductRoute(
      new NextRequest(`${BASE}/api/return-to-product?redirect=${encodeURIComponent(evilUrl)}`, {
        headers: {
          cookie: `${RETURN_CLIENT_COOKIE}=${encodeURIComponent(evilUrl)}`,
          host: "zly.example",
        },
      }),
    );
    expect(tampered.status).toBe(303);
    expect(tampered.headers.get("location")).toBe(`${BASE}/account`);
    expect(tampered.headers.get("location")).not.toContain("zly.example");
    expect(findSetCookie(tampered, RETURN_CLIENT_COOKIE)).toContain("Max-Age=0");
  });
});
