import { type NextRequest, NextResponse } from "next/server";
import { config } from "@/server/config";
import { clearReturnClientCookie, findReturnClient, RETURN_CLIENT_COOKIE } from "@/server/return-to-product";

/**
 * Powrót do produktu po założeniu i aktywacji firmy (MonoriseCore#32).
 * Adres powrotu pochodzi wyłącznie z rejestru klientów w bazie (nigdy z żądania).
 */
export async function GET(request: NextRequest) {
  const rawClientId = request.cookies.get(RETURN_CLIENT_COOKIE)?.value;
  const client = await findReturnClient(rawClientId);
  const target = client ? client.uri : new URL("/account", config.authUrl);
  const response = NextResponse.redirect(target, {
    status: 303,
    headers: { "Cache-Control": "no-store" },
  });
  if (rawClientId !== undefined) clearReturnClientCookie(response);
  return response;
}
