import { VerifyOrganizationDomain } from "@core/contracts";
import type { NextRequest } from "next/server";
import { auth } from "@/server/auth";
import { verifyOrganizationDomain } from "@/server/domains";
import { CoreError } from "@/server/errors";
import { fail, ok } from "@/server/http";

/** Sprawdza rekord DNS TXT głównej domeny firmy zalogowanego konta. */
export async function POST(request: NextRequest) {
  try {
    const session = await auth.api.getSession({ headers: request.headers });
    if (!session) throw new CoreError("UNAUTHENTICATED", 401, "Zaloguj się ponownie");

    const rawText = await request.text();
    let rawBody: unknown = {};
    if (rawText.trim().length > 0) {
      try {
        rawBody = JSON.parse(rawText);
      } catch {
        throw new CoreError("VALIDATION_FAILED", 422, "Nieprawidłowy format JSON w treści żądania");
      }
    }
    const body = VerifyOrganizationDomain.parse(rawBody);

    return ok(
      await verifyOrganizationDomain(session.user.id, {
        trustLocally: body.trustLocally ?? false,
        ipAddress: request.headers.get("x-forwarded-for") ?? request.headers.get("x-real-ip"),
        userAgent: request.headers.get("user-agent"),
      }),
    );
  } catch (error) {
    return fail(error);
  }
}
