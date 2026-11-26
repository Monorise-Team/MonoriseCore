import type { NextRequest } from "next/server";
import { z } from "zod";
import { auth } from "@/server/auth";
import { verifyOrganizationDomain } from "@/server/domains";
import { CoreError } from "@/server/errors";
import { fail, ok } from "@/server/http";

const Body = z.object({ trustLocally: z.boolean().optional() });

/** Sprawdza rekord DNS TXT domeny firmy zalogowanego konta. */
export async function POST(request: NextRequest) {
  try {
    const session = await auth.api.getSession({ headers: request.headers });
    if (!session) throw new CoreError("UNAUTHENTICATED", 401, "Zaloguj się ponownie");
    const body = Body.parse(await request.json().catch(() => ({})));
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
