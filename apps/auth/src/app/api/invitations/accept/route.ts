import { AcceptInvitationRequest } from "@core/contracts";
import type { NextRequest } from "next/server";
import { fail, ok } from "@/server/http";
import { acceptInvitation } from "@/server/invitations";

/** Aktywacja konta pracownika na podstawie linku zaproszenia: ustawienie hasła i zmiana statusu na ACTIVE. */
export async function POST(request: NextRequest) {
  try {
    const input = AcceptInvitationRequest.parse(await request.json());
    const result = await acceptInvitation(input, {
      ipAddress: request.headers.get("x-forwarded-for") ?? request.headers.get("x-real-ip"),
      userAgent: request.headers.get("user-agent"),
    });
    return ok(result, 200);
  } catch (error) {
    return fail(error);
  }
}
