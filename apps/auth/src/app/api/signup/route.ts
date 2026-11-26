import { SignUpRequest } from "@core/contracts";
import type { NextRequest } from "next/server";
import { z } from "zod";
import { fail, ok } from "@/server/http";
import { findReturnClient, setReturnClientCookie } from "@/server/return-to-product";
import { signUpOrganization } from "@/server/signup";

const SignUpBody = SignUpRequest.extend({
  client_id: z.unknown().optional(),
});

/** Samorejestracja firmy: konto właściciela i firma czekająca na potwierdzenie domeny. */
export async function POST(request: NextRequest) {
  try {
    const { client_id: rawClientId, ...input } = SignUpBody.parse(await request.json());
    const result = await signUpOrganization(input);
    const response = ok(result, 201);
    const returnClient = await findReturnClient(rawClientId);
    if (returnClient) setReturnClientCookie(response, returnClient.clientId);
    return response;
  } catch (error) {
    return fail(error);
  }
}
