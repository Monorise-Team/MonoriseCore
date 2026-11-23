import { SignUpRequest } from "@core/contracts";
import type { NextRequest } from "next/server";
import { fail, ok } from "@/server/http";
import { signUpOrganization } from "@/server/signup";

/** Samorejestracja firmy: konto właściciela i firma czekająca na potwierdzenie domeny. */
export async function POST(request: NextRequest) {
  try {
    const input = SignUpRequest.parse(await request.json());
    return ok(await signUpOrganization(input), 201);
  } catch (error) {
    return fail(error);
  }
}
