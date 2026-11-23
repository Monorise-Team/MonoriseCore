import "server-only";
import type { ApiResponse } from "@core/contracts";
import { NextResponse } from "next/server";
import { ZodError } from "zod";
import { CoreError } from "./errors";

const requestId = () => `req_${crypto.randomUUID().replaceAll("-", "").slice(0, 16)}`;

export function ok<T>(data: T, status = 200) {
  const body: ApiResponse<T> = { data, meta: { requestId: requestId() }, error: null };
  return NextResponse.json(body, { status, headers: { "Cache-Control": "no-store" } });
}

/** Błąd jako odpowiedź `{ data, meta, error }`; szczegóły nieoczekiwanych błędów tylko w logach. */
export function fail(error: unknown) {
  const id = requestId();
  let failure: CoreError;
  if (error instanceof CoreError) failure = error;
  else if (error instanceof ZodError) {
    failure = new CoreError(
      "VALIDATION_FAILED",
      422,
      "Niepoprawne dane",
      error.issues.map((issue) => ({ field: issue.path.join(".") || undefined, message: issue.message })),
    );
  } else if ((error as { status?: unknown })?.status === "UNPROCESSABLE_ENTITY") {
    // Better Auth: np. hasło za krótkie albo adres już zajęty; bez zdradzania, czy konto istnieje
    failure = new CoreError("VALIDATION_FAILED", 422, "Nie udało się założyć konta z tymi danymi");
  } else {
    console.error(`[${id}]`, process.env.NODE_ENV === "production" ? (error as Error)?.name : error);
    failure = new CoreError("INTERNAL", 500, "Wewnętrzny błąd serwera");
  }
  const body: ApiResponse<null> = {
    data: null,
    meta: { requestId: id },
    error: { code: failure.code, message: failure.message, details: failure.details },
  };
  return NextResponse.json(body, { status: failure.status, headers: { "Cache-Control": "no-store" } });
}
