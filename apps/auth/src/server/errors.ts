import type { ApiErrorBody, ErrorCode } from "@core/contracts";

/** Błąd ze stałym kodem (standard API Monorise, ADR-0044). */
export class CoreError extends Error {
  constructor(
    readonly code: ErrorCode,
    readonly status: number,
    message: string,
    readonly details: ApiErrorBody["details"] = [],
  ) {
    super(message);
  }
}

/** Naruszenie unikalności w PostgreSQL (np. domena albo adres e-mail już zajęte). */
export function isUniqueViolation(error: unknown): boolean {
  const text =
    String((error as { code?: string; message?: string })?.code ?? "") + String((error as Error)?.message ?? "");
  return text.includes("P2002") || text.includes("23505") || /unique constraint/i.test(text);
}
