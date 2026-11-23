import { toNextJsHandler } from "better-auth/next-js";
import { auth } from "@/server/auth";

// Wszystkie ścieżki Better Auth: logowanie, sesje, potwierdzanie e-maila, /token i /jwks.
export const { GET, POST } = toNextJsHandler(auth);
