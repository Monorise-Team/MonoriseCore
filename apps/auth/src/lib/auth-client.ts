import { createAuthClient } from "better-auth/react";

/** Klient logowania w przeglądarce (ta sama domena co serwer logowania). */
export const authClient = createAuthClient();
