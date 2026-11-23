import { oauthProviderClient } from "@better-auth/oauth-provider/client";
import { createAuthClient } from "better-auth/react";

/**
 * Klient logowania w przeglądarce (ta sama domena co serwer logowania). Wtyczka OAuth przekazuje przy
 * logowaniu podpisane parametry z adresu strony, żeby po zalogowaniu wrócić do produktu (AvenMail, TimoTime).
 */
export const authClient = createAuthClient({ plugins: [oauthProviderClient()] });
