import { auth } from "@/server/auth";
import { isPasswordResetTokenValid } from "@/server/password-reset";
import { ExpiredResetLinkCard, ResetPasswordForm } from "./ResetPasswordForm";

export const dynamic = "force-dynamic";
export const metadata = { title: "Ustaw nowe hasło — Monorise" };

export default async function ResetPasswordPage({
  searchParams,
}: {
  searchParams: Promise<{ token?: string | string[]; error?: string | string[] }>;
}) {
  const params = await searchParams;
  const rawToken = typeof params.token === "string" ? params.token.trim() : "";
  const hasError = typeof params.error === "string" && params.error.length > 0;

  if (hasError || !rawToken) {
    return <ExpiredResetLinkCard />;
  }

  const authCtx = await auth.$context;
  const valid = await isPasswordResetTokenValid(authCtx.internalAdapter, rawToken);
  if (!valid) {
    return <ExpiredResetLinkCard />;
  }

  return <ResetPasswordForm token={rawToken} />;
}
