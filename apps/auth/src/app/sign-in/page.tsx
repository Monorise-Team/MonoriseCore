import { parseClientId } from "@/server/return-to-product";
import { SignInForm } from "./SignInForm";

export const metadata = { title: "Zaloguj się — Monorise" };

export default async function SignInPage({
  searchParams,
}: {
  searchParams: Promise<{ activated?: string | string[]; client_id?: string | string[] }>;
}) {
  const params = await searchParams;
  const activated = params.activated === "1";
  const clientId = parseClientId(params.client_id) ?? undefined;
  return <SignInForm activated={activated} clientId={clientId} />;
}
