import { parseClientId } from "@/server/return-to-product";
import { SignUpForm } from "./SignUpForm";

export const metadata = { title: "Załóż konto firmy — Monorise" };

export default async function SignUpPage({
  searchParams,
}: {
  searchParams: Promise<{ client_id?: string | string[] }>;
}) {
  const params = await searchParams;
  const clientId = parseClientId(params.client_id) ?? undefined;
  return <SignUpForm clientId={clientId} />;
}
