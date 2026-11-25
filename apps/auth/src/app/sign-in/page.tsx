import { SignInForm } from "./SignInForm";

export const metadata = { title: "Zaloguj się — Monorise" };

export default async function SignInPage({
  searchParams,
}: {
  searchParams: Promise<{ activated?: string | string[] }>;
}) {
  const params = await searchParams;
  const activated = params.activated === "1";
  return <SignInForm activated={activated} />;
}
