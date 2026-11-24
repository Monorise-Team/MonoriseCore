import { Card } from "@monorise-team/ui";
import Link from "next/link";
import { inspectInvitation, INVALID_INVITATION_MESSAGE } from "@/server/invitations";
import { InviteAcceptForm } from "./InviteAcceptForm";

export const dynamic = "force-dynamic";
export const metadata = { title: "Aktywuj konto — Monorise" };

export default async function InvitePage({ searchParams }: { searchParams: Promise<{ token?: string | string[] }> }) {
  const params = await searchParams;
  const rawToken = typeof params.token === "string" ? params.token : "";
  const state = await inspectInvitation(rawToken);

  if (!state.valid) {
    return (
      <Card surface="float" className="mr-enter flex w-full max-w-sm flex-col gap-4 p-6">
        <div className="flex flex-col gap-1">
          <h1 className="font-display text-xl font-semibold">Aktywacja konta</h1>
          <p className="text-sm text-text-secondary">{INVALID_INVITATION_MESSAGE}</p>
        </div>
        <p className="text-sm text-text-tertiary">
          <Link className="text-accent underline-offset-2 hover:underline" href="/sign-in">
            Przejdź do logowania
          </Link>
        </p>
      </Card>
    );
  }

  return <InviteAcceptForm token={rawToken} organizationName={state.organizationName} email={state.email} />;
}
