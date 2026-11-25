import { domainVerificationHost } from "@core/contracts";
import { accountClaims, withOrganization } from "@core/db";
import { Badge, Card } from "@monorise-team/ui";
import { cookies, headers } from "next/headers";
import { redirect } from "next/navigation";
import { auth } from "@/server/auth";
import { config } from "@/server/config";
import { db } from "@/server/db";
import { domainTxtValue } from "@/server/domains";
import { findReturnClient, resolveAccountReturnButton, RETURN_CLIENT_COOKIE } from "@/server/return-to-product";
import { AccountActions, DomainActions, ReturnToProductAction } from "./AccountActions";

export const dynamic = "force-dynamic";
export const metadata = { title: "Konto firmy — Monorise" };

const STATUS = {
  PENDING_VERIFICATION: { label: "czeka na potwierdzenie domeny", tone: "warning" },
  ACTIVE: { label: "aktywna", tone: "success" },
  SUSPENDED: { label: "wstrzymana", tone: "danger" },
  OFFBOARDING: { label: "kończy współpracę", tone: "warning" },
  DELETED: { label: "usunięta", tone: "danger" },
} as const;

export default async function AccountPage() {
  const session = await auth.api.getSession({ headers: await headers() });
  if (!session) redirect("/sign-in");
  const claims = await accountClaims(db, session.user.id);
  if (!claims) redirect("/sign-in");
  const { organization, employee } = await withOrganization(db, claims.organizationId, async (tx) => ({
    organization: await tx.organization.findUniqueOrThrow({
      where: { id: claims.organizationId },
      include: { domains: { orderBy: { createdAt: "asc" } } },
    }),
    employee: await tx.employee.findUniqueOrThrow({ where: { id: claims.employeeId } }),
  }));
  const status = STATUS[organization.status];
  const pending = organization.domains.find((d) => d.isPrimary && d.status !== "VERIFIED");
  const cookieStore = await cookies();
  const returnClientId = cookieStore.get(RETURN_CLIENT_COOKIE)?.value;
  const returnClient =
    organization.status === "ACTIVE" && !pending && session.user.emailVerified
      ? await findReturnClient(returnClientId)
      : null;
  const returnButton = resolveAccountReturnButton({
    organizationStatus: organization.status,
    hasPendingPrimaryDomain: Boolean(pending),
    emailVerified: session.user.emailVerified,
    client: returnClient,
  });

  return (
    <Card surface="float" className="mr-enter flex w-full max-w-lg flex-col gap-5 p-6">
      <div className="flex items-start justify-between gap-3">
        <div className="flex flex-col gap-1">
          <h1 className="font-display text-xl font-semibold">{organization.name}</h1>
          <p className="text-sm text-text-tertiary">
            {employee.firstName} {employee.lastName} · {session.user.email}
          </p>
        </div>
        <Badge tone={status.tone}>{status.label}</Badge>
      </div>

      {pending ? (
        <div className="flex flex-col gap-3">
          <p className="text-sm text-text-secondary">
            Potwierdź, że domena <strong>{pending.domain}</strong> należy do firmy: dodaj w jej DNS rekord TXT, potem
            kliknij „Sprawdź rekord”.
          </p>
          <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 rounded-lg bg-bg-tertiary p-3 font-mono text-xs">
            <dt className="text-text-tertiary">Nazwa</dt>
            <dd className="break-all">{domainVerificationHost(pending.domain)}</dd>
            <dt className="text-text-tertiary">Wartość</dt>
            <dd className="break-all">{domainTxtValue(organization.id, pending.domain)}</dd>
          </dl>
          <DomainActions devTrust={config.devTrustDomains} />
        </div>
      ) : (
        <div className="flex flex-col gap-3">
          <p className="text-sm text-text-secondary">
            Domeny firmy: {organization.domains.map((d) => d.domain).join(", ")}. Produkty Monorise zalogują Cię tym
            kontem.
          </p>
          {returnButton ? <ReturnToProductAction href={returnButton.href} label={returnButton.label} /> : null}
        </div>
      )}

      <AccountActions />
    </Card>
  );
}
