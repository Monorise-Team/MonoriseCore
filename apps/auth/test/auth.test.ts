import { withOrganization } from "@core/db";
import { createLocalJWKSet, jwtVerify } from "jose";
import { afterAll, describe, expect, it } from "vitest";
import { auth } from "@/server/auth";
import { db } from "@/server/db";
import { verifyOrganizationDomain } from "@/server/domains";
import { sentMails } from "@/server/mail";
import { signUpOrganization } from "@/server/signup";

const PASSWORD = "bardzo-dlugie-haslo-1";
const created: { organizationId: string; email: string }[] = [];

function uniqueDomain(name: string) {
  return `${crypto.randomUUID().slice(0, 8)}-${name}.test`;
}

async function signUp(name: string) {
  const email = `anna@${uniqueDomain(name)}`;
  const result = await signUpOrganization({
    organizationName: name,
    firstName: "Anna",
    lastName: "Kowalska",
    email,
    password: PASSWORD,
  });
  created.push({ organizationId: result.organizationId, email });
  return { ...result, email };
}

async function confirmEmail(email: string) {
  const mail = [...sentMails()].reverse().find((m) => m.to === email);
  expect(mail?.subject).toMatch(/Potwierdź adres e-mail/);
  const url = new URL(/https?:\/\/\S+/.exec(mail!.text)![0]);
  await auth.api.verifyEmail({ query: { token: url.searchParams.get("token")! } });
}

async function signIn(email: string) {
  const response = await auth.api.signInEmail({ body: { email, password: PASSWORD }, asResponse: true });
  const cookie = response.headers
    .getSetCookie()
    .map((c) => c.split(";")[0])
    .join("; ");
  return { response, headers: new Headers({ cookie }) };
}

afterAll(async () => {
  for (const { organizationId, email } of created) {
    await withOrganization(db, organizationId, (tx) => tx.organization.deleteMany({ where: { id: organizationId } }));
    await db.authUser.deleteMany({ where: { email } });
  }
  await db.$disconnect();
});

describe("samorejestracja firmy i logowanie", () => {
  it("zakłada firmę, potwierdza e-mail i wydaje token z firmą i pracownikiem", async () => {
    const { organizationId, email } = await signUp("acme");
    await confirmEmail(email);
    const { response, headers } = await signIn(email);
    expect(response.status).toBe(200);

    const { token } = await auth.api.getToken({ headers });
    const jwks = createLocalJWKSet(await auth.api.getJwks());
    const { payload, protectedHeader } = await jwtVerify(token, jwks, {
      issuer: "http://localhost:3100",
      audience: "http://localhost:3200",
    });
    expect(protectedHeader.alg).toBe("EdDSA");
    expect(payload.org_id).toBe(organizationId);
    expect(payload.employee_id).toEqual(expect.any(String));
    expect(payload.authz_rev).toBe(0);
    expect(payload.amr).toEqual(["pwd"]);
    // Token dostępu ważny 5 minut (ADR-0023)
    expect(payload.exp! - payload.iat!).toBe(300);

    const account = await withOrganization(db, organizationId, (tx) =>
      tx.account.findUniqueOrThrow({ where: { id: payload.sub! } }),
    );
    expect(account.lastLoginAt).not.toBeNull();
  });

  it("odrzuca darmowe skrzynki i domenę, która ma już firmę", async () => {
    await expect(
      signUpOrganization({
        organizationName: "X",
        firstName: "Jan",
        lastName: "Nowak",
        email: "jan@wp.pl",
        password: PASSWORD,
      }),
    ).rejects.toMatchObject({ code: "EMAIL_DOMAIN_NOT_ALLOWED" });

    const { domain } = await signUp("globex");
    await expect(
      signUpOrganization({
        organizationName: "Globex 2",
        firstName: "Jan",
        lastName: "Nowak",
        email: `jan@${domain}`,
        password: PASSWORD,
      }),
    ).rejects.toMatchObject({ code: "ORGANIZATION_EXISTS" });
  });

  it("nie loguje bez potwierdzonego adresu ani po dezaktywacji konta", async () => {
    const { organizationId, email } = await signUp("initech");
    await expect(auth.api.signInEmail({ body: { email, password: PASSWORD } })).rejects.toMatchObject({
      statusCode: 403,
    });

    await confirmEmail(email);
    await withOrganization(db, organizationId, (tx) =>
      tx.account.updateMany({ data: { status: "DEACTIVATED", deactivatedAt: new Date() } }),
    );
    await expect(auth.api.signInEmail({ body: { email, password: PASSWORD } })).rejects.toThrow();
  });

  it("potwierdza domenę i włącza firmę (lokalnie bez DNS)", async () => {
    const { organizationId, email, domain } = await signUp("umbrella");
    await confirmEmail(email);
    const { headers } = await signIn(email);
    const session = await auth.api.getSession({ headers });

    expect(await verifyOrganizationDomain(session!.user.id)).toEqual({ domain, status: "PENDING" });
    expect(await verifyOrganizationDomain(session!.user.id, { trustLocally: true })).toEqual({
      domain,
      status: "VERIFIED",
    });
    const organization = await withOrganization(db, organizationId, (tx) =>
      tx.organization.findUniqueOrThrow({ where: { id: organizationId } }),
    );
    expect(organization.status).toBe("ACTIVE");
  });
});
