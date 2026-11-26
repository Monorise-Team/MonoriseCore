import { CORE_PERMISSIONS } from "@core/contracts";
import { uuidv7, withOrganization } from "@core/db";
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
      tx.account.findUniqueOrThrow({ where: { id: payload.sub! }, include: { organization: true } }),
    );
    expect(account.lastLoginAt).not.toBeNull();
    expect(account.organization.ownerAccountId).toBe(account.id);
  });

  it("odrzuca darmowe skrzynki (w tym subdomeny), niepoprawne domeny i zweryfikowane domeny innych firm, ale pozwala na rejestrację z domeną PENDING", async () => {
    for (const email of ["jan@wp.pl", "jan@mail.gmail.com", "jan@pm.me", "jan@tuta.com", "jan@tutanota.com"]) {
      await expect(
        signUpOrganization({
          organizationName: "X",
          firstName: "Jan",
          lastName: "Nowak",
          email,
          password: PASSWORD,
        }),
      ).rejects.toMatchObject({ code: "EMAIL_DOMAIN_NOT_ALLOWED", status: 422 });
    }

    for (const email of ["jan@localhost", "jan@acme.123"]) {
      await expect(
        signUpOrganization({
          organizationName: "X",
          firstName: "Jan",
          lastName: "Nowak",
          email,
          password: PASSWORD,
        }),
      ).rejects.toMatchObject({ code: "VALIDATION_FAILED", status: 422 });
    }

    // Domena jest tylko PENDING w pierwszej firmie -> druga firma może się zarejestrować („wygrywa weryfikacja”)
    const first = await signUp("globex");
    const secondEmail = `jan@${first.domain}`;
    const second = await signUpOrganization({
      organizationName: "Globex 2",
      firstName: "Jan",
      lastName: "Nowak",
      email: secondEmail,
      password: PASSWORD,
    });
    created.push({ organizationId: second.organizationId, email: secondEmail });

    // Pierwsza firma weryfikuje domenę -> kolejna samorejestracja dostaje 409 ORGANIZATION_EXISTS,
    // a próba weryfikacji w drugiej firmie (nieusunięta główna PENDING) kończy się 409 CONFLICT
    await confirmEmail(first.email);
    const { headers: firstHeaders } = await signIn(first.email);
    const firstSession = await auth.api.getSession({ headers: firstHeaders });
    expect(await verifyOrganizationDomain(firstSession!.user.id, { trustLocally: true })).toEqual({
      domain: first.domain,
      status: "VERIFIED",
    });

    await expect(
      signUpOrganization({
        organizationName: "Globex 3",
        firstName: "Marek",
        lastName: "Nowak",
        email: `marek@${first.domain}`,
        password: PASSWORD,
      }),
    ).rejects.toMatchObject({ code: "ORGANIZATION_EXISTS", status: 409 });

    await confirmEmail(secondEmail);
    const { headers: secondHeaders } = await signIn(secondEmail);
    const secondSession = await auth.api.getSession({ headers: secondHeaders });
    await expect(verifyOrganizationDomain(secondSession!.user.id, { trustLocally: true })).rejects.toMatchObject({
      code: "CONFLICT",
      status: 409,
    });
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

  it("potwierdza domenę i włącza firmę (lokalnie bez DNS), zapisuje audyt aktywacji i odrzuca trustLocally przy wyłączonym dev trust", async () => {
    const { organizationId, email, domain } = await signUp("umbrella");
    await confirmEmail(email);
    const { headers } = await signIn(email);
    const session = await auth.api.getSession({ headers });

    // Wyłączenie CORE_DEV_TRUST_DOMAINS odrzuca trustLocally kodem 403
    const prevDevTrust = process.env.CORE_DEV_TRUST_DOMAINS;
    process.env.CORE_DEV_TRUST_DOMAINS = "0";
    try {
      await expect(verifyOrganizationDomain(session!.user.id, { trustLocally: true })).rejects.toMatchObject({
        code: "PERMISSION_DENIED",
        status: 403,
      });
    } finally {
      if (prevDevTrust === undefined) delete process.env.CORE_DEV_TRUST_DOMAINS;
      else process.env.CORE_DEV_TRUST_DOMAINS = prevDevTrust;
    }

    expect(await verifyOrganizationDomain(session!.user.id)).toEqual({ domain, status: "PENDING" });
    expect(await verifyOrganizationDomain(session!.user.id, { trustLocally: true })).toEqual({
      domain,
      status: "VERIFIED",
    });
    const organization = await withOrganization(db, organizationId, (tx) =>
      tx.organization.findUniqueOrThrow({ where: { id: organizationId } }),
    );
    expect(organization.status).toBe("ACTIVE");

    const audits = await withOrganization(db, organizationId, (tx) =>
      tx.auditLog.findMany({
        where: { action: { in: ["organization.domain.verified", "organization.activated"] } },
        orderBy: [{ createdAt: "asc" }, { id: "asc" }],
      }),
    );
    expect(audits.map((row) => ({ action: row.action, metadata: row.metadata }))).toEqual([
      { action: "organization.domain.verified", metadata: { domain, method: "DEV_TRUST" } },
      {
        action: "organization.activated",
        metadata: expect.objectContaining({ previousStatus: "PENDING_VERIFICATION", status: "ACTIVE", domain }),
      },
    ]);
  });

  it("aktywuje firmę PENDING_VERIFICATION nawet gdy główna domena była już wcześniej VERIFIED", async () => {
    const { organizationId, email, domain } = await signUp("already-verified");
    await confirmEmail(email);
    const { headers } = await signIn(email);
    const session = await auth.api.getSession({ headers });

    await withOrganization(db, organizationId, (tx) =>
      tx.organizationDomain.updateMany({
        where: { isPrimary: true },
        data: { status: "VERIFIED", verifiedAt: new Date() },
      }),
    );

    expect(await verifyOrganizationDomain(session!.user.id)).toEqual({ domain, status: "VERIFIED" });

    const organization = await withOrganization(db, organizationId, (tx) =>
      tx.organization.findUniqueOrThrow({ where: { id: organizationId } }),
    );
    expect(organization.status).toBe("ACTIVE");

    const audits = await withOrganization(db, organizationId, (tx) =>
      tx.auditLog.findMany({
        where: { action: { in: ["organization.domain.verified", "organization.activated"] } },
      }),
    );
    expect(audits.map((row) => row.action)).toEqual(["organization.activated"]);
  });

  it("wymaga Ownera albo core.organization.manage w zakresie ORGANIZATION w verifyOrganizationDomain", async () => {
    const { organizationId, email, domain } = await signUp("authz-domains");
    await confirmEmail(email);
    const { headers } = await signIn(email);
    const ownerSession = await auth.api.getSession({ headers });
    const ownerId = ownerSession!.user.id;

    const regularAccId = uuidv7();
    const regularEmpId = uuidv7();
    const regularEmail = `regular-${regularAccId.slice(-6)}@${domain}`;
    const unitAdminAccId = uuidv7();
    const unitAdminEmpId = uuidv7();
    const unitAdminEmail = `unitadmin-${unitAdminAccId.slice(-6)}@${domain}`;
    const orgAdminAccId = uuidv7();
    const orgAdminEmpId = uuidv7();
    const orgAdminEmail = `orgadmin-${orgAdminAccId.slice(-6)}@${domain}`;

    await db.authUser.createMany({
      data: [
        { id: regularAccId, name: "Piotr Zwykły", email: regularEmail, emailVerified: true },
        { id: unitAdminAccId, name: "Tomasz Oddział", email: unitAdminEmail, emailVerified: true },
        { id: orgAdminAccId, name: "Marta Admin", email: orgAdminEmail, emailVerified: true },
      ],
    });

    const orgManagePerm = await db.permission.upsert({
      where: { key: CORE_PERMISSIONS.keys["organization.manage"] },
      create: {
        id: uuidv7(),
        key: CORE_PERMISSIONS.keys["organization.manage"],
        productId: null,
        description: "Zmiana danych firmy i zarządzanie domenami e-mail",
      },
      update: {},
      select: { id: true },
    });

    try {
      await withOrganization(db, organizationId, async (tx) => {
        const unitId = uuidv7();
        const roleId = uuidv7();
        await tx.organizationUnit.create({
          data: { id: unitId, organizationId, name: "Kraków", type: "BRANCH" },
        });
        await tx.role.create({
          data: { id: roleId, organizationId, productId: null, name: "Zarząd firmy test" },
        });
        await tx.rolePermission.create({ data: { roleId, permissionId: orgManagePerm.id } });

        for (const [accId, empId, em, first] of [
          [regularAccId, regularEmpId, regularEmail, "Piotr"],
          [unitAdminAccId, unitAdminEmpId, unitAdminEmail, "Tomasz"],
          [orgAdminAccId, orgAdminEmpId, orgAdminEmail, "Marta"],
        ] as const) {
          await tx.employee.create({
            data: { id: empId, organizationId, firstName: first, lastName: "Test", workEmail: em },
          });
          await tx.account.create({
            data: { id: accId, organizationId, employeeId: empId, email: em, normalizedEmail: em, status: "ACTIVE" },
          });
        }

        await tx.roleAssignment.create({
          data: {
            id: uuidv7(),
            organizationId,
            accountId: unitAdminAccId,
            roleId,
            scopeType: "UNIT",
            scopeId: unitId,
            grantedByAccountId: ownerId,
          },
        });
        await tx.roleAssignment.create({
          data: {
            id: uuidv7(),
            organizationId,
            accountId: orgAdminAccId,
            roleId,
            scopeType: "ORGANIZATION",
            grantedByAccountId: ownerId,
          },
        });
      });

      // Zwykły pracownik i zakres UNIT dostają 403 PERMISSION_DENIED
      await expect(verifyOrganizationDomain(regularAccId, { trustLocally: true })).rejects.toMatchObject({
        code: "PERMISSION_DENIED",
        status: 403,
      });
      await expect(verifyOrganizationDomain(unitAdminAccId, { trustLocally: true })).rejects.toMatchObject({
        code: "PERMISSION_DENIED",
        status: 403,
      });

      // Konto z core.organization.manage w zakresie ORGANIZATION przechodzi
      expect(await verifyOrganizationDomain(orgAdminAccId, { trustLocally: true })).toEqual({
        domain,
        status: "VERIFIED",
      });
      const organization = await withOrganization(db, organizationId, (tx) =>
        tx.organization.findUniqueOrThrow({ where: { id: organizationId } }),
      );
      expect(organization.status).toBe("ACTIVE");
    } finally {
      await withOrganization(db, organizationId, (tx) => tx.roleAssignment.deleteMany({}));
      await db.authUser.deleteMany({ where: { id: { in: [regularAccId, unitAdminAccId, orgAdminAccId] } } });
    }
  });

  it("verifyOrganizationDomain nie zmienia statusu firmy SUSPENDED na ACTIVE i zapisuje wpis audytu", async () => {
    const { organizationId, email, domain } = await signUp("suspended");
    await confirmEmail(email);
    const { headers } = await signIn(email);
    const session = await auth.api.getSession({ headers });

    await withOrganization(db, organizationId, (tx) =>
      tx.organization.update({
        where: { id: organizationId },
        data: { status: "SUSPENDED", suspendedAt: new Date() },
      }),
    );

    expect(await verifyOrganizationDomain(session!.user.id, { trustLocally: true })).toEqual({
      domain,
      status: "VERIFIED",
    });

    const organization = await withOrganization(db, organizationId, (tx) =>
      tx.organization.findUniqueOrThrow({ where: { id: organizationId } }),
    );
    expect(organization.status).toBe("SUSPENDED");

    const audits = await withOrganization(db, organizationId, (tx) =>
      tx.auditLog.findMany({ where: { action: "organization.domain.verified" } }),
    );
    expect(audits).toHaveLength(1);
    expect(audits[0]).toMatchObject({
      actorType: "ACCOUNT",
      actorAccountId: session!.user.id,
      action: "organization.domain.verified",
      resourceType: "organization_domain",
      metadata: { domain, method: "DEV_TRUST" },
    });
  });
});
