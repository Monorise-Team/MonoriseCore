import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { accountClaims, createDb, domainOwner, uuidv7, withOrganization } from "../src/index.js";

// Rola aplikacji (core_app): RLS obowiązuje ją zawsze. Lokalnie: pnpm db:up && pnpm db:migrate.
const url =
  process.env.CORE_TEST_APP_DATABASE_URL ?? "postgresql://core_app:core_app@localhost:5433/monorise_core_test";
const db = createDb(url);

interface Company {
  id: string;
  domain: string;
  employeeId: string;
  accountId: string;
}

async function createCompany(name: string): Promise<Company> {
  const id = uuidv7();
  const domain = `${id.slice(-8)}-${name.toLowerCase()}.test`;
  const employeeId = uuidv7();
  const accountId = uuidv7();
  const email = `anna@${domain}`;
  await db.authUser.create({ data: { id: accountId, name: `Anna ${name}`, email, emailVerified: true } });
  await withOrganization(db, id, async (tx) => {
    await tx.organization.create({ data: { id, name, createdVia: "SELF_SIGNUP" } });
    await tx.organizationDomain.create({
      data: { id: uuidv7(), organizationId: id, domain, verificationMethod: "DNS_TXT", isPrimary: true },
    });
    await tx.employee.create({ data: { id: employeeId, organizationId: id, firstName: "Anna", lastName: name } });
    await tx.account.create({
      data: { id: accountId, organizationId: id, employeeId, email, normalizedEmail: email, status: "ACTIVE" },
    });
  });
  return { id, domain, employeeId, accountId };
}

let acme: Company;
let globex: Company;

beforeAll(async () => {
  acme = await createCompany("Acme");
  globex = await createCompany("Globex");
});

afterAll(async () => {
  for (const company of [acme, globex]) {
    if (!company) continue;
    await withOrganization(db, company.id, (tx) => tx.organization.delete({ where: { id: company.id } }));
    await db.authUser.delete({ where: { id: company.accountId } });
  }
  await db.$disconnect();
});

describe("separacja firm (RLS)", () => {
  it("rola aplikacji nie omija RLS i nie jest właścicielem tabel", async () => {
    const [role] = await db.$queryRaw<{ bypass: boolean; owner: boolean }[]>`
      SELECT r.rolbypassrls AS bypass,
             EXISTS (SELECT 1 FROM pg_tables t WHERE t.tableowner = current_user) AS owner
      FROM pg_roles r WHERE r.rolname = current_user`;
    expect(role).toEqual({ bypass: false, owner: false });
  });

  it("firma widzi tylko swoich pracowników i siebie", async () => {
    const employees = await withOrganization(db, acme.id, (tx) => tx.employee.findMany());
    expect(employees.map((e) => e.id)).toContain(acme.employeeId);
    expect(employees.every((e) => e.organizationId === acme.id)).toBe(true);

    const organizations = await withOrganization(db, acme.id, (tx) => tx.organization.findMany());
    expect(organizations.map((o) => o.id)).toEqual([acme.id]);
  });

  it("bez wskazania firmy baza nie zwraca żadnych danych firm", async () => {
    expect(await db.employee.findMany()).toEqual([]);
    expect(await db.organization.findMany()).toEqual([]);
    expect(await db.account.findMany()).toEqual([]);
  });

  it("nie da się zmienić ani usunąć danych innej firmy", async () => {
    const updated = await withOrganization(db, acme.id, (tx) =>
      tx.employee.updateMany({ where: { id: globex.employeeId }, data: { jobTitle: "Przejęty" } }),
    );
    expect(updated.count).toBe(0);
    const deleted = await withOrganization(db, acme.id, (tx) =>
      tx.account.deleteMany({ where: { id: globex.accountId } }),
    );
    expect(deleted.count).toBe(0);
  });

  it("nie da się dopisać danych do innej firmy", async () => {
    await expect(
      withOrganization(db, acme.id, (tx) =>
        tx.employee.create({
          data: { id: uuidv7(), organizationId: globex.id, firstName: "Jan", lastName: "Intruz" },
        }),
      ),
    ).rejects.toThrow(/row-level security|violates/i);
  });

  it("dane do tokenu i właściciel domeny działają ponad granicą firm, tylko dla wskazanego konta", async () => {
    expect(await accountClaims(db, globex.accountId)).toEqual({
      organizationId: globex.id,
      employeeId: globex.employeeId,
      authzRevision: 0,
      accountStatus: "ACTIVE",
      organizationStatus: "PENDING_VERIFICATION",
    });
    expect(await accountClaims(db, uuidv7())).toBeNull();
    expect(await domainOwner(db, acme.domain.toUpperCase())).toEqual({ organizationId: acme.id, status: "PENDING" });
    expect(await domainOwner(db, "nieznana-domena.test")).toBeNull();
  });
});
