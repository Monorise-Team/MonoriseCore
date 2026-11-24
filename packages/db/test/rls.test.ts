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
    await tx.organization.update({ where: { id }, data: { ownerAccountId: accountId } });
  });
  return { id, domain, employeeId, accountId };
}

let acme: Company;
let globex: Company;
let acmeKrakowId: string;
let acmeMagazynId: string;
let acmeMembershipId: string;
let globexGdanskId: string;
let globexMembershipId: string;

beforeAll(async () => {
  acme = await createCompany("Acme");
  globex = await createCompany("Globex");

  acmeKrakowId = uuidv7();
  acmeMagazynId = uuidv7();
  acmeMembershipId = uuidv7();
  await withOrganization(db, acme.id, async (tx) => {
    await tx.organizationUnit.create({
      data: { id: acmeKrakowId, organizationId: acme.id, name: "Kraków", type: "BRANCH" },
    });
    await tx.organizationUnit.create({
      data: {
        id: acmeMagazynId,
        organizationId: acme.id,
        parentId: acmeKrakowId,
        name: "Magazyn",
        type: "TEAM",
      },
    });
    await tx.unitMembership.create({
      data: {
        id: acmeMembershipId,
        organizationId: acme.id,
        unitId: acmeMagazynId,
        employeeId: acme.employeeId,
        role: "LEADER",
      },
    });
  });

  globexGdanskId = uuidv7();
  globexMembershipId = uuidv7();
  await withOrganization(db, globex.id, async (tx) => {
    await tx.organizationUnit.create({
      data: { id: globexGdanskId, organizationId: globex.id, name: "Gdańsk", type: "BRANCH" },
    });
    await tx.unitMembership.create({
      data: {
        id: globexMembershipId,
        organizationId: globex.id,
        unitId: globexGdanskId,
        employeeId: globex.employeeId,
        role: "MEMBER",
      },
    });
  });
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

  it("firma widzi tylko swoich pracowników, jednostki, członkostwa i siebie", async () => {
    const employees = await withOrganization(db, acme.id, (tx) => tx.employee.findMany());
    expect(employees.map((e) => e.id)).toContain(acme.employeeId);
    expect(employees.every((e) => e.organizationId === acme.id)).toBe(true);

    const organizations = await withOrganization(db, acme.id, (tx) => tx.organization.findMany());
    expect(organizations.map((o) => o.id)).toEqual([acme.id]);
    expect(organizations[0]?.ownerAccountId).toBe(acme.accountId);

    const units = await withOrganization(db, acme.id, (tx) => tx.organizationUnit.findMany());
    expect(units.map((u) => u.id).sort()).toEqual([acmeKrakowId, acmeMagazynId].sort());
    expect(units.every((u) => u.organizationId === acme.id)).toBe(true);

    const memberships = await withOrganization(db, acme.id, (tx) => tx.unitMembership.findMany());
    expect(memberships.map((m) => m.id)).toEqual([acmeMembershipId]);
    expect(memberships.every((m) => m.organizationId === acme.id)).toBe(true);
  });

  it("bez wskazania firmy baza nie zwraca żadnych danych firm", async () => {
    expect(await db.employee.findMany()).toEqual([]);
    expect(await db.organization.findMany()).toEqual([]);
    expect(await db.account.findMany()).toEqual([]);
    expect(await db.organizationUnit.findMany()).toEqual([]);
    expect(await db.unitMembership.findMany()).toEqual([]);
  });

  it("nie da się zmienić ani usunąć danych innej firmy", async () => {
    const updatedEmployee = await withOrganization(db, acme.id, (tx) =>
      tx.employee.updateMany({ where: { id: globex.employeeId }, data: { jobTitle: "Przejęty" } }),
    );
    expect(updatedEmployee.count).toBe(0);
    const deletedAccount = await withOrganization(db, acme.id, (tx) =>
      tx.account.deleteMany({ where: { id: globex.accountId } }),
    );
    expect(deletedAccount.count).toBe(0);
    const updatedUnit = await withOrganization(db, acme.id, (tx) =>
      tx.organizationUnit.updateMany({ where: { id: globexGdanskId }, data: { name: "Przejęty" } }),
    );
    expect(updatedUnit.count).toBe(0);
    const deletedUnit = await withOrganization(db, acme.id, (tx) =>
      tx.organizationUnit.deleteMany({ where: { id: globexGdanskId } }),
    );
    expect(deletedUnit.count).toBe(0);
    const updatedMembership = await withOrganization(db, acme.id, (tx) =>
      tx.unitMembership.updateMany({ where: { id: globexMembershipId }, data: { role: "LEADER" } }),
    );
    expect(updatedMembership.count).toBe(0);
    const deletedMembership = await withOrganization(db, acme.id, (tx) =>
      tx.unitMembership.deleteMany({ where: { id: globexMembershipId } }),
    );
    expect(deletedMembership.count).toBe(0);
  });

  it("nie da się dopisać danych do innej firmy", async () => {
    await expect(
      withOrganization(db, acme.id, (tx) =>
        tx.employee.create({
          data: { id: uuidv7(), organizationId: globex.id, firstName: "Jan", lastName: "Intruz" },
        }),
      ),
    ).rejects.toThrow(/row-level security|violates/i);

    await expect(
      withOrganization(db, acme.id, (tx) =>
        tx.organizationUnit.create({
          data: { id: uuidv7(), organizationId: globex.id, name: "Obcy oddział", type: "BRANCH" },
        }),
      ),
    ).rejects.toThrow(/row-level security|violates/i);

    await expect(
      withOrganization(db, acme.id, (tx) =>
        tx.unitMembership.create({
          data: {
            id: uuidv7(),
            organizationId: globex.id,
            unitId: globexGdanskId,
            employeeId: globex.employeeId,
            role: "MEMBER",
          },
        }),
      ),
    ).rejects.toThrow(/row-level security|violates/i);
  });

  it("klucze złożone odrzucają rodzica, jednostkę, pracownika i Ownera z innej firmy", async () => {
    await expect(
      withOrganization(db, acme.id, (tx) =>
        tx.organizationUnit.create({
          data: {
            id: uuidv7(),
            organizationId: acme.id,
            parentId: globexGdanskId,
            name: "Zły rodzic",
            type: "TEAM",
          },
        }),
      ),
    ).rejects.toThrow(/foreign key|violates/i);

    await expect(
      withOrganization(db, acme.id, (tx) =>
        tx.unitMembership.create({
          data: {
            id: uuidv7(),
            organizationId: acme.id,
            unitId: globexGdanskId,
            employeeId: acme.employeeId,
            role: "MEMBER",
          },
        }),
      ),
    ).rejects.toThrow(/foreign key|violates/i);

    await expect(
      withOrganization(db, acme.id, (tx) =>
        tx.unitMembership.create({
          data: {
            id: uuidv7(),
            organizationId: acme.id,
            unitId: acmeKrakowId,
            employeeId: globex.employeeId,
            role: "MEMBER",
          },
        }),
      ),
    ).rejects.toThrow(/foreign key|violates/i);

    const globexMemberEmployeeId = uuidv7();
    const globexMemberAccountId = uuidv7();
    const globexMemberEmail = `jan@${globex.domain}`;
    await db.authUser.create({
      data: { id: globexMemberAccountId, name: "Jan Globex", email: globexMemberEmail, emailVerified: true },
    });
    try {
      await withOrganization(db, globex.id, async (tx) => {
        await tx.employee.create({
          data: { id: globexMemberEmployeeId, organizationId: globex.id, firstName: "Jan", lastName: "Globex" },
        });
        await tx.account.create({
          data: {
            id: globexMemberAccountId,
            organizationId: globex.id,
            employeeId: globexMemberEmployeeId,
            email: globexMemberEmail,
            normalizedEmail: globexMemberEmail,
            status: "ACTIVE",
          },
        });
      });

      // Używamy konta z Globex, które NIE jest Ownerem Globex, żeby pominąć indeks unikalny
      // organizations_ownerAccountId_key i rzeczywiście przetestować klucz złożony organizations_id_ownerAccountId_fkey.
      await expect(
        withOrganization(db, acme.id, (tx) =>
          tx.organization.update({
            where: { id: acme.id },
            data: { ownerAccountId: globexMemberAccountId },
          }),
        ),
      ).rejects.toThrow(/organizations_id_ownerAccountId_fkey|foreign key/i);
    } finally {
      await withOrganization(db, globex.id, async (tx) => {
        await tx.account.deleteMany({ where: { id: globexMemberAccountId } });
        await tx.employee.deleteMany({ where: { id: globexMemberEmployeeId } });
      });
      await db.authUser.deleteMany({ where: { id: globexMemberAccountId } });
    }
  });

  it("wyzwalacz blokuje cykle w drzewie jednostek, a FK chroni konto Ownera przed usunięciem", async () => {
    const selfId = uuidv7();
    await expect(
      withOrganization(db, acme.id, (tx) =>
        tx.organizationUnit.create({
          data: { id: selfId, organizationId: acme.id, parentId: selfId, name: "Pętla", type: "TEAM" },
        }),
      ),
    ).rejects.toThrow(/cycle/i);

    await expect(
      withOrganization(db, acme.id, (tx) =>
        tx.organizationUnit.update({ where: { id: acmeKrakowId }, data: { parentId: acmeKrakowId } }),
      ),
    ).rejects.toThrow(/cycle/i);

    await expect(
      withOrganization(db, acme.id, (tx) =>
        tx.organizationUnit.update({ where: { id: acmeKrakowId }, data: { parentId: acmeMagazynId } }),
      ),
    ).rejects.toThrow(/cycle/i);

    const subTeamId = uuidv7();
    await withOrganization(db, acme.id, (tx) =>
      tx.organizationUnit.create({
        data: { id: subTeamId, organizationId: acme.id, parentId: acmeMagazynId, name: "Zmiana A", type: "TEAM" },
      }),
    );
    await expect(
      withOrganization(db, acme.id, (tx) =>
        tx.organizationUnit.update({ where: { id: acmeKrakowId }, data: { parentId: subTeamId } }),
      ),
    ).rejects.toThrow(/cycle/i);
    await withOrganization(db, acme.id, (tx) => tx.organizationUnit.delete({ where: { id: subTeamId } }));

    await expect(
      withOrganization(db, acme.id, (tx) => tx.account.delete({ where: { id: acme.accountId } })),
    ).rejects.toThrow(/foreign key|restrict|violates/i);
  });

  it("równoległe transakcje tworzące cykl A->B i B->A są serializowane i dokładnie jedna kończy się błędem cyklu", async () => {
    const unitAId = uuidv7();
    const unitBId = uuidv7();
    await withOrganization(db, acme.id, async (tx) => {
      await tx.organizationUnit.create({
        data: { id: unitAId, organizationId: acme.id, name: "Równoległa A", type: "BRANCH" },
      });
      await tx.organizationUnit.create({
        data: { id: unitBId, organizationId: acme.id, name: "Równoległa B", type: "BRANCH" },
      });
    });

    const deferred = () => {
      let resolve!: () => void;
      const promise = new Promise<void>((r) => {
        resolve = r;
      });
      return { promise, resolve };
    };

    const db2 = createDb(url);
    const tx1Updated = deferred();
    const tx2Started = deferred();
    const allowTx1Commit = deferred();

    try {
      const tx1 = withOrganization(db, acme.id, async (tx) => {
        await tx.organizationUnit.update({ where: { id: unitAId }, data: { parentId: unitBId } });
        tx1Updated.resolve();
        await allowTx1Commit.promise;
      });

      const tx2 = tx1Updated.promise.then(() =>
        withOrganization(db2, acme.id, async (tx) => {
          tx2Started.resolve();
          await tx.organizationUnit.update({ where: { id: unitBId }, data: { parentId: unitAId } });
        }),
      );

      await tx2Started.promise;
      // Krótka chwila, by druga transakcja weszła w UPDATE i zatrzymała się na pg_advisory_xact_lock.
      await new Promise((resolve) => setTimeout(resolve, 50));
      allowTx1Commit.resolve();

      const results = await Promise.allSettled([tx1, tx2]);
      const fulfilled = results.filter((r) => r.status === "fulfilled");
      const rejected = results.filter((r): r is PromiseRejectedResult => r.status === "rejected");

      expect(fulfilled).toHaveLength(1);
      expect(rejected).toHaveLength(1);
      expect(String(rejected[0]!.reason)).toMatch(/cycle/i);
    } finally {
      allowTx1Commit.resolve();
      await db2.$disconnect();
      await withOrganization(db, acme.id, async (tx) => {
        await tx.organizationUnit.updateMany({
          where: { id: { in: [unitAId, unitBId] } },
          data: { parentId: null },
        });
        await tx.organizationUnit.deleteMany({ where: { id: { in: [unitAId, unitBId] } } });
      });
    }
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
