import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  accountClaims,
  claimMailOutboxJobs,
  cleanupExpiredIdempotencyKeys,
  cleanupMailOutbox,
  createDb,
  domainOwner,
  hashToken,
  invitationByTokenHash,
  releaseCompetingDomainClaims,
  uuidv7,
  withOrganization,
} from "../src/index.js";

// Rola aplikacji (core_app): RLS obowiązuje ją zawsze. Lokalnie: pnpm db:up && pnpm db:migrate.
const url =
  process.env.CORE_TEST_APP_DATABASE_URL ?? "postgresql://core_app:core_app@localhost:5433/monorise_core_test";
const ownerUrl =
  process.env.CORE_TEST_DATABASE_URL ?? "postgresql://core_owner:core_owner@localhost:5433/monorise_core_test";
const db = createDb(url);
const ownerDb = createDb(ownerUrl);

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
  await ownerDb.$disconnect();
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
    // Zasada „wygrywa weryfikacja”: domain_owner zwraca wyłącznie domeny ze statusem VERIFIED
    expect(await domainOwner(db, acme.domain.toUpperCase())).toBeNull();
    expect(await domainOwner(db, "nieznana-domena.test")).toBeNull();
  });
});

describe("dziennik zdarzeń i rejestr uprawnień", () => {
  it("izoluje wpisy firm przez RLS, ukrywa wpisy platformy i blokuje UPDATE oraz DELETE", async () => {
    const acmeEntryId = uuidv7();
    const globexEntryId = uuidv7();
    const platformEntryId = uuidv7();

    await withOrganization(db, acme.id, (tx) =>
      tx.auditLog.create({
        data: {
          id: acmeEntryId,
          organizationId: acme.id,
          actorType: "ACCOUNT",
          actorAccountId: acme.accountId,
          action: "unit.created",
          resourceType: "unit",
          resourceId: acmeKrakowId,
          metadata: { type: "BRANCH" },
        },
      }),
    );

    await withOrganization(db, globex.id, (tx) =>
      tx.auditLog.create({
        data: {
          id: globexEntryId,
          organizationId: globex.id,
          actorType: "ACCOUNT",
          actorAccountId: globex.accountId,
          action: "unit.created",
          resourceType: "unit",
          resourceId: globexGdanskId,
          metadata: { type: "BRANCH" },
        },
      }),
    );

    // Wpis platformowy bez kontekstu firmy
    await db.auditLog.create({
      data: {
        id: platformEntryId,
        organizationId: null,
        actorType: "SYSTEM",
        action: "product.permissions.registered",
        resourceType: "product",
        resourceId: "core",
        metadata: { unchanged: 0 },
      },
    });

    try {
      // Firma A widzi wyłącznie swój wpis; nie widzi wpisów firmy B ani wpisów platformy
      const acmeEntries = await withOrganization(db, acme.id, (tx) => tx.auditLog.findMany());
      expect(acmeEntries.map((entry) => entry.id)).toContain(acmeEntryId);
      expect(acmeEntries.map((entry) => entry.id)).not.toContain(globexEntryId);
      expect(acmeEntries.map((entry) => entry.id)).not.toContain(platformEntryId);
      expect(acmeEntries.every((entry) => entry.organizationId === acme.id)).toBe(true);

      // Bez kontekstu firmy core_app widzi tylko wpisy platformy, nigdy wpisów firm
      const platformEntries = await db.auditLog.findMany();
      expect(platformEntries.map((entry) => entry.id)).toContain(platformEntryId);
      expect(platformEntries.every((entry) => entry.organizationId === null)).toBe(true);

      // Nie można zapisać wpisu cudzej firmy ani wpisu platformowego w kontekście firmy
      await expect(
        withOrganization(db, acme.id, (tx) =>
          tx.auditLog.create({
            data: {
              id: uuidv7(),
              organizationId: globex.id,
              actorType: "ACCOUNT",
              actorAccountId: acme.accountId,
              action: "unit.created",
              resourceType: "unit",
              resourceId: globexGdanskId,
            },
          }),
        ),
      ).rejects.toThrow(/row-level security|violates/i);

      await expect(
        withOrganization(db, acme.id, (tx) =>
          tx.auditLog.create({
            data: {
              id: uuidv7(),
              organizationId: null,
              actorType: "SYSTEM",
              action: "product.permissions.registered",
              resourceType: "product",
              resourceId: "core",
            },
          }),
        ),
      ).rejects.toThrow(/row-level security|violates/i);

      // core_app nie może ani zmieniać, ani usuwać wpisów dziennika
      await expect(
        withOrganization(db, acme.id, (tx) =>
          tx.auditLog.updateMany({ where: { id: acmeEntryId }, data: { action: "tampered" } }),
        ),
      ).rejects.toThrow(/permission denied/i);

      await expect(
        withOrganization(db, acme.id, (tx) => tx.auditLog.deleteMany({ where: { id: acmeEntryId } })),
      ).rejects.toThrow(/permission denied/i);

      // Nawet właściciel tabel (core_owner) nie może zmodyfikować wpisu dziennika
      await expect(
        ownerDb.auditLog.updateMany({ where: { id: acmeEntryId }, data: { action: "tampered" } }),
      ).rejects.toThrow(/immutable|cannot be updated/i);

      await expect(
        ownerDb.auditLog.updateMany({ where: { id: platformEntryId }, data: { action: "tampered" } }),
      ).rejects.toThrow(/immutable|cannot be updated/i);
    } finally {
      await ownerDb.auditLog.deleteMany({ where: { id: { in: [acmeEntryId, globexEntryId, platformEntryId] } } });
    }
  });

  it("usunięcie firmy kaskadowo usuwa jej wpisy dziennika (ADR-0041)", async () => {
    const temp = await createCompany("TempAudit");
    const entryId = uuidv7();
    await withOrganization(db, temp.id, (tx) =>
      tx.auditLog.create({
        data: {
          id: entryId,
          organizationId: temp.id,
          actorType: "ACCOUNT",
          actorAccountId: temp.accountId,
          action: "employee.created",
          resourceType: "employee",
          resourceId: temp.employeeId,
        },
      }),
    );

    expect(await ownerDb.auditLog.count({ where: { id: entryId } })).toBe(1);

    await withOrganization(db, temp.id, (tx) => tx.organization.delete({ where: { id: temp.id } }));
    await db.authUser.delete({ where: { id: temp.accountId } });

    expect(await ownerDb.auditLog.count({ where: { id: entryId } })).toBe(0);
    expect(await withOrganization(db, temp.id, (tx) => tx.auditLog.findMany())).toEqual([]);
  });

  it("egzekwuje prefiks klucza uprawnienia względem produktu i blokuje DELETE uprawnień dla core_app", async () => {
    const suffix = uuidv7().replaceAll("-", "").slice(-6);
    const productKey = `prod${suffix}`;
    const otherProductKey = `other${suffix}`;
    const productId = uuidv7();
    const otherProductId = uuidv7();
    const validPermId = uuidv7();
    const corePermId = uuidv7();
    const coreKey = `core.rls_test_${suffix}.read`;

    await db.product.create({ data: { id: productId, key: productKey, name: "Produkt testowy" } });
    await db.product.create({ data: { id: otherProductId, key: otherProductKey, name: "Inny produkt" } });

    try {
      // Poprawne uprawnienie produktu i platformowe core.*
      await db.permission.create({
        data: { id: validPermId, key: `${productKey}.items.read`, productId, description: "Odczyt pozycji" },
      });
      await db.permission.create({
        data: { id: corePermId, key: coreKey, productId: null, description: "Uprawnienie testowe platformy" },
      });

      // Klucz innego produktu pod tym productId -> odrzucony przez wyzwalacz
      await expect(
        db.permission.create({
          data: { id: uuidv7(), key: `${otherProductKey}.items.read`, productId, description: "Zły prefiks" },
        }),
      ).rejects.toThrow(/permissions_product_prefix|does not match product key/i);

      // Klucz core.* z przypisanym productId -> odrzucony przez CHECK
      await expect(
        db.permission.create({
          data: { id: uuidv7(), key: `core.bad_${suffix}.write`, productId, description: "Core z produktem" },
        }),
      ).rejects.toThrow(
        /permissions_core_product_consistency|permissions_product_prefix|must start with|does not match product key|check constraint|violates/i,
      );

      // Klucz produktu bez productId -> odrzucony przez CHECK
      await expect(
        db.permission.create({
          data: {
            id: uuidv7(),
            key: `${productKey}.items.orphan`,
            productId: null,
            description: "Produkt bez productId",
          },
        }),
      ).rejects.toThrow(
        /permissions_core_product_consistency|permissions_product_prefix|must start with|does not match product key|check constraint|violates/i,
      );

      // Niepoprawny format klucza -> odrzucony przez CHECK
      await expect(
        db.permission.create({
          data: { id: uuidv7(), key: `${productKey}.short`, productId, description: "Za krótki klucz" },
        }),
      ).rejects.toThrow(/permissions_key_format|check constraint|violates/i);

      // core_app nie może usuwać uprawnień ani produktów
      await expect(db.permission.delete({ where: { id: validPermId } })).rejects.toThrow(/permission denied/i);
      await expect(db.product.delete({ where: { id: otherProductId } })).rejects.toThrow(/permission denied/i);
    } finally {
      await ownerDb.permission.deleteMany({ where: { id: { in: [validPermId, corePermId] } } });
      await ownerDb.product.deleteMany({ where: { id: { in: [productId, otherProductId] } } });
    }
  });
});

describe("role, uprawnienia ról i przypisania ról (RLS i wyzwalacze)", () => {
  it("izoluje role i przypisania firm, udostępnia szablony do odczytu i blokuje modyfikację szablonów przez firmę", async () => {
    const suffix = uuidv7().replaceAll("-", "").slice(-6);
    const productKey = `roleprod${suffix}`;
    const productId = uuidv7();
    const prodPermId = uuidv7();
    const prodPerm2Id = uuidv7();
    const corePermId = uuidv7();
    const templateRoleId = uuidv7();
    const acmeRoleId = uuidv7();
    const globexRoleId = uuidv7();
    const acmeAssignmentId = uuidv7();
    const globexAssignmentId = uuidv7();

    await db.product.create({ data: { id: productId, key: productKey, name: "Produkt testowy ról" } });
    await db.permission.create({
      data: { id: prodPermId, key: `${productKey}.entries.read`, productId, description: "Odczyt wpisów" },
    });
    await db.permission.create({
      data: { id: prodPerm2Id, key: `${productKey}.entries.write`, productId, description: "Zapis wpisów" },
    });
    await db.permission.create({
      data: { id: corePermId, key: `core.role_rls_${suffix}.manage`, productId: null, description: "Uprawnienie Core" },
    });

    // Szablon roli tworzony bez kontekstu firmy (przez Core)
    await db.role.create({
      data: {
        id: templateRoleId,
        organizationId: null,
        productId,
        key: `${productKey}.viewer`,
        name: "Podgląd",
        description: "Gotowa rola produktu",
      },
    });
    await db.rolePermission.create({ data: { roleId: templateRoleId, permissionId: prodPermId } });

    try {
      // Role firmowe tworzone w kontekście firmy
      await withOrganization(db, acme.id, async (tx) => {
        await tx.role.create({
          data: { id: acmeRoleId, organizationId: acme.id, productId, name: "Kierownik Acme" },
        });
        await tx.rolePermission.create({ data: { roleId: acmeRoleId, permissionId: prodPermId } });
        await tx.roleAssignment.create({
          data: {
            id: acmeAssignmentId,
            organizationId: acme.id,
            accountId: acme.accountId,
            roleId: acmeRoleId,
            scopeType: "UNIT",
            scopeId: acmeKrakowId,
            grantedByAccountId: acme.accountId,
          },
        });
      });

      await withOrganization(db, globex.id, async (tx) => {
        await tx.role.create({
          data: { id: globexRoleId, organizationId: globex.id, productId, name: "Kierownik Globex" },
        });
        await tx.rolePermission.create({ data: { roleId: globexRoleId, permissionId: prodPermId } });
        await tx.roleAssignment.create({
          data: {
            id: globexAssignmentId,
            organizationId: globex.id,
            accountId: globex.accountId,
            roleId: globexRoleId,
            scopeType: "ORGANIZATION",
            grantedByAccountId: globex.accountId,
          },
        });
      });

      // Firma A widzi swoje role i szablony, ale nie widzi ról firmy B
      const acmeRoles = await withOrganization(db, acme.id, (tx) => tx.role.findMany());
      expect(acmeRoles.map((r) => r.id)).toContain(acmeRoleId);
      expect(acmeRoles.map((r) => r.id)).toContain(templateRoleId);
      expect(acmeRoles.map((r) => r.id)).not.toContain(globexRoleId);

      // Firma A widzi uprawnienia swoich ról i szablonów (wyzwalacz skopiował organizationId), ale nie firmy B
      const acmeRolePerms = await withOrganization(db, acme.id, (tx) => tx.rolePermission.findMany());
      expect(acmeRolePerms.some((rp) => rp.roleId === acmeRoleId && rp.organizationId === acme.id)).toBe(true);
      expect(acmeRolePerms.some((rp) => rp.roleId === templateRoleId && rp.organizationId === null)).toBe(true);
      expect(acmeRolePerms.some((rp) => rp.roleId === globexRoleId)).toBe(false);

      // Firma A widzi wyłącznie swoje przypisania
      const acmeAssignments = await withOrganization(db, acme.id, (tx) => tx.roleAssignment.findMany());
      expect(acmeAssignments.map((a) => a.id)).toEqual([acmeAssignmentId]);

      // Bez kontekstu firmy nie widać ról firmowych ani przypisań (tylko szablony)
      const noContextRoles = await db.role.findMany();
      expect(noContextRoles.map((r) => r.id)).toContain(templateRoleId);
      expect(noContextRoles.map((r) => r.id)).not.toContain(acmeRoleId);
      expect(await db.roleAssignment.findMany()).toEqual([]);

      // Firma nie może utworzyć szablonu ani zmienić istniejącego szablonu ani jego uprawnień
      await expect(
        withOrganization(db, acme.id, (tx) =>
          tx.role.create({
            data: {
              id: uuidv7(),
              organizationId: null,
              productId,
              key: `${productKey}.forged`,
              name: "Fałszywy szablon",
            },
          }),
        ),
      ).rejects.toThrow(/row-level security|violates/i);

      const updatedTemplate = await withOrganization(db, acme.id, (tx) =>
        tx.role.updateMany({ where: { id: templateRoleId }, data: { name: "Przejęty szablon" } }),
      );
      expect(updatedTemplate.count).toBe(0);

      await expect(
        withOrganization(db, acme.id, (tx) =>
          tx.rolePermission.create({
            data: { roleId: templateRoleId, permissionId: prodPerm2Id, organizationId: acme.id },
          }),
        ),
      ).rejects.toThrow(/row-level security|violates/i);

      const deletedTemplatePerm = await withOrganization(db, acme.id, (tx) =>
        tx.rolePermission.deleteMany({ where: { roleId: templateRoleId } }),
      );
      expect(deletedTemplatePerm.count).toBe(0);

      // core_app nie może usuwać ról (tylko archiwizacja)
      await expect(
        withOrganization(db, acme.id, (tx) => tx.role.delete({ where: { id: acmeRoleId } })),
      ).rejects.toThrow(/permission denied/i);

      // Rola firmowa musi mieć NULL w key, a szablon musi mieć niepusty key
      await expect(
        withOrganization(db, acme.id, (tx) =>
          tx.role.create({
            data: {
              id: uuidv7(),
              organizationId: acme.id,
              productId,
              key: `${productKey}.forbidden`,
              name: "Firmowa z kluczem",
            },
          }),
        ),
      ).rejects.toThrow(/roles_template_key_consistency|check constraint|violates/i);

      // Unikalność nazw aktywnych ról firmy bez względu na wielkość liter
      await expect(
        withOrganization(db, acme.id, (tx) =>
          tx.role.create({
            data: { id: uuidv7(), organizationId: acme.id, productId, name: "kierownik acme" },
          }),
        ),
      ).rejects.toThrow(/roles_organizationId_lower_name_active_key|unique|duplicate/i);
    } finally {
      await withOrganization(db, acme.id, (tx) => tx.roleAssignment.deleteMany({ where: { id: acmeAssignmentId } }));
      await withOrganization(db, globex.id, (tx) =>
        tx.roleAssignment.deleteMany({ where: { id: globexAssignmentId } }),
      );
      await withOrganization(ownerDb, acme.id, (tx) => tx.role.deleteMany({ where: { id: acmeRoleId } }));
      await withOrganization(ownerDb, globex.id, (tx) => tx.role.deleteMany({ where: { id: globexRoleId } }));
      await ownerDb.role.deleteMany({ where: { id: templateRoleId } });
      await ownerDb.permission.deleteMany({ where: { id: { in: [prodPermId, prodPerm2Id, corePermId] } } });
      await ownerDb.product.deleteMany({ where: { id: productId } });
    }
  });

  it("egzekwuje spójność produktu w role_permissions, archiwizację roli, granice firm oraz CHECKi w role_assignments", async () => {
    const suffix = uuidv7().replaceAll("-", "").slice(-6);
    const productKey = `chkprod${suffix}`;
    const productId = uuidv7();
    const prodPermId = uuidv7();
    const corePermId = uuidv7();
    const platformRoleId = uuidv7();
    const archivedRoleId = uuidv7();
    const globexRoleId = uuidv7();

    await db.product.create({ data: { id: productId, key: productKey, name: "Produkt walidacji" } });
    await db.permission.create({
      data: { id: prodPermId, key: `${productKey}.entries.read`, productId, description: "Odczyt wpisów" },
    });
    await db.permission.create({
      data: { id: corePermId, key: `core.chk_rls_${suffix}.read`, productId: null, description: "Odczyt Core" },
    });

    try {
      await withOrganization(db, acme.id, async (tx) => {
        await tx.role.create({
          data: { id: platformRoleId, organizationId: acme.id, productId: null, name: "Rola platformowa" },
        });
        await tx.role.create({
          data: {
            id: archivedRoleId,
            organizationId: acme.id,
            productId: null,
            name: "Zarchiwizowana",
            archivedAt: new Date(),
          },
        });
      });

      await withOrganization(db, globex.id, (tx) =>
        tx.role.create({
          data: { id: globexRoleId, organizationId: globex.id, productId: null, name: "Rola Globex" },
        }),
      );

      // Rola platformowa nie może przyjąć uprawnienia produktu
      await expect(
        withOrganization(db, acme.id, (tx) =>
          tx.rolePermission.create({ data: { roleId: platformRoleId, permissionId: prodPermId } }),
        ),
      ).rejects.toThrow(/role_permissions_product_match|does not match/i);

      // Uprawnienie platformowe do roli platformowej przechodzi
      await withOrganization(db, acme.id, (tx) =>
        tx.rolePermission.create({ data: { roleId: platformRoleId, permissionId: corePermId } }),
      );

      // Przypisanie zarchiwizowanej roli odrzucone
      await expect(
        withOrganization(db, acme.id, (tx) =>
          tx.roleAssignment.create({
            data: {
              id: uuidv7(),
              organizationId: acme.id,
              accountId: acme.accountId,
              roleId: archivedRoleId,
              scopeType: "ORGANIZATION",
              grantedByAccountId: acme.accountId,
            },
          }),
        ),
      ).rejects.toThrow(/role_assignments_role_not_archived|archived/i);

      // Rola z innej firmy odrzucona
      await expect(
        withOrganization(db, acme.id, (tx) =>
          tx.roleAssignment.create({
            data: {
              id: uuidv7(),
              organizationId: acme.id,
              accountId: acme.accountId,
              roleId: globexRoleId,
              scopeType: "ORGANIZATION",
              grantedByAccountId: acme.accountId,
            },
          }),
        ),
      ).rejects.toThrow(/role_assignments_role_org_check|does not exist|different organization/i);

      // Konto z innej firmy odrzucone kluczem złożonym
      await expect(
        withOrganization(db, acme.id, (tx) =>
          tx.roleAssignment.create({
            data: {
              id: uuidv7(),
              organizationId: acme.id,
              accountId: globex.accountId,
              roleId: platformRoleId,
              scopeType: "ORGANIZATION",
              grantedByAccountId: acme.accountId,
            },
          }),
        ),
      ).rejects.toThrow(/foreign key|violates/i);

      // Jednostka z innej firmy odrzucona wyzwalaczem
      await expect(
        withOrganization(db, acme.id, (tx) =>
          tx.roleAssignment.create({
            data: {
              id: uuidv7(),
              organizationId: acme.id,
              accountId: acme.accountId,
              roleId: platformRoleId,
              scopeType: "UNIT",
              scopeId: globexGdanskId,
              grantedByAccountId: acme.accountId,
            },
          }),
        ),
      ).rejects.toThrow(/role_assignments_unit_scope_check|does not belong/i);

      // CHECKi zakresu i zakresu dat
      await expect(
        withOrganization(db, acme.id, (tx) =>
          tx.roleAssignment.create({
            data: {
              id: uuidv7(),
              organizationId: acme.id,
              accountId: acme.accountId,
              roleId: platformRoleId,
              scopeType: "ORGANIZATION",
              scopeId: acmeKrakowId,
              grantedByAccountId: acme.accountId,
            },
          }),
        ),
      ).rejects.toThrow(/role_assignments_scope_consistency|check constraint|violates/i);

      await expect(
        withOrganization(db, acme.id, (tx) =>
          tx.roleAssignment.create({
            data: {
              id: uuidv7(),
              organizationId: acme.id,
              accountId: acme.accountId,
              roleId: platformRoleId,
              scopeType: "UNIT",
              scopeId: null,
              grantedByAccountId: acme.accountId,
            },
          }),
        ),
      ).rejects.toThrow(/role_assignments_scope_consistency|check constraint|violates/i);

      await expect(
        withOrganization(db, acme.id, (tx) =>
          tx.roleAssignment.create({
            data: {
              id: uuidv7(),
              organizationId: acme.id,
              accountId: acme.accountId,
              roleId: platformRoleId,
              scopeType: "ORGANIZATION",
              validFrom: new Date("2026-12-10T00:00:00.000Z"),
              validUntil: new Date("2026-12-01T00:00:00.000Z"),
              grantedByAccountId: acme.accountId,
            },
          }),
        ),
      ).rejects.toThrow(/role_assignments_validity_range|check constraint|violates/i);

      // Duplikat przypisania (ORGANIZATION z scopeId = NULL) odrzucony indeksem unikalnym
      const firstId = uuidv7();
      await withOrganization(db, acme.id, (tx) =>
        tx.roleAssignment.create({
          data: {
            id: firstId,
            organizationId: acme.id,
            accountId: acme.accountId,
            roleId: platformRoleId,
            scopeType: "ORGANIZATION",
            grantedByAccountId: acme.accountId,
          },
        }),
      );
      try {
        await expect(
          withOrganization(db, acme.id, (tx) =>
            tx.roleAssignment.create({
              data: {
                id: uuidv7(),
                organizationId: acme.id,
                accountId: acme.accountId,
                roleId: platformRoleId,
                scopeType: "ORGANIZATION",
                grantedByAccountId: acme.accountId,
              },
            }),
          ),
        ).rejects.toThrow(/role_assignments_accountId_roleId_scope_key|unique|duplicate/i);
      } finally {
        await withOrganization(db, acme.id, (tx) => tx.roleAssignment.deleteMany({ where: { id: firstId } }));
      }
    } finally {
      await withOrganization(ownerDb, acme.id, (tx) =>
        tx.role.deleteMany({ where: { id: { in: [platformRoleId, archivedRoleId] } } }),
      );
      await withOrganization(ownerDb, globex.id, (tx) => tx.role.deleteMany({ where: { id: globexRoleId } }));
      await ownerDb.permission.deleteMany({ where: { id: { in: [prodPermId, corePermId] } } });
      await ownerDb.product.deleteMany({ where: { id: productId } });
    }
  });

  it("izoluje entitlements między firmami (brak widoczności bez kontekstu), chroni zapisy i egzekwuje unikalność oraz CHECKi", async () => {
    const suffix = uuidv7().replaceAll("-", "").slice(-6);
    const productKey = `entprod${suffix}`;
    const productId = uuidv7();
    const acmeEntId = uuidv7();
    const globexEntId = uuidv7();
    const secondAcmeEntId = uuidv7();

    await db.product.create({ data: { id: productId, key: productKey, name: "Produkt Entitlement" } });

    const withEntitlementWrite = <T>(
      organizationId: string,
      fn: (tx: Parameters<Parameters<typeof withOrganization>[2]>[0]) => Promise<T>,
    ) =>
      withOrganization(db, organizationId, async (tx) => {
        await tx.$executeRaw`SELECT set_config('app.entitlement_write', 'on', true)`;
        return fn(tx);
      });

    try {
      // Zapis bez flagi operatora jest zablokowany zarówno w zwykłym withOrganization, jak i bez kontekstu firmy
      await expect(
        withOrganization(db, acme.id, (tx) =>
          tx.entitlement.create({
            data: {
              id: uuidv7(),
              organizationId: acme.id,
              productId,
              sourceType: "MANUAL",
              status: "ACTIVE",
            },
          }),
        ),
      ).rejects.toThrow(/row-level security|violates/i);

      await expect(
        db.entitlement.create({
          data: {
            id: uuidv7(),
            organizationId: acme.id,
            productId,
            sourceType: "MANUAL",
            status: "ACTIVE",
          },
        }),
      ).rejects.toThrow(/row-level security|violates/i);

      // Ścieżka operatora Core (kontekst firmy + transakcyjna flaga app.entitlement_write) zapisuje wyłącznie tę firmę
      const createdAcme = await withEntitlementWrite(acme.id, (tx) =>
        tx.entitlement.create({
          data: {
            id: acmeEntId,
            organizationId: acme.id,
            productId,
            sourceType: "MANUAL",
            status: "ACTIVE",
          },
        }),
      );
      expect(createdAcme.id).toBe(acmeEntId);

      // Nawet z flagą operatora nie można zapisać wiersza innej firmy
      await expect(
        withEntitlementWrite(acme.id, (tx) =>
          tx.entitlement.create({
            data: {
              id: uuidv7(),
              organizationId: globex.id,
              productId,
              sourceType: "MANUAL",
              status: "ACTIVE",
            },
          }),
        ),
      ).rejects.toThrow(/row-level security|violates/i);

      await withEntitlementWrite(globex.id, (tx) =>
        tx.entitlement.create({
          data: {
            id: globexEntId,
            organizationId: globex.id,
            productId,
            sourceType: "MANUAL",
            status: "ACTIVE",
          },
        }),
      );

      // Bez kontekstu firmy core_app nie widzi żadnych wierszy entitlements (ścisła izolacja firm)
      expect(await db.entitlement.findMany({ where: { productId } })).toEqual([]);
      expect(await db.entitlement.findMany()).toEqual([]);

      // Firma widzi wyłącznie własny entitlement
      const acmeVisible = await withOrganization(db, acme.id, (tx) =>
        tx.entitlement.findMany({ where: { productId } }),
      );
      expect(acmeVisible.map((e) => e.id)).toEqual([acmeEntId]);

      const globexVisible = await withOrganization(db, globex.id, (tx) =>
        tx.entitlement.findMany({ where: { productId } }),
      );
      expect(globexVisible.map((e) => e.id)).toEqual([globexEntId]);

      // Zwykły kontekst firmy nie może zaktualizować nawet własnego entitlementu, a core_app nie ma DELETE
      const updatedInTenant = await withOrganization(db, acme.id, (tx) =>
        tx.entitlement.updateMany({ where: { id: acmeEntId }, data: { status: "ENDED" } }),
      );
      expect(updatedInTenant.count).toBe(0);

      await expect(
        withEntitlementWrite(acme.id, (tx) => tx.entitlement.delete({ where: { id: acmeEntId } })),
      ).rejects.toThrow(/permission denied/i);

      // Drugi nie-ENDED entitlement dla tej samej pary (firma, produkt) odrzucony indeksem częściowym
      await expect(
        withEntitlementWrite(acme.id, (tx) =>
          tx.entitlement.create({
            data: {
              id: uuidv7(),
              organizationId: acme.id,
              productId,
              sourceType: "MANUAL",
              status: "SUSPENDED",
              suspendedReason: "OVERDUE",
            },
          }),
        ),
      ).rejects.toThrow(/entitlements_organizationId_productId_open_key|unique|duplicate/i);

      // CHECKi: endsAt <= startsAt oraz suspendedReason przy statusie innym niż SUSPENDED
      await expect(
        withEntitlementWrite(acme.id, (tx) =>
          tx.entitlement.create({
            data: {
              id: uuidv7(),
              organizationId: acme.id,
              productId,
              sourceType: "MANUAL",
              status: "ENDED",
              startsAt: new Date("2026-12-10T00:00:00.000Z"),
              endsAt: new Date("2026-12-01T00:00:00.000Z"),
            },
          }),
        ),
      ).rejects.toThrow(/entitlements_period_range|check constraint|violates/i);

      await expect(
        withEntitlementWrite(acme.id, (tx) =>
          tx.entitlement.create({
            data: {
              id: uuidv7(),
              organizationId: acme.id,
              productId,
              sourceType: "MANUAL",
              status: "ENDED",
              suspendedReason: "OVERDUE",
            },
          }),
        ),
      ).rejects.toThrow(/entitlements_suspended_reason_consistency|check constraint|violates/i);

      // Po zakończeniu pierwszego (ENDED) można dodać nowy ACTIVE dla tej samej pary (firma, produkt)
      await withEntitlementWrite(acme.id, (tx) =>
        tx.entitlement.update({ where: { id: acmeEntId }, data: { status: "ENDED" } }),
      );
      const second = await withEntitlementWrite(acme.id, (tx) =>
        tx.entitlement.create({
          data: {
            id: secondAcmeEntId,
            organizationId: acme.id,
            productId,
            sourceType: "MANUAL",
            status: "ACTIVE",
          },
        }),
      );
      expect(second.id).toBe(secondAcmeEntId);
    } finally {
      await ownerDb.entitlement.deleteMany({ where: { id: { in: [acmeEntId, globexEntId, secondAcmeEntId] } } });
      await ownerDb.product.deleteMany({ where: { id: productId } });
    }
  });

  it("izoluje app_access przez RLS, pilnuje klucza złożonego, unikalności ACTIVE i CHECK status/revokedAt", async () => {
    const suffix = uuidv7().replaceAll("-", "").slice(-6);
    const productKey = `appprod${suffix}`;
    const productId = uuidv7();
    const acmeAccessId = uuidv7();
    const acmeRegrantId = uuidv7();
    const globexAccessId = uuidv7();

    await db.product.create({ data: { id: productId, key: productKey, name: "Produkt AppAccess" } });

    try {
      // Bez kontekstu firmy odczyt pusty, zapis odrzucony
      expect(await db.appAccess.findMany({ where: { productId } })).toEqual([]);
      await expect(
        db.appAccess.create({
          data: {
            id: uuidv7(),
            organizationId: acme.id,
            accountId: acme.accountId,
            productId,
            status: "ACTIVE",
            grantedByAccountId: acme.accountId,
          },
        }),
      ).rejects.toThrow(/row-level security|violates/i);

      // Zapis w kontekście firmy działa; DELETE jest zablokowane dla core_app
      await withOrganization(db, acme.id, (tx) =>
        tx.appAccess.create({
          data: {
            id: acmeAccessId,
            organizationId: acme.id,
            accountId: acme.accountId,
            productId,
            status: "ACTIVE",
            grantedByAccountId: acme.accountId,
          },
        }),
      );
      await withOrganization(db, globex.id, (tx) =>
        tx.appAccess.create({
          data: {
            id: globexAccessId,
            organizationId: globex.id,
            accountId: globex.accountId,
            productId,
            status: "ACTIVE",
            grantedByAccountId: globex.accountId,
          },
        }),
      );

      // Izolacja odczytu i aktualizacji między firmami
      const acmeRows = await withOrganization(db, acme.id, (tx) => tx.appAccess.findMany({ where: { productId } }));
      expect(acmeRows.map((row) => row.id)).toEqual([acmeAccessId]);

      const crossUpdate = await withOrganization(db, acme.id, (tx) =>
        tx.appAccess.updateMany({ where: { id: globexAccessId }, data: { status: "REVOKED", revokedAt: new Date() } }),
      );
      expect(crossUpdate.count).toBe(0);

      await expect(
        withOrganization(db, acme.id, (tx) => tx.appAccess.delete({ where: { id: acmeAccessId } })),
      ).rejects.toThrow(/permission denied/i);

      // Klucz złożony odrzuca konto z innej firmy (używamy status: REVOKED, żeby ominąć częściowy indeks ACTIVE)
      await expect(
        withOrganization(db, acme.id, (tx) =>
          tx.appAccess.create({
            data: {
              id: uuidv7(),
              organizationId: acme.id,
              accountId: globex.accountId,
              productId,
              status: "REVOKED",
              revokedAt: new Date(),
              grantedByAccountId: acme.accountId,
            },
          }),
        ),
      ).rejects.toThrow(/app_access_organizationId_accountId_fkey|foreign key/i);

      // Drugi wiersz ACTIVE dla tego samego (accountId, productId) odrzucony
      await expect(
        withOrganization(db, acme.id, (tx) =>
          tx.appAccess.create({
            data: {
              id: uuidv7(),
              organizationId: acme.id,
              accountId: acme.accountId,
              productId,
              status: "ACTIVE",
              grantedByAccountId: acme.accountId,
            },
          }),
        ),
      ).rejects.toThrow(/app_access_accountId_productId_active_key|unique|duplicate/i);

      // CHECK status/revokedAt
      await expect(
        withOrganization(db, acme.id, (tx) =>
          tx.appAccess.update({ where: { id: acmeAccessId }, data: { status: "REVOKED", revokedAt: null } }),
        ),
      ).rejects.toThrow(/app_access_status_revoked_consistency|check constraint|violates/i);

      // Po cofnięciu (REVOKED + revokedAt) można ponownie nadać dostęp nowym wierszem ACTIVE
      await withOrganization(db, acme.id, (tx) =>
        tx.appAccess.update({ where: { id: acmeAccessId }, data: { status: "REVOKED", revokedAt: new Date() } }),
      );
      const regranted = await withOrganization(db, acme.id, (tx) =>
        tx.appAccess.create({
          data: {
            id: acmeRegrantId,
            organizationId: acme.id,
            accountId: acme.accountId,
            productId,
            status: "ACTIVE",
            grantedByAccountId: acme.accountId,
          },
        }),
      );
      expect(regranted.id).toBe(acmeRegrantId);
    } finally {
      await withOrganization(ownerDb, acme.id, (tx) =>
        tx.appAccess.deleteMany({ where: { id: { in: [acmeAccessId, acmeRegrantId] } } }),
      );
      await withOrganization(ownerDb, globex.id, (tx) => tx.appAccess.deleteMany({ where: { id: globexAccessId } }));
      await ownerDb.product.deleteMany({ where: { id: productId } });
    }
  });

  it("izoluje outbox_events przez RLS (z RETURNING), blokuje DELETE dla core_app i sprawdza CHECKi", async () => {
    const acmeEventId = uuidv7();
    const globexEventId = uuidv7();
    const platformEventId = uuidv7();

    try {
      // Zdarzenie firmowe w kontekście firmy (z RETURNING)
      const acmeEvent = await withOrganization(db, acme.id, (tx) =>
        tx.outboxEvent.create({
          data: {
            id: acmeEventId,
            organizationId: acme.id,
            type: "organization.permissions.changed",
            version: 1,
            resourceType: "account",
            resourceId: acme.accountId,
            resourceVersion: 1,
            payload: { authzRevision: 1 },
            occurredAt: new Date(),
            publishedAt: null,
          },
        }),
      );
      expect(acmeEvent.id).toBe(acmeEventId);

      await withOrganization(db, globex.id, (tx) =>
        tx.outboxEvent.create({
          data: {
            id: globexEventId,
            organizationId: globex.id,
            type: "organization.permissions.changed",
            version: 1,
            resourceType: "account",
            resourceId: globex.accountId,
            resourceVersion: 1,
            payload: { authzRevision: 1 },
            occurredAt: new Date(),
            publishedAt: null,
          },
        }),
      );

      // Zdarzenie platformowe (organizationId = null) wyłącznie bez kontekstu firmy
      const platformEvent = await db.outboxEvent.create({
        data: {
          id: platformEventId,
          organizationId: null,
          type: "platform.test.recorded",
          version: 1,
          resourceType: "platform",
          resourceId: "core",
          resourceVersion: 0,
          payload: {},
          occurredAt: new Date(),
          publishedAt: null,
        },
      });
      expect(platformEvent.id).toBe(platformEventId);

      // Firma widzi wyłącznie swoje zdarzenia (nie widzi innej firmy ani platformowych)
      const acmeVisible = await withOrganization(db, acme.id, (tx) =>
        tx.outboxEvent.findMany({ where: { id: { in: [acmeEventId, globexEventId, platformEventId] } } }),
      );
      expect(acmeVisible.map((e) => e.id)).toEqual([acmeEventId]);

      // Bez kontekstu firmy widać wyłącznie zdarzenia platformowe
      const platformVisible = await db.outboxEvent.findMany({
        where: { id: { in: [acmeEventId, globexEventId, platformEventId] } },
      });
      expect(platformVisible.map((e) => e.id)).toEqual([platformEventId]);

      // Nie można dopisać zdarzenia innej firmy ani zdarzenia firmowego bez kontekstu
      await expect(
        withOrganization(db, acme.id, (tx) =>
          tx.outboxEvent.create({
            data: {
              id: uuidv7(),
              organizationId: globex.id,
              type: "organization.permissions.changed",
              version: 1,
              resourceType: "account",
              resourceId: globex.accountId,
              resourceVersion: 2,
              payload: { authzRevision: 2 },
              occurredAt: new Date(),
            },
          }),
        ),
      ).rejects.toThrow(/row-level security|violates/i);

      await expect(
        db.outboxEvent.create({
          data: {
            id: uuidv7(),
            organizationId: acme.id,
            type: "organization.permissions.changed",
            version: 1,
            resourceType: "account",
            resourceId: acme.accountId,
            resourceVersion: 2,
            payload: { authzRevision: 2 },
            occurredAt: new Date(),
          },
        }),
      ).rejects.toThrow(/row-level security|violates/i);

      // core_app nie zmienia zdarzeń (UPDATE) ani ich nie usuwa (DELETE); wysyła je tylko funkcja
      // outbox_publish_pending, która nadaje numer w kanale produktów (MonoriseCore#53)
      await expect(
        withOrganization(db, acme.id, (tx) =>
          tx.outboxEvent.update({ where: { id: acmeEventId }, data: { publishedAt: new Date() } }),
        ),
      ).rejects.toThrow(/permission denied/i);
      await db.$queryRaw`SELECT "public"."outbox_publish_pending"(1000)`;
      const published = await withOrganization(db, acme.id, (tx) =>
        tx.outboxEvent.findUniqueOrThrow({ where: { id: acmeEventId } }),
      );
      expect(published.publishedAt).not.toBeNull();
      expect(published.sequence).toEqual(expect.any(BigInt));

      await expect(
        withOrganization(db, acme.id, (tx) => tx.outboxEvent.delete({ where: { id: acmeEventId } })),
      ).rejects.toThrow(/permission denied/i);

      // CHECKi wersji i resourceVersion
      await expect(
        withOrganization(db, acme.id, (tx) =>
          tx.outboxEvent.create({
            data: {
              id: uuidv7(),
              organizationId: acme.id,
              type: "organization.permissions.changed",
              version: 0,
              resourceType: "account",
              resourceId: acme.accountId,
              resourceVersion: 1,
              payload: {},
              occurredAt: new Date(),
            },
          }),
        ),
      ).rejects.toThrow(/outbox_events_version_positive|check constraint|violates/i);

      await expect(
        withOrganization(db, acme.id, (tx) =>
          tx.outboxEvent.create({
            data: {
              id: uuidv7(),
              organizationId: acme.id,
              type: "organization.permissions.changed",
              version: 1,
              resourceType: "account",
              resourceId: acme.accountId,
              resourceVersion: -1,
              payload: {},
              occurredAt: new Date(),
            },
          }),
        ),
      ).rejects.toThrow(/outbox_events_resource_version_nonnegative|check constraint|violates/i);
    } finally {
      await ownerDb.outboxEvent.deleteMany({ where: { id: { in: [acmeEventId, globexEventId, platformEventId] } } });
    }
  });
});

describe("zaproszenia pracowników (RLS, jeden PENDING na konto i wyszukiwanie po skrócie tokenu)", () => {
  it("izoluje zaproszenia między firmami, egzekwuje jeden PENDING na konto i ogranicza invitation_by_token_hash do samych id", async () => {
    const acmeInvitedEmpId = uuidv7();
    const acmeInvitedAccId = uuidv7();
    const acmeInvitedEmail = `jan-${acmeInvitedAccId.slice(-6)}@${acme.domain}`;

    const globexInvitedEmpId = uuidv7();
    const globexInvitedAccId = uuidv7();
    const globexInvitedEmail = `ewa-${globexInvitedAccId.slice(-6)}@${globex.domain}`;

    const acmeInvId = uuidv7();
    const acmeInv2Id = uuidv7();
    const globexInvId = uuidv7();
    const acmeTokenHash = hashToken(`acme-token-${acmeInvId}`);
    const acmeToken2Hash = hashToken(`acme-token-2-${acmeInv2Id}`);
    const globexTokenHash = hashToken(`globex-token-${globexInvId}`);
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

    await db.authUser.create({
      data: { id: acmeInvitedAccId, name: "Jan Acme", email: acmeInvitedEmail, emailVerified: false },
    });
    await db.authUser.create({
      data: { id: globexInvitedAccId, name: "Ewa Globex", email: globexInvitedEmail, emailVerified: false },
    });

    try {
      await withOrganization(db, acme.id, async (tx) => {
        await tx.employee.create({
          data: { id: acmeInvitedEmpId, organizationId: acme.id, firstName: "Jan", lastName: "Acme" },
        });
        await tx.account.create({
          data: {
            id: acmeInvitedAccId,
            organizationId: acme.id,
            employeeId: acmeInvitedEmpId,
            email: acmeInvitedEmail,
            normalizedEmail: acmeInvitedEmail,
            status: "INVITED",
          },
        });
        await tx.invitation.create({
          data: {
            id: acmeInvId,
            organizationId: acme.id,
            accountId: acmeInvitedAccId,
            email: acmeInvitedEmail,
            normalizedEmail: acmeInvitedEmail,
            tokenHash: acmeTokenHash,
            status: "PENDING",
            expiresAt,
            invitedByAccountId: acme.accountId,
          },
        });
      });

      await withOrganization(db, globex.id, async (tx) => {
        await tx.employee.create({
          data: { id: globexInvitedEmpId, organizationId: globex.id, firstName: "Ewa", lastName: "Globex" },
        });
        await tx.account.create({
          data: {
            id: globexInvitedAccId,
            organizationId: globex.id,
            employeeId: globexInvitedEmpId,
            email: globexInvitedEmail,
            normalizedEmail: globexInvitedEmail,
            status: "INVITED",
          },
        });
        await tx.invitation.create({
          data: {
            id: globexInvId,
            organizationId: globex.id,
            accountId: globexInvitedAccId,
            email: globexInvitedEmail,
            normalizedEmail: globexInvitedEmail,
            tokenHash: globexTokenHash,
            status: "PENDING",
            expiresAt,
            invitedByAccountId: globex.accountId,
          },
        });
      });

      // Izolacja odczytu między firmami oraz brak widoczności bez kontekstu firmy
      const acmeInvitations = await withOrganization(db, acme.id, (tx) => tx.invitation.findMany());
      expect(acmeInvitations.map((i) => i.id)).toEqual([acmeInvId]);
      expect(await db.invitation.findMany()).toEqual([]);

      // Firma A nie zmieni zaproszenia firmy B ani nie utworzy zaproszenia dla cudzej firmy lub cudzego konta
      const crossUpdate = await withOrganization(db, acme.id, (tx) =>
        tx.invitation.updateMany({ where: { id: globexInvId }, data: { status: "REVOKED" } }),
      );
      expect(crossUpdate.count).toBe(0);

      await expect(
        withOrganization(db, acme.id, (tx) =>
          tx.invitation.create({
            data: {
              id: uuidv7(),
              organizationId: globex.id,
              accountId: globexInvitedAccId,
              email: globexInvitedEmail,
              normalizedEmail: globexInvitedEmail,
              tokenHash: hashToken("cross-org"),
              status: "PENDING",
              expiresAt,
            },
          }),
        ),
      ).rejects.toThrow(/row-level security|violates/i);

      await expect(
        withOrganization(db, acme.id, (tx) =>
          tx.invitation.create({
            data: {
              id: uuidv7(),
              organizationId: acme.id,
              accountId: globexInvitedAccId,
              email: globexInvitedEmail,
              normalizedEmail: globexInvitedEmail,
              tokenHash: hashToken("cross-account-fk"),
              // REVOKED, żeby indeks „jedno PENDING na konto” nie zadziałał przed kluczem obcym
              status: "REVOKED",
              expiresAt,
            },
          }),
        ),
      ).rejects.toThrow(/invitations_organizationId_accountId_fkey|foreign key|violates/i);

      // core_app nie może usuwać zaproszeń
      await expect(
        withOrganization(db, acme.id, (tx) => tx.invitation.delete({ where: { id: acmeInvId } })),
      ).rejects.toThrow(/permission denied/i);

      // Co najwyżej jedno zaproszenie PENDING na konto (częściowy indeks unikalny)
      await expect(
        withOrganization(db, acme.id, (tx) =>
          tx.invitation.create({
            data: {
              id: uuidv7(),
              organizationId: acme.id,
              accountId: acmeInvitedAccId,
              email: acmeInvitedEmail,
              normalizedEmail: acmeInvitedEmail,
              tokenHash: hashToken("second-pending"),
              status: "PENDING",
              expiresAt,
            },
          }),
        ),
      ).rejects.toThrow(/invitations_accountId_pending_key|unique|duplicate/i);

      // CHECK spójności statusu i acceptedAt
      await expect(
        withOrganization(db, acme.id, (tx) =>
          tx.invitation.update({ where: { id: acmeInvId }, data: { status: "ACCEPTED", acceptedAt: null } }),
        ),
      ).rejects.toThrow(/invitations_status_accepted_consistency|check constraint|violates/i);

      // Po cofnięciu pierwszego zaproszenia można utworzyć nowe PENDING dla tego samego konta
      await withOrganization(db, acme.id, async (tx) => {
        await tx.invitation.update({ where: { id: acmeInvId }, data: { status: "REVOKED" } });
        await tx.invitation.create({
          data: {
            id: acmeInv2Id,
            organizationId: acme.id,
            accountId: acmeInvitedAccId,
            email: acmeInvitedEmail,
            normalizedEmail: acmeInvitedEmail,
            tokenHash: acmeToken2Hash,
            status: "PENDING",
            expiresAt,
          },
        });
      });

      // Funkcja SECURITY DEFINER zwraca wyłącznie (organizationId, invitationId) i null dla nieznanych skrótów
      const found = await invitationByTokenHash(db, globexTokenHash);
      expect(found).toEqual({ organizationId: globex.id, invitationId: globexInvId });
      expect(Object.keys(found!).sort()).toEqual(["invitationId", "organizationId"]);
      expect(await invitationByTokenHash(db, hashToken("nieznany-token"))).toBeNull();
    } finally {
      await withOrganization(db, acme.id, async (tx) => {
        await tx.account.deleteMany({ where: { id: acmeInvitedAccId } });
        await tx.employee.deleteMany({ where: { id: acmeInvitedEmpId } });
      });
      await withOrganization(db, globex.id, async (tx) => {
        await tx.account.deleteMany({ where: { id: globexInvitedAccId } });
        await tx.employee.deleteMany({ where: { id: globexInvitedEmpId } });
      });
      await db.authUser.deleteMany({ where: { id: { in: [acmeInvitedAccId, globexInvitedAccId] } } });
    }
  });
});

describe("klucze powtórzeń Idempotency-Key (RLS i sprzątanie wygasłych)", () => {
  it("izoluje klucze między firmami, egzekwuje CHECKi, blokuje DELETE dla core_app i usuwa wygasłe wiersze porcjami", async () => {
    const acmeActiveId = uuidv7();
    const acmeExpiredId = uuidv7();
    const acmeOtherPrincipalId = uuidv7();
    const globexActiveId = uuidv7();
    const globexExpiredId = uuidv7();
    const sharedKey = `rls-idem-${uuidv7()}`;
    const expiredKey = `rls-expired-${uuidv7()}`;
    const acmePrincipal = `account:${acme.accountId}`;
    const globexPrincipal = `account:${globex.accountId}`;
    const validHash = hashToken("POST\n/core/v1/employees\n{}");
    const futureExpiry = new Date(Date.now() + 24 * 60 * 60 * 1000);
    const pastExpiry = new Date(Date.now() - 60 * 1000);

    // Czyścimy ewentualne wygasłe klucze z innych testów, żeby asercje dla p_limit=1 były deterministyczne
    await cleanupExpiredIdempotencyKeys(db, 10000);

    try {
      await withOrganization(db, acme.id, async (tx) => {
        await tx.idempotencyKey.create({
          data: {
            id: acmeActiveId,
            organizationId: acme.id,
            principal: acmePrincipal,
            key: sharedKey,
            method: "POST",
            path: "/core/v1/employees",
            requestHash: validHash,
            responseStatus: 201,
            responseBody: { data: { id: acmeActiveId }, meta: { requestId: "req_1" }, error: null },
            expiresAt: futureExpiry,
          },
        });
        await tx.idempotencyKey.create({
          data: {
            id: acmeExpiredId,
            organizationId: acme.id,
            principal: acmePrincipal,
            key: expiredKey,
            method: "POST",
            path: "/core/v1/employees",
            requestHash: validHash,
            responseStatus: 201,
            responseBody: { data: { id: acmeExpiredId }, meta: { requestId: "req_2" }, error: null },
            expiresAt: pastExpiry,
          },
        });
        // Inny principal w tej samej firmie może użyć tego samego klucza (np. klient maszynowy OAuth)
        await tx.idempotencyKey.create({
          data: {
            id: acmeOtherPrincipalId,
            organizationId: acme.id,
            principal: "client:timotime-web",
            key: sharedKey,
            method: "POST",
            path: "/core/v1/employees",
            requestHash: validHash,
            responseStatus: 201,
            responseBody: { data: { id: acmeOtherPrincipalId }, meta: { requestId: "req_3" }, error: null },
            expiresAt: futureExpiry,
          },
        });
      });

      await withOrganization(db, globex.id, async (tx) => {
        await tx.idempotencyKey.create({
          data: {
            id: globexActiveId,
            organizationId: globex.id,
            principal: globexPrincipal,
            key: sharedKey,
            method: "POST",
            path: "/core/v1/employees",
            requestHash: validHash,
            responseStatus: 201,
            responseBody: { data: { id: globexActiveId }, meta: { requestId: "req_4" }, error: null },
            expiresAt: futureExpiry,
          },
        });
        await tx.idempotencyKey.create({
          data: {
            id: globexExpiredId,
            organizationId: globex.id,
            principal: globexPrincipal,
            key: expiredKey,
            method: "POST",
            path: "/core/v1/employees",
            requestHash: validHash,
            responseStatus: 201,
            responseBody: { data: { id: globexExpiredId }, meta: { requestId: "req_5" }, error: null },
            expiresAt: pastExpiry,
          },
        });
      });

      // Firma A widzi wyłącznie swoje klucze, nie widzi kluczy firmy B; bez kontekstu firmy wynik jest pusty
      const acmeVisible = await withOrganization(db, acme.id, (tx) => tx.idempotencyKey.findMany());
      expect(acmeVisible.map((row) => row.id).sort()).toEqual(
        [acmeActiveId, acmeExpiredId, acmeOtherPrincipalId].sort(),
      );
      expect(acmeVisible.every((row) => row.organizationId === acme.id)).toBe(true);
      expect(await db.idempotencyKey.findMany()).toEqual([]);

      // Firma A nie może zapisać klucza w firmie B ani zmodyfikować klucza firmy B
      await expect(
        withOrganization(db, acme.id, (tx) =>
          tx.idempotencyKey.create({
            data: {
              id: uuidv7(),
              organizationId: globex.id,
              principal: globexPrincipal,
              key: `cross-${uuidv7()}`,
              method: "POST",
              path: "/core/v1/employees",
              requestHash: validHash,
              responseStatus: 201,
              responseBody: {},
              expiresAt: futureExpiry,
            },
          }),
        ),
      ).rejects.toThrow(/row-level security|violates/i);

      const crossUpdate = await withOrganization(db, acme.id, (tx) =>
        tx.idempotencyKey.updateMany({ where: { id: globexActiveId }, data: { responseStatus: 200 } }),
      );
      expect(crossUpdate.count).toBe(0);

      // core_app nie może usuwać wierszy bezpośrednio (sprząta wyłącznie funkcja SECURITY DEFINER)
      await expect(
        withOrganization(db, acme.id, (tx) => tx.idempotencyKey.delete({ where: { id: acmeActiveId } })),
      ).rejects.toThrow(/permission denied/i);

      // Unikalność (organizationId, principal, key)
      await expect(
        withOrganization(db, acme.id, (tx) =>
          tx.idempotencyKey.create({
            data: {
              id: uuidv7(),
              organizationId: acme.id,
              principal: acmePrincipal,
              key: sharedKey,
              method: "POST",
              path: "/core/v1/employees",
              requestHash: validHash,
              responseStatus: 201,
              responseBody: {},
              expiresAt: futureExpiry,
            },
          }),
        ),
      ).rejects.toThrow(/idempotency_keys_organizationId_principal_key_key|unique|duplicate/i);

      // CHECKi: principal (wymaga prefiksu account: lub client:), requestHash (64 znaki hex), status 2xx i format klucza
      for (const badPrincipal of [acme.accountId, "account:", "client:", "user:123", ""]) {
        await expect(
          withOrganization(db, acme.id, (tx) =>
            tx.idempotencyKey.create({
              data: {
                id: uuidv7(),
                organizationId: acme.id,
                principal: badPrincipal,
                key: `bad-principal-${uuidv7()}`,
                method: "POST",
                path: "/core/v1/employees",
                requestHash: validHash,
                responseStatus: 201,
                responseBody: {},
                expiresAt: futureExpiry,
              },
            }),
          ),
        ).rejects.toThrow(/idempotency_keys_principal_format|check constraint|violates/i);
      }

      for (const badHash of ["not-a-sha256", validHash.toUpperCase(), validHash.slice(0, 63)]) {
        await expect(
          withOrganization(db, acme.id, (tx) =>
            tx.idempotencyKey.create({
              data: {
                id: uuidv7(),
                organizationId: acme.id,
                principal: acmePrincipal,
                key: `bad-hash-${uuidv7()}`,
                method: "POST",
                path: "/core/v1/employees",
                requestHash: badHash,
                responseStatus: 201,
                responseBody: {},
                expiresAt: futureExpiry,
              },
            }),
          ),
        ).rejects.toThrow(/idempotency_keys_request_hash_format|check constraint|violates/i);
      }

      await expect(
        withOrganization(db, acme.id, (tx) =>
          tx.idempotencyKey.create({
            data: {
              id: uuidv7(),
              organizationId: acme.id,
              principal: acmePrincipal,
              key: `bad-status-${uuidv7()}`,
              method: "POST",
              path: "/core/v1/employees",
              requestHash: validHash,
              responseStatus: 409,
              responseBody: {},
              expiresAt: futureExpiry,
            },
          }),
        ),
      ).rejects.toThrow(/idempotency_keys_response_status_2xx|check constraint|violates/i);

      await expect(
        withOrganization(db, acme.id, (tx) =>
          tx.idempotencyKey.create({
            data: {
              id: uuidv7(),
              organizationId: acme.id,
              principal: acmePrincipal,
              key: "niedrukowalny\nklucz",
              method: "POST",
              path: "/core/v1/employees",
              requestHash: validHash,
              responseStatus: 201,
              responseBody: {},
              expiresAt: futureExpiry,
            },
          }),
        ),
      ).rejects.toThrow(/idempotency_keys_key_format|check constraint|violates/i);

      // Walidacja zakresu p_limit (0 i 10001 zgłaszają błąd)
      await expect(cleanupExpiredIdempotencyKeys(db, 0)).rejects.toThrow(/p_limit/i);
      await expect(cleanupExpiredIdempotencyKeys(db, 10001)).rejects.toThrow(/p_limit/i);

      // p_limit = 1 usuwa dokładnie jeden wygasły wiersz na wywołanie i nie rusza ważnych
      expect(await cleanupExpiredIdempotencyKeys(db, 1)).toBe(1);
      expect(await cleanupExpiredIdempotencyKeys(db, 1)).toBe(1);
      expect(await cleanupExpiredIdempotencyKeys(db, 1)).toBe(0);

      const acmeRemaining = await withOrganization(db, acme.id, (tx) => tx.idempotencyKey.findMany());
      expect(acmeRemaining.map((row) => row.id).sort()).toEqual([acmeActiveId, acmeOtherPrincipalId].sort());

      const globexRemaining = await withOrganization(db, globex.id, (tx) => tx.idempotencyKey.findMany());
      expect(globexRemaining.map((row) => row.id)).toEqual([globexActiveId]);
    } finally {
      await withOrganization(ownerDb, acme.id, (tx) =>
        tx.idempotencyKey.deleteMany({ where: { id: { in: [acmeActiveId, acmeExpiredId, acmeOtherPrincipalId] } } }),
      );
      await withOrganization(ownerDb, globex.id, (tx) =>
        tx.idempotencyKey.deleteMany({ where: { id: { in: [globexActiveId, globexExpiredId] } } }),
      );
    }
  });

  it("usunięcie firmy kaskadowo usuwa jej klucze Idempotency-Key", async () => {
    const temp = await createCompany("TempIdem");
    const keyId = uuidv7();
    await withOrganization(db, temp.id, (tx) =>
      tx.idempotencyKey.create({
        data: {
          id: keyId,
          organizationId: temp.id,
          principal: `account:${temp.accountId}`,
          key: `cascade-${uuidv7()}`,
          method: "POST",
          path: "/core/v1/employees",
          requestHash: hashToken("POST\n/core/v1/employees\n{}"),
          responseStatus: 201,
          responseBody: {},
          expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000),
        },
      }),
    );

    expect(await withOrganization(ownerDb, temp.id, (tx) => tx.idempotencyKey.count({ where: { id: keyId } }))).toBe(1);

    await withOrganization(db, temp.id, (tx) => tx.organization.delete({ where: { id: temp.id } }));
    await db.authUser.delete({ where: { id: temp.accountId } });

    expect(await withOrganization(ownerDb, temp.id, (tx) => tx.idempotencyKey.count({ where: { id: keyId } }))).toBe(0);
  });
});

describe("domeny firm (indeksy „wygrywa weryfikacja”, jedna domena główna, RLS i zwalnianie roszczeń)", () => {
  it("egzekwuje SELECT/UPDATE/DELETE RLS, unikalność per firma i co najwyżej jedną domenę główną", async () => {
    const acmeSecondId = uuidv7();
    const acmeThirdId = uuidv7();
    const acmeSecondDomain = `sec-${acmeSecondId.slice(-8)}.acme.test`;
    const acmeThirdDomain = `third-${acmeThirdId.slice(-8)}.acme.test`;

    const globexPrimary = await withOrganization(db, globex.id, (tx) =>
      tx.organizationDomain.findFirstOrThrow({ where: { isPrimary: true } }),
    );

    try {
      // SELECT RLS: bez kontekstu firmy brak wierszy; firma Acme widzi tylko własne domeny, nigdy Globex
      expect(await db.organizationDomain.findMany()).toEqual([]);
      const acmeDomains = await withOrganization(db, acme.id, (tx) => tx.organizationDomain.findMany());
      expect(acmeDomains.length).toBeGreaterThanOrEqual(1);
      expect(acmeDomains.every((d) => d.organizationId === acme.id)).toBe(true);
      expect(acmeDomains.map((d) => d.id)).not.toContain(globexPrimary.id);
      expect(
        await withOrganization(db, acme.id, (tx) =>
          tx.organizationDomain.findUnique({ where: { id: globexPrimary.id } }),
        ),
      ).toBeNull();

      // Próba dodania drugiej domeny głównej w tej samej firmie -> naruszenie częściowego indeksu unikalnego
      await expect(
        withOrganization(db, acme.id, (tx) =>
          tx.organizationDomain.create({
            data: {
              id: uuidv7(),
              organizationId: acme.id,
              domain: `dup-primary-${uuidv7().slice(-8)}.acme.test`,
              verificationMethod: "DNS_TXT",
              isPrimary: true,
            },
          }),
        ),
      ).rejects.toThrow(/organization_domains_organizationId_primary_key|unique|duplicate/i);

      // Wiele domen niegłównych (isPrimary = false) w tej samej firmie działa bez konfliktu
      await withOrganization(db, acme.id, async (tx) => {
        await tx.organizationDomain.create({
          data: {
            id: acmeSecondId,
            organizationId: acme.id,
            domain: acmeSecondDomain,
            status: "VERIFIED",
            verificationMethod: "DNS_TXT",
            verifiedAt: new Date(),
            isPrimary: false,
          },
        });
        await tx.organizationDomain.create({
          data: {
            id: acmeThirdId,
            organizationId: acme.id,
            domain: acmeThirdDomain,
            status: "PENDING",
            verificationMethod: "DNS_TXT",
            isPrimary: false,
          },
        });
      });

      // Duplikat tej samej domeny (bez względu na wielkość liter) w obrębie jednej firmy -> odrzucony
      await expect(
        withOrganization(db, acme.id, (tx) =>
          tx.organizationDomain.create({
            data: {
              id: uuidv7(),
              organizationId: acme.id,
              domain: acmeThirdDomain.toUpperCase(),
              status: "PENDING",
              verificationMethod: "DNS_TXT",
              isPrimary: false,
            },
          }),
        ),
      ).rejects.toThrow(/organization_domains_organizationId_domain_key|unique|duplicate/i);

      // Próba ustawienia isPrimary = true bez wcześniejszego zdjęcia flagi z obecnej głównej -> błąd unikalności
      await expect(
        withOrganization(db, acme.id, (tx) =>
          tx.organizationDomain.update({
            where: { id: acmeSecondId },
            data: { isPrimary: true },
          }),
        ),
      ).rejects.toThrow(/organization_domains_organizationId_primary_key|unique|duplicate/i);

      // RLS: firma Acme nie może zmienić ani usunąć domeny firmy Globex (0 wierszy), ani dopisać domeny dla Globex
      const crossUpdate = await withOrganization(db, acme.id, (tx) =>
        tx.organizationDomain.updateMany({ where: { id: globexPrimary.id }, data: { status: "REVOKED" } }),
      );
      expect(crossUpdate.count).toBe(0);

      const crossDelete = await withOrganization(db, acme.id, (tx) =>
        tx.organizationDomain.deleteMany({ where: { id: globexPrimary.id } }),
      );
      expect(crossDelete.count).toBe(0);

      await expect(
        withOrganization(db, acme.id, (tx) =>
          tx.organizationDomain.create({
            data: {
              id: uuidv7(),
              organizationId: globex.id,
              domain: `cross-${uuidv7().slice(-8)}.globex.test`,
              verificationMethod: "DNS_TXT",
              isPrimary: false,
            },
          }),
        ),
      ).rejects.toThrow(/row-level security|violates/i);

      // Domena Globex pozostaje nienaruszona
      const stillGlobex = await withOrganization(db, globex.id, (tx) =>
        tx.organizationDomain.findUniqueOrThrow({ where: { id: globexPrimary.id } }),
      );
      expect(stillGlobex.status).toBe(globexPrimary.status);
    } finally {
      await withOrganization(db, acme.id, (tx) =>
        tx.organizationDomain.deleteMany({ where: { id: { in: [acmeSecondId, acmeThirdId] } } }),
      );
    }
  });

  it("wspiera zasadę „wygrywa weryfikacja”, globalną unikalność wyłącznie VERIFIED oraz bezpieczne releaseCompetingDomainClaims", async () => {
    const sharedDomain = `shared-${uuidv7().slice(-8)}.claim.test`;
    const acmeClaimId = uuidv7();
    const globexClaimId = uuidv7();
    const pendingOrgId = uuidv7();
    const pendingPrimaryId = uuidv7();
    const pendingEmpId = uuidv7();
    const pendingAccId = uuidv7();
    const pendingEmail = `signup@${sharedDomain}`;

    await db.authUser.create({
      data: { id: pendingAccId, name: "Anna Signup", email: pendingEmail, emailVerified: true },
    });

    try {
      // Trzy firmy równocześnie zgłaszają niezweryfikowane roszczenie do tej samej domeny:
      // Acme (niegłówna PENDING), Globex (niegłówna FAILED) oraz PendingSignup (główna PENDING — rejestracja w toku)
      await withOrganization(db, acme.id, (tx) =>
        tx.organizationDomain.create({
          data: {
            id: acmeClaimId,
            organizationId: acme.id,
            domain: sharedDomain,
            status: "PENDING",
            verificationMethod: "DNS_TXT",
            isPrimary: false,
          },
        }),
      );
      await withOrganization(db, globex.id, (tx) =>
        tx.organizationDomain.create({
          data: {
            id: globexClaimId,
            organizationId: globex.id,
            domain: sharedDomain.toUpperCase(),
            status: "FAILED",
            verificationMethod: "DNS_TXT",
            isPrimary: false,
          },
        }),
      );
      await withOrganization(db, pendingOrgId, async (tx) => {
        await tx.organization.create({
          data: { id: pendingOrgId, name: "PendingSignup", createdVia: "SELF_SIGNUP", status: "PENDING_VERIFICATION" },
        });
        await tx.organizationDomain.create({
          data: {
            id: pendingPrimaryId,
            organizationId: pendingOrgId,
            domain: sharedDomain,
            status: "PENDING",
            verificationMethod: "DNS_TXT",
            isPrimary: true,
          },
        });
        await tx.employee.create({
          data: { id: pendingEmpId, organizationId: pendingOrgId, firstName: "Anna", lastName: "Signup" },
        });
        await tx.account.create({
          data: {
            id: pendingAccId,
            organizationId: pendingOrgId,
            employeeId: pendingEmpId,
            email: pendingEmail,
            normalizedEmail: pendingEmail,
            status: "ACTIVE",
          },
        });
        await tx.organization.update({ where: { id: pendingOrgId }, data: { ownerAccountId: pendingAccId } });
      });

      // Dopóki nikt nie zweryfikował domeny, domain_owner zwraca null
      expect(await domainOwner(db, sharedDomain.toUpperCase())).toBeNull();

      // releaseCompetingDomainClaims wymaga kontekstu firmy oraz posiadania zweryfikowanego wiersza
      await expect(releaseCompetingDomainClaims(db, sharedDomain)).rejects.toThrow(/Brak kontekstu firmy/i);
      await expect(
        withOrganization(db, acme.id, (tx) => releaseCompetingDomainClaims(tx, sharedDomain)),
      ).rejects.toThrow(/nie ma zweryfikowanej domeny/i);

      // Acme weryfikuje domenę -> domain_owner zwraca Acme (VERIFIED)
      await withOrganization(db, acme.id, (tx) =>
        tx.organizationDomain.update({
          where: { id: acmeClaimId },
          data: { status: "VERIFIED", verifiedAt: new Date() },
        }),
      );
      expect(await domainOwner(db, sharedDomain.toUpperCase())).toEqual({
        organizationId: acme.id,
        status: "VERIFIED",
      });

      // Częściowy indeks unikalny blokuje ustawienie VERIFIED dla innej firmy na tej samej domenie
      await expect(
        withOrganization(db, globex.id, (tx) =>
          tx.organizationDomain.update({
            where: { id: globexClaimId },
            data: { status: "VERIFIED", verifiedAt: new Date() },
          }),
        ),
      ).rejects.toThrow(/organization_domains_domain_verified_key|unique|duplicate/i);

      // releaseCompetingDomainClaims usuwa wyłącznie niegłówne, niezweryfikowane roszczenia innych firm (Globex),
      // ale zostawia główną niezweryfikowaną domenę rejestracji w toku (PendingSignup) oraz wiersz Acme
      const removedCount = await withOrganization(db, acme.id, (tx) =>
        releaseCompetingDomainClaims(tx, sharedDomain.toUpperCase()),
      );
      expect(removedCount).toBe(1);

      expect(
        await withOrganization(db, globex.id, (tx) =>
          tx.organizationDomain.findUnique({ where: { id: globexClaimId } }),
        ),
      ).toBeNull();

      const preservedPendingPrimary = await withOrganization(db, pendingOrgId, (tx) =>
        tx.organizationDomain.findUnique({ where: { id: pendingPrimaryId } }),
      );
      expect(preservedPendingPrimary?.status).toBe("PENDING");
      expect(preservedPendingPrimary?.isPrimary).toBe(true);

      // Próba późniejszej weryfikacji przez PendingSignup również zostaje zablokowana indeksem VERIFIED
      await expect(
        withOrganization(db, pendingOrgId, (tx) =>
          tx.organizationDomain.update({
            where: { id: pendingPrimaryId },
            data: { status: "VERIFIED", verifiedAt: new Date() },
          }),
        ),
      ).rejects.toThrow(/organization_domains_domain_verified_key|unique|duplicate/i);
    } finally {
      await withOrganization(db, acme.id, (tx) => tx.organizationDomain.deleteMany({ where: { id: acmeClaimId } }));
      await withOrganization(db, globex.id, (tx) => tx.organizationDomain.deleteMany({ where: { id: globexClaimId } }));
      await withOrganization(db, pendingOrgId, (tx) => tx.organization.deleteMany({ where: { id: pendingOrgId } }));
      await db.authUser.deleteMany({ where: { id: pendingAccId } });
    }
  });
});

describe("kolejka poczty mail_outbox (RLS, klucze złożone, CHECKi i funkcje SECURITY DEFINER)", () => {
  it("izoluje zadania firm przez RLS, wymusza złożony FK do invitations, blokuje DELETE i obsługuje claim/cleanup", async () => {
    const acmeEmpId = uuidv7();
    const acmeAccId = uuidv7();
    const acmeInvId = uuidv7();
    const acmeEmail = `outbox-acme-${acmeAccId.slice(-6)}@${acme.domain}`;
    const globexEmpId = uuidv7();
    const globexAccId = uuidv7();
    const globexInvId = uuidv7();
    const globexEmail = `outbox-globex-${globexAccId.slice(-6)}@${globex.domain}`;
    const acmeJobId = uuidv7();
    const globexJobId = uuidv7();
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

    await db.authUser.create({ data: { id: acmeAccId, name: "Jan Acme", email: acmeEmail, emailVerified: false } });
    await db.authUser.create({
      data: { id: globexAccId, name: "Jan Globex", email: globexEmail, emailVerified: false },
    });

    try {
      await withOrganization(db, acme.id, async (tx) => {
        await tx.employee.create({
          data: { id: acmeEmpId, organizationId: acme.id, firstName: "Jan", lastName: "Acme" },
        });
        await tx.account.create({
          data: {
            id: acmeAccId,
            organizationId: acme.id,
            employeeId: acmeEmpId,
            email: acmeEmail,
            normalizedEmail: acmeEmail,
            status: "INVITED",
          },
        });
        await tx.invitation.create({
          data: {
            id: acmeInvId,
            organizationId: acme.id,
            accountId: acmeAccId,
            email: acmeEmail,
            normalizedEmail: acmeEmail,
            tokenHash: hashToken(`rls-mail-acme-${acmeInvId}`),
            status: "PENDING",
            expiresAt,
          },
        });
        await tx.mailOutbox.create({
          data: {
            id: acmeJobId,
            organizationId: acme.id,
            kind: "INVITATION",
            invitationId: acmeInvId,
            status: "PENDING",
          },
        });
      });

      await withOrganization(db, globex.id, async (tx) => {
        await tx.employee.create({
          data: { id: globexEmpId, organizationId: globex.id, firstName: "Jan", lastName: "Globex" },
        });
        await tx.account.create({
          data: {
            id: globexAccId,
            organizationId: globex.id,
            employeeId: globexEmpId,
            email: globexEmail,
            normalizedEmail: globexEmail,
            status: "INVITED",
          },
        });
        await tx.invitation.create({
          data: {
            id: globexInvId,
            organizationId: globex.id,
            accountId: globexAccId,
            email: globexEmail,
            normalizedEmail: globexEmail,
            tokenHash: hashToken(`rls-mail-globex-${globexInvId}`),
            status: "PENDING",
            expiresAt,
          },
        });
        await tx.mailOutbox.create({
          data: {
            id: globexJobId,
            organizationId: globex.id,
            kind: "INVITATION",
            invitationId: globexInvId,
            status: "PENDING",
          },
        });
      });

      // Izolacja RLS i brak widoczności bez kontekstu firmy
      const acmeVisible = await withOrganization(db, acme.id, (tx) => tx.mailOutbox.findMany());
      expect(acmeVisible.map((row) => row.id)).toEqual([acmeJobId]);
      expect(await db.mailOutbox.findMany()).toEqual([]);

      // Złożony klucz obcy odrzuca zaproszenie z innej firmy
      await expect(
        withOrganization(db, acme.id, (tx) =>
          tx.mailOutbox.create({
            data: {
              id: uuidv7(),
              organizationId: acme.id,
              kind: "INVITATION",
              invitationId: globexInvId,
              status: "PENDING",
            },
          }),
        ),
      ).rejects.toThrow(/mail_outbox_organizationId_invitationId_fkey|foreign key|violates/i);

      // CHECKi spójności i ograniczenie długości lastError
      await expect(
        withOrganization(db, acme.id, (tx) =>
          tx.mailOutbox.update({ where: { id: acmeJobId }, data: { status: "SENT", sentAt: null } }),
        ),
      ).rejects.toThrow(/mail_outbox_status_sent_consistency|check constraint|violates/i);

      await expect(
        withOrganization(db, acme.id, (tx) =>
          tx.mailOutbox.update({ where: { id: acmeJobId }, data: { lastError: "x".repeat(501) } }),
        ),
      ).rejects.toThrow(/mail_outbox_last_error_length|check constraint|violates/i);

      // core_app nie może bezpośrednio usuwać wierszy
      await expect(
        withOrganization(db, acme.id, (tx) => tx.mailOutbox.delete({ where: { id: acmeJobId } })),
      ).rejects.toThrow(/permission denied/i);

      // PUBLIC nie ma EXECUTE na funkcjach SECURITY DEFINER, a core_app ma
      const [privs] = await db.$queryRaw<
        { claim_public: boolean; cleanup_public: boolean; claim_app: boolean; cleanup_app: boolean }[]
      >`
        SELECT
          has_function_privilege('public', 'public.mail_outbox_claim(integer, integer)', 'EXECUTE') AS claim_public,
          has_function_privilege('public', 'public.mail_outbox_cleanup(integer)', 'EXECUTE') AS cleanup_public,
          has_function_privilege('core_app', 'public.mail_outbox_claim(integer, integer)', 'EXECUTE') AS claim_app,
          has_function_privilege('core_app', 'public.mail_outbox_cleanup(integer)', 'EXECUTE') AS cleanup_app`;
      expect(privs).toEqual({
        claim_public: false,
        cleanup_public: false,
        claim_app: true,
        cleanup_app: true,
      });

      // Walidacja zakresów p_limit i p_lease_ms w funkcjach SECURITY DEFINER
      await expect(claimMailOutboxJobs(db, { limit: 0, leaseMs: 60_000 })).rejects.toThrow(/p_limit/i);
      await expect(claimMailOutboxJobs(db, { limit: 1001, leaseMs: 60_000 })).rejects.toThrow(/p_limit/i);
      await expect(claimMailOutboxJobs(db, { limit: 10, leaseMs: 0 })).rejects.toThrow(/p_lease_ms/i);
      await expect(claimMailOutboxJobs(db, { limit: 10, leaseMs: 3_600_001 })).rejects.toThrow(/p_lease_ms/i);
      await expect(cleanupMailOutbox(db, 0)).rejects.toThrow(/p_limit/i);
      await expect(cleanupMailOutbox(db, 10001)).rejects.toThrow(/p_limit/i);

      // Funkcja SECURITY DEFINER mail_outbox_claim rezerwuje gotowe zadania ponad granicą firm według now() bazy
      const claimed = await claimMailOutboxJobs(db, { limit: 10, leaseMs: 90_000 });
      expect(claimed.map((row) => row.id).sort()).toEqual([acmeJobId, globexJobId].sort());
      expect(
        claimed.every(
          (row) =>
            row.attempts === 1 && row.kind === "INVITATION" && row.invitationId !== null && row.notificationId === null,
        ),
      ).toBe(true);

      // Oznaczamy jedno zadanie jako SENT sprzed 31 dni (przez zegar bazy) i sprzątamy przez mail_outbox_cleanup
      await withOrganization(
        ownerDb,
        acme.id,
        (tx) =>
          tx.$executeRaw`
          UPDATE "public"."mail_outbox"
          SET "status" = 'SENT',
              "sentAt" = now() - interval '31 days',
              "lockedUntil" = NULL,
              "createdAt" = now() - interval '31 days',
              "updatedAt" = now() - interval '31 days'
          WHERE "id" = ${acmeJobId}::uuid`,
      );
      expect(await cleanupMailOutbox(db, 100)).toBeGreaterThanOrEqual(1);
      expect(
        await withOrganization(db, acme.id, (tx) => tx.mailOutbox.findUnique({ where: { id: acmeJobId } })),
      ).toBeNull();
      expect(
        await withOrganization(db, globex.id, (tx) => tx.mailOutbox.findUnique({ where: { id: globexJobId } })),
      ).not.toBeNull();
    } finally {
      await withOrganization(db, acme.id, async (tx) => {
        await tx.account.deleteMany({ where: { id: acmeAccId } });
        await tx.employee.deleteMany({ where: { id: acmeEmpId } });
      });
      await withOrganization(db, globex.id, async (tx) => {
        await tx.account.deleteMany({ where: { id: globexAccId } });
        await tx.employee.deleteMany({ where: { id: globexEmpId } });
      });
      await db.authUser.deleteMany({ where: { id: { in: [acmeAccId, globexAccId] } } });
    }
  });
});

describe("powiadomienia, preferencje i mail_outbox NOTIFICATION (MonoriseCore#86, RLS, FK złożony, CHECKi)", () => {
  it("izoluje notifications i notification_preferences przez RLS, wymusza klucze złożone i CHECKi spójności", async () => {
    const acmeNotifId = uuidv7();
    const globexNotifId = uuidv7();
    const acmeOutboxId = uuidv7();
    const acmePrefId = uuidv7();
    const globexPrefId = uuidv7();

    try {
      await withOrganization(db, acme.id, async (tx) => {
        await tx.notification.create({
          data: {
            id: acmeNotifId,
            organizationId: acme.id,
            product: "timotime",
            category: "timotime.reminders",
            recipientAccountId: acme.accountId,
            title: "Przypomnienie Acme",
            body: "Uzupełnij czas pracy za piątek.",
            actionUrl: "http://timo-time.localhost:3300/app",
            status: "QUEUED",
          },
        });
        await tx.mailOutbox.create({
          data: {
            id: acmeOutboxId,
            organizationId: acme.id,
            kind: "NOTIFICATION",
            notificationId: acmeNotifId,
            status: "PENDING",
          },
        });
        await tx.notificationPreference.create({
          data: {
            id: acmePrefId,
            organizationId: acme.id,
            accountId: acme.accountId,
            category: "timotime.reminders",
            channel: "EMAIL",
            enabled: false,
          },
        });
      });

      await withOrganization(db, globex.id, async (tx) => {
        await tx.notification.create({
          data: {
            id: globexNotifId,
            organizationId: globex.id,
            product: "kivotasks",
            category: "kivotasks.assignments",
            recipientAccountId: globex.accountId,
            title: "Zadanie Globex",
            body: "Przypisano Ci zadanie KT-1.",
            status: "QUEUED",
          },
        });
        await tx.notificationPreference.create({
          data: {
            id: globexPrefId,
            organizationId: globex.id,
            accountId: globex.accountId,
            category: "kivotasks.assignments",
            channel: "EMAIL",
            enabled: false,
          },
        });
      });

      // 1. RLS na notifications: firma widzi wyłącznie własne wiersze, bez kontekstu pusto, brak zapisu/zmiany dla innej firmy
      const acmeNotifications = await withOrganization(db, acme.id, (tx) => tx.notification.findMany());
      expect(acmeNotifications.map((n) => n.id)).toEqual([acmeNotifId]);
      expect(await db.notification.findMany()).toEqual([]);

      const crossNotifUpdate = await withOrganization(db, acme.id, (tx) =>
        tx.notification.updateMany({ where: { id: globexNotifId }, data: { status: "FAILED" } }),
      );
      expect(crossNotifUpdate.count).toBe(0);

      await expect(
        withOrganization(db, acme.id, (tx) =>
          tx.notification.create({
            data: {
              id: uuidv7(),
              organizationId: globex.id,
              product: "timotime",
              category: "timotime.reminders",
              recipientAccountId: globex.accountId,
              title: "Intruz",
              body: "Treść",
              status: "QUEUED",
            },
          }),
        ),
      ).rejects.toThrow(/row-level security|violates/i);

      // core_app nie może usuwać wierszy notifications
      await expect(
        withOrganization(db, acme.id, (tx) => tx.notification.delete({ where: { id: acmeNotifId } })),
      ).rejects.toThrow(/permission denied/i);

      // CHECKi spójności i długości na notifications
      await expect(
        withOrganization(db, acme.id, (tx) =>
          tx.notification.create({
            data: {
              id: uuidv7(),
              organizationId: acme.id,
              product: "timotime",
              category: "timotime.reminders",
              recipientAccountId: acme.accountId,
              title: "x".repeat(201),
              body: "Treść",
              status: "QUEUED",
            },
          }),
        ),
      ).rejects.toThrow(/notifications_title_length|check constraint|violates/i);

      await expect(
        withOrganization(db, acme.id, (tx) =>
          tx.notification.create({
            data: {
              id: uuidv7(),
              organizationId: acme.id,
              product: "timotime",
              category: "timotime.reminders",
              recipientAccountId: acme.accountId,
              title: "Tytuł",
              body: "y".repeat(4001),
              status: "QUEUED",
            },
          }),
        ),
      ).rejects.toThrow(/notifications_body_length|check constraint|violates/i);

      await expect(
        withOrganization(db, acme.id, (tx) =>
          tx.notification.update({ where: { id: acmeNotifId }, data: { status: "SENT", sentAt: null } }),
        ),
      ).rejects.toThrow(/notifications_status_sent_consistency|check constraint|violates/i);

      await expect(
        withOrganization(db, acme.id, (tx) =>
          tx.notification.update({ where: { id: acmeNotifId }, data: { status: "SKIPPED", skipReason: null } }),
        ),
      ).rejects.toThrow(/notifications_status_skip_reason_consistency|check constraint|violates/i);

      // 2. RLS i ograniczenia na notification_preferences
      const acmePrefs = await withOrganization(db, acme.id, (tx) => tx.notificationPreference.findMany());
      expect(acmePrefs.map((p) => p.id)).toEqual([acmePrefId]);
      expect(await db.notificationPreference.findMany()).toEqual([]);

      const crossPrefUpdate = await withOrganization(db, acme.id, (tx) =>
        tx.notificationPreference.updateMany({ where: { id: globexPrefId }, data: { enabled: true } }),
      );
      expect(crossPrefUpdate.count).toBe(0);

      const crossPrefDelete = await withOrganization(db, acme.id, (tx) =>
        tx.notificationPreference.deleteMany({ where: { id: globexPrefId } }),
      );
      expect(crossPrefDelete.count).toBe(0);

      await expect(
        withOrganization(db, acme.id, (tx) =>
          tx.notificationPreference.create({
            data: {
              id: uuidv7(),
              organizationId: globex.id,
              accountId: globex.accountId,
              category: "timotime.reminders",
              channel: "EMAIL",
              enabled: false,
            },
          }),
        ),
      ).rejects.toThrow(/row-level security|violates/i);

      // Złożony klucz obcy odrzuca konto z innej firmy
      await expect(
        withOrganization(db, acme.id, (tx) =>
          tx.notificationPreference.create({
            data: {
              id: uuidv7(),
              organizationId: acme.id,
              accountId: globex.accountId,
              category: "timotime.reminders",
              channel: "EMAIL",
              enabled: false,
            },
          }),
        ),
      ).rejects.toThrow(/notification_preferences_organizationId_accountId_fkey|foreign key|violates/i);

      // Unikalność (organizationId, accountId, category, channel), ale inny kanał (PUSH) jest dopuszczalny
      await expect(
        withOrganization(db, acme.id, (tx) =>
          tx.notificationPreference.create({
            data: {
              id: uuidv7(),
              organizationId: acme.id,
              accountId: acme.accountId,
              category: "timotime.reminders",
              channel: "EMAIL",
              enabled: true,
            },
          }),
        ),
      ).rejects.toThrow(/notification_preferences_org_account_category_channel_key|unique|duplicate/i);

      const pushPrefId = uuidv7();
      await withOrganization(db, acme.id, (tx) =>
        tx.notificationPreference.create({
          data: {
            id: pushPrefId,
            organizationId: acme.id,
            accountId: acme.accountId,
            category: "timotime.reminders",
            channel: "PUSH",
            enabled: false,
          },
        }),
      );
      await withOrganization(db, acme.id, (tx) => tx.notificationPreference.delete({ where: { id: pushPrefId } }));

      // 3. Złożony FK mail_outbox(organizationId, notificationId) -> notifications(organizationId, id) odrzuca inną firmę
      await expect(
        withOrganization(db, acme.id, (tx) =>
          tx.mailOutbox.create({
            data: {
              id: uuidv7(),
              organizationId: acme.id,
              kind: "NOTIFICATION",
              notificationId: globexNotifId,
              status: "PENDING",
            },
          }),
        ),
      ).rejects.toThrow(/mail_outbox_organizationId_notificationId_fkey|foreign key|violates/i);

      // 4. CHECK mail_outbox_kind_reference_consistency pilnuje dokładnie jednej referencji zgodnej z kind
      await expect(
        withOrganization(db, acme.id, (tx) =>
          tx.mailOutbox.create({
            data: {
              id: uuidv7(),
              organizationId: acme.id,
              kind: "NOTIFICATION",
              invitationId: null,
              notificationId: null,
              status: "PENDING",
            },
          }),
        ),
      ).rejects.toThrow(/mail_outbox_kind_reference_consistency|check constraint|violates/i);

      await expect(
        withOrganization(db, acme.id, (tx) =>
          tx.mailOutbox.create({
            data: {
              id: uuidv7(),
              organizationId: acme.id,
              kind: "INVITATION",
              invitationId: null,
              notificationId: acmeNotifId,
              status: "PENDING",
            },
          }),
        ),
      ).rejects.toThrow(/mail_outbox_kind_reference_consistency|check constraint|violates/i);

      // 5. Funkcja mail_outbox_claim zwraca notificationId dla zadań NOTIFICATION i zachowuje uprawnienia core_app
      const claimed = await claimMailOutboxJobs(db, { limit: 10, leaseMs: 90_000 });
      const claimedNotif = claimed.find((row) => row.id === acmeOutboxId);
      expect(claimedNotif).toEqual({
        id: acmeOutboxId,
        organizationId: acme.id,
        kind: "NOTIFICATION",
        invitationId: null,
        notificationId: acmeNotifId,
        attempts: 1,
      });
    } finally {
      await withOrganization(ownerDb, acme.id, async (tx) => {
        await tx.mailOutbox.deleteMany({ where: { id: acmeOutboxId } });
        await tx.notification.deleteMany({ where: { id: acmeNotifId } });
        await tx.notificationPreference.deleteMany({ where: { id: acmePrefId } });
      });
      await withOrganization(ownerDb, globex.id, async (tx) => {
        await tx.notification.deleteMany({ where: { id: globexNotifId } });
        await tx.notificationPreference.deleteMany({ where: { id: globexPrefId } });
      });
    }
  });
});
