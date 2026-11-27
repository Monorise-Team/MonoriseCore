import { CORE_PERMISSIONS } from "@core/contracts";
import { createDb, uuidv7, withOrganization } from "@core/db";
import { createLocalJWKSet, exportJWK, generateKeyPair, SignJWT, type CryptoKey } from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { registerCorePermissions } from "../src/permissions-registry.js";
import { buildServer } from "../src/server.js";
import { createMachineTokenVerifier, createTokenVerifier } from "../src/tokens.js";

const ISSUER = "http://localhost:3100";
const AUDIENCE = "http://localhost:3200";

const db = createDb(
  process.env.CORE_TEST_APP_DATABASE_URL ?? "postgresql://core_app:core_app@localhost:5433/monorise_core_test",
);

interface Identity {
  organizationId: string;
  employeeId: string;
  accountId: string;
  email: string;
}

interface Company extends Identity {
  id: string;
  domain: string;
  pendingDomain: string;
  extraAccountIds: string[];
}

let signingKey: CryptoKey;
let app: ReturnType<typeof buildServer>;
let acme: Company;
let globex: Company;
let acmeRegular: Identity;
let acmeOrgHr: Identity;
let acmeUnitHr: Identity;
let acmeUnitId: string;

async function createCompany(name: string): Promise<Company> {
  const id = uuidv7();
  const domain = `${id.slice(-8)}-${name.toLowerCase()}.test`;
  const pendingDomain = `pending-${domain}`;
  const employeeId = uuidv7();
  const accountId = uuidv7();
  const email = `anna@${domain}`;

  await db.authUser.create({ data: { id: accountId, name: `Anna ${name}`, email, emailVerified: true } });
  await withOrganization(db, id, async (tx) => {
    await tx.organization.create({ data: { id, name, createdVia: "SELF_SIGNUP", status: "ACTIVE" } });
    await tx.organizationDomain.create({
      data: {
        id: uuidv7(),
        organizationId: id,
        domain,
        status: "VERIFIED",
        verificationMethod: "DNS_TXT",
        verifiedAt: new Date("2026-11-20T00:00:00.000Z"),
        isPrimary: true,
      },
    });
    await tx.organizationDomain.create({
      data: {
        id: uuidv7(),
        organizationId: id,
        domain: pendingDomain,
        status: "PENDING",
        verificationMethod: "DNS_TXT",
        isPrimary: false,
      },
    });
    await tx.employee.create({
      data: { id: employeeId, organizationId: id, firstName: "Anna", lastName: name, workEmail: email },
    });
    await tx.account.create({
      data: { id: accountId, organizationId: id, employeeId, email, normalizedEmail: email, status: "ACTIVE" },
    });
    await tx.organization.update({ where: { id }, data: { ownerAccountId: accountId } });
  });

  return { id, domain, pendingDomain, organizationId: id, employeeId, accountId, email, extraAccountIds: [] };
}

async function createMember(
  company: Company,
  firstName: string,
  lastName: string,
  options?: { workEmail?: string | null; status?: "ACTIVE" | "INVITED" | "DEACTIVATED" },
): Promise<Identity> {
  const employeeId = uuidv7();
  const accountId = uuidv7();
  const email = `${firstName.toLowerCase()}-${accountId.slice(-6)}@${company.domain}`;
  const workEmail = options?.workEmail !== undefined ? options.workEmail : email;
  const accountStatus = options?.status ?? "ACTIVE";

  await db.authUser.create({
    data: { id: accountId, name: `${firstName} ${lastName}`, email, emailVerified: accountStatus === "ACTIVE" },
  });
  await withOrganization(db, company.id, async (tx) => {
    await tx.employee.create({
      data: { id: employeeId, organizationId: company.id, firstName, lastName, workEmail },
    });
    await tx.account.create({
      data: {
        id: accountId,
        organizationId: company.id,
        employeeId,
        email,
        normalizedEmail: email,
        status: accountStatus,
        ...(accountStatus === "DEACTIVATED" ? { deactivatedAt: new Date() } : {}),
      },
    });
  });
  company.extraAccountIds.push(accountId);
  return { organizationId: company.id, employeeId, accountId, email };
}

function token(identity: Identity) {
  return new SignJWT({
    org_id: identity.organizationId,
    employee_id: identity.employeeId,
    authz_rev: 0,
    amr: ["pwd"],
  })
    .setProtectedHeader({ alg: "EdDSA" })
    .setIssuer(ISSUER)
    .setAudience(AUDIENCE)
    .setSubject(identity.accountId)
    .setIssuedAt()
    .setExpirationTime("5m")
    .sign(signingKey);
}

function request(method: "GET" | "POST" | "PATCH", url: string, bearer?: string, payload?: Record<string, unknown>) {
  return app.inject({
    method,
    url,
    headers: bearer ? { authorization: `Bearer ${bearer}` } : {},
    ...(payload !== undefined ? { payload } : {}),
  });
}

beforeAll(async () => {
  process.env.CORE_SMTP_URL = "memory";
  await registerCorePermissions(db);

  const pair = await generateKeyPair("EdDSA", { crv: "Ed25519" });
  signingKey = pair.privateKey;
  const jwk = { ...(await exportJWK(pair.publicKey)), alg: "EdDSA", kid: "test-emp-edit" };
  const tokenOptions = { keys: createLocalJWKSet({ keys: [jwk] }), issuer: ISSUER, audience: AUDIENCE };

  app = buildServer({
    db,
    verifyToken: createTokenVerifier(tokenOptions),
    verifyMachineToken: createMachineTokenVerifier(tokenOptions),
  });

  acme = await createCompany("Acme");
  globex = await createCompany("Globex");
  acmeRegular = await createMember(acme, "Piotr", "Zwykly");
  acmeOrgHr = await createMember(acme, "Marta", "Kadry");
  acmeUnitHr = await createMember(acme, "Tomasz", "Oddzial");

  acmeUnitId = uuidv7();
  const hrRoleId = uuidv7();
  const empManagePerm = await db.permission.findUniqueOrThrow({
    where: { key: CORE_PERMISSIONS.keys["employees.manage"] },
    select: { id: true },
  });

  await withOrganization(db, acme.id, async (tx) => {
    await tx.organizationUnit.create({
      data: { id: acmeUnitId, organizationId: acme.id, name: "Kraków", type: "BRANCH" },
    });
    await tx.role.create({
      data: { id: hrRoleId, organizationId: acme.id, productId: null, name: "Kadry" },
    });
    await tx.rolePermission.create({
      data: { roleId: hrRoleId, permissionId: empManagePerm.id },
    });
    await tx.roleAssignment.create({
      data: {
        id: uuidv7(),
        organizationId: acme.id,
        accountId: acmeOrgHr.accountId,
        roleId: hrRoleId,
        scopeType: "ORGANIZATION",
        grantedByAccountId: acme.accountId,
      },
    });
    await tx.roleAssignment.create({
      data: {
        id: uuidv7(),
        organizationId: acme.id,
        accountId: acmeUnitHr.accountId,
        roleId: hrRoleId,
        scopeType: "UNIT",
        scopeId: acmeUnitId,
        grantedByAccountId: acme.accountId,
      },
    });
  });
});

afterAll(async () => {
  await app?.close();
  for (const company of [acme, globex]) {
    if (!company) continue;
    const allAccounts = await withOrganization(db, company.id, (tx) => tx.account.findMany({ select: { id: true } }));
    const ids = [...new Set([company.accountId, ...company.extraAccountIds, ...allAccounts.map((a) => a.id)])];
    await withOrganization(db, company.id, async (tx) => {
      await tx.roleAssignment.deleteMany({});
      await tx.organization.delete({ where: { id: company.id } });
    });
    await db.authUser.deleteMany({ where: { id: { in: ids } } });
  }
  await db.$disconnect();
});

describe("Edycja danych pracownika (PATCH /core/v1/employees/{employeeId}) i walidacja workEmail w POST", () => {
  it("aktualizuje firstName, lastName i jobTitle pracownika z kontem, synchronizuje auth.users.name, odbija w GET /me i /employees oraz nie zapisuje PII w audycie", async () => {
    const ownerToken = await token(acme);
    const jan = await createMember(acme, "Jan", "Kowlski");
    const janToken = await token(jan);

    const patched = await request("PATCH", `/core/v1/employees/${jan.employeeId}`, ownerToken, {
      firstName: "  Janusz ",
      lastName: " Kowalski ",
      jobTitle: " Kierownik magazynu ",
    });
    expect(patched.statusCode).toBe(200);
    expect(patched.json()).toMatchObject({
      data: {
        id: jan.employeeId,
        accountId: jan.accountId,
        accountStatus: "ACTIVE",
        firstName: "Janusz",
        lastName: "Kowalski",
        workEmail: jan.email,
        jobTitle: "Kierownik magazynu",
        status: "ACTIVE",
      },
      error: null,
    });

    // Odzwierciedlone w GET /core/v1/employees, GET /core/v1/me oraz auth.users.name
    const listRes = await request("GET", "/core/v1/employees?limit=100", ownerToken);
    expect(listRes.statusCode).toBe(200);
    expect(
      (listRes.json().data as Array<{ id: string; firstName: string; lastName: string; jobTitle: string | null }>).find(
        (e) => e.id === jan.employeeId,
      ),
    ).toMatchObject({ firstName: "Janusz", lastName: "Kowalski", jobTitle: "Kierownik magazynu" });

    const meRes = await request("GET", "/core/v1/me", janToken);
    expect(meRes.statusCode).toBe(200);
    expect(meRes.json().data.employee).toMatchObject({
      id: jan.employeeId,
      firstName: "Janusz",
      lastName: "Kowalski",
      jobTitle: "Kierownik magazynu",
    });

    const authUser = await db.authUser.findUniqueOrThrow({ where: { id: jan.accountId } });
    expect(authUser.name).toBe("Janusz Kowalski");

    // Wpis audytu zawiera wyłącznie nazwy zmienionych pól, bez danych osobowych
    const auditsAfterEdit = await withOrganization(db, acme.id, (tx) =>
      tx.auditLog.findMany({
        where: { action: "employee.updated", resourceType: "employee", resourceId: jan.employeeId },
        orderBy: { createdAt: "asc" },
      }),
    );
    expect(auditsAfterEdit).toHaveLength(1);
    expect(auditsAfterEdit[0]?.metadata).toEqual({ fields: ["firstName", "lastName", "jobTitle"] });
    const serializedMeta = JSON.stringify(auditsAfterEdit[0]?.metadata);
    expect(serializedMeta).not.toContain("Janusz");
    expect(serializedMeta).not.toContain("Kowlski");
    expect(serializedMeta).not.toContain("Kowalski");
    expect(serializedMeta).not.toContain("Kierownik");

    // Wyczyszczenie jobTitle: null -> 200 i nowy wpis audytu tylko z ["jobTitle"]
    const clearedTitle = await request("PATCH", `/core/v1/employees/${jan.employeeId}`, ownerToken, {
      jobTitle: null,
    });
    expect(clearedTitle.statusCode).toBe(200);
    expect(clearedTitle.json().data.jobTitle).toBeNull();

    // No-op PATCH z niezmienionymi wartościami -> 200 i zero nowych wpisów audytu
    const noOp = await request("PATCH", `/core/v1/employees/${jan.employeeId}`, ownerToken, {
      firstName: "Janusz",
      lastName: "Kowalski",
      jobTitle: null,
      workEmail: jan.email.toUpperCase(),
    });
    expect(noOp.statusCode).toBe(200);

    const auditsAfterNoOp = await withOrganization(db, acme.id, (tx) =>
      tx.auditLog.findMany({
        where: { action: "employee.updated", resourceType: "employee", resourceId: jan.employeeId },
        orderBy: { createdAt: "asc" },
      }),
    );
    expect(auditsAfterNoOp).toHaveLength(2);
    expect(auditsAfterNoOp[1]?.metadata).toEqual({ fields: ["jobTitle"] });
  });

  it("pozwala Ownerowi edytować własny profil (firstName, lastName, jobTitle)", async () => {
    const ownerToken = await token(acme);

    const res = await request("PATCH", `/core/v1/employees/${acme.employeeId}`, ownerToken, {
      lastName: "Nowak-Owner",
      jobTitle: "Prezeska",
    });
    expect(res.statusCode).toBe(200);
    expect(res.json().data).toMatchObject({
      id: acme.employeeId,
      firstName: "Anna",
      lastName: "Nowak-Owner",
      jobTitle: "Prezeska",
    });

    const authUser = await db.authUser.findUniqueOrThrow({ where: { id: acme.accountId } });
    expect(authUser.name).toBe("Anna Nowak-Owner");

    // Przywracamy nazwisko Ownera, żeby nie wpływać na inne testy
    await request("PATCH", `/core/v1/employees/${acme.employeeId}`, ownerToken, {
      lastName: "Acme",
      jobTitle: null,
    });
  });

  it("blokuje zmianę lub wyczyszczenie workEmail pracownika z kontem (409), ale dopuszcza zgodny adres i uzupełnienie brakującego workEmail", async () => {
    const ownerToken = await token(acme);
    const activeWithoutWorkEmail = await createMember(acme, "Ewa", "BezMaila", { workEmail: null });
    const invitedMember = await createMember(acme, "Karol", "Zaproszony", { status: "INVITED" });
    const deactivatedMember = await createMember(acme, "Adam", "Wylaczony", { status: "DEACTIVATED" });

    // Zmiana na inny adres albo wyczyszczenie na koncie ACTIVE / INVITED / DEACTIVATED -> 409 CONFLICT
    for (const target of [activeWithoutWorkEmail, invitedMember, deactivatedMember]) {
      const changeRes = await request("PATCH", `/core/v1/employees/${target.employeeId}`, ownerToken, {
        workEmail: `inny-${uuidv7().slice(-4)}@${acme.domain}`,
      });
      expect(changeRes.statusCode).toBe(409);
      expect(changeRes.json().error.code).toBe("CONFLICT");

      const clearRes = await request("PATCH", `/core/v1/employees/${target.employeeId}`, ownerToken, {
        workEmail: null,
      });
      expect(clearRes.statusCode).toBe(409);
      expect(clearRes.json().error.code).toBe("CONFLICT");
    }

    // Uzupełnienie brakującego workEmail adresem zgodnym z kontem (inna wielkość liter) -> 200 i zapis znormalizowany
    const backfillRes = await request("PATCH", `/core/v1/employees/${activeWithoutWorkEmail.employeeId}`, ownerToken, {
      workEmail: activeWithoutWorkEmail.email.toUpperCase(),
    });
    expect(backfillRes.statusCode).toBe(200);
    expect(backfillRes.json().data.workEmail).toBe(activeWithoutWorkEmail.email);

    const audits = await withOrganization(db, acme.id, (tx) =>
      tx.auditLog.findMany({
        where: { action: "employee.updated", resourceId: activeWithoutWorkEmail.employeeId },
      }),
    );
    expect(audits).toHaveLength(1);
    expect(audits[0]?.metadata).toEqual({ fields: ["workEmail"] });
    expect(JSON.stringify(audits[0]?.metadata)).not.toContain(activeWithoutWorkEmail.email);
  });

  it("waliduje i normalizuje workEmail w POST i PATCH pracownika bez konta: zweryfikowana domena (200/201), czyszczenie null (200), darmowe/niezweryfikowane domeny (422 EMAIL_DOMAIN_NOT_ALLOWED), duplikat (409)", async () => {
    const ownerToken = await token(acme);

    // POST z darmową domeną -> 422 EMAIL_DOMAIN_NOT_ALLOWED
    for (const badEmail of [
      "jan@gmail.com",
      "jan@wp.pl",
      `jan@${acme.pendingDomain}`,
      `jan@${globex.domain}`,
      "jan@nieznana-domena.test",
    ]) {
      const badPost = await request("POST", "/core/v1/employees", ownerToken, {
        firstName: "Błędny",
        lastName: "Mail",
        workEmail: badEmail,
      });
      expect(badPost.statusCode).toBe(422);
      expect(badPost.json().error.code).toBe("EMAIL_DOMAIN_NOT_ALLOWED");
    }

    // POST z duplikatem adresu istniejącego konta (wielkie litery) -> 409 CONFLICT
    const dupAccountPost = await request("POST", "/core/v1/employees", ownerToken, {
      firstName: "Duplikat",
      lastName: "Konta",
      workEmail: acme.email.toUpperCase(),
    });
    expect(dupAccountPost.statusCode).toBe(409);
    expect(dupAccountPost.json().error.code).toBe("CONFLICT");

    // POST z poprawnym adresem w zweryfikowanej domenie normalizuje workEmail do małych liter
    const firstEmail = `Marek.Nowak@${acme.domain.toUpperCase()}`;
    const created1 = await request("POST", "/core/v1/employees", ownerToken, {
      firstName: "Marek",
      lastName: "Nowak",
      workEmail: firstEmail,
      jobTitle: "Operator",
    });
    expect(created1.statusCode).toBe(201);
    const emp1 = created1.json().data as { id: string; workEmail: string | null };
    expect(emp1.workEmail).toBe(firstEmail.toLowerCase());

    // POST z duplikatem workEmail innego pracownika bez konta -> 409 CONFLICT
    const dupEmpPost = await request("POST", "/core/v1/employees", ownerToken, {
      firstName: "Drugi",
      lastName: "Marek",
      workEmail: firstEmail.toLowerCase(),
    });
    expect(dupEmpPost.statusCode).toBe(409);
    expect(dupEmpPost.json().error.code).toBe("CONFLICT");

    // Drugi pracownik bez konta i bez workEmail
    const created2 = await request("POST", "/core/v1/employees", ownerToken, {
      firstName: "Zofia",
      lastName: "BezMaila",
    });
    expect(created2.statusCode).toBe(201);
    const emp2Id = created2.json().data.id as string;

    // PATCH z darmową, niezweryfikowaną lub cudzą domeną -> 422 EMAIL_DOMAIN_NOT_ALLOWED
    for (const badEmail of [
      "zofia@gmail.com",
      "zofia@onet.pl",
      `zofia@${acme.pendingDomain}`,
      `zofia@${globex.domain}`,
    ]) {
      const badPatch = await request("PATCH", `/core/v1/employees/${emp2Id}`, ownerToken, {
        workEmail: badEmail,
      });
      expect(badPatch.statusCode).toBe(422);
      expect(badPatch.json().error.code).toBe("EMAIL_DOMAIN_NOT_ALLOWED");
    }

    // PATCH z adresem zajętym przez innego pracownika albo konto -> 409 CONFLICT
    const dupEmpPatch = await request("PATCH", `/core/v1/employees/${emp2Id}`, ownerToken, {
      workEmail: firstEmail.toUpperCase(),
    });
    expect(dupEmpPatch.statusCode).toBe(409);
    expect(dupEmpPatch.json().error.code).toBe("CONFLICT");

    const dupAccPatch = await request("PATCH", `/core/v1/employees/${emp2Id}`, ownerToken, {
      workEmail: acmeRegular.email.toUpperCase(),
    });
    expect(dupAccPatch.statusCode).toBe(409);
    expect(dupAccPatch.json().error.code).toBe("CONFLICT");

    // PATCH ustawia znormalizowany workEmail w zweryfikowanej domenie firmy -> 200
    const zofiaEmail = `Zofia.Nowa@${acme.domain.toUpperCase()}`;
    const setEmail = await request("PATCH", `/core/v1/employees/${emp2Id}`, ownerToken, {
      workEmail: zofiaEmail,
    });
    expect(setEmail.statusCode).toBe(200);
    expect(setEmail.json().data.workEmail).toBe(zofiaEmail.toLowerCase());

    // Ponowne wysłanie tego samego adresu dla tego samego pracownika nie konfliktuje z samym sobą (200 no-op)
    const sameEmail = await request("PATCH", `/core/v1/employees/${emp2Id}`, ownerToken, {
      workEmail: zofiaEmail.toLowerCase(),
    });
    expect(sameEmail.statusCode).toBe(200);

    // Wyczyszczenie workEmail: null -> 200
    const clearEmail = await request("PATCH", `/core/v1/employees/${emp2Id}`, ownerToken, {
      workEmail: null,
    });
    expect(clearEmail.statusCode).toBe(200);
    expect(clearEmail.json().data.workEmail).toBeNull();
  });

  it("egzekwuje uprawnienia (403 bez core.employees.manage w ORGANIZATION), izolację firm (404), status ANONYMIZED (409) i walidację (422)", async () => {
    const ownerToken = await token(acme);
    const regularToken = await token(acmeRegular);
    const unitHrToken = await token(acmeUnitHr);
    const orgHrToken = await token(acmeOrgHr);
    const globexToken = await token(globex);

    const created = await request("POST", "/core/v1/employees", ownerToken, {
      firstName: "Cel",
      lastName: "Testowy",
    });
    expect(created.statusCode).toBe(201);
    const targetId = created.json().data.id as string;

    // Brak uprawnienia albo zakres UNIT -> 403 PERMISSION_DENIED
    for (const deniedToken of [regularToken, unitHrToken]) {
      const res = await request("PATCH", `/core/v1/employees/${targetId}`, deniedToken, { firstName: "Zmiana" });
      expect(res.statusCode).toBe(403);
      expect(res.json().error.code).toBe("PERMISSION_DENIED");
    }

    // Pracownik innej firmy (nawet bez uprawnień) albo nieistniejący UUID -> 404 NOT_FOUND
    for (const [bearer, empId] of [
      [globexToken, targetId],
      [regularToken, globex.employeeId],
      [ownerToken, uuidv7()],
    ] as const) {
      const res = await request("PATCH", `/core/v1/employees/${empId}`, bearer, { firstName: "Obcy" });
      expect(res.statusCode).toBe(404);
      expect(res.json().error.code).toBe("NOT_FOUND");
    }

    // Konto z core.employees.manage w zakresie ORGANIZATION może edytować -> 200
    const hrRes = await request("PATCH", `/core/v1/employees/${targetId}`, orgHrToken, {
      jobTitle: "Specjalista",
    });
    expect(hrRes.statusCode).toBe(200);
    expect(hrRes.json().data.jobTitle).toBe("Specjalista");

    // Walidacja: puste {}, puste stringi, nieznane pola, zły UUID -> 422 VALIDATION_FAILED
    for (const invalid of [
      await request("PATCH", `/core/v1/employees/${targetId}`, ownerToken, {}),
      await request("PATCH", `/core/v1/employees/${targetId}`, ownerToken, { firstName: "   " }),
      await request("PATCH", `/core/v1/employees/${targetId}`, ownerToken, { jobTitle: "   " }),
      await request("PATCH", `/core/v1/employees/${targetId}`, ownerToken, { firstName: "Ok", status: "FORMER" }),
      await request("PATCH", "/core/v1/employees/not-a-uuid", ownerToken, { firstName: "Ok" }),
    ]) {
      expect(invalid.statusCode).toBe(422);
      expect(invalid.json().error.code).toBe("VALIDATION_FAILED");
      expect(invalid.json().error.details.length).toBeGreaterThan(0);
    }

    // Zanonimizowany pracownik (ANONYMIZED) -> 409 CONFLICT
    await withOrganization(db, acme.id, (tx) =>
      tx.employee.update({
        where: { id: targetId },
        data: { status: "ANONYMIZED", anonymizedAt: new Date() },
      }),
    );

    const anonymizedRes = await request("PATCH", `/core/v1/employees/${targetId}`, ownerToken, {
      firstName: "Proba",
    });
    expect(anonymizedRes.statusCode).toBe(409);
    expect(anonymizedRes.json().error.code).toBe("CONFLICT");
  });

  it("uzupełnia brakujący workEmail istniejącego pracownika przy tworzeniu zaproszenia (createInvitation)", async () => {
    const ownerToken = await token(acme);

    const empRes = await request("POST", "/core/v1/employees", ownerToken, {
      firstName: "Alicja",
      lastName: "Zaproszenie",
    });
    expect(empRes.statusCode).toBe(201);
    const employeeId = empRes.json().data.id as string;
    expect(empRes.json().data.workEmail).toBeNull();

    const inviteEmail = `Alicja.Zaproszenie@${acme.domain.toUpperCase()}`;
    const invRes = await request("POST", "/core/v1/invitations", ownerToken, {
      email: inviteEmail,
      employeeId,
    });
    expect(invRes.statusCode).toBe(201);

    const updated = await withOrganization(db, acme.id, (tx) =>
      tx.employee.findUniqueOrThrow({ where: { id: employeeId } }),
    );
    expect(updated.workEmail).toBe(inviteEmail.toLowerCase());
  });

  it("zarządza harmonogramem pracy (workSchedule): walidacja, null, no-op, uprawnienia, /me, /employees i wpis audytu", async () => {
    const ownerToken = await token(acme);
    const regularToken = await token(acmeRegular);
    const unitHrToken = await token(acmeUnitHr);
    const orgHrToken = await token(acmeOrgHr);

    const jan = await createMember(acme, "Jan", "Harmonogram");
    const janToken = await token(jan);

    // Domyślnie workSchedule i effectiveWorkSchedule to null w /me
    const initialMe = await request("GET", "/core/v1/me", janToken);
    expect(initialMe.statusCode).toBe(200);
    expect(initialMe.json().data.employee.workSchedule).toBeNull();
    expect(initialMe.json().data.employee.effectiveWorkSchedule).toBeNull();
    expect(initialMe.json().data.organization.timeZone).toBe("Europe/Warsaw");
    expect(initialMe.json().data.organization.defaultWorkSchedule).toBeNull();

    const annaFullTime = { "1": 480, "2": 480, "3": 480, "4": 480, "5": 480 };
    const janPartTime = { "1": 240, "2": 240, "3": 240 };

    // Gdy firma ma ustawiony domyślny harmonogram, pracownik bez własnego dostaje go jako effectiveWorkSchedule
    expect(
      (await request("PATCH", "/core/v1/organization", ownerToken, { defaultWorkSchedule: annaFullTime })).statusCode,
    ).toBe(200);
    const meWithCompanyDefault = await request("GET", "/core/v1/me", janToken);
    expect(meWithCompanyDefault.statusCode).toBe(200);
    expect(meWithCompanyDefault.json().data.employee.workSchedule).toBeNull();
    expect(meWithCompanyDefault.json().data.employee.effectiveWorkSchedule).toEqual(annaFullTime);
    expect(meWithCompanyDefault.json().data.organization.defaultWorkSchedule).toEqual(annaFullTime);

    // Uprawnienia: zwykłe konto oraz zakres UNIT dostają 403 PERMISSION_DENIED
    for (const deniedToken of [regularToken, unitHrToken]) {
      const denied = await request("PATCH", `/core/v1/employees/${jan.employeeId}`, deniedToken, {
        workSchedule: janPartTime,
      });
      expect(denied.statusCode).toBe(403);
      expect(denied.json().error.code).toBe("PERMISSION_DENIED");
    }

    // Nieprawidłowe harmonogramy -> 422 VALIDATION_FAILED (klucz 0, klucz 8, 1441, ułamek, tablica)
    for (const badSchedule of [{ "0": 480 }, { "8": 480 }, { "1": 1441 }, { "1": 480.5 }, [480]]) {
      const bad = await request("PATCH", `/core/v1/employees/${jan.employeeId}`, ownerToken, {
        workSchedule: badSchedule,
      });
      expect(bad.statusCode).toBe(422);
      expect(bad.json().error.code).toBe("VALIDATION_FAILED");
    }

    // Ustawienie pełnego etatu przez konto z core.employees.manage w ORGANIZATION
    const setFull = await request("PATCH", `/core/v1/employees/${jan.employeeId}`, orgHrToken, {
      workSchedule: annaFullTime,
    });
    expect(setFull.statusCode).toBe(200);
    expect(setFull.json().data.workSchedule).toEqual(annaFullTime);

    // Zmiana na 12 h/tydz. (Jan) przez Ownera
    const setPart = await request("PATCH", `/core/v1/employees/${jan.employeeId}`, ownerToken, {
      workSchedule: janPartTime,
    });
    expect(setPart.statusCode).toBe(200);
    expect(setPart.json().data.workSchedule).toEqual(janPartTime);

    // Odzwierciedlone w GET /me (indywidualny harmonogram Jana wygrywa z domyślnym firmy) i GET /employees
    const meAfter = await request("GET", "/core/v1/me", janToken);
    expect(meAfter.statusCode).toBe(200);
    expect(meAfter.json().data.employee.workSchedule).toEqual(janPartTime);
    expect(meAfter.json().data.employee.effectiveWorkSchedule).toEqual(janPartTime);

    const listRes = await request("GET", "/core/v1/employees?limit=100", ownerToken);
    expect(listRes.statusCode).toBe(200);
    expect(
      (listRes.json().data as Array<{ id: string; workSchedule: Record<string, number> | null }>).find(
        (e) => e.id === jan.employeeId,
      )?.workSchedule,
    ).toEqual(janPartTime);

    // No-op z tą samą zawartością w innej kolejności kluczy nie tworzy nowego wpisu audytu
    const noop = await request("PATCH", `/core/v1/employees/${jan.employeeId}`, ownerToken, {
      workSchedule: { "3": 240, "1": 240, "2": 240 },
    });
    expect(noop.statusCode).toBe(200);

    // Wyczyszczenie harmonogramu: null -> 200; effectiveWorkSchedule wraca do domyślnego firmy, a po wyczyszczeniu domyślnego firmy -> null
    const cleared = await request("PATCH", `/core/v1/employees/${jan.employeeId}`, ownerToken, {
      workSchedule: null,
    });
    expect(cleared.statusCode).toBe(200);
    expect(cleared.json().data.workSchedule).toBeNull();

    const meAfterEmployeeClear = await request("GET", "/core/v1/me", janToken);
    expect(meAfterEmployeeClear.statusCode).toBe(200);
    expect(meAfterEmployeeClear.json().data.employee.workSchedule).toBeNull();
    expect(meAfterEmployeeClear.json().data.employee.effectiveWorkSchedule).toEqual(annaFullTime);

    expect(
      (await request("PATCH", "/core/v1/organization", ownerToken, { defaultWorkSchedule: null })).statusCode,
    ).toBe(200);
    const meAfterOrgClear = await request("GET", "/core/v1/me", janToken);
    expect(meAfterOrgClear.statusCode).toBe(200);
    expect(meAfterOrgClear.json().data.employee.effectiveWorkSchedule).toBeNull();

    // Wpisy audytu employee.updated (2 ustawienia + 1 czyszczenie, bez no-op)
    const audits = await withOrganization(db, acme.id, (tx) =>
      tx.auditLog.findMany({
        where: { action: "employee.updated", resourceType: "employee", resourceId: jan.employeeId },
        orderBy: [{ createdAt: "asc" }, { id: "asc" }],
      }),
    );
    expect(audits).toHaveLength(3);
    expect(audits.map((row) => row.metadata)).toEqual([
      { fields: ["workSchedule"] },
      { fields: ["workSchedule"] },
      { fields: ["workSchedule"] },
    ]);
  });
});
