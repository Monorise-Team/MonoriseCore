import { describe, expect, it } from "vitest";
import {
  AcceptInvitationRequest,
  AccessTokenClaims,
  ApiErrorBody,
  ApiErrorResponse,
  ApiListMeta,
  apiListSuccessSchema,
  ApiMeta,
  apiErrorSchema,
  apiSuccessSchema,
  AppAccess,
  AUDIT_LOG_RETENTION_DAYS,
  AUDIT_LOG_RETENTION_MS,
  AuditActorType,
  AuditLogEntry,
  canManageOrganizationAssignments,
  canManageOrganizationSnapshot,
  CORE_PERMISSIONS,
  CORE_ROLE_TEMPLATES,
  CopyRole,
  CreateAppAccess,
  CreateEmployee,
  CreateInvitation,
  CreateNotification,
  CreateOrganizationDomain,
  CreateRole,
  CreateRoleAssignment,
  CreateRoleFromScratch,
  CreateUnit,
  DEFAULT_ORGANIZATION_TIME_ZONE,
  DEFAULT_PAGE_LIMIT,
  DIRECTORY_READ_SCOPE,
  DirectoryEmployee,
  DirectoryOrganization,
  DomainName,
  Employee,
  DirectoryUnitMember,
  effectiveWorkSchedule,
  emailDomain,
  Entitlement,
  getNotificationCategory,
  Health,
  IDEMPOTENCY_KEY_HEADER,
  IDEMPOTENCY_KEY_MAX_LENGTH,
  IDEMPOTENCY_KEY_TTL_HOURS,
  IDEMPOTENCY_KEY_TTL_MS,
  IDEMPOTENCY_REPLAYED_HEADER,
  IdempotencyKeyHeader,
  Invitation,
  InvitationDelivery,
  InvitationStatus,
  INVITATION_TTL_DAYS,
  INVITATION_TTL_MS,
  isFreeEmailDomain,
  isValidIanaTimeZone,
  ListAuditLogQuery,
  MachineTokenClaims,
  MailDeliveryStatus,
  MAX_ORGANIZATION_DOMAINS,
  MAX_PAGE_LIMIT,
  MAX_PERMISSION_MANIFEST_ENTRIES,
  Me,
  NOTIFICATION_BODY_MAX_LENGTH,
  NOTIFICATION_CATEGORIES,
  NOTIFICATION_CATEGORY_KEYS,
  NOTIFICATION_TITLE_MAX_LENGTH,
  NotificationCategoryKey,
  NotificationChannel,
  NotificationMailChannel,
  NotificationPreference,
  NotificationResult,
  NotificationSkipReason,
  NotificationStatus,
  NOTIFICATIONS_SEND_SCOPE,
  normalizeEmail,
  Organization,
  OrganizationDomain,
  OrganizationOwner,
  PageQuery,
  Permission,
  PERMISSIONS_READ_SCOPE,
  PERMISSIONS_REGISTER_SCOPE,
  PermissionSnapshot,
  ProductKey,
  PutUnitMember,
  RegisterPermissionsRequest,
  RegisterPermissionsResult,
  RegisterRoleTemplatesRequest,
  RegisterRoleTemplatesResult,
  Role,
  RoleAssignment,
  RoleTemplateKey,
  SignUpRequest,
  TimeZone,
  TransferOrganizationOwner,
  Unit,
  UnitMember,
  UnsubscribeNotificationResult,
  UpdateEmployee,
  UpdateNotificationPreference,
  UpdateOrganization,
  UpdateRole,
  UpdateUnit,
  VerifyOrganizationDomain,
  WORK_SCHEDULE_FULL_TIME_MINUTES,
  WORK_SCHEDULE_MAX_DAY_MINUTES,
  WorkSchedule,
  workScheduleEquals,
  workScheduleFte,
  workScheduleWeeklyMinutes,
} from "../src/index.js";

const UUID_1 = "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6a7b";
const UUID_2 = "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6a7c";
const UUID_3 = "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6a7d";

describe("adresy e-mail", () => {
  it("rozpoznaje domenę i normalizuje adres", () => {
    expect(emailDomain("Anna.Kowalska@Acme.COM")).toBe("acme.com");
    expect(normalizeEmail("  Anna@Acme.com ")).toBe("anna@acme.com");
  });

  it("odrzuca darmowe skrzynki, polskie, nowe domeny i ich subdomeny", () => {
    for (const domain of [
      "gmail.com",
      "WP.pl",
      "onet.pl",
      "interia.pl",
      "o2.pl",
      "pm.me",
      "tuta.com",
      "tutanota.com",
      "mail.gmail.com",
      "sub.a.proton.me",
      "mail.wp.pl",
      "  team.pm.me  ",
      "desk.tuta.com",
      "legacy.tutanota.com",
    ]) {
      expect(isFreeEmailDomain(domain), `Powinno odrzucić ${domain}`).toBe(true);
    }
    for (const allowed of ["acme.com", "notgmail.com", "my-tuta.com", "fpm.me", "company-wp.pl"]) {
      expect(isFreeEmailDomain(allowed), `Powinno przepuścić ${allowed}`).toBe(false);
    }
  });
});

describe("uprawnienia core.organization.manage", () => {
  const now = new Date("2026-11-26T12:00:00.000Z");

  it("przyznaje dostęp Ownerowi lub kontu z aktywnym zakresem ORGANIZATION, odrzuca UNIT/RESOURCE, wygasłe i wycofane", () => {
    expect(
      canManageOrganizationAssignments({
        accountId: UUID_1,
        organizationId: UUID_2,
        isOwner: true,
        authzRevision: 0,
        assignments: [],
        now,
      }),
    ).toBe(true);

    expect(
      canManageOrganizationAssignments({
        accountId: UUID_1,
        organizationId: UUID_2,
        isOwner: false,
        authzRevision: 0,
        assignments: [
          {
            scopeType: "ORGANIZATION",
            scopeId: null,
            validFrom: null,
            validUntil: null,
            role: {
              archivedAt: null,
              permissions: [{ permission: { key: CORE_PERMISSIONS.keys["organization.manage"], deprecatedAt: null } }],
            },
          },
        ],
        now,
      }),
    ).toBe(true);

    // Zakres UNIT lub RESOURCE nie wystarcza dla operacji na poziomie całej firmy
    for (const scope of [
      { scopeType: "UNIT" as const, scopeId: UUID_3 },
      { scopeType: "RESOURCE" as const, scopeId: "res_1" },
    ]) {
      expect(
        canManageOrganizationAssignments({
          accountId: UUID_1,
          organizationId: UUID_2,
          isOwner: false,
          authzRevision: 0,
          assignments: [
            {
              ...scope,
              validFrom: null,
              validUntil: null,
              role: {
                archivedAt: null,
                permissions: [
                  { permission: { key: CORE_PERMISSIONS.keys["organization.manage"], deprecatedAt: null } },
                ],
              },
            },
          ],
          now,
        }),
      ).toBe(false);
    }

    // Zarchiwizowana rola, wycofane uprawnienie, wygasłe lub przyszłe przypisanie -> false
    const deniedCases = [
      {
        role: {
          archivedAt: new Date("2026-11-25T00:00:00.000Z"),
          permissions: [{ permission: { key: CORE_PERMISSIONS.keys["organization.manage"], deprecatedAt: null } }],
        },
        validFrom: null,
        validUntil: null,
      },
      {
        role: {
          archivedAt: null,
          permissions: [
            {
              permission: {
                key: CORE_PERMISSIONS.keys["organization.manage"],
                deprecatedAt: new Date("2026-11-25T00:00:00.000Z"),
              },
            },
          ],
        },
        validFrom: null,
        validUntil: null,
      },
      {
        role: {
          archivedAt: null,
          permissions: [{ permission: { key: CORE_PERMISSIONS.keys["organization.manage"], deprecatedAt: null } }],
        },
        validFrom: null,
        validUntil: new Date("2026-11-26T11:59:59.000Z"),
      },
      {
        role: {
          archivedAt: null,
          permissions: [{ permission: { key: CORE_PERMISSIONS.keys["organization.manage"], deprecatedAt: null } }],
        },
        validFrom: new Date("2026-11-26T12:00:01.000Z"),
        validUntil: null,
      },
    ];
    for (const c of deniedCases) {
      expect(
        canManageOrganizationAssignments({
          accountId: UUID_1,
          organizationId: UUID_2,
          isOwner: false,
          authzRevision: 0,
          assignments: [{ scopeType: "ORGANIZATION", scopeId: null, ...c }],
          now,
        }),
      ).toBe(false);
    }

    // Bezpośrednia ocena gotowej migawki
    expect(
      canManageOrganizationSnapshot(
        {
          accountId: UUID_1,
          organizationId: UUID_2,
          authzRevision: 1,
          isOwner: false,
          products: ["core"],
          grants: [
            {
              permission: CORE_PERMISSIONS.keys["organization.manage"],
              scope: { type: "ORGANIZATION" },
              validFrom: null,
              validUntil: null,
            },
          ],
          units: [],
        },
        now,
      ),
    ).toBe(true);
  });
});

describe("kontrakty", () => {
  it("wymaga hasła co najmniej 12 znaków przy zakładaniu firmy", () => {
    const base = { organizationName: "Acme", firstName: "Anna", lastName: "Kowalska", email: "anna@acme.com" };
    expect(SignUpRequest.safeParse({ ...base, password: "krótkie" }).success).toBe(false);
    expect(SignUpRequest.safeParse({ ...base, password: "długie-hasło-123" }).success).toBe(true);
  });

  it("token zawiera firmę, pracownika i rewizję uprawnień", () => {
    const claims = AccessTokenClaims.parse({
      iss: "https://auth.monorise.studio",
      sub: UUID_1,
      aud: "https://api.monorise.studio",
      org_id: UUID_2,
      employee_id: UUID_3,
      authz_rev: 0,
      iat: 1,
      exp: 2,
    });
    expect(claims.amr).toEqual([]);
  });

  it("waliduje kopertę sukcesu i błędu zgodnie ze standardem API", () => {
    const okSchema = apiSuccessSchema(Health);
    expect(okSchema.parse({ data: { status: "ok" }, meta: { requestId: "req_123" }, error: null })).toEqual({
      data: { status: "ok" },
      meta: { requestId: "req_123" },
      error: null,
    });
    expect(okSchema.safeParse({ data: { status: "fail" }, meta: { requestId: "req_123" }, error: null }).success).toBe(
      false,
    );

    const err = {
      data: null,
      meta: ApiMeta.parse({ requestId: "req_456" }),
      error: ApiErrorBody.parse({
        code: "UNAUTHENTICATED",
        message: "Brak tokenu dostępu",
        details: [],
      }),
    };
    expect(ApiErrorResponse.parse(err)).toEqual(err);
    expect(apiErrorSchema().safeParse({ ...err, error: { ...err.error, code: "UNKNOWN_CODE" } }).success).toBe(false);
  });

  it("waliduje schematy pracowników, jednostek, członkostw i Me z isOwner", () => {
    expect(
      CreateEmployee.parse({
        firstName: " Anna ",
        lastName: " Nowak ",
        workEmail: "anna@acme.test",
        jobTitle: "Magazyn",
      }),
    ).toEqual({ firstName: "Anna", lastName: "Nowak", workEmail: "anna@acme.test", jobTitle: "Magazyn" });
    expect(CreateEmployee.safeParse({ firstName: "   ", lastName: "Nowak" }).success).toBe(false);

    expect(
      UpdateEmployee.parse({
        firstName: " Jan ",
        lastName: " Kowalski ",
        workEmail: "Jan.Kowalski@Acme.test",
        jobTitle: " Kierownik ",
      }),
    ).toEqual({
      firstName: "Jan",
      lastName: "Kowalski",
      workEmail: "Jan.Kowalski@Acme.test",
      jobTitle: "Kierownik",
    });
    expect(UpdateEmployee.parse({ jobTitle: null, workEmail: null })).toEqual({ jobTitle: null, workEmail: null });
    expect(UpdateEmployee.safeParse({}).success).toBe(false);
    expect(UpdateEmployee.safeParse({ firstName: "   " }).success).toBe(false);
    expect(UpdateEmployee.safeParse({ lastName: "" }).success).toBe(false);
    expect(UpdateEmployee.safeParse({ jobTitle: "   " }).success).toBe(false);
    expect(UpdateEmployee.safeParse({ workEmail: "nie-email" }).success).toBe(false);
    expect(UpdateEmployee.safeParse({ firstName: "Jan", status: "FORMER" }).success).toBe(false);

    expect(CreateUnit.parse({ name: " Kraków ", type: "BRANCH" })).toEqual({ name: "Kraków", type: "BRANCH" });
    expect(CreateUnit.parse({ name: "Magazyn", type: "TEAM", parentId: UUID_1 })).toEqual({
      name: "Magazyn",
      type: "TEAM",
      parentId: UUID_1,
    });
    expect(CreateUnit.safeParse({ name: "Kraków", type: "OFFICE" }).success).toBe(false);

    expect(UpdateUnit.safeParse({}).success).toBe(false);
    expect(UpdateUnit.parse({ parentId: null })).toEqual({ parentId: null });
    expect(UpdateUnit.parse({ name: "Oddział Kraków", status: "ARCHIVED" })).toEqual({
      name: "Oddział Kraków",
      status: "ARCHIVED",
    });

    // Stan konta: null bez konta, zaproszone konto ma INVITED, nieznany stan jest odrzucany
    const marek = {
      id: UUID_2,
      accountId: null,
      firstName: "Marek",
      lastName: "Nowak",
      workEmail: null,
      jobTitle: null,
      workSchedule: null,
      status: "ACTIVE",
    };
    expect(Employee.parse({ ...marek, accountStatus: null }).accountStatus).toBeNull();
    expect(Employee.parse({ ...marek, accountId: UUID_1, accountStatus: "INVITED" }).accountStatus).toBe("INVITED");
    expect(Employee.safeParse({ ...marek, accountStatus: "BLOCKED" }).success).toBe(false);
    expect(Employee.safeParse(marek).success).toBe(false);

    expect(PutUnitMember.parse({ role: "LEADER" })).toEqual({ role: "LEADER" });
    expect(PutUnitMember.safeParse({ role: "OWNER" }).success).toBe(false);

    expect(
      Unit.parse({
        id: UUID_1,
        parentId: null,
        name: "Kraków",
        type: "BRANCH",
        status: "ACTIVE",
        createdAt: "2026-11-24T12:00:00.000Z",
        updatedAt: "2026-11-24T12:00:00.000Z",
      }).parentId,
    ).toBeNull();

    expect(
      UnitMember.parse({
        unitId: UUID_1,
        employeeId: UUID_2,
        role: "MEMBER",
        joinedAt: "2026-11-24T12:00:00.000Z",
        employee: {
          id: UUID_2,
          accountId: UUID_1,
          accountStatus: "ACTIVE",
          firstName: "Anna",
          lastName: "Nowak",
          workEmail: "anna@acme.test",
          jobTitle: null,
          workSchedule: { "1": 480, "2": 480, "3": 480, "4": 480, "5": 480 },
          status: "ACTIVE",
        },
      }).role,
    ).toBe("MEMBER");

    expect(
      Me.parse({
        account: { id: UUID_1, email: "anna@acme.test", status: "ACTIVE", isOwner: true },
        employee: {
          id: UUID_2,
          accountId: UUID_1,
          accountStatus: "ACTIVE",
          firstName: "Anna",
          lastName: "Nowak",
          workEmail: "anna@acme.test",
          jobTitle: null,
          workSchedule: { "1": 480, "2": 480, "3": 480, "4": 480, "5": 480 },
          effectiveWorkSchedule: { "1": 480, "2": 480, "3": 480, "4": 480, "5": 480 },
          status: "ACTIVE",
        },
        organization: {
          id: UUID_3,
          name: "Acme",
          status: "ACTIVE",
          timeZone: "Europe/Warsaw",
          defaultWorkSchedule: null,
        },
      }).account.isOwner,
    ).toBe(true);
  });

  it("waliduje parametry stronicowania i kopertę listy z nextCursor", () => {
    expect(PageQuery.parse({})).toEqual({ limit: DEFAULT_PAGE_LIMIT });
    expect(PageQuery.parse({ limit: "25", cursor: "abc_123" })).toEqual({ limit: 25, cursor: "abc_123" });
    expect(PageQuery.safeParse({ limit: String(MAX_PAGE_LIMIT + 1) }).success).toBe(false);
    expect(PageQuery.safeParse({ limit: "0" }).success).toBe(false);
    expect(PageQuery.safeParse({ limit: "" }).success).toBe(false);
    expect(PageQuery.safeParse({ limit: "1.5" }).success).toBe(false);
    expect(PageQuery.safeParse({ cursor: "" }).success).toBe(false);

    const listSchema = apiListSuccessSchema(Health);
    expect(
      listSchema.parse({
        data: { status: "ok" },
        meta: ApiListMeta.parse({ requestId: "req_123", nextCursor: null }),
        error: null,
      }).meta.nextCursor,
    ).toBeNull();
  });

  it("definiuje uprawnienia Core i waliduje schematy rejestru oraz tokenu maszynowego", () => {
    expect(CORE_PERMISSIONS.product).toBe("core");
    expect(CORE_PERMISSIONS.manifest.map((entry) => entry.key)).toEqual([
      "core.structure.manage",
      "core.employees.manage",
      "core.roles.manage",
      "core.roles.assign",
      "core.app_access.manage",
      "core.audit.read",
      "core.organization.manage",
    ]);
    expect(RegisterPermissionsRequest.parse(CORE_PERMISSIONS.manifest)).toHaveLength(7);
    expect(PERMISSIONS_READ_SCOPE).toBe("core:permissions.read");

    expect(ProductKey.safeParse("timotime").success).toBe(true);
    expect(ProductKey.safeParse("TimoTime").success).toBe(false);
    expect(ProductKey.safeParse("timo_time").success).toBe(false);

    expect(RegisterPermissionsRequest.safeParse([]).success).toBe(false);
    const tooMany = Array.from({ length: MAX_PERMISSION_MANIFEST_ENTRIES + 1 }, (_, i) => ({
      key: `timotime.item_${i}.read`,
      description: `Pozycja ${i}`,
    }));
    expect(RegisterPermissionsRequest.safeParse(tooMany).success).toBe(false);

    expect(
      RegisterPermissionsResult.parse({
        added: ["timotime.leave.approve"],
        updated: [],
        deprecated: [],
        restored: [],
        unchanged: 2,
      }).unchanged,
    ).toBe(2);

    expect(
      Permission.parse({
        key: "core.roles.manage",
        product: null,
        description: "Tworzenie i zmiana ról firmy",
        deprecated: false,
      }).product,
    ).toBeNull();

    const machine = MachineTokenClaims.parse({
      iss: "https://auth.monorise.studio",
      sub: "timotime-web",
      aud: "https://api.monorise.studio",
      client_id: "timotime-web",
      scope: PERMISSIONS_REGISTER_SCOPE,
      iat: 1,
      exp: 2,
    });
    expect(machine.client_id).toBe("timotime-web");
    expect(machine.scope).toBe("core:permissions.register");

    // Token użytkownika z org_id nie przechodzi walidacji tokenu maszynowego
    expect(
      MachineTokenClaims.safeParse({
        iss: "https://auth.monorise.studio",
        sub: UUID_1,
        aud: "https://api.monorise.studio",
        client_id: "timotime-web",
        org_id: UUID_2,
        scope: PERMISSIONS_REGISTER_SCOPE,
        iat: 1,
        exp: 2,
      }).success,
    ).toBe(false);
  });

  it("waliduje schematy ról, szablonów, przypisań i przekazania Ownera", () => {
    expect(CORE_ROLE_TEMPLATES).toHaveLength(1);
    expect(CORE_ROLE_TEMPLATES[0]?.key).toBe("core.company_admin");
    expect(CORE_ROLE_TEMPLATES[0]?.permissions).toEqual(CORE_PERMISSIONS.manifest.map((p) => p.key));
    expect(CORE_ROLE_TEMPLATES[0]?.permissions).toContain("core.organization.manage");

    expect(RoleTemplateKey.safeParse("core.company_admin").success).toBe(true);
    expect(RoleTemplateKey.safeParse("timotime.manager").success).toBe(true);
    expect(RoleTemplateKey.safeParse("invalid").success).toBe(false);

    expect(
      RegisterRoleTemplatesRequest.parse([
        {
          key: "timotime.manager",
          name: " Kierownik ",
          description: " Zatwierdza czas ",
          permissions: ["timotime.entries.read", "timotime.entries.approve"],
        },
      ])[0]?.name,
    ).toBe("Kierownik");
    expect(
      RegisterRoleTemplatesRequest.safeParse([
        { key: "timotime.dup", name: "A", permissions: ["timotime.entries.read"] },
        { key: "timotime.dup", name: "B", permissions: ["timotime.entries.read"] },
      ]).success,
    ).toBe(false);
    expect(
      RegisterRoleTemplatesRequest.safeParse([
        { key: "timotime.manager", name: "A", permissions: ["timotime.entries.read", "timotime.entries.read"] },
      ]).success,
    ).toBe(false);

    expect(
      RegisterRoleTemplatesResult.parse({
        added: ["timotime.manager"],
        updated: [],
        archived: [],
        restored: [],
        unchanged: 0,
      }).added,
    ).toEqual(["timotime.manager"]);

    expect(
      CreateRoleFromScratch.parse({
        name: " Kierownik ",
        product: "timotime",
        permissions: ["timotime.entries.read"],
      }).name,
    ).toBe("Kierownik");
    expect(CopyRole.parse({ copyFromRoleId: UUID_1, name: "Moja rola" }).copyFromRoleId).toBe(UUID_1);
    expect(
      CreateRole.safeParse({
        copyFromRoleId: UUID_1,
        product: "timotime",
        permissions: ["timotime.entries.read"],
      }).success,
    ).toBe(false);
    expect(UpdateRole.safeParse({}).success).toBe(false);
    expect(UpdateRole.parse({ name: "Nowa nazwa" }).name).toBe("Nowa nazwa");

    expect(
      Role.parse({
        id: UUID_1,
        key: "core.company_admin",
        product: null,
        name: "Administrator firmy",
        description: null,
        isTemplate: true,
        copiedFromRoleId: null,
        archivedAt: null,
        permissions: ["core.roles.manage"],
        createdAt: "2026-11-24T12:00:00.000Z",
        updatedAt: "2026-11-24T12:00:00.000Z",
      }).isTemplate,
    ).toBe(true);

    expect(
      CreateRoleAssignment.parse({
        accountId: UUID_1,
        roleId: UUID_2,
        scopeType: "ORGANIZATION",
      }).scopeType,
    ).toBe("ORGANIZATION");
    expect(
      CreateRoleAssignment.safeParse({
        accountId: UUID_1,
        roleId: UUID_2,
        scopeType: "ORGANIZATION",
        scopeId: UUID_3,
      }).success,
    ).toBe(false);
    expect(
      CreateRoleAssignment.safeParse({
        accountId: UUID_1,
        roleId: UUID_2,
        scopeType: "UNIT",
      }).success,
    ).toBe(false);
    expect(
      CreateRoleAssignment.safeParse({
        accountId: UUID_1,
        roleId: UUID_2,
        scopeType: "UNIT",
        scopeId: "not-a-uuid",
      }).success,
    ).toBe(false);
    expect(
      CreateRoleAssignment.parse({
        accountId: UUID_1,
        roleId: UUID_2,
        scopeType: "UNIT",
        scopeId: UUID_3,
        validFrom: "2026-11-24T00:00:00.000Z",
        validUntil: "2026-12-01T00:00:00.000Z",
      }).scopeId,
    ).toBe(UUID_3);
    expect(
      CreateRoleAssignment.safeParse({
        accountId: UUID_1,
        roleId: UUID_2,
        scopeType: "ORGANIZATION",
        validFrom: "2026-12-10T00:00:00.000Z",
        validUntil: "2026-12-01T00:00:00.000Z",
      }).success,
    ).toBe(false);

    expect(
      RoleAssignment.parse({
        id: UUID_1,
        accountId: UUID_2,
        roleId: UUID_3,
        scopeType: "RESOURCE",
        scopeId: "proj_1",
        validFrom: null,
        validUntil: null,
        grantedByAccountId: UUID_2,
        createdAt: "2026-11-24T12:00:00.000Z",
      }).scopeId,
    ).toBe("proj_1");

    expect(TransferOrganizationOwner.parse({ accountId: UUID_1 }).accountId).toBe(UUID_1);
    expect(OrganizationOwner.parse({ ownerAccountId: UUID_1 }).ownerAccountId).toBe(UUID_1);
  });

  it("waliduje schematy firmy i zarządzania domenami", () => {
    expect(MAX_ORGANIZATION_DOMAINS).toBe(20);

    expect(DomainName.parse("  ACME.EU  ")).toBe("acme.eu");
    expect(DomainName.parse("sub.acme-group.co.uk")).toBe("sub.acme-group.co.uk");
    expect(DomainName.parse("a.pl")).toBe("a.pl");
    for (const invalid of [
      "",
      "a.b",
      "localhost",
      "-acme.eu",
      "acme-.eu",
      "acme..eu",
      "acme.123",
      "https://acme.eu",
      "anna@acme.eu",
      `${"a".repeat(64)}.eu`,
      `${"a.".repeat(127)}eu`,
    ]) {
      expect(DomainName.safeParse(invalid).success, `Powinno odrzucić domenę "${invalid}"`).toBe(false);
    }

    expect(UpdateOrganization.parse({ name: "  Acme Europe Sp. z o.o.  " })).toEqual({
      name: "Acme Europe Sp. z o.o.",
    });
    expect(UpdateOrganization.safeParse({ name: "A" }).success).toBe(false);
    expect(UpdateOrganization.safeParse({ name: "   " }).success).toBe(false);
    expect(UpdateOrganization.safeParse({ name: "a".repeat(121) }).success).toBe(false);
    expect(UpdateOrganization.safeParse({ name: "Acme", status: "ACTIVE" }).success).toBe(false);

    expect(CreateOrganizationDomain.parse({ domain: "  Acme.EU " })).toEqual({ domain: "acme.eu" });
    expect(CreateOrganizationDomain.safeParse({ domain: "acme.eu", isPrimary: true }).success).toBe(false);

    expect(VerifyOrganizationDomain.parse({})).toEqual({});
    expect(VerifyOrganizationDomain.parse({ trustLocally: true })).toEqual({ trustLocally: true });
    expect(VerifyOrganizationDomain.parse({ trustLocally: false })).toEqual({ trustLocally: false });
    expect(VerifyOrganizationDomain.safeParse({ trustLocally: "1" }).success).toBe(false);
    expect(VerifyOrganizationDomain.safeParse({ extra: true }).success).toBe(false);

    const parsedDomain = OrganizationDomain.parse({
      id: UUID_1,
      domain: "acme.eu",
      status: "PENDING",
      isPrimary: false,
      verifiedAt: null,
      lastCheckedAt: null,
      verificationTxtName: "_monorise-verification.acme.eu",
      verificationTxtValue: "monorise-verification=abc",
    });
    expect(parsedDomain.verificationTxtName).toBe("_monorise-verification.acme.eu");

    const parsedOrg = Organization.parse({
      id: UUID_2,
      name: "Acme",
      status: "ACTIVE",
      timeZone: "Europe/Warsaw",
      defaultWorkSchedule: { "1": 480, "2": 480, "3": 480, "4": 480, "5": 480 },
      domains: [parsedDomain],
      createdAt: "2026-11-26T10:00:00.000Z",
    });
    expect(parsedOrg.domains).toHaveLength(1);
    expect(parsedOrg.timeZone).toBe("Europe/Warsaw");
    expect(parsedOrg.defaultWorkSchedule).toEqual({ "1": 480, "2": 480, "3": 480, "4": 480, "5": 480 });
  });

  it("waliduje schematy dostępu do produktów, aplikacji i migawki uprawnień", () => {
    expect(
      Entitlement.parse({
        id: UUID_1,
        product: "timotime",
        planId: null,
        sourceType: "MANUAL",
        status: "ACTIVE",
        isActive: true,
        startsAt: "2026-11-24T12:00:00.000Z",
        endsAt: null,
        suspendedReason: null,
        createdAt: "2026-11-24T12:00:00.000Z",
        updatedAt: "2026-11-24T12:00:00.000Z",
      }).isActive,
    ).toBe(true);

    expect(CreateAppAccess.parse({ accountId: UUID_1, product: "timotime" })).toEqual({
      accountId: UUID_1,
      product: "timotime",
    });
    expect(CreateAppAccess.safeParse({ accountId: "bad", product: "timotime" }).success).toBe(false);

    expect(
      AppAccess.parse({
        id: UUID_1,
        accountId: UUID_2,
        product: "timotime",
        status: "ACTIVE",
        grantedByAccountId: UUID_3,
        createdAt: "2026-11-24T12:00:00.000Z",
        revokedAt: null,
      }).status,
    ).toBe("ACTIVE");

    expect(
      PermissionSnapshot.parse({
        accountId: UUID_1,
        organizationId: UUID_2,
        authzRevision: 3,
        isOwner: false,
        products: ["timotime"],
        grants: [
          {
            permission: "timotime.entries.approve",
            scope: { type: "UNIT", unitId: UUID_3 },
            validFrom: null,
            validUntil: null,
          },
        ],
        units: [{ id: UUID_3, parentId: null }],
      }).products,
    ).toEqual(["timotime"]);

    expect(DIRECTORY_READ_SCOPE).toBe("core:directory.read");
    expect(
      DirectoryUnitMember.parse({
        unitId: UUID_1,
        employeeId: UUID_2,
        accountId: UUID_3,
        role: "LEADER",
        workSchedule: { "1": 480, "2": 480 },
        effectiveWorkSchedule: { "1": 480, "2": 480 },
      }),
    ).toMatchObject({
      accountId: UUID_3,
      workSchedule: { "1": 480, "2": 480 },
      effectiveWorkSchedule: { "1": 480, "2": 480 },
    });
    expect(
      DirectoryEmployee.parse({
        id: UUID_1,
        accountId: null,
        firstName: "Anna",
        lastName: "Nowak",
        status: "ACTIVE",
        workSchedule: null,
        effectiveWorkSchedule: { "1": 480, "2": 480, "3": 480, "4": 480, "5": 480 },
      }),
    ).toMatchObject({
      accountId: null,
      workSchedule: null,
      effectiveWorkSchedule: { "1": 480, "2": 480, "3": 480, "4": 480, "5": 480 },
    });
    expect(
      DirectoryOrganization.parse({
        id: UUID_2,
        name: "Acme",
        status: "ACTIVE",
        timeZone: "Europe/Warsaw",
        defaultWorkSchedule: null,
      }),
    ).toEqual({
      id: UUID_2,
      name: "Acme",
      status: "ACTIVE",
      timeZone: "Europe/Warsaw",
      defaultWorkSchedule: null,
    });
  });

  it("waliduje schematy zaproszeń pracowników i aktywacji konta", () => {
    expect(INVITATION_TTL_DAYS).toBe(7);
    expect(INVITATION_TTL_MS).toBe(7 * 24 * 60 * 60 * 1000);
    expect(InvitationStatus.parse("PENDING")).toBe("PENDING");
    expect(MailDeliveryStatus.parse("PENDING")).toBe("PENDING");
    expect(MailDeliveryStatus.parse("SENT")).toBe("SENT");
    expect(MailDeliveryStatus.parse("FAILED")).toBe("FAILED");
    expect(MailDeliveryStatus.parse("CANCELLED")).toBe("CANCELLED");

    expect(
      InvitationDelivery.parse({
        status: null,
        attempts: 0,
        lastAttemptAt: null,
        sentAt: null,
      }),
    ).toEqual({
      status: null,
      attempts: 0,
      lastAttemptAt: null,
      sentAt: null,
    });
    expect(
      InvitationDelivery.safeParse({
        status: "SENT",
        attempts: -1,
        lastAttemptAt: null,
        sentAt: null,
      }).success,
    ).toBe(false);

    expect(
      CreateInvitation.parse({
        email: "jan@acme.com",
        firstName: " Jan ",
        lastName: " Kowalski ",
      }),
    ).toEqual({
      email: "jan@acme.com",
      firstName: "Jan",
      lastName: "Kowalski",
    });

    expect(CreateInvitation.parse({ email: "jan@acme.com", employeeId: UUID_1 })).toEqual({
      email: "jan@acme.com",
      employeeId: UUID_1,
    });

    expect(CreateInvitation.safeParse({ email: "jan@acme.com" }).success).toBe(false);
    expect(CreateInvitation.safeParse({ email: "jan@acme.com", firstName: "Jan" }).success).toBe(false);
    expect(CreateInvitation.safeParse({ email: "jan@acme.com", lastName: "Kowalski" }).success).toBe(false);
    expect(CreateInvitation.safeParse({ email: "nie-email", employeeId: UUID_1 }).success).toBe(false);

    expect(
      Invitation.parse({
        id: UUID_1,
        accountId: UUID_2,
        employeeId: UUID_3,
        email: "jan@acme.com",
        status: "PENDING",
        expiresAt: "2026-12-02T12:00:00.000Z",
        invitedByAccountId: null,
        acceptedAt: null,
        delivery: {
          status: "PENDING",
          attempts: 0,
          lastAttemptAt: null,
          sentAt: null,
        },
        createdAt: "2026-11-25T12:00:00.000Z",
        updatedAt: "2026-11-25T12:00:00.000Z",
      }).invitedByAccountId,
    ).toBeNull();

    expect(AcceptInvitationRequest.safeParse({ token: "abc", password: "za-krotkie" }).success).toBe(false);
    expect(AcceptInvitationRequest.safeParse({ token: "", password: "dlugie-haslo-123" }).success).toBe(false);
    expect(AcceptInvitationRequest.parse({ token: " token-123 ", password: "dlugie-haslo-123" })).toEqual({
      token: "token-123",
      password: "dlugie-haslo-123",
    });
  });

  it("waliduje nagłówek Idempotency-Key i stałe czasu życia", () => {
    expect(IDEMPOTENCY_KEY_HEADER).toBe("Idempotency-Key");
    expect(IDEMPOTENCY_REPLAYED_HEADER).toBe("Idempotency-Replayed");
    expect(IDEMPOTENCY_KEY_MAX_LENGTH).toBe(255);
    expect(IDEMPOTENCY_KEY_TTL_HOURS).toBe(24);
    expect(IDEMPOTENCY_KEY_TTL_MS).toBe(24 * 60 * 60 * 1000);

    expect(IdempotencyKeyHeader.parse("a")).toBe("a");
    expect(IdempotencyKeyHeader.parse(UUID_1)).toBe(UUID_1);
    expect(IdempotencyKeyHeader.parse("a".repeat(255))).toBe("a".repeat(255));
    expect(IdempotencyKeyHeader.parse("key with space")).toBe("key with space");

    expect(IdempotencyKeyHeader.safeParse("").success).toBe(false);
    expect(IdempotencyKeyHeader.safeParse("   ").success).toBe(false);
    expect(IdempotencyKeyHeader.safeParse(" leading").success).toBe(false);
    expect(IdempotencyKeyHeader.safeParse("trailing ").success).toBe(false);
    expect(IdempotencyKeyHeader.safeParse("a".repeat(256)).success).toBe(false);
    expect(IdempotencyKeyHeader.safeParse("bad\tkey").success).toBe(false);
    expect(IdempotencyKeyHeader.safeParse("bad\nkey").success).toBe(false);
    expect(IdempotencyKeyHeader.safeParse("bad\x7fkey").success).toBe(false);
    expect(IdempotencyKeyHeader.safeParse("klucz-ą").success).toBe(false);
  });

  it("waliduje schematy dziennika zdarzeń firmy i parametry zapytania", () => {
    expect(AUDIT_LOG_RETENTION_DAYS).toBe(730);
    expect(AUDIT_LOG_RETENTION_MS).toBe(730 * 24 * 60 * 60 * 1000);

    for (const actorType of ["ACCOUNT", "OPERATOR", "SYSTEM", "PRODUCT"]) {
      expect(AuditActorType.parse(actorType)).toBe(actorType);
    }
    expect(AuditActorType.safeParse("ADMIN").success).toBe(false);

    expect(
      ListAuditLogQuery.parse({
        limit: "25",
        actorAccountId: UUID_1,
        actorType: "ACCOUNT",
        action: " role.assigned ",
        resourceType: " role_assignment ",
        resourceId: ` ${UUID_2} `,
        from: "2026-11-01T00:00:00.000Z",
        to: "2026-11-26T23:59:59.000Z",
      }),
    ).toEqual({
      limit: 25,
      actorAccountId: UUID_1,
      actorType: "ACCOUNT",
      action: "role.assigned",
      resourceType: "role_assignment",
      resourceId: UUID_2,
      from: "2026-11-01T00:00:00.000Z",
      to: "2026-11-26T23:59:59.000Z",
    });

    expect(ListAuditLogQuery.parse({})).toEqual({ limit: DEFAULT_PAGE_LIMIT });
    expect(ListAuditLogQuery.safeParse({ limit: MAX_PAGE_LIMIT + 1 }).success).toBe(false);
    expect(ListAuditLogQuery.safeParse({ limit: 0 }).success).toBe(false);
    expect(ListAuditLogQuery.safeParse({ actorAccountId: "not-a-uuid" }).success).toBe(false);
    expect(ListAuditLogQuery.safeParse({ actorType: "UNKNOWN" }).success).toBe(false);
    expect(ListAuditLogQuery.safeParse({ action: "   " }).success).toBe(false);
    expect(ListAuditLogQuery.safeParse({ from: "2026-11-26" }).success).toBe(false);

    const invertedRange = ListAuditLogQuery.safeParse({
      from: "2026-11-26T12:00:00.000Z",
      to: "2026-11-26T11:59:59.000Z",
    });
    expect(invertedRange.success).toBe(false);
    if (!invertedRange.success) {
      expect(invertedRange.error.issues[0]?.path).toEqual(["to"]);
    }

    expect(
      ListAuditLogQuery.safeParse({
        from: "2026-11-26T12:00:00.000Z",
        to: "2026-11-26T12:00:00.000Z",
      }).success,
    ).toBe(true);

    const entry = AuditLogEntry.parse({
      id: UUID_1,
      actorType: "ACCOUNT",
      actorAccountId: UUID_2,
      actorDisplayName: "Anna Kowalska",
      product: "timotime",
      action: "app_access.revoked",
      actionLabel: "Wyłączono dostęp do aplikacji",
      resourceType: "app_access",
      resourceId: UUID_3,
      metadata: { product: "timotime", accountId: UUID_2 },
      ipAddress: "127.0.0.1",
      userAgent: "MonorisePortal/1.0",
      requestId: "req_1234567890abcdef",
      supportAccessGrantId: null,
      createdAt: "2026-11-26T14:05:00.000Z",
    });
    expect(entry.actorDisplayName).toBe("Anna Kowalska");
    expect(entry.product).toBe("timotime");
  });

  it("definiuje stały katalog kategorii powiadomień, zakres i schematy API (ADR-0048)", () => {
    expect(NOTIFICATIONS_SEND_SCOPE).toBe("core:notifications.send");
    expect(NOTIFICATION_TITLE_MAX_LENGTH).toBe(200);
    expect(NOTIFICATION_BODY_MAX_LENGTH).toBe(4000);

    expect(NOTIFICATION_CATEGORY_KEYS).toEqual([
      "security",
      "account",
      "timotime.reminders",
      "kivotasks.assignments",
      "avenmail.alerts",
    ]);
    expect(NOTIFICATION_CATEGORIES).toHaveLength(5);
    expect(getNotificationCategory("avenmail.alerts")).toMatchObject({
      product: "avenmail",
      channel: "notifications",
      optional: true,
    });

    expect(getNotificationCategory("security")).toMatchObject({
      key: "security",
      product: null,
      channel: "login",
      optional: false,
    });
    expect(getNotificationCategory("account")).toMatchObject({
      key: "account",
      product: null,
      channel: "login",
      optional: false,
    });
    expect(getNotificationCategory("timotime.reminders")).toMatchObject({
      key: "timotime.reminders",
      product: "timotime",
      channel: "notifications",
      optional: true,
    });
    expect(getNotificationCategory("kivotasks.assignments")).toMatchObject({
      key: "kivotasks.assignments",
      product: "kivotasks",
      channel: "notifications",
      optional: true,
    });
    expect(getNotificationCategory("unknown.category")).toBeUndefined();

    expect(NotificationCategoryKey.safeParse("timotime.reminders").success).toBe(true);
    expect(NotificationCategoryKey.safeParse("other.category").success).toBe(false);
    expect(NotificationMailChannel.parse("login")).toBe("login");
    expect(NotificationMailChannel.parse("notifications")).toBe("notifications");
    expect(NotificationChannel.parse("EMAIL")).toBe("EMAIL");
    expect(NotificationChannel.parse("PUSH")).toBe("PUSH");
    expect(NotificationStatus.parse("QUEUED")).toBe("QUEUED");
    expect(NotificationSkipReason.parse("PREFERENCE_OFF")).toBe("PREFERENCE_OFF");
    expect(NotificationSkipReason.parse("NO_ACCESS")).toBe("NO_ACCESS");

    expect(
      CreateNotification.parse({
        recipientAccountId: UUID_1,
        category: "kivotasks.assignments",
        title: "  Przypisano zadanie KT-12  ",
        body: "  Anna przypisała Ci zadanie.\nSprawdź szczegóły.  ",
        actionUrl: "https://kivotasks.monorise.studio/issues/KT-12",
      }),
    ).toEqual({
      recipientAccountId: UUID_1,
      category: "kivotasks.assignments",
      title: "Przypisano zadanie KT-12",
      body: "Anna przypisała Ci zadanie.\nSprawdź szczegóły.",
      actionUrl: "https://kivotasks.monorise.studio/issues/KT-12",
    });

    expect(
      CreateNotification.parse({
        recipientAccountId: UUID_1,
        category: "timotime.reminders",
        title: "Uzupełnij czas pracy",
        body: "Brakuje wpisu za piątek.",
      }),
    ).toEqual({
      recipientAccountId: UUID_1,
      category: "timotime.reminders",
      title: "Uzupełnij czas pracy",
      body: "Brakuje wpisu za piątek.",
    });

    expect(
      CreateNotification.safeParse({
        recipientAccountId: UUID_1,
        category: "timotime.reminders",
        title: "   ",
        body: "Treść",
      }).success,
    ).toBe(false);
    expect(
      CreateNotification.safeParse({
        recipientAccountId: UUID_1,
        category: "timotime.reminders",
        title: "Linia 1\nLinia 2",
        body: "Treść",
      }).success,
    ).toBe(false);
    expect(
      CreateNotification.safeParse({
        recipientAccountId: UUID_1,
        category: "timotime.reminders",
        title: "a".repeat(201),
        body: "Treść",
      }).success,
    ).toBe(false);
    expect(
      CreateNotification.safeParse({
        recipientAccountId: UUID_1,
        category: "timotime.reminders",
        title: "Tytuł",
        body: "b".repeat(4001),
      }).success,
    ).toBe(false);
    expect(
      CreateNotification.safeParse({
        recipientAccountId: UUID_1,
        category: "timotime.reminders",
        title: "Tytuł",
        body: "Treść",
        actionUrl: "not-a-url",
      }).success,
    ).toBe(false);
    for (const unsafeUrl of [
      "https://kivotasks.monorise.studio\\@evil.example/x",
      "https://kivotasks.monorise.studio/issues/KT 1",
      " https://kivotasks.monorise.studio/issues/KT-1",
      "https://kivotasks.monorise.studio/issues/KT-1\u0000",
      "https://kivotasks.monorise.studio/issues/KT-1\t",
    ]) {
      expect(
        CreateNotification.safeParse({
          recipientAccountId: UUID_1,
          category: "timotime.reminders",
          title: "Tytuł",
          body: "Treść",
          actionUrl: unsafeUrl,
        }).success,
        `Powinno odrzucić ${JSON.stringify(unsafeUrl)}`,
      ).toBe(false);
    }
    expect(
      CreateNotification.safeParse({
        recipientAccountId: UUID_1,
        category: "timotime.reminders",
        title: "Tytuł",
        body: "Treść",
        extra: true,
      }).success,
    ).toBe(false);

    expect(NotificationResult.parse({ id: UUID_1, status: "QUEUED", skipReason: null })).toEqual({
      id: UUID_1,
      status: "QUEUED",
      skipReason: null,
    });
    expect(NotificationResult.parse({ id: UUID_1, status: "SKIPPED", skipReason: "PREFERENCE_OFF" })).toEqual({
      id: UUID_1,
      status: "SKIPPED",
      skipReason: "PREFERENCE_OFF",
    });

    expect(
      NotificationPreference.parse({
        category: "security",
        product: null,
        channel: "login",
        optional: false,
        name: "Bezpieczeństwo",
        description: "Wiadomości dotyczące bezpieczeństwa konta.",
        enabled: true,
      }).optional,
    ).toBe(false);

    expect(UpdateNotificationPreference.parse({ enabled: false })).toEqual({ enabled: false });
    expect(UpdateNotificationPreference.safeParse({ enabled: "false" }).success).toBe(false);
    expect(UpdateNotificationPreference.safeParse({ enabled: false, extra: 1 }).success).toBe(false);

    expect(UnsubscribeNotificationResult.parse({ category: "timotime.reminders", enabled: false })).toEqual({
      category: "timotime.reminders",
      enabled: false,
    });
    expect(UnsubscribeNotificationResult.safeParse({ category: "timotime.reminders", enabled: true }).success).toBe(
      false,
    );
  });

  it("waliduje harmonogram pracy (WorkSchedule), wylicza minuty tygodniowe i FTE oraz strefę czasową firmy (TimeZone)", () => {
    expect(DEFAULT_ORGANIZATION_TIME_ZONE).toBe("Europe/Warsaw");
    expect(WORK_SCHEDULE_MAX_DAY_MINUTES).toBe(1440);
    expect(WORK_SCHEDULE_FULL_TIME_MINUTES).toBe(2400);

    const annaFullTime = { "1": 480, "2": 480, "3": 480, "4": 480, "5": 480 };
    const janPartTime = { "1": 240, "2": 240, "3": 240 };

    expect(WorkSchedule.parse(annaFullTime)).toEqual(annaFullTime);
    expect(WorkSchedule.parse(janPartTime)).toEqual(janPartTime);
    expect(WorkSchedule.parse({})).toEqual({});
    expect(WorkSchedule.parse({ "1": 0, "7": 1440 })).toEqual({ "1": 0, "7": 1440 });

    // Pomocniki FTE i sumy tygodniowej
    expect(workScheduleWeeklyMinutes(annaFullTime)).toBe(2400);
    expect(workScheduleFte(annaFullTime)).toBe(1);
    expect(workScheduleWeeklyMinutes(janPartTime)).toBe(720);
    expect(workScheduleFte(janPartTime)).toBe(0.3);
    expect(workScheduleWeeklyMinutes({})).toBe(0);
    expect(workScheduleFte({})).toBe(0);
    expect(workScheduleWeeklyMinutes(null)).toBeNull();
    expect(workScheduleFte(null)).toBeNull();
    expect(workScheduleWeeklyMinutes(undefined)).toBeNull();
    expect(workScheduleFte(undefined)).toBeNull();

    // Porównywanie harmonogramów niezależnie od kolejności kluczy
    expect(workScheduleEquals(null, null)).toBe(true);
    expect(workScheduleEquals(null, {})).toBe(false);
    expect(workScheduleEquals({ "1": 480, "2": 240 }, { "2": 240, "1": 480 })).toBe(true);
    expect(workScheduleEquals({ "1": 480 }, { "1": 240 })).toBe(false);
    expect(workScheduleEquals({ "1": 0 }, {})).toBe(false);

    // Niepoprawne harmonogramy: klucz 0, klucz 8, obcy klucz, >1440, <0, ułamek, string, null w polu dnia, tablica, prymityw
    for (const badSchedule of [
      { "0": 480 },
      { "8": 480 },
      { monday: 480 },
      { "1": -1 },
      { "1": 1441 },
      { "1": 480.5 },
      { "1": "480" },
      { "1": null },
      { "1": true },
      [480, 480],
      480,
      "480",
      null,
    ]) {
      expect(
        WorkSchedule.safeParse(badSchedule).success,
        `Powinno odrzucić harmonogram ${JSON.stringify(badSchedule)}`,
      ).toBe(false);
    }

    // UpdateEmployee akceptuje workSchedule (obiekt albo null)
    expect(UpdateEmployee.parse({ workSchedule: annaFullTime })).toEqual({ workSchedule: annaFullTime });
    expect(UpdateEmployee.parse({ workSchedule: null })).toEqual({ workSchedule: null });
    expect(UpdateEmployee.safeParse({ workSchedule: { "0": 480 } }).success).toBe(false);
    expect(UpdateEmployee.safeParse({ workSchedule: [480] }).success).toBe(false);

    // Poprawne strefy IANA
    for (const validTz of [
      "Europe/Warsaw",
      "  Europe/London  ",
      "America/New_York",
      "Asia/Tokyo",
      "UTC",
      "Etc/UTC",
      "Europe/Kyiv",
    ]) {
      const parsed = TimeZone.safeParse(validTz);
      expect(parsed.success, `Powinno przyjąć strefę "${validTz}"`).toBe(true);
      if (parsed.success) {
        expect(parsed.data).toBe(validTz.trim());
        expect(isValidIanaTimeZone(parsed.data)).toBe(true);
      }
    }

    // Niepoprawne strefy czasowe
    for (const badTz of [
      "",
      "   ",
      "Mars/Olympus",
      "Europe/Nowhere",
      "+02:00",
      "-05:00",
      "GMT+2",
      "EST",
      "CET",
      "europe/warsaw",
      "Europe/warsaw",
    ]) {
      expect(TimeZone.safeParse(badTz).success, `Powinno odrzucić strefę "${badTz}"`).toBe(false);
    }

    // Efektywny harmonogram: własny pracownika -> domyślny firmy -> null
    const companyDefault = { "1": 480, "2": 480, "3": 480, "4": 480, "5": 480 };
    // Jan z własnym harmonogramem zachowuje swój mimo domyślnego harmonogramu firmy
    expect(effectiveWorkSchedule(janPartTime, companyDefault)).toEqual(janPartTime);
    // Anna bez indywidualnego harmonogramu dostaje domyślny harmonogram firmy
    expect(effectiveWorkSchedule(null, companyDefault)).toEqual(companyDefault);
    expect(effectiveWorkSchedule(undefined, companyDefault)).toEqual(companyDefault);
    // Jawny pusty harmonogram pracownika {} nie spada do domyślnego firmy
    expect(effectiveWorkSchedule({}, companyDefault)).toEqual({});
    // Oba nieustawione -> null
    expect(effectiveWorkSchedule(null, null)).toBeNull();
    expect(effectiveWorkSchedule(undefined, undefined)).toBeNull();

    // UpdateOrganization akceptuje samo name, samo timeZone, samo defaultWorkSchedule (obiekt albo null), dowolną kombinację; odrzuca {} i błędne wartości
    expect(UpdateOrganization.parse({ timeZone: "  America/New_York " })).toEqual({ timeZone: "America/New_York" });
    expect(UpdateOrganization.parse({ defaultWorkSchedule: companyDefault })).toEqual({
      defaultWorkSchedule: companyDefault,
    });
    expect(UpdateOrganization.parse({ defaultWorkSchedule: null })).toEqual({ defaultWorkSchedule: null });
    expect(UpdateOrganization.parse({ name: "Acme", timeZone: "UTC", defaultWorkSchedule: janPartTime })).toEqual({
      name: "Acme",
      timeZone: "UTC",
      defaultWorkSchedule: janPartTime,
    });
    expect(UpdateOrganization.safeParse({}).success).toBe(false);
    expect(UpdateOrganization.safeParse({ timeZone: null }).success).toBe(false);
    expect(UpdateOrganization.safeParse({ timeZone: "Mars/Olympus" }).success).toBe(false);
    expect(UpdateOrganization.safeParse({ defaultWorkSchedule: { "0": 480 } }).success).toBe(false);
    expect(UpdateOrganization.safeParse({ defaultWorkSchedule: [480] }).success).toBe(false);
  });
});
