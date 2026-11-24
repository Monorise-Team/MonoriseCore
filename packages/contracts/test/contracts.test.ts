import { describe, expect, it } from "vitest";
import {
  AccessTokenClaims,
  ApiErrorBody,
  ApiErrorResponse,
  ApiListMeta,
  apiListSuccessSchema,
  ApiMeta,
  apiErrorSchema,
  apiSuccessSchema,
  AppAccess,
  CORE_PERMISSIONS,
  CORE_ROLE_TEMPLATES,
  CopyRole,
  CreateAppAccess,
  CreateEmployee,
  CreateRole,
  CreateRoleAssignment,
  CreateRoleFromScratch,
  CreateUnit,
  DEFAULT_PAGE_LIMIT,
  emailDomain,
  Entitlement,
  Health,
  isFreeEmailDomain,
  MachineTokenClaims,
  MAX_PAGE_LIMIT,
  MAX_PERMISSION_MANIFEST_ENTRIES,
  Me,
  normalizeEmail,
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
  TransferOrganizationOwner,
  Unit,
  UnitMember,
  UpdateRole,
  UpdateUnit,
} from "../src/index.js";

const UUID_1 = "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6a7b";
const UUID_2 = "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6a7c";
const UUID_3 = "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6a7d";

describe("adresy e-mail", () => {
  it("rozpoznaje domenę i normalizuje adres", () => {
    expect(emailDomain("Anna.Kowalska@Acme.COM")).toBe("acme.com");
    expect(normalizeEmail("  Anna@Acme.com ")).toBe("anna@acme.com");
  });

  it("odrzuca darmowe skrzynki, także polskie", () => {
    for (const domain of ["gmail.com", "WP.pl", "onet.pl", "interia.pl", "o2.pl"]) {
      expect(isFreeEmailDomain(domain)).toBe(true);
    }
    expect(isFreeEmailDomain("acme.com")).toBe(false);
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
          firstName: "Anna",
          lastName: "Nowak",
          workEmail: "anna@acme.test",
          jobTitle: null,
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
          firstName: "Anna",
          lastName: "Nowak",
          workEmail: "anna@acme.test",
          jobTitle: null,
          status: "ACTIVE",
        },
        organization: { id: UUID_3, name: "Acme", status: "ACTIVE" },
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
    ]);
    expect(RegisterPermissionsRequest.parse(CORE_PERMISSIONS.manifest)).toHaveLength(6);
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
  });
});
