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
  CORE_PERMISSIONS,
  CreateEmployee,
  CreateUnit,
  DEFAULT_PAGE_LIMIT,
  emailDomain,
  Health,
  isFreeEmailDomain,
  MachineTokenClaims,
  MAX_PAGE_LIMIT,
  MAX_PERMISSION_MANIFEST_ENTRIES,
  Me,
  normalizeEmail,
  PageQuery,
  Permission,
  PERMISSIONS_REGISTER_SCOPE,
  ProductKey,
  PutUnitMember,
  RegisterPermissionsRequest,
  RegisterPermissionsResult,
  SignUpRequest,
  Unit,
  UnitMember,
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
      "core.audit.read",
    ]);
    expect(RegisterPermissionsRequest.parse(CORE_PERMISSIONS.manifest)).toHaveLength(5);

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
});
