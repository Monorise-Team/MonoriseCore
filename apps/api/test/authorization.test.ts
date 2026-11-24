import { CORE_PERMISSIONS } from "@core/contracts";
import { PermissionError, type PermissionSnapshot } from "@monorise-team/permissions";
import { describe, expect, it } from "vitest";
import {
  assertCanAssignInScope,
  assertCanDelegateRole,
  assertCorePermission,
  canViewAllRoleAssignments,
  hasAnyRoleAssignPermission,
  toGrantScope,
} from "../src/authorization.js";

const ORG_ID = "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6a00";
const ACC_ID = "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6a01";
const KRAKOW_ID = "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6a10";
const MAGAZYN_ID = "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6a11";
const WARSZAWA_ID = "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6a12";

const UNITS = [
  { id: KRAKOW_ID, parentId: null },
  { id: MAGAZYN_ID, parentId: KRAKOW_ID },
  { id: WARSZAWA_ID, parentId: null },
];

function makeSnapshot(overrides: Partial<PermissionSnapshot> = {}): PermissionSnapshot {
  return {
    accountId: ACC_ID,
    organizationId: ORG_ID,
    authzRevision: 1,
    isOwner: false,
    products: ["core"],
    grants: [],
    units: UNITS,
    ...overrides,
  };
}

describe("authorization (reguły Core oparte na @monorise-team/permissions)", () => {
  it("Owner może wszystko i omija sprawdzanie core.roles.assign oraz delegowania", () => {
    const owner = makeSnapshot({ isOwner: true });

    expect(() => assertCorePermission(owner, CORE_PERMISSIONS.keys["employees.manage"], {})).not.toThrow();
    expect(() => assertCorePermission(owner, CORE_PERMISSIONS.keys["roles.manage"], {})).not.toThrow();
    expect(() => assertCorePermission(owner, CORE_PERMISSIONS.keys["structure.manage"], {})).not.toThrow();
    expect(() => assertCanAssignInScope(owner, { type: "ORGANIZATION" })).not.toThrow();
    expect(() => assertCanAssignInScope(owner, { type: "RESOURCE", resourceId: "proj_1" })).not.toThrow();
    expect(() =>
      assertCanDelegateRole(owner, ["timotime.entries.approve"], { type: "UNIT", unitId: KRAKOW_ID }),
    ).not.toThrow();
    expect(canViewAllRoleAssignments(owner)).toBe(true);
    expect(hasAnyRoleAssignPermission(owner)).toBe(true);
  });

  it("egzekwuje zakres UNIT z dziedziczeniem w poddrzewie oraz ograniczenie delegowania", () => {
    const manager = makeSnapshot({
      products: ["core", "timotime"],
      grants: [
        { permission: CORE_PERMISSIONS.keys["roles.assign"], scope: { type: "UNIT", unitId: KRAKOW_ID } },
        { permission: CORE_PERMISSIONS.keys["structure.manage"], scope: { type: "UNIT", unitId: KRAKOW_ID } },
        { permission: "timotime.entries.read", scope: { type: "UNIT", unitId: KRAKOW_ID } },
        { permission: "timotime.entries.approve", scope: { type: "UNIT", unitId: KRAKOW_ID } },
      ],
    });

    // Kraków i podjednostka Magazyn -> zgoda
    expect(() =>
      assertCorePermission(manager, CORE_PERMISSIONS.keys["structure.manage"], { unitIds: [KRAKOW_ID] }),
    ).not.toThrow();
    expect(() =>
      assertCorePermission(manager, CORE_PERMISSIONS.keys["structure.manage"], { unitIds: [MAGAZYN_ID] }),
    ).not.toThrow();
    expect(() => assertCanAssignInScope(manager, toGrantScope("UNIT", KRAKOW_ID))).not.toThrow();
    expect(() => assertCanAssignInScope(manager, toGrantScope("UNIT", MAGAZYN_ID))).not.toThrow();
    expect(() =>
      assertCanDelegateRole(manager, ["timotime.entries.read", "timotime.entries.approve"], {
        type: "UNIT",
        unitId: MAGAZYN_ID,
      }),
    ).not.toThrow();

    // Warszawa, ORGANIZATION, RESOURCE i brakujące uprawnienie -> PermissionError
    expect(() =>
      assertCorePermission(manager, CORE_PERMISSIONS.keys["structure.manage"], { unitIds: [WARSZAWA_ID] }),
    ).toThrow(PermissionError);
    expect(() => assertCorePermission(manager, CORE_PERMISSIONS.keys["structure.manage"], {})).toThrow(PermissionError);
    expect(() => assertCanAssignInScope(manager, toGrantScope("UNIT", WARSZAWA_ID))).toThrow(PermissionError);
    expect(() => assertCanAssignInScope(manager, toGrantScope("ORGANIZATION", null))).toThrow(PermissionError);
    expect(() => assertCanAssignInScope(manager, toGrantScope("RESOURCE", "proj_1"))).toThrow(PermissionError);
    expect(() =>
      assertCanDelegateRole(manager, ["timotime.entries.read", "timotime.reports.export"], {
        type: "UNIT",
        unitId: KRAKOW_ID,
      }),
    ).toThrow(PermissionError);

    expect(canViewAllRoleAssignments(manager)).toBe(true);
    expect(hasAnyRoleAssignPermission(manager)).toBe(true);
  });

  it("odmawia uprawnień z przypisań wygasłych lub jeszcze nieważnych oraz ukrywa cudze przypisania zwykłemu kontu", () => {
    const past = new Date(Date.now() - 60_000).toISOString();
    const future = new Date(Date.now() + 60_000).toISOString();

    const expired = makeSnapshot({
      grants: [
        {
          permission: CORE_PERMISSIONS.keys["roles.assign"],
          scope: { type: "ORGANIZATION" },
          validUntil: past,
        },
        {
          permission: CORE_PERMISSIONS.keys["roles.manage"],
          scope: { type: "ORGANIZATION" },
          validFrom: future,
        },
      ],
    });

    expect(() => assertCanAssignInScope(expired, { type: "ORGANIZATION" })).toThrow(PermissionError);
    expect(canViewAllRoleAssignments(expired)).toBe(false);
    expect(hasAnyRoleAssignPermission(expired)).toBe(false);
  });

  it("pozwala na RESOURCE przy core.roles.assign z zakresem ORGANIZATION i odpowiednim uprawnieniu", () => {
    const orgAdmin = makeSnapshot({
      products: ["core", "timotime"],
      grants: [
        { permission: CORE_PERMISSIONS.keys["roles.assign"], scope: { type: "ORGANIZATION" } },
        { permission: "timotime.entries.read", scope: { type: "ORGANIZATION" } },
      ],
    });

    const resourceScope = toGrantScope("RESOURCE", "proj_42");
    expect(() => assertCanAssignInScope(orgAdmin, resourceScope)).not.toThrow();
    expect(() => assertCanDelegateRole(orgAdmin, ["timotime.entries.read"], resourceScope)).not.toThrow();
  });
});
