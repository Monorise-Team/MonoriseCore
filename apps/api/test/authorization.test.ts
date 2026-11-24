import { CORE_PERMISSIONS } from "@core/contracts";
import { coreEvents, fromOutboxRecord } from "@monorise-team/events";
import { PermissionError, type PermissionSnapshot } from "@monorise-team/permissions";
import { describe, expect, it } from "vitest";
import {
  assertCanAssignInScope,
  assertCanDelegateRole,
  assertCanManageAppAccessForUnits,
  assertCorePermission,
  canViewAllAppAccess,
  canViewAllRoleAssignments,
  hasAnyAppAccessManagePermission,
  hasAnyRoleAssignPermission,
  toGrantScope,
} from "../src/authorization.js";
import { isEntitlementActive } from "../src/entitlements.js";
import { buildPermissionsChangedRecord } from "../src/outbox.js";

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

  it("egzekwuje core.app_access.manage po jednostkach pracownika (brak jednostek wymaga ORGANIZATION)", () => {
    const owner = makeSnapshot({ isOwner: true });
    expect(() => assertCanManageAppAccessForUnits(owner, [])).not.toThrow();
    expect(() => assertCanManageAppAccessForUnits(owner, [WARSZAWA_ID])).not.toThrow();
    expect(canViewAllAppAccess(owner)).toBe(true);
    expect(hasAnyAppAccessManagePermission(owner)).toBe(true);

    const krakowManager = makeSnapshot({
      grants: [{ permission: CORE_PERMISSIONS.keys["app_access.manage"], scope: { type: "UNIT", unitId: KRAKOW_ID } }],
    });
    expect(() => assertCanManageAppAccessForUnits(krakowManager, [KRAKOW_ID])).not.toThrow();
    expect(() => assertCanManageAppAccessForUnits(krakowManager, [MAGAZYN_ID])).not.toThrow();
    expect(() => assertCanManageAppAccessForUnits(krakowManager, [WARSZAWA_ID, MAGAZYN_ID])).not.toThrow();
    expect(() => assertCanManageAppAccessForUnits(krakowManager, [WARSZAWA_ID])).toThrow(PermissionError);
    expect(() => assertCanManageAppAccessForUnits(krakowManager, [])).toThrow(PermissionError);
    expect(canViewAllAppAccess(krakowManager)).toBe(true);
    expect(hasAnyAppAccessManagePermission(krakowManager)).toBe(true);

    const orgAdmin = makeSnapshot({
      grants: [{ permission: CORE_PERMISSIONS.keys["app_access.manage"], scope: { type: "ORGANIZATION" } }],
    });
    expect(() => assertCanManageAppAccessForUnits(orgAdmin, [])).not.toThrow();
    expect(() => assertCanManageAppAccessForUnits(orgAdmin, [WARSZAWA_ID])).not.toThrow();

    const regular = makeSnapshot();
    expect(() => assertCanManageAppAccessForUnits(regular, [KRAKOW_ID])).toThrow(PermissionError);
    expect(canViewAllAppAccess(regular)).toBe(false);
    expect(hasAnyAppAccessManagePermission(regular)).toBe(false);
  });

  it("wyznacza aktywność Entitlement na podstawie statusu oraz przedziału [startsAt, endsAt)", () => {
    const now = new Date("2026-11-24T12:00:00.000Z");
    const past = new Date("2026-11-24T11:00:00.000Z");
    const future = new Date("2026-11-24T13:00:00.000Z");

    expect(isEntitlementActive({ status: "ACTIVE", startsAt: past, endsAt: null }, now)).toBe(true);
    expect(isEntitlementActive({ status: "ACTIVE", startsAt: now, endsAt: future }, now)).toBe(true);
    expect(isEntitlementActive({ status: "ACTIVE", startsAt: future, endsAt: null }, now)).toBe(false);
    expect(isEntitlementActive({ status: "ACTIVE", startsAt: past, endsAt: now }, now)).toBe(false);
    expect(isEntitlementActive({ status: "SUSPENDED", startsAt: past, endsAt: future }, now)).toBe(false);
    expect(isEntitlementActive({ status: "ENDED", startsAt: past, endsAt: future }, now)).toBe(false);
  });

  it("buduje poprawny rekord outbox dla organization.permissions.changed zgodny z katalogiem coreEvents", () => {
    const record = buildPermissionsChangedRecord({
      organizationId: ORG_ID,
      accountId: ACC_ID,
      authzRevision: 7,
    });
    expect(record).toMatchObject({
      organizationId: ORG_ID,
      type: "organization.permissions.changed",
      version: 1,
      resourceType: "account",
      resourceId: ACC_ID,
      resourceVersion: 7,
      payload: { authzRevision: 7 },
      publishedAt: null,
    });

    const envelope = fromOutboxRecord(
      {
        id: record.id,
        organizationId: record.organizationId ?? null,
        type: record.type,
        version: record.version,
        resourceType: record.resourceType,
        resourceId: record.resourceId,
        resourceVersion: record.resourceVersion,
        payload: record.payload as Record<string, unknown>,
        occurredAt: record.occurredAt as Date,
        publishedAt: null,
      },
      { source: "core" },
    );
    const parsed = coreEvents.parse(envelope);
    expect(parsed.status).toBe("known");
    if (parsed.status === "known") {
      expect(parsed.event.type).toBe("organization.permissions.changed");
      expect(parsed.event.data).toEqual({ authzRevision: 7 });
    }
  });
});
