import type * as CoreDb from "@core/db";
import { domainTxtValue as computeDomainTxtValue, hashToken } from "@core/db";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const ORG_ID = "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6b01";
const ACC_ID = "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6b11";
const DOM_ID = "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6b21";

interface MockState {
  orgStatus: "PENDING_VERIFICATION" | "ACTIVE" | "SUSPENDED" | "OFFBOARDING" | "DELETED";
  domain: {
    id: string;
    domain: string;
    status: "PENDING" | "VERIFIED" | "FAILED" | "REVOKED";
    verificationTokenHash: string | null;
    verifiedAt: Date | null;
    lastCheckedAt: Date | null;
    isPrimary: boolean;
  };
  audits: {
    action: string;
    resourceType: string;
    resourceId: string;
    actorAccountId: string | null;
    metadata: unknown;
    ipAddress: string | null;
    userAgent: string | null;
  }[];
}

const state: MockState = {
  orgStatus: "PENDING_VERIFICATION",
  domain: {
    id: DOM_ID,
    domain: "acme.test",
    status: "PENDING",
    verificationTokenHash: null,
    verifiedAt: null,
    lastCheckedAt: null,
    isPrimary: true,
  },
  audits: [],
};

vi.mock("@core/db", async (importOriginal) => {
  const actual = await importOriginal<typeof CoreDb>();
  return {
    ...actual,
    accountClaims: vi.fn(async () => ({
      organizationId: ORG_ID,
      employeeId: "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6b12",
      authzRevision: 0,
      accountStatus: "ACTIVE",
      organizationStatus: state.orgStatus,
    })),
    withOrganization: vi.fn(async (_db: unknown, _orgId: string, fn: (tx: unknown) => Promise<unknown>) => {
      const tx = {
        $executeRaw: async () => 1,
        organizationDomain: {
          findFirst: async () => (state.domain.isPrimary ? { ...state.domain } : null),
          findUnique: async ({ where }: { where: { id: string } }) =>
            where.id === state.domain.id ? { ...state.domain } : null,
          update: async ({ data }: { data: Partial<MockState["domain"]> }) => {
            state.domain = { ...state.domain, ...data };
            return { ...state.domain };
          },
        },
        organization: {
          updateMany: async ({
            where,
            data,
          }: {
            where: { id: string; status?: MockState["orgStatus"] };
            data: { status: MockState["orgStatus"] };
          }) => {
            if (where.id === ORG_ID && (where.status === undefined || state.orgStatus === where.status)) {
              state.orgStatus = data.status;
              return { count: 1 };
            }
            return { count: 0 };
          },
        },
        auditLog: {
          create: async ({ data }: { data: MockState["audits"][number] }) => {
            state.audits.push({
              action: data.action,
              resourceType: data.resourceType,
              resourceId: data.resourceId,
              actorAccountId: data.actorAccountId,
              metadata: data.metadata,
              ipAddress: data.ipAddress,
              userAgent: data.userAgent,
            });
            return data;
          },
        },
      };
      return fn(tx);
    }),
  };
});

vi.mock("@/server/db", () => ({ db: {} }));

const originalVerificationSecret = process.env.CORE_DOMAIN_VERIFICATION_SECRET;

beforeEach(() => {
  delete process.env.CORE_DOMAIN_VERIFICATION_SECRET;
  state.orgStatus = "PENDING_VERIFICATION";
  state.domain = {
    id: DOM_ID,
    domain: "acme.test",
    status: "PENDING",
    verificationTokenHash: hashToken(computeDomainTxtValue(process.env.BETTER_AUTH_SECRET!, ORG_ID, "acme.test")),
    verifiedAt: null,
    lastCheckedAt: null,
    isPrimary: true,
  };
  state.audits = [];
});

afterEach(() => {
  if (originalVerificationSecret === undefined) {
    delete process.env.CORE_DOMAIN_VERIFICATION_SECRET;
  } else {
    process.env.CORE_DOMAIN_VERIFICATION_SECRET = originalVerificationSecret;
  }
});

describe("apps/auth verifyOrganizationDomain i sekret weryfikacji (testy jednostkowe bez bazy)", () => {
  it("używa CORE_DOMAIN_VERIFICATION_SECRET, a przy braku wraca do BETTER_AUTH_SECRET", async () => {
    const { domainTxtValue } = await import("@/server/domains");
    const fallback = domainTxtValue(ORG_ID, "acme.test");
    expect(fallback).toBe(computeDomainTxtValue(process.env.BETTER_AUTH_SECRET!, ORG_ID, "acme.test"));

    process.env.CORE_DOMAIN_VERIFICATION_SECRET = "shared-domain-secret-1234567890";
    const dedicated = domainTxtValue(ORG_ID, "acme.test");
    expect(dedicated).toBe(computeDomainTxtValue("shared-domain-secret-1234567890", ORG_ID, "acme.test"));
    expect(dedicated).not.toBe(fallback);
  });

  it("aktywuje firmę z PENDING_VERIFICATION i zapisuje wpis audytu organization.domain.verified (DNS_TXT)", async () => {
    const { domainTxtValue, verifyOrganizationDomain } = await import("@/server/domains");
    const expected = domainTxtValue(ORG_ID, "acme.test");

    const missing = await verifyOrganizationDomain(ACC_ID, { resolveTxt: async () => [] });
    expect(missing).toEqual({ domain: "acme.test", status: "PENDING" });
    expect(state.orgStatus).toBe("PENDING_VERIFICATION");
    expect(state.domain.lastCheckedAt).not.toBeNull();
    expect(state.audits).toHaveLength(0);

    const verified = await verifyOrganizationDomain(ACC_ID, {
      resolveTxt: async () => [[expected]],
      ipAddress: "127.0.0.1, 10.0.0.1",
      userAgent: "MonoriseTest/1.0",
    });
    expect(verified).toEqual({ domain: "acme.test", status: "VERIFIED" });
    expect(state.orgStatus).toBe("ACTIVE");
    expect(state.domain.verifiedAt).not.toBeNull();
    expect(state.audits).toEqual([
      {
        action: "organization.domain.verified",
        resourceType: "organization_domain",
        resourceId: DOM_ID,
        actorAccountId: ACC_ID,
        metadata: { domain: "acme.test", method: "DNS_TXT" },
        ipAddress: "127.0.0.1",
        userAgent: "MonoriseTest/1.0",
      },
    ]);

    // Powtórne wywołanie jest idempotentne i nie dubluje audytu
    const repeat = await verifyOrganizationDomain(ACC_ID, { trustLocally: true });
    expect(repeat).toEqual({ domain: "acme.test", status: "VERIFIED" });
    expect(state.audits).toHaveLength(1);
  });

  it("nie zmienia statusu firmy SUSPENDED ani OFFBOARDING na ACTIVE i zapisuje audyt DEV_TRUST", async () => {
    const { verifyOrganizationDomain } = await import("@/server/domains");

    for (const status of ["SUSPENDED", "OFFBOARDING"] as const) {
      state.orgStatus = status;
      state.domain.status = "PENDING";
      state.domain.verifiedAt = null;
      state.audits = [];

      const res = await verifyOrganizationDomain(ACC_ID, { trustLocally: true });
      expect(res).toEqual({ domain: "acme.test", status: "VERIFIED" });
      expect(state.orgStatus).toBe(status);
      expect(state.audits).toEqual([
        {
          action: "organization.domain.verified",
          resourceType: "organization_domain",
          resourceId: DOM_ID,
          actorAccountId: ACC_ID,
          metadata: { domain: "acme.test", method: "DEV_TRUST" },
          ipAddress: null,
          userAgent: null,
        },
      ]);
    }
  });
});
