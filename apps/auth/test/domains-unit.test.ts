import { CORE_PERMISSIONS } from "@core/contracts";
import type * as CoreDb from "@core/db";
import { domainTxtValue as computeDomainTxtValue, hashToken } from "@core/db";
import type { NextRequest } from "next/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const ORG_ID = "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6b01";
const OTHER_ORG_ID = "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6b02";
const OWNER_ACC = "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6b11";
const ORG_ADMIN_ACC = "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6b12";
const UNIT_ADMIN_ACC = "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6b13";
const REGULAR_ACC = "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6b14";
const DOM_ID = "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6b21";
const UNIT_ID = "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6b31";

interface MockState {
  sessionUserId: string | null;
  orgStatus: "PENDING_VERIFICATION" | "ACTIVE" | "SUSPENDED" | "OFFBOARDING" | "DELETED";
  ownerAccountId: string | null;
  verifiedOwnerByDomain: Map<string, string>;
  releasedDomains: string[];
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
  dnsResolver: (hostname: string) => Promise<string[][]>;
}

const state: MockState = {
  sessionUserId: OWNER_ACC,
  orgStatus: "PENDING_VERIFICATION",
  ownerAccountId: OWNER_ACC,
  verifiedOwnerByDomain: new Map(),
  releasedDomains: [],
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
  dnsResolver: async () => [],
};

vi.mock("node:dns/promises", () => ({
  resolveTxt: (hostname: string) => state.dnsResolver(hostname),
}));

vi.mock("@core/db", async (importOriginal) => {
  const actual = await importOriginal<typeof CoreDb>();
  return {
    ...actual,
    accountClaims: vi.fn(async () => ({
      organizationId: ORG_ID,
      employeeId: "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6b19",
      authzRevision: 0,
      accountStatus: "ACTIVE",
      organizationStatus: state.orgStatus,
    })),
    domainOwner: vi.fn(async (_db: unknown, domain: string) => {
      const ownerOrgId = state.verifiedOwnerByDomain.get(domain.toLowerCase());
      return ownerOrgId ? { organizationId: ownerOrgId, status: "VERIFIED" as const } : null;
    }),
    releaseCompetingDomainClaims: vi.fn(async (_tx: unknown, domain: string) => {
      state.releasedDomains.push(domain.toLowerCase());
      return 1;
    }),
    withOrganization: vi.fn(async (_db: unknown, _orgId: string, fn: (tx: unknown) => Promise<unknown>) => {
      const tx = {
        $executeRaw: async () => 1,
        organizationDomain: {
          findFirst: async () => (state.domain.isPrimary ? { ...state.domain } : null),
          findUnique: async ({ where }: { where: { id: string } }) =>
            where.id === state.domain.id ? { ...state.domain } : null,
          create: async ({ data }: { data: Record<string, unknown> }) => data,
          update: async ({ data }: { data: Partial<MockState["domain"]> }) => {
            if (data.status === "VERIFIED") {
              const ownerOrgId = state.verifiedOwnerByDomain.get(state.domain.domain.toLowerCase());
              if (ownerOrgId && ownerOrgId !== ORG_ID) {
                throw Object.assign(new Error("organization_domains_domain_verified_key"), { code: "P2002" });
              }
              state.verifiedOwnerByDomain.set(state.domain.domain.toLowerCase(), ORG_ID);
            }
            state.domain = { ...state.domain, ...data };
            return { ...state.domain };
          },
        },
        organization: {
          findUniqueOrThrow: async () => ({
            id: ORG_ID,
            status: state.orgStatus,
            ownerAccountId: state.ownerAccountId,
          }),
          create: async ({ data }: { data: Record<string, unknown> }) => data,
          update: async ({ data }: { data: Record<string, unknown> }) => data,
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
        employee: {
          create: async ({ data }: { data: Record<string, unknown> }) => data,
        },
        account: {
          create: async ({ data }: { data: Record<string, unknown> }) => data,
        },
        roleAssignment: {
          findMany: async ({ where }: { where: { accountId: string } }) => {
            if (where.accountId === ORG_ADMIN_ACC) {
              return [
                {
                  scopeType: "ORGANIZATION",
                  scopeId: null,
                  validFrom: null,
                  validUntil: null,
                  role: {
                    archivedAt: null,
                    permissions: [
                      { permission: { key: CORE_PERMISSIONS.keys["organization.manage"], deprecatedAt: null } },
                    ],
                  },
                },
              ];
            }
            if (where.accountId === UNIT_ADMIN_ACC) {
              return [
                {
                  scopeType: "UNIT",
                  scopeId: UNIT_ID,
                  validFrom: null,
                  validUntil: null,
                  role: {
                    archivedAt: null,
                    permissions: [
                      { permission: { key: CORE_PERMISSIONS.keys["organization.manage"], deprecatedAt: null } },
                    ],
                  },
                },
              ];
            }
            return [];
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

const signUpEmailMock = vi.fn(async () => ({
  user: { id: "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6b99" },
}));

vi.mock("@/server/auth", () => ({
  auth: {
    api: {
      getSession: vi.fn(async () => (state.sessionUserId ? { user: { id: state.sessionUserId } } : null)),
      signUpEmail: signUpEmailMock,
    },
  },
}));

vi.mock("@/server/db", () => ({
  db: {
    authUser: { delete: vi.fn(async () => undefined) },
  },
}));

const originalEnv = {
  CORE_DOMAIN_VERIFICATION_SECRET: process.env.CORE_DOMAIN_VERIFICATION_SECRET,
  CORE_DEV_TRUST_DOMAINS: process.env.CORE_DEV_TRUST_DOMAINS,
  NODE_ENV: process.env.NODE_ENV,
};

function setEnv(
  key: "CORE_DOMAIN_VERIFICATION_SECRET" | "CORE_DEV_TRUST_DOMAINS" | "NODE_ENV",
  value: string | undefined,
) {
  const env = process.env as Record<string, string | undefined>;
  if (value === undefined) delete env[key];
  else env[key] = value;
}

function makeRequest(body: string, headers: Record<string, string> = {}): NextRequest {
  return new Request("http://localhost:3100/api/organization/domain/verify", {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body,
  }) as unknown as NextRequest;
}

beforeEach(() => {
  setEnv("CORE_DOMAIN_VERIFICATION_SECRET", undefined);
  setEnv("CORE_DEV_TRUST_DOMAINS", "1");
  setEnv("NODE_ENV", "test");
  signUpEmailMock.mockClear();

  state.sessionUserId = OWNER_ACC;
  state.orgStatus = "PENDING_VERIFICATION";
  state.ownerAccountId = OWNER_ACC;
  state.verifiedOwnerByDomain = new Map();
  state.releasedDomains = [];
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
  state.dnsResolver = async () => [];
});

afterEach(() => {
  vi.useRealTimers();
  setEnv("CORE_DOMAIN_VERIFICATION_SECRET", originalEnv.CORE_DOMAIN_VERIFICATION_SECRET);
  setEnv("CORE_DEV_TRUST_DOMAINS", originalEnv.CORE_DEV_TRUST_DOMAINS);
  setEnv("NODE_ENV", originalEnv.NODE_ENV);
});

describe("apps/auth domeny: konfiguracja sekretu, dev trust i rotacja (Blocker 1, Nit #9)", () => {
  it("poza produkcją wraca do BETTER_AUTH_SECRET, a na produkcji wymaga CORE_DOMAIN_VERIFICATION_SECRET (>= 32 znaki po trim)", async () => {
    const { config } = await import("@/server/config");
    const { domainTxtValue } = await import("@/server/domains");

    // Poza produkcją -> fallback do BETTER_AUTH_SECRET
    const fallback = domainTxtValue(ORG_ID, "acme.test");
    expect(fallback).toBe(computeDomainTxtValue(process.env.BETTER_AUTH_SECRET!, ORG_ID, "acme.test"));

    // Na produkcji -> brak / za krótki sekret rzuca błąd (brak fallbacku!)
    setEnv("NODE_ENV", "production");
    expect(() => config.domainVerificationSecret).toThrow(/CORE_DOMAIN_VERIFICATION_SECRET/);

    setEnv("CORE_DOMAIN_VERIFICATION_SECRET", `  ${"x".repeat(31)}  `);
    expect(() => config.domainVerificationSecret).toThrow(/32/);

    setEnv("CORE_DOMAIN_VERIFICATION_SECRET", `  ${"x".repeat(32)}  `);
    expect(config.domainVerificationSecret).toBe("x".repeat(32));

    // Nit #9: devTrustDomains wyłączone na produkcji, staging oraz bez NODE_ENV lub bez CORE_DEV_TRUST_DOMAINS=1
    setEnv("CORE_DEV_TRUST_DOMAINS", "1");
    expect(config.devTrustDomains).toBe(false);
    setEnv("NODE_ENV", "staging");
    expect(config.devTrustDomains).toBe(false);
    setEnv("NODE_ENV", undefined);
    expect(config.devTrustDomains).toBe(false);
    setEnv("NODE_ENV", "development");
    expect(config.devTrustDomains).toBe(true);
    setEnv("CORE_DEV_TRUST_DOMAINS", "0");
    expect(config.devTrustDomains).toBe(false);
  });

  it("po zmianie sekretu oczekująca domena weryfikuje się zarówno TXT ze starego, jak i nowego sekretu", async () => {
    const { verifyOrganizationDomain } = await import("@/server/domains");
    const oldSecret = process.env.BETTER_AUTH_SECRET!;
    const newSecret = "rotated-auth-domain-verification-secret-0123456789";
    setEnv("CORE_DOMAIN_VERIFICATION_SECRET", newSecret);

    // 1) Stary TXT zapisany jako verificationTokenHash -> działa
    const oldTxt = computeDomainTxtValue(oldSecret, ORG_ID, "acme.test");
    expect(await verifyOrganizationDomain(OWNER_ACC, { resolveTxt: async () => [[oldTxt]] })).toEqual({
      domain: "acme.test",
      status: "VERIFIED",
    });

    // 2) Nowy TXT pokazywany pod nowym sekretem -> też działa
    state.domain.status = "PENDING";
    state.domain.verifiedAt = null;
    state.orgStatus = "PENDING_VERIFICATION";
    state.verifiedOwnerByDomain.clear();
    const newTxt = computeDomainTxtValue(newSecret, ORG_ID, "acme.test");
    expect(newTxt).not.toBe(oldTxt);
    expect(await verifyOrganizationDomain(OWNER_ACC, { resolveTxt: async () => [[newTxt]] })).toEqual({
      domain: "acme.test",
      status: "VERIFIED",
    });
  });
});

describe("apps/auth verifyOrganizationDomain i widok /account (Blockery 2-3, wygrywa weryfikacja, Should-fix #6)", () => {
  it("aktywuje firmę z PENDING_VERIFICATION (również gdy domena była już VERIFIED), zwalnia cudze roszczenia i zapisuje audyt", async () => {
    const { domainTxtValue, verifyOrganizationDomain } = await import("@/server/domains");
    const expected = domainTxtValue(ORG_ID, "acme.test");

    const missing = await verifyOrganizationDomain(OWNER_ACC, { resolveTxt: async () => [] });
    expect(missing).toEqual({ domain: "acme.test", status: "PENDING" });
    expect(state.orgStatus).toBe("PENDING_VERIFICATION");
    expect(state.domain.lastCheckedAt).not.toBeNull();
    expect(state.audits).toHaveLength(0);

    const verified = await verifyOrganizationDomain(OWNER_ACC, {
      resolveTxt: async () => [[expected]],
      ipAddress: "127.0.0.1, 10.0.0.1",
      userAgent: "MonoriseTest/1.0",
    });
    expect(verified).toEqual({ domain: "acme.test", status: "VERIFIED" });
    expect(state.orgStatus).toBe("ACTIVE");
    expect(state.releasedDomains).toEqual(["acme.test"]);
    expect(state.audits).toEqual([
      {
        action: "organization.domain.verified",
        resourceType: "organization_domain",
        resourceId: DOM_ID,
        actorAccountId: OWNER_ACC,
        metadata: { domain: "acme.test", method: "DNS_TXT" },
        ipAddress: "127.0.0.1",
        userAgent: "MonoriseTest/1.0",
      },
      {
        action: "organization.activated",
        resourceType: "organization",
        resourceId: ORG_ID,
        actorAccountId: OWNER_ACC,
        metadata: {
          previousStatus: "PENDING_VERIFICATION",
          status: "ACTIVE",
          domainId: DOM_ID,
          domain: "acme.test",
        },
        ipAddress: "127.0.0.1",
        userAgent: "MonoriseTest/1.0",
      },
    ]);

    // Powtórne wywołanie na ACTIVE firmie jest idempotentne bez nowego audytu
    expect(await verifyOrganizationDomain(OWNER_ACC, { trustLocally: true })).toEqual({
      domain: "acme.test",
      status: "VERIFIED",
    });
    expect(state.audits).toHaveLength(2);

    // Blocker 2: domena już VERIFIED, ale firma nadal PENDING_VERIFICATION -> aktywuje firmę z audytem organization.activated
    state.orgStatus = "PENDING_VERIFICATION";
    state.audits = [];
    expect(await verifyOrganizationDomain(OWNER_ACC)).toEqual({ domain: "acme.test", status: "VERIFIED" });
    expect(state.orgStatus).toBe("ACTIVE");
    expect(state.audits.map((a) => a.action)).toEqual(["organization.activated"]);
  });

  it("nie odblokowuje SUSPENDED/OFFBOARDING, odrzuca REVOKED (409), odrzuca domenę zweryfikowaną przez inną firmę (409) i trustLocally przy wyłączonym dev trust (403)", async () => {
    const { verifyOrganizationDomain } = await import("@/server/domains");

    // Wyłączenie dev trust -> 403
    setEnv("CORE_DEV_TRUST_DOMAINS", "0");
    await expect(verifyOrganizationDomain(OWNER_ACC, { trustLocally: true })).rejects.toMatchObject({
      code: "PERMISSION_DENIED",
      status: 403,
    });
    setEnv("CORE_DEV_TRUST_DOMAINS", "1");

    // REVOKED -> 409
    state.domain.status = "REVOKED";
    await expect(verifyOrganizationDomain(OWNER_ACC, { trustLocally: true })).rejects.toMatchObject({
      code: "CONFLICT",
      status: 409,
    });
    state.domain.status = "PENDING";

    // Zweryfikowana przez inną firmę -> 409
    state.verifiedOwnerByDomain.set("acme.test", OTHER_ORG_ID);
    await expect(verifyOrganizationDomain(OWNER_ACC, { trustLocally: true })).rejects.toMatchObject({
      code: "CONFLICT",
      status: 409,
    });
    state.verifiedOwnerByDomain.clear();

    // SUSPENDED / OFFBOARDING pozostają bez zmiany statusu
    for (const status of ["SUSPENDED", "OFFBOARDING"] as const) {
      state.orgStatus = status;
      state.domain.status = "PENDING";
      state.domain.verifiedAt = null;
      state.verifiedOwnerByDomain.clear();
      state.audits = [];

      expect(await verifyOrganizationDomain(OWNER_ACC, { trustLocally: true })).toEqual({
        domain: "acme.test",
        status: "VERIFIED",
      });
      expect(state.orgStatus).toBe(status);
      expect(state.audits.map((a) => a.action)).toEqual(["organization.domain.verified"]);
    }
  });

  it("Blocker 3: wymaga Ownera lub core.organization.manage (ORGANIZATION) w verifyOrganizationDomain oraz w widoku /account", async () => {
    const { resolveAccountPendingDomainView, verifyOrganizationDomain } = await import("@/server/domains");

    // Zwykły pracownik i zakres UNIT dostają 403 PERMISSION_DENIED
    await expect(verifyOrganizationDomain(REGULAR_ACC, { trustLocally: true })).rejects.toMatchObject({
      code: "PERMISSION_DENIED",
      status: 403,
    });
    await expect(verifyOrganizationDomain(UNIT_ADMIN_ACC, { trustLocally: true })).rejects.toMatchObject({
      code: "PERMISSION_DENIED",
      status: 403,
    });

    // Konto z core.organization.manage w zakresie ORGANIZATION może zweryfikować domenę
    expect(await verifyOrganizationDomain(ORG_ADMIN_ACC, { trustLocally: true })).toEqual({
      domain: "acme.test",
      status: "VERIFIED",
    });
    expect(state.orgStatus).toBe("ACTIVE");

    // Widok /account: TXT i przyciski tylko dla canManage=true i statusu PENDING/FAILED
    expect(
      resolveAccountPendingDomainView({
        organizationId: ORG_ID,
        domain: "acme.test",
        status: "PENDING",
        canManage: true,
        devTrust: true,
      }),
    ).toMatchObject({
      canManage: true,
      domain: "acme.test",
      txtHost: "_monorise-verification.acme.test",
      devTrust: true,
    });
    expect(
      resolveAccountPendingDomainView({
        organizationId: ORG_ID,
        domain: "acme.test",
        status: "FAILED",
        canManage: true,
        devTrust: false,
      }).canManage,
    ).toBe(true);
    expect(
      resolveAccountPendingDomainView({
        organizationId: ORG_ID,
        domain: "acme.test",
        status: "PENDING",
        canManage: false,
        devTrust: true,
      }),
    ).toEqual({ canManage: false, domain: "acme.test" });
    expect(
      resolveAccountPendingDomainView({
        organizationId: ORG_ID,
        domain: "acme.test",
        status: "REVOKED",
        canManage: true,
        devTrust: true,
      }),
    ).toEqual({ canManage: false, domain: "acme.test" });
  });

  it("Should-fix #6 i Nit #8: trasa HTTP POST /api/organization/domain/verify zwraca 401, 403, 422 (błędny JSON / nieznane pole), akceptuje puste body i obsługuje timeout DNS", async () => {
    const { POST } = await import("@/app/api/organization/domain/verify/route");
    const { DNS_TXT_TIMEOUT_MS } = await import("@/server/domains");

    // 401 bez sesji
    state.sessionUserId = null;
    const unauth = await POST(makeRequest("{}"));
    expect(unauth.status).toBe(401);
    expect((await unauth.json()).error.code).toBe("UNAUTHENTICATED");

    // 403 zwykły użytkownik (oraz UNIT-admin)
    state.sessionUserId = REGULAR_ACC;
    const forbidden = await POST(makeRequest("{}"));
    expect(forbidden.status).toBe(403);
    expect((await forbidden.json()).error.code).toBe("PERMISSION_DENIED");

    // 403 trustLocally gdy dev trust wyłączony
    state.sessionUserId = OWNER_ACC;
    setEnv("CORE_DEV_TRUST_DOMAINS", "0");
    const noDevTrust = await POST(makeRequest(JSON.stringify({ trustLocally: true })));
    expect(noDevTrust.status).toBe(403);
    expect((await noDevTrust.json()).error.code).toBe("PERMISSION_DENIED");
    setEnv("CORE_DEV_TRUST_DOMAINS", "1");

    // 422 błędny JSON, nieznane pole (strict) i zły typ
    for (const badBody of ["{invalid-json", JSON.stringify({ extra: true }), JSON.stringify({ trustLocally: "yes" })]) {
      const bad = await POST(makeRequest(badBody));
      expect(bad.status).toBe(422);
      expect((await bad.json()).error.code).toBe("VALIDATION_FAILED");
    }

    // Puste body -> traktowane jako {} (DNS zwraca [], więc 200 z PENDING)
    const emptyBody = await POST(makeRequest(""));
    expect(emptyBody.status).toBe(200);
    expect((await emptyBody.json()).data).toEqual({ domain: "acme.test", status: "PENDING" });

    // Timeout DNS -> nie zawiesza żądania, utrwala lastCheckedAt i zwraca 200 z PENDING
    vi.useFakeTimers();
    state.dnsResolver = () => new Promise(() => undefined);
    const pendingResPromise = POST(makeRequest("{}"));
    await vi.advanceTimersByTimeAsync(DNS_TXT_TIMEOUT_MS + 50);
    const timedOutRes = await pendingResPromise;
    expect(timedOutRes.status).toBe(200);
    expect((await timedOutRes.json()).data).toEqual({ domain: "acme.test", status: "PENDING" });
  });

  it("Should-fix #5: signUpOrganization odrzuca darmowe subdomeny i błędne DomainName, przepuszcza domenę PENDING w innej firmie, ale blokuje VERIFIED", async () => {
    const { signUpOrganization } = await import("@/server/signup");

    for (const email of ["anna@mail.gmail.com", "anna@pm.me", "anna@tuta.com", "anna@tutanota.com"]) {
      await expect(
        signUpOrganization({
          organizationName: "Acme",
          firstName: "Anna",
          lastName: "Nowak",
          email,
          password: "bardzo-dlugie-haslo-1",
        }),
      ).rejects.toMatchObject({ code: "EMAIL_DOMAIN_NOT_ALLOWED", status: 422 });
    }

    for (const email of ["anna@localhost", "anna@acme.123"]) {
      await expect(
        signUpOrganization({
          organizationName: "Acme",
          firstName: "Anna",
          lastName: "Nowak",
          email,
          password: "bardzo-dlugie-haslo-1",
        }),
      ).rejects.toMatchObject({ code: "VALIDATION_FAILED", status: 422 });
    }

    // Brak zweryfikowanego właściciela (domena tylko PENDING gdzie indziej) -> rejestracja przechodzi
    const ok = await signUpOrganization({
      organizationName: "Acme 2",
      firstName: "Anna",
      lastName: "Nowak",
      email: "anna@acme.test",
      password: "bardzo-dlugie-haslo-1",
    });
    expect(ok.domain).toBe("acme.test");
    expect(signUpEmailMock).toHaveBeenCalledTimes(1);

    // Zweryfikowany właściciel -> 409 ORGANIZATION_EXISTS
    state.verifiedOwnerByDomain.set("acme.test", OTHER_ORG_ID);
    await expect(
      signUpOrganization({
        organizationName: "Acme 3",
        firstName: "Anna",
        lastName: "Nowak",
        email: "anna@acme.test",
        password: "bardzo-dlugie-haslo-1",
      }),
    ).rejects.toMatchObject({ code: "ORGANIZATION_EXISTS", status: 409 });
  });
});
