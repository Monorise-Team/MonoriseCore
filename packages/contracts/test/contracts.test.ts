import { describe, expect, it } from "vitest";
import { AccessTokenClaims, emailDomain, isFreeEmailDomain, normalizeEmail, SignUpRequest } from "../src/index.js";

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
      sub: "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6a7b",
      aud: "https://api.monorise.studio",
      org_id: "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6a7c",
      employee_id: "0193a5b2-7c3d-7e4f-8a1b-2c3d4e5f6a7d",
      authz_rev: 0,
      iat: 1,
      exp: 2,
    });
    expect(claims.amr).toEqual([]);
  });
});
