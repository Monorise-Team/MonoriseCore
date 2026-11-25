import { hashToken } from "@core/db";
import { describe, expect, it } from "vitest";
import { buildInviteUrl, effectiveInvitationStatus } from "../src/invitations.js";
import { invitationMail, isLocalMailSink } from "../src/mail.js";

describe("zaproszenia — testy jednostkowe bez bazy", () => {
  it("wyznacza rzeczywisty status zaproszenia na podstawie czasu wygaśnięcia", () => {
    const expiresAt = new Date("2026-12-02T12:00:00.000Z");

    expect(effectiveInvitationStatus("PENDING", expiresAt, new Date("2026-12-02T11:59:59.999Z"))).toBe("PENDING");
    expect(effectiveInvitationStatus("PENDING", expiresAt, new Date("2026-12-02T12:00:00.000Z"))).toBe("EXPIRED");
    expect(effectiveInvitationStatus("PENDING", expiresAt, new Date("2026-12-03T00:00:00.000Z"))).toBe("EXPIRED");
    expect(effectiveInvitationStatus("ACCEPTED", expiresAt, new Date("2026-12-03T00:00:00.000Z"))).toBe("ACCEPTED");
    expect(effectiveInvitationStatus("REVOKED", expiresAt, new Date("2026-12-03T00:00:00.000Z"))).toBe("REVOKED");
    expect(effectiveInvitationStatus("EXPIRED", expiresAt, new Date("2026-11-26T00:00:00.000Z"))).toBe("EXPIRED");
  });

  it("buduje link aktywacyjny i wiadomość e-mail z nazwą firmy oraz zapraszającego", () => {
    const url = buildInviteUrl("abc_123-XYZ", "https://auth.monorise.studio///");
    expect(url).toBe("https://auth.monorise.studio/invite?token=abc_123-XYZ");

    const withInviter = invitationMail({
      to: "jan@acme.test",
      organizationName: "Acme",
      inviterName: "Anna Kowalska",
      inviteUrl: url,
    });
    expect(withInviter.to).toBe("jan@acme.test");
    expect(withInviter.subject).toBe("Zaproszenie do Monorise od firmy Acme");
    expect(withInviter.text).toContain("Anna Kowalska");
    expect(withInviter.text).toContain("Acme");
    expect(withInviter.text).toContain(url);
    expect(withInviter.html).toContain(url);

    const fromCli = invitationMail({
      to: "jan@acme.test",
      organizationName: 'Acme & "Spółka"',
      inviterName: null,
      inviteUrl: url,
    });
    expect(fromCli.text).toContain('Firma Acme & "Spółka" zaprasza Cię');
    expect(fromCli.html).toContain("Acme &amp; &quot;Spółka&quot;");
  });

  it("rozpoznaje lokalny transport poczty (memory / localhost) i wylicza deterministyczny skrót tokenu", () => {
    expect(isLocalMailSink("memory")).toBe(true);
    expect(isLocalMailSink("smtp://localhost:1125")).toBe(true);
    expect(isLocalMailSink("smtp://127.0.0.1:1025")).toBe(true);
    expect(isLocalMailSink("smtp://mail.acme.com:587")).toBe(false);
    expect(isLocalMailSink("smtps://user:pass@smtp.postmarkapp.com:465")).toBe(false);
    expect(isLocalMailSink("niepoprawny-url")).toBe(false);

    const h1 = hashToken("sekretny-token");
    const h2 = hashToken("sekretny-token");
    expect(h1).toBe(h2);
    expect(h1).toMatch(/^[0-9a-f]{64}$/);
    expect(h1).not.toBe(hashToken("inny-token"));
  });
});
