import "server-only";
import { emailDomain, isFreeEmailDomain, normalizeEmail, type SignUpRequest } from "@core/contracts";
import { domainOwner, uuidv7, withOrganization } from "@core/db";
import { auth } from "./auth";
import { db } from "./db";
import { domainTxtValue, hashToken } from "./domains";
import { CoreError, isUniqueViolation } from "./errors";

/**
 * Samorejestracja firmy (ADR-0021): osoba z adresem w domenie firmy zakłada konto i firmę. Firma czeka na
 * potwierdzenie domeny rekordem DNS TXT, a konto na potwierdzenie adresu e-mail.
 */
export async function signUpOrganization(input: SignUpRequest): Promise<{ organizationId: string; domain: string }> {
  const email = normalizeEmail(input.email);
  const domain = emailDomain(email);
  if (!domain || isFreeEmailDomain(domain)) {
    throw new CoreError(
      "EMAIL_DOMAIN_NOT_ALLOWED",
      422,
      "Firmę zakłada się adresem w domenie firmy, a nie w darmowej skrzynce (np. Gmail, WP, Onet)",
    );
  }
  if (await domainOwner(db, domain)) {
    throw new CoreError(
      "ORGANIZATION_EXISTS",
      409,
      `Firma z domeną ${domain} już jest w Monorise. Poproś jej administratora o zaproszenie.`,
    );
  }

  const { user } = await auth.api.signUpEmail({
    body: { email, password: input.password, name: `${input.firstName} ${input.lastName}`, callbackURL: "/account" },
  });

  const organizationId = uuidv7();
  const employeeId = uuidv7();
  try {
    await withOrganization(db, organizationId, async (tx) => {
      await tx.organization.create({
        data: { id: organizationId, name: input.organizationName, createdVia: "SELF_SIGNUP" },
      });
      await tx.organizationDomain.create({
        data: {
          id: uuidv7(),
          organizationId,
          domain,
          verificationMethod: "DNS_TXT",
          verificationTokenHash: hashToken(domainTxtValue(organizationId, domain)),
          isPrimary: true,
        },
      });
      await tx.employee.create({
        data: {
          id: employeeId,
          organizationId,
          firstName: input.firstName,
          lastName: input.lastName,
          workEmail: email,
        },
      });
      await tx.account.create({
        data: { id: user.id, organizationId, employeeId, email, normalizedEmail: email, status: "ACTIVE" },
      });
      await tx.organization.update({
        where: { id: organizationId },
        data: { ownerAccountId: user.id },
      });
    });
  } catch (error) {
    // Bez firmy konto logowania nie ma sensu: cofamy je
    await db.authUser.delete({ where: { id: user.id } }).catch(() => undefined);
    if (isUniqueViolation(error)) {
      throw new CoreError("ORGANIZATION_EXISTS", 409, `Firma z domeną ${domain} już jest w Monorise.`);
    }
    throw error;
  }
  return { organizationId, domain };
}
