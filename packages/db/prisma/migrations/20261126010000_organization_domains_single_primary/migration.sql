-- Co najwyżej jedna domena główna (isPrimary = true) w firmie (MonoriseCore#66, ADR-0019).

-- CreateIndex
CREATE UNIQUE INDEX "organization_domains_organizationId_primary_key"
  ON "public"."organization_domains" ("organizationId")
  WHERE "isPrimary" = true;
