-- Domeny firm (MonoriseCore#66, ADR-0019):
-- 1. Zasada „wygrywa weryfikacja”: wiele firm może zgłosić niezweryfikowane roszczenie (PENDING/FAILED)
--    do tej samej domeny, ale globalnie unikalna jest wyłącznie domena ze statusem VERIFIED.
-- 2. Jedna firma może mieć co najwyżej jeden wiersz na domenę (organizationId, domain) oraz co najwyżej
--    jedną domenę główną (isPrimary = true).
-- 3. Funkcja domain_owner zwraca wyłącznie zweryfikowanego właściciela domeny.
-- 4. Funkcja SECURITY DEFINER usuwa konkurencyjne niezweryfikowane, niegłówne roszczenia innych firm
--    w tej samej transakcji co weryfikacja domeny; nie usuwa cudzej głównej domeny z rejestracji w toku
--    (taka firma dostanie 409 CONFLICT przy próbie weryfikacji).

-- DropIndex
DROP INDEX "public"."organization_domains_domain_key";

-- CreateIndex
CREATE UNIQUE INDEX "organization_domains_organizationId_domain_key"
  ON "public"."organization_domains" ("organizationId", "domain");

-- CreateIndex
CREATE UNIQUE INDEX "organization_domains_domain_verified_key"
  ON "public"."organization_domains" ("domain")
  WHERE "status" = 'VERIFIED';

-- CreateIndex
CREATE UNIQUE INDEX "organization_domains_organizationId_primary_key"
  ON "public"."organization_domains" ("organizationId")
  WHERE "isPrimary" = true;

-- ── Właściciel domeny: wyłącznie domeny VERIFIED (ADR-0019, „wygrywa weryfikacja”) ─────────────────
CREATE OR REPLACE FUNCTION "public"."domain_owner"(p_domain citext)
  RETURNS TABLE (organization_id uuid, domain_status "public"."DomainStatus")
  LANGUAGE sql STABLE SECURITY DEFINER
  SET search_path = pg_catalog, public
  AS $$
    SELECT d."organizationId", d."status"
    FROM "public"."organization_domains" d
    WHERE d."domain" = p_domain
      AND d."status" = 'VERIFIED'
  $$;

-- ── Usunięcie konkurencyjnych niezweryfikowanych, niegłównych roszczeń innych firm ──────────────────
-- Funkcja należy do roli core_lookup (BYPASSRLS) i wymaga kontekstu firmy (app.organization_id), która
-- już posiada zweryfikowany wiersz dla p_domain w bieżącej transakcji. Nie usuwa głównych
-- niezweryfikowanych domen innych firm (samorejestracja w toku).
GRANT DELETE ON "public"."organization_domains" TO core_lookup;

CREATE FUNCTION "public"."organization_domains_release_competing_claims"(p_domain citext)
  RETURNS integer
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER
  SET search_path = pg_catalog, public
  AS $$
  DECLARE
    v_org_id uuid;
    v_deleted integer := 0;
  BEGIN
    v_org_id := "public"."current_organization_id"();
    IF v_org_id IS NULL THEN
      RAISE EXCEPTION 'Brak kontekstu firmy (app.organization_id)';
    END IF;

    IF NOT EXISTS (
      SELECT 1
      FROM "public"."organization_domains" d
      WHERE d."organizationId" = v_org_id
        AND d."domain" = p_domain
        AND d."status" = 'VERIFIED'
    ) THEN
      RAISE EXCEPTION 'Bieżąca firma nie ma zweryfikowanej domeny "%"', p_domain;
    END IF;

    DELETE FROM "public"."organization_domains" d
    WHERE d."domain" = p_domain
      AND d."organizationId" <> v_org_id
      AND d."status" <> 'VERIFIED'
      AND d."isPrimary" = false;

    GET DIAGNOSTICS v_deleted = ROW_COUNT;
    RETURN v_deleted;
  END;
  $$;

GRANT CREATE ON SCHEMA "public" TO core_lookup;
ALTER FUNCTION "public"."organization_domains_release_competing_claims"(citext) OWNER TO core_lookup;
REVOKE CREATE ON SCHEMA "public" FROM core_lookup;
REVOKE ALL ON FUNCTION "public"."organization_domains_release_competing_claims"(citext) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION "public"."organization_domains_release_competing_claims"(citext) TO core_app;
