-- Separacja firm (ADR-0037): uprawnienia roli aplikacji, RLS i wąskie wyszukiwanie ponad granicą firm.
-- ── Uprawnienia roli aplikacji (ADR-0037) ──────────────────────────────────────────────────────────
-- core_app pracuje na danych, ale nie jest właścicielem tabel i nie omija RLS.
GRANT USAGE ON SCHEMA "public", "auth" TO core_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA "public", "auth" TO core_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA "public", "auth" GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO core_app;
-- Historia migracji Prismy nie jest dla aplikacji (tabela powstaje przed tą migracją przy prisma migrate).
DO $$ BEGIN
  IF to_regclass('public._prisma_migrations') IS NOT NULL THEN
    REVOKE ALL ON "public"."_prisma_migrations" FROM core_app;
  END IF;
END $$;

-- ── Separacja firm: RLS włączone i wymuszone w każdej tabeli z danymi firmy ───────────────────────
-- Firma przychodzi ze zmiennej transakcji ustawianej przez aplikację:
--   SELECT set_config('app.organization_id', '<uuid>', true)
-- Bez niej polityki nie zwracają żadnego wiersza i nie pozwalają nic zapisać.
CREATE FUNCTION "public"."current_organization_id"() RETURNS uuid
  LANGUAGE sql STABLE
  AS $$ SELECT NULLIF(current_setting('app.organization_id', true), '')::uuid $$;

ALTER TABLE "public"."organizations" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "public"."organizations" FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON "public"."organizations"
  USING ("id" = "public"."current_organization_id"())
  WITH CHECK ("id" = "public"."current_organization_id"());

ALTER TABLE "public"."organization_domains" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "public"."organization_domains" FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON "public"."organization_domains"
  USING ("organizationId" = "public"."current_organization_id"())
  WITH CHECK ("organizationId" = "public"."current_organization_id"());

ALTER TABLE "public"."employees" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "public"."employees" FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON "public"."employees"
  USING ("organizationId" = "public"."current_organization_id"())
  WITH CHECK ("organizationId" = "public"."current_organization_id"());

ALTER TABLE "public"."accounts" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "public"."accounts" FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON "public"."accounts"
  USING ("organizationId" = "public"."current_organization_id"())
  WITH CHECK ("organizationId" = "public"."current_organization_id"());

-- ── Wąskie wyszukiwanie ponad granicą firm ─────────────────────────────────────────────────────────
-- Tylko te funkcje widzą wiersze wszystkich firm. Należą do roli core_lookup (BYPASSRLS), zwracają
-- wyłącznie pola potrzebne do logowania i mogą je wywołać tylko role Core.
GRANT USAGE ON SCHEMA "public" TO core_lookup;
GRANT SELECT ON "public"."organizations", "public"."organization_domains", "public"."accounts" TO core_lookup;

-- Dane do tokenu (ADR-0023): firma, pracownik i rewizja uprawnień konta.
CREATE FUNCTION "public"."account_claims"(p_account_id uuid)
  RETURNS TABLE (
    organization_id uuid,
    employee_id uuid,
    authz_revision integer,
    account_status "public"."AccountStatus",
    organization_status "public"."OrganizationStatus"
  )
  LANGUAGE sql STABLE SECURITY DEFINER
  SET search_path = pg_catalog, public
  AS $$
    SELECT a."organizationId", a."employeeId", a."authzRevision", a."status", o."status"
    FROM "public"."accounts" a
    JOIN "public"."organizations" o ON o."id" = a."organizationId"
    WHERE a."id" = p_account_id
  $$;

-- Czy domena należy już do jakiejś firmy (samorejestracja i zaproszenia, ADR-0019 i ADR-0021).
CREATE FUNCTION "public"."domain_owner"(p_domain citext)
  RETURNS TABLE (organization_id uuid, domain_status "public"."DomainStatus")
  LANGUAGE sql STABLE SECURITY DEFINER
  SET search_path = pg_catalog, public
  AS $$
    SELECT d."organizationId", d."status" FROM "public"."organization_domains" d WHERE d."domain" = p_domain
  $$;

-- Zmiana właściciela wymaga, żeby nowy właściciel mógł tworzyć obiekty w schemacie; tylko na tę chwilę.
GRANT CREATE ON SCHEMA "public" TO core_lookup;
ALTER FUNCTION "public"."account_claims"(uuid) OWNER TO core_lookup;
ALTER FUNCTION "public"."domain_owner"(citext) OWNER TO core_lookup;
REVOKE CREATE ON SCHEMA "public" FROM core_lookup;
REVOKE ALL ON FUNCTION "public"."account_claims"(uuid), "public"."domain_owner"(citext) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION "public"."account_claims"(uuid), "public"."domain_owner"(citext) TO core_app;
GRANT EXECUTE ON FUNCTION "public"."current_organization_id"() TO core_app;
