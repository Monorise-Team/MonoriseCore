-- Separacja firm (ADR-0037) dla jednostek organizacyjnych i członkostw, ochrona przed cyklami w drzewie
-- jednostek (ADR-0032) oraz uzupełnienie Ownera dla istniejących firm.

-- ── Uprawnienia roli aplikacji ─────────────────────────────────────────────────────────────────────
GRANT SELECT, INSERT, UPDATE, DELETE ON "public"."organization_units", "public"."unit_memberships" TO core_app;

-- ── Separacja firm: RLS włączone i wymuszone ───────────────────────────────────────────────────────
ALTER TABLE "public"."organization_units" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "public"."organization_units" FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON "public"."organization_units"
  USING ("organizationId" = "public"."current_organization_id"())
  WITH CHECK ("organizationId" = "public"."current_organization_id"());

ALTER TABLE "public"."unit_memberships" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "public"."unit_memberships" FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON "public"."unit_memberships"
  USING ("organizationId" = "public"."current_organization_id"())
  WITH CHECK ("organizationId" = "public"."current_organization_id"());

-- ── Brak cykli w drzewie jednostek (ADR-0032) ──────────────────────────────────────────────────────
CREATE FUNCTION "public"."prevent_organization_unit_cycle"() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog, public
  AS $$
DECLARE
  has_cycle boolean;
BEGIN
  -- Serializujemy zapisy w drzewie jednostek w obrębie firmy na czas transakcji, żeby dwa równoległe
  -- zapisy (np. A->B i B->A) nie sprawdziły starego stanu jednocześnie i nie utworzyły cyklu.
  PERFORM pg_advisory_xact_lock(hashtextextended('organization_units:' || NEW."organizationId"::text, 0));

  IF NEW."parentId" IS NULL THEN
    RETURN NEW;
  END IF;

  IF NEW."parentId" = NEW."id" THEN
    RAISE EXCEPTION 'Organization unit cycle detected: unit % cannot be its own parent', NEW."id"
      USING ERRCODE = '23514', CONSTRAINT = 'organization_units_no_cycle';
  END IF;

  WITH RECURSIVE ancestors(id, parent_id, visited) AS (
    SELECT u."id", u."parentId", ARRAY[u."id"]
    FROM "public"."organization_units" u
    WHERE u."organizationId" = NEW."organizationId"
      AND u."id" = NEW."parentId"
    UNION ALL
    SELECT u."id", u."parentId", a.visited || u."id"
    FROM "public"."organization_units" u
    JOIN ancestors a ON u."id" = a.parent_id
    WHERE u."organizationId" = NEW."organizationId"
      AND NOT (u."id" = ANY(a.visited))
  )
  SELECT EXISTS (
    SELECT 1 FROM ancestors WHERE id = NEW."id" OR parent_id = NEW."id"
  ) INTO has_cycle;

  IF has_cycle THEN
    RAISE EXCEPTION 'Organization unit cycle detected for unit % with parent %', NEW."id", NEW."parentId"
      USING ERRCODE = '23514', CONSTRAINT = 'organization_units_no_cycle';
  END IF;

  RETURN NEW;
END;
$$;

GRANT EXECUTE ON FUNCTION "public"."prevent_organization_unit_cycle"() TO core_app;

CREATE TRIGGER "organization_units_prevent_cycle"
  BEFORE INSERT OR UPDATE OF "parentId"
  ON "public"."organization_units"
  FOR EACH ROW
  EXECUTE FUNCTION "public"."prevent_organization_unit_cycle"();

-- ── Uzupełnienie Ownera dla istniejących firm ──────────────────────────────────────────────────────
-- Tabele mają FORCE ROW LEVEL SECURITY, a migracje uruchamia core_owner (właściciel bez BYPASSRLS),
-- więc na czas jednej instrukcji w transakcji migracji zdejmujemy FORCE i od razu przywracamy.
ALTER TABLE "public"."organizations" NO FORCE ROW LEVEL SECURITY;
ALTER TABLE "public"."accounts" NO FORCE ROW LEVEL SECURITY;

UPDATE "public"."organizations" o
SET "ownerAccountId" = earliest."id"
FROM (
  -- Najpierw najstarsze aktywne konto; konto zaproszone albo wyłączone tylko wtedy, gdy firma nie ma aktywnego.
  SELECT DISTINCT ON ("organizationId") "organizationId", "id"
  FROM "public"."accounts"
  ORDER BY "organizationId", ("status" = 'ACTIVE') DESC, "createdAt" ASC, "id" ASC
) earliest
WHERE o."id" = earliest."organizationId"
  AND o."ownerAccountId" IS NULL;

ALTER TABLE "public"."accounts" FORCE ROW LEVEL SECURITY;
ALTER TABLE "public"."organizations" FORCE ROW LEVEL SECURITY;
