-- Role, uprawnienia ról i przypisania ról z zakresem (ADR-0033, ADR-0034, ADR-0035, ADR-0037).

-- ── Uprawnienia roli aplikacji ─────────────────────────────────────────────────────────────────────
-- Domyślne uprawnienia schematu dały core_app także DELETE; tu zawężamy je do dozwolonych operacji:
-- ról nie usuwamy (archiwizacja), role_permissions nie aktualizujemy, a cofnięcie przypisania usuwa wiersz.
REVOKE ALL ON "public"."roles", "public"."role_permissions", "public"."role_assignments" FROM core_app;
GRANT SELECT, INSERT, UPDATE ON "public"."roles" TO core_app;
GRANT SELECT, INSERT, DELETE ON "public"."role_permissions" TO core_app;
GRANT SELECT, INSERT, DELETE ON "public"."role_assignments" TO core_app;

-- ── Role: indeks unikalny nazw aktywnych ról firmy, ograniczenia i spójność szablonów ──────────────
CREATE UNIQUE INDEX "roles_organizationId_lower_name_active_key"
  ON "public"."roles" ("organizationId", lower("name"))
  WHERE "organizationId" IS NOT NULL AND "archivedAt" IS NULL;

ALTER TABLE "public"."roles"
  ADD CONSTRAINT "roles_template_key_consistency"
  CHECK (("organizationId" IS NULL) = ("key" IS NOT NULL));

ALTER TABLE "public"."roles"
  ADD CONSTRAINT "roles_key_format"
  CHECK ("key" IS NULL OR "key" ~ '^[a-z][a-z0-9]*(\.[a-z][a-z0-9_]*)+$');

ALTER TABLE "public"."roles"
  ADD CONSTRAINT "roles_core_product_consistency"
  CHECK (
    "key" IS NULL
    OR (split_part("key", '.', 1) = 'core' AND "productId" IS NULL)
    OR (split_part("key", '.', 1) <> 'core' AND "productId" IS NOT NULL)
  );

CREATE FUNCTION "public"."validate_role"() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog, public
  AS $$
DECLARE
  v_product_key text;
  v_prefix text;
  v_source_org_id uuid;
BEGIN
  IF TG_OP = 'UPDATE' THEN
    IF NEW."organizationId" IS DISTINCT FROM OLD."organizationId" THEN
      RAISE EXCEPTION 'Cannot change organizationId of role %', OLD."id"
        USING ERRCODE = '23514', CONSTRAINT = 'roles_organization_immutable';
    END IF;

    IF NEW."productId" IS DISTINCT FROM OLD."productId"
       AND EXISTS (SELECT 1 FROM "public"."role_permissions" WHERE "roleId" = NEW."id") THEN
      RAISE EXCEPTION 'Cannot change productId of role % while permissions are attached', NEW."id"
        USING ERRCODE = '23514', CONSTRAINT = 'role_permissions_product_match';
    END IF;
  END IF;

  IF NEW."key" IS NOT NULL AND NEW."productId" IS NOT NULL THEN
    v_prefix := split_part(NEW."key", '.', 1);
    SELECT p."key" INTO v_product_key
    FROM "public"."products" p
    WHERE p."id" = NEW."productId";

    IF v_product_key IS NULL OR v_prefix <> v_product_key THEN
      RAISE EXCEPTION 'Role template key "%" does not match product key "%"', NEW."key", COALESCE(v_product_key, '')
        USING ERRCODE = '23514', CONSTRAINT = 'roles_template_product_prefix';
    END IF;
  END IF;

  IF NEW."copiedFromRoleId" IS NOT NULL THEN
    SELECT r."organizationId" INTO v_source_org_id
    FROM "public"."roles" r
    WHERE r."id" = NEW."copiedFromRoleId";

    IF NOT FOUND THEN
      RAISE EXCEPTION 'Source role % not found', NEW."copiedFromRoleId"
        USING ERRCODE = '23503', CONSTRAINT = 'roles_copied_from_org_check';
    END IF;

    IF v_source_org_id IS NOT NULL AND v_source_org_id IS DISTINCT FROM NEW."organizationId" THEN
      RAISE EXCEPTION 'Cannot copy role % from another organization', NEW."copiedFromRoleId"
        USING ERRCODE = '23514', CONSTRAINT = 'roles_copied_from_org_check';
    END IF;
  END IF;

  RETURN NEW;
END;
$$;

GRANT EXECUTE ON FUNCTION "public"."validate_role"() TO core_app;

CREATE TRIGGER "roles_validate"
  BEFORE INSERT OR UPDATE
  ON "public"."roles"
  FOR EACH ROW
  EXECUTE FUNCTION "public"."validate_role"();

CREATE FUNCTION "public"."prevent_product_key_change_with_roles"() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog, public
  AS $$
BEGIN
  IF NEW."key" IS DISTINCT FROM OLD."key"
     AND EXISTS (SELECT 1 FROM "public"."roles" WHERE "productId" = NEW."id" AND "key" IS NOT NULL) THEN
    RAISE EXCEPTION 'Cannot change product key from "%" to "%" while role templates reference this product', OLD."key", NEW."key"
      USING ERRCODE = '23514', CONSTRAINT = 'roles_template_product_prefix';
  END IF;
  RETURN NEW;
END;
$$;

GRANT EXECUTE ON FUNCTION "public"."prevent_product_key_change_with_roles"() TO core_app;

CREATE TRIGGER "products_prevent_key_change_with_roles"
  BEFORE UPDATE OF "key"
  ON "public"."products"
  FOR EACH ROW
  EXECUTE FUNCTION "public"."prevent_product_key_change_with_roles"();

-- ── Role: RLS ──────────────────────────────────────────────────────────────────────────────────────
ALTER TABLE "public"."roles" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "public"."roles" FORCE ROW LEVEL SECURITY;

CREATE POLICY roles_select ON "public"."roles"
  FOR SELECT
  USING ("organizationId" IS NULL OR "organizationId" = "public"."current_organization_id"());

CREATE POLICY roles_insert ON "public"."roles"
  FOR INSERT
  WITH CHECK ("organizationId" IS NOT DISTINCT FROM "public"."current_organization_id"());

CREATE POLICY roles_update ON "public"."roles"
  FOR UPDATE
  USING ("organizationId" IS NOT DISTINCT FROM "public"."current_organization_id"())
  WITH CHECK ("organizationId" IS NOT DISTINCT FROM "public"."current_organization_id"());

CREATE POLICY roles_delete ON "public"."roles"
  FOR DELETE
  USING ("organizationId" IS NOT DISTINCT FROM "public"."current_organization_id"());

-- ── Uprawnienia ról: wyzwalacz spójności produktu, kopiowanie organizationId i RLS ────────────────
CREATE FUNCTION "public"."validate_role_permission"() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog, public
  AS $$
DECLARE
  v_role_org_id uuid;
  v_role_product_id uuid;
  v_perm_product_id uuid;
BEGIN
  SELECT r."organizationId", r."productId"
  INTO v_role_org_id, v_role_product_id
  FROM "public"."roles" r
  WHERE r."id" = NEW."roleId";

  IF NOT FOUND THEN
    RAISE EXCEPTION 'Role % not found', NEW."roleId"
      USING ERRCODE = '23503', CONSTRAINT = 'role_permissions_role_check';
  END IF;

  SELECT p."productId"
  INTO v_perm_product_id
  FROM "public"."permissions" p
  WHERE p."id" = NEW."permissionId";

  IF NOT FOUND THEN
    RAISE EXCEPTION 'Permission % not found', NEW."permissionId"
      USING ERRCODE = '23503', CONSTRAINT = 'role_permissions_permission_check';
  END IF;

  IF v_perm_product_id IS DISTINCT FROM v_role_product_id THEN
    RAISE EXCEPTION 'Permission % product does not match role % product', NEW."permissionId", NEW."roleId"
      USING ERRCODE = '23514', CONSTRAINT = 'role_permissions_product_match';
  END IF;

  NEW."organizationId" := v_role_org_id;
  RETURN NEW;
END;
$$;

GRANT EXECUTE ON FUNCTION "public"."validate_role_permission"() TO core_app;

CREATE TRIGGER "role_permissions_validate"
  BEFORE INSERT OR UPDATE
  ON "public"."role_permissions"
  FOR EACH ROW
  EXECUTE FUNCTION "public"."validate_role_permission"();

ALTER TABLE "public"."role_permissions" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "public"."role_permissions" FORCE ROW LEVEL SECURITY;

CREATE POLICY role_permissions_select ON "public"."role_permissions"
  FOR SELECT
  USING ("organizationId" IS NULL OR "organizationId" = "public"."current_organization_id"());

CREATE POLICY role_permissions_insert ON "public"."role_permissions"
  FOR INSERT
  WITH CHECK ("organizationId" IS NOT DISTINCT FROM "public"."current_organization_id"());

CREATE POLICY role_permissions_update ON "public"."role_permissions"
  FOR UPDATE
  USING ("organizationId" IS NOT DISTINCT FROM "public"."current_organization_id"())
  WITH CHECK ("organizationId" IS NOT DISTINCT FROM "public"."current_organization_id"());

CREATE POLICY role_permissions_delete ON "public"."role_permissions"
  FOR DELETE
  USING ("organizationId" IS NOT DISTINCT FROM "public"."current_organization_id"());

-- ── Przypisania ról: ograniczenia zakresu i dat, duplikaty, wyzwalacz i RLS ───────────────────────
ALTER TABLE "public"."role_assignments"
  ADD CONSTRAINT "role_assignments_scope_consistency"
  CHECK (
    ("scopeType" = 'ORGANIZATION' AND "scopeId" IS NULL)
    OR ("scopeType" <> 'ORGANIZATION' AND "scopeId" IS NOT NULL AND btrim("scopeId") <> '')
  );

ALTER TABLE "public"."role_assignments"
  ADD CONSTRAINT "role_assignments_validity_range"
  CHECK ("validFrom" IS NULL OR "validUntil" IS NULL OR "validUntil" > "validFrom");

CREATE UNIQUE INDEX "role_assignments_accountId_roleId_scope_key"
  ON "public"."role_assignments" ("accountId", "roleId", "scopeType", COALESCE("scopeId", ''));

CREATE FUNCTION "public"."validate_role_assignment"() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog, public
  AS $$
DECLARE
  v_role_org_id uuid;
  v_role_archived_at timestamptz;
  v_unit_id uuid;
BEGIN
  SELECT r."organizationId", r."archivedAt"
  INTO v_role_org_id, v_role_archived_at
  FROM "public"."roles" r
  WHERE r."id" = NEW."roleId";

  IF NOT FOUND THEN
    RAISE EXCEPTION 'Role % does not exist or is not accessible in organization %', NEW."roleId", NEW."organizationId"
      USING ERRCODE = '23503', CONSTRAINT = 'role_assignments_role_org_check';
  END IF;

  IF v_role_org_id IS NOT NULL AND v_role_org_id <> NEW."organizationId" THEN
    RAISE EXCEPTION 'Role % belongs to a different organization than %', NEW."roleId", NEW."organizationId"
      USING ERRCODE = '23514', CONSTRAINT = 'role_assignments_role_org_check';
  END IF;

  IF v_role_archived_at IS NOT NULL THEN
    RAISE EXCEPTION 'Cannot assign archived role %', NEW."roleId"
      USING ERRCODE = '23514', CONSTRAINT = 'role_assignments_role_not_archived';
  END IF;

  IF NEW."scopeType" = 'UNIT' AND NEW."scopeId" IS NOT NULL AND btrim(NEW."scopeId") <> '' THEN
    BEGIN
      v_unit_id := NEW."scopeId"::uuid;
    EXCEPTION WHEN invalid_text_representation THEN
      RAISE EXCEPTION 'Unit scopeId "%" must be a valid UUID', NEW."scopeId"
        USING ERRCODE = '23514', CONSTRAINT = 'role_assignments_unit_scope_check';
    END;

    IF NOT EXISTS (
      SELECT 1
      FROM "public"."organization_units" u
      WHERE u."id" = v_unit_id
        AND u."organizationId" = NEW."organizationId"
    ) THEN
      RAISE EXCEPTION 'Unit % does not belong to organization %', v_unit_id, NEW."organizationId"
        USING ERRCODE = '23514', CONSTRAINT = 'role_assignments_unit_scope_check';
    END IF;
  END IF;

  RETURN NEW;
END;
$$;

GRANT EXECUTE ON FUNCTION "public"."validate_role_assignment"() TO core_app;

CREATE TRIGGER "role_assignments_validate"
  BEFORE INSERT OR UPDATE
  ON "public"."role_assignments"
  FOR EACH ROW
  EXECUTE FUNCTION "public"."validate_role_assignment"();

ALTER TABLE "public"."role_assignments" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "public"."role_assignments" FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON "public"."role_assignments"
  USING ("organizationId" = "public"."current_organization_id"())
  WITH CHECK ("organizationId" = "public"."current_organization_id"());
