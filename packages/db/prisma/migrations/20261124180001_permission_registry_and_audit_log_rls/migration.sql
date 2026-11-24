-- Rejestr produktów i uprawnień (ADR-0036) oraz niezmienny dziennik zdarzeń z RLS (ADR-0039, ADR-0041).

-- ── Uprawnienia roli aplikacji ─────────────────────────────────────────────────────────────────────
-- Domyślne uprawnienia schematu dały core_app także DELETE; tu zawężamy je do dozwolonych operacji:
-- produktów i uprawnień aplikacja nie usuwa, a do dziennika może wyłącznie dopisywać i czytać.
REVOKE ALL ON "public"."products", "public"."permissions", "public"."audit_log" FROM core_app;
GRANT SELECT, INSERT, UPDATE ON "public"."products" TO core_app;
GRANT SELECT, INSERT, UPDATE ON "public"."permissions" TO core_app;
GRANT SELECT, INSERT ON "public"."audit_log" TO core_app;

-- ── Formaty kluczy i spójność prefiksu produktu (ADR-0036) ─────────────────────────────────────────
ALTER TABLE "public"."products"
  ADD CONSTRAINT "products_key_format"
  CHECK ("key" ~ '^[a-z][a-z0-9]*$' AND "key" <> 'core');

ALTER TABLE "public"."permissions"
  ADD CONSTRAINT "permissions_key_format"
  CHECK ("key" ~ '^[a-z][a-z0-9]*(\.[a-z][a-z0-9_]*){2,}$');

ALTER TABLE "public"."permissions"
  ADD CONSTRAINT "permissions_core_product_consistency"
  CHECK (
    (split_part("key", '.', 1) = 'core' AND "productId" IS NULL)
    OR (split_part("key", '.', 1) <> 'core' AND "productId" IS NOT NULL)
  );

CREATE FUNCTION "public"."check_permission_product_prefix"() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog, public
  AS $$
DECLARE
  v_product_key text;
  v_prefix text;
BEGIN
  v_prefix := split_part(NEW."key", '.', 1);

  IF NEW."productId" IS NULL THEN
    IF v_prefix <> 'core' THEN
      RAISE EXCEPTION 'Platform permission key "%" must start with "core."', NEW."key"
        USING ERRCODE = '23514', CONSTRAINT = 'permissions_product_prefix';
    END IF;
    RETURN NEW;
  END IF;

  SELECT p."key" INTO v_product_key
  FROM "public"."products" p
  WHERE p."id" = NEW."productId";

  IF v_product_key IS NULL OR v_prefix <> v_product_key THEN
    RAISE EXCEPTION 'Permission key "%" does not match product key "%"', NEW."key", COALESCE(v_product_key, '')
      USING ERRCODE = '23514', CONSTRAINT = 'permissions_product_prefix';
  END IF;

  RETURN NEW;
END;
$$;

GRANT EXECUTE ON FUNCTION "public"."check_permission_product_prefix"() TO core_app;

CREATE TRIGGER "permissions_check_product_prefix"
  BEFORE INSERT OR UPDATE OF "key", "productId"
  ON "public"."permissions"
  FOR EACH ROW
  EXECUTE FUNCTION "public"."check_permission_product_prefix"();

CREATE FUNCTION "public"."prevent_product_key_change_with_permissions"() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog, public
  AS $$
BEGIN
  IF NEW."key" IS DISTINCT FROM OLD."key"
     AND EXISTS (SELECT 1 FROM "public"."permissions" WHERE "productId" = NEW."id") THEN
    RAISE EXCEPTION 'Cannot change product key from "%" to "%" while permissions reference this product', OLD."key", NEW."key"
      USING ERRCODE = '23514', CONSTRAINT = 'permissions_product_prefix';
  END IF;
  RETURN NEW;
END;
$$;

GRANT EXECUTE ON FUNCTION "public"."prevent_product_key_change_with_permissions"() TO core_app;

CREATE TRIGGER "products_prevent_key_change_with_permissions"
  BEFORE UPDATE OF "key"
  ON "public"."products"
  FOR EACH ROW
  EXECUTE FUNCTION "public"."prevent_product_key_change_with_permissions"();

-- ── Dziennik zdarzeń: RLS i niezmienność (ADR-0039) ────────────────────────────────────────────────
ALTER TABLE "public"."audit_log" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "public"."audit_log" FORCE ROW LEVEL SECURITY;

-- Firma (kontekst withOrganization) widzi wyłącznie swoje wpisy; wpisy platformy (organizationId IS NULL)
-- i innych firm są dla niej ukryte. Bez kontekstu firmy (Core sam rejestruje uprawnienia) widać tylko wpisy
-- platformy: zapis z RETURNING musi przejść także tę regułę odczytu.
CREATE POLICY audit_log_tenant_select ON "public"."audit_log"
  FOR SELECT
  TO core_app
  USING ("organizationId" IS NOT DISTINCT FROM "public"."current_organization_id"());

-- Właściciel tabel (core_owner) zachowuje odczyt i usuwanie dla retencji i operacji serwisowych (ADR-0041).
CREATE POLICY audit_log_owner_select ON "public"."audit_log"
  FOR SELECT
  TO core_owner
  USING (true);

CREATE POLICY audit_log_owner_delete ON "public"."audit_log"
  FOR DELETE
  TO core_owner
  USING (true);

-- Wpisy firmowe wymagają kontekstu tej firmy (withOrganization), a platformowe — braku kontekstu firmy.
CREATE POLICY audit_log_tenant_insert ON "public"."audit_log"
  FOR INSERT
  WITH CHECK ("organizationId" IS NOT DISTINCT FROM "public"."current_organization_id"());

-- Nikt (nawet właściciel tabel core_owner) nie może zmieniać wpisów dziennika.
-- Wyzwalacz FOR EACH STATEMENT działa przed filtrowaniem wierszy przez RLS, więc blokuje każdy UPDATE.
CREATE FUNCTION "public"."prevent_audit_log_update"() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog, public
  AS $$
BEGIN
  RAISE EXCEPTION 'Audit log entries are immutable and cannot be updated'
    USING ERRCODE = '42501';
END;
$$;

GRANT EXECUTE ON FUNCTION "public"."prevent_audit_log_update"() TO core_app;

CREATE TRIGGER "audit_log_prevent_update"
  BEFORE UPDATE
  ON "public"."audit_log"
  FOR EACH STATEMENT
  EXECUTE FUNCTION "public"."prevent_audit_log_update"();
