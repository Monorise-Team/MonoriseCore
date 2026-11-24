-- Dostęp firm do produktów (Entitlement), włączanie aplikacji pracownikom (AppAccess) i tabela outbox (ADR-0035, ADR-0037, ADR-0045, ADR-0051).

-- ── Uprawnienia roli aplikacji ─────────────────────────────────────────────────────────────────────
-- Domyślne uprawnienia schematu dały core_app także DELETE; tu zawężamy je do dozwolonych operacji:
-- dostępów i zdarzeń aplikacja nie usuwa (entitlement -> ENDED, app_access -> REVOKED, outbox -> publishedAt).
REVOKE ALL ON "public"."entitlements", "public"."app_access", "public"."outbox_events" FROM core_app;
GRANT SELECT, INSERT, UPDATE ON "public"."entitlements" TO core_app;
GRANT SELECT, INSERT, UPDATE ON "public"."app_access" TO core_app;
GRANT SELECT, INSERT, UPDATE ON "public"."outbox_events" TO core_app;

-- ── Entitlement: co najwyżej jeden wpis nie-ENDED na (firma, produkt), CHECKi i RLS ───────────────
CREATE UNIQUE INDEX "entitlements_organizationId_productId_open_key"
  ON "public"."entitlements" ("organizationId", "productId")
  WHERE "status" <> 'ENDED';

ALTER TABLE "public"."entitlements"
  ADD CONSTRAINT "entitlements_period_range"
  CHECK ("endsAt" IS NULL OR "endsAt" > "startsAt");

ALTER TABLE "public"."entitlements"
  ADD CONSTRAINT "entitlements_suspended_reason_consistency"
  CHECK ("suspendedReason" IS NULL OR "status" = 'SUSPENDED');

ALTER TABLE "public"."entitlements" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "public"."entitlements" FORCE ROW LEVEL SECURITY;

-- Ścisła izolacja odczytu: firma (withOrganization) widzi wyłącznie własne wpisy, a bez kontekstu firmy
-- rola core_app nie widzi żadnych wierszy. Zapisy (INSERT/UPDATE) wymagają jednocześnie kontekstu tej
-- firmy oraz jawnej flagi transakcyjnej app.entitlement_write = 'on' (ścieżka operatora Core / CLI).
-- PostgreSQL stosuje politykę SELECT również do UPDATE ... WHERE ..., dlatego zapis musi działać w
-- kontekście docelowej firmy (z osobną flagą blokującą zapisy z normalnych wywołań withOrganization).
CREATE POLICY entitlements_select ON "public"."entitlements"
  FOR SELECT
  TO core_app
  USING ("organizationId" = "public"."current_organization_id"());

CREATE POLICY entitlements_owner_select ON "public"."entitlements"
  FOR SELECT
  TO core_owner
  USING (true);

CREATE POLICY entitlements_insert ON "public"."entitlements"
  FOR INSERT
  WITH CHECK (
    "organizationId" = "public"."current_organization_id"()
    AND current_setting('app.entitlement_write', true) = 'on'
  );

CREATE POLICY entitlements_update ON "public"."entitlements"
  FOR UPDATE
  USING (
    "organizationId" = "public"."current_organization_id"()
    AND current_setting('app.entitlement_write', true) = 'on'
  )
  WITH CHECK (
    "organizationId" = "public"."current_organization_id"()
    AND current_setting('app.entitlement_write', true) = 'on'
  );

CREATE POLICY entitlements_owner_delete ON "public"."entitlements"
  FOR DELETE
  TO core_owner
  USING (true);

-- ── AppAccess: jeden aktywny wiersz na (konto, produkt), CHECK status/revokedAt i RLS ─────────────
CREATE UNIQUE INDEX "app_access_accountId_productId_active_key"
  ON "public"."app_access" ("accountId", "productId")
  WHERE "status" = 'ACTIVE';

ALTER TABLE "public"."app_access"
  ADD CONSTRAINT "app_access_status_revoked_consistency"
  CHECK (
    ("status" = 'ACTIVE' AND "revokedAt" IS NULL)
    OR ("status" = 'REVOKED' AND "revokedAt" IS NOT NULL)
  );

ALTER TABLE "public"."app_access" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "public"."app_access" FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON "public"."app_access"
  USING ("organizationId" = "public"."current_organization_id"())
  WITH CHECK ("organizationId" = "public"."current_organization_id"());

-- ── OutboxEvent: indeks niewysłanych zdarzeń, CHECKi i RLS ────────────────────────────────────────
CREATE INDEX "outbox_events_unpublished_idx"
  ON "public"."outbox_events" ("occurredAt", "id")
  WHERE "publishedAt" IS NULL;

ALTER TABLE "public"."outbox_events"
  ADD CONSTRAINT "outbox_events_version_positive"
  CHECK ("version" >= 1);

ALTER TABLE "public"."outbox_events"
  ADD CONSTRAINT "outbox_events_resource_version_nonnegative"
  CHECK ("resourceVersion" >= 0);

ALTER TABLE "public"."outbox_events" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "public"."outbox_events" FORCE ROW LEVEL SECURITY;

-- Wpisy firmowe wymagają kontekstu tej firmy (withOrganization), a platformowe — braku kontekstu firmy.
-- Polityka SELECT używa tego samego warunku, żeby INSERT ... RETURNING w Prismie przechodziło RLS.
CREATE POLICY outbox_events_tenant_select ON "public"."outbox_events"
  FOR SELECT
  TO core_app
  USING ("organizationId" IS NOT DISTINCT FROM "public"."current_organization_id"());

CREATE POLICY outbox_events_owner_select ON "public"."outbox_events"
  FOR SELECT
  TO core_owner
  USING (true);

CREATE POLICY outbox_events_owner_delete ON "public"."outbox_events"
  FOR DELETE
  TO core_owner
  USING (true);

CREATE POLICY outbox_events_tenant_insert ON "public"."outbox_events"
  FOR INSERT
  WITH CHECK ("organizationId" IS NOT DISTINCT FROM "public"."current_organization_id"());

CREATE POLICY outbox_events_tenant_update ON "public"."outbox_events"
  FOR UPDATE
  USING ("organizationId" IS NOT DISTINCT FROM "public"."current_organization_id"())
  WITH CHECK ("organizationId" IS NOT DISTINCT FROM "public"."current_organization_id"());
