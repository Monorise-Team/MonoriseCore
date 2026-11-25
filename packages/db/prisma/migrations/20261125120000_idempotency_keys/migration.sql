-- Klucze powtórzeń (Idempotency-Key) dla operacji tworzących Core API (MonoriseCore#30, ADR-0037).
-- Zapobiegają utworzeniu duplikatu przy ponowieniu żądania po utraconej odpowiedzi.

-- CreateTable
CREATE TABLE "public"."idempotency_keys" (
    "id" UUID NOT NULL,
    "organizationId" UUID NOT NULL,
    "principal" TEXT NOT NULL,
    "key" TEXT NOT NULL,
    "method" TEXT NOT NULL,
    "path" TEXT NOT NULL,
    "requestHash" TEXT NOT NULL,
    "responseStatus" INTEGER NOT NULL,
    "responseBody" JSONB NOT NULL,
    "createdAt" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expiresAt" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "idempotency_keys_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "idempotency_keys_organizationId_principal_key_key"
  ON "public"."idempotency_keys"("organizationId", "principal", "key");

-- CreateIndex
CREATE INDEX "idempotency_keys_organizationId_idx"
  ON "public"."idempotency_keys"("organizationId");

-- CreateIndex
CREATE INDEX "idempotency_keys_expiresAt_idx"
  ON "public"."idempotency_keys"("expiresAt");

-- AddForeignKey
ALTER TABLE "public"."idempotency_keys"
  ADD CONSTRAINT "idempotency_keys_organizationId_fkey"
  FOREIGN KEY ("organizationId") REFERENCES "public"."organizations"("id")
  ON DELETE CASCADE ON UPDATE CASCADE;

-- ── Ograniczenia spójności ─────────────────────────────────────────────────────────────────────────
ALTER TABLE "public"."idempotency_keys"
  ADD CONSTRAINT "idempotency_keys_principal_nonempty"
  CHECK (char_length("principal") >= 1);

ALTER TABLE "public"."idempotency_keys"
  ADD CONSTRAINT "idempotency_keys_key_format"
  CHECK (char_length("key") BETWEEN 1 AND 255 AND "key" ~ '^[!-~]([ -~]*[!-~])?$');

ALTER TABLE "public"."idempotency_keys"
  ADD CONSTRAINT "idempotency_keys_request_hash_format"
  CHECK ("requestHash" ~ '^[0-9a-f]{64}$');

ALTER TABLE "public"."idempotency_keys"
  ADD CONSTRAINT "idempotency_keys_response_status_2xx"
  CHECK ("responseStatus" BETWEEN 200 AND 299);

-- ── Uprawnienia roli aplikacji ─────────────────────────────────────────────────────────────────────
-- Domyślne uprawnienia schematu dały core_app także DELETE; tu zawężamy je do tego, czego wymaga mechanizm:
-- odczyt, zapis i nadpisanie wygasłego wiersza (sprząta wyłącznie funkcja SECURITY DEFINER poniżej).
REVOKE ALL ON "public"."idempotency_keys" FROM core_app;
GRANT SELECT, INSERT, UPDATE ON "public"."idempotency_keys" TO core_app;

-- ── RLS: pełna izolacja firm ───────────────────────────────────────────────────────────────────────
ALTER TABLE "public"."idempotency_keys" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "public"."idempotency_keys" FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON "public"."idempotency_keys"
  USING ("organizationId" = "public"."current_organization_id"())
  WITH CHECK ("organizationId" = "public"."current_organization_id"());

-- ── Sprzątanie wygasłych kluczy ponad granicą firm ─────────────────────────────────────────────────
-- Funkcja należy do roli core_lookup (BYPASSRLS), bo usuwa wygasłe wiersze wszystkich firm.
-- Zwraca liczbę usuniętych wierszy.
CREATE FUNCTION "public"."idempotency_keys_cleanup_expired"(p_limit integer DEFAULT 1000)
  RETURNS integer
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER
  SET search_path = pg_catalog, public
  AS $$
  DECLARE
    v_deleted integer := 0;
  BEGIN
    IF p_limit IS NULL OR p_limit < 1 OR p_limit > 10000 THEN
      RAISE EXCEPTION 'p_limit musi być w zakresie 1..10000';
    END IF;
    -- Jeden sprzątający naraz, do końca transakcji (także między instancjami Core API)
    PERFORM pg_advisory_xact_lock(hashtextextended('idempotency_keys:cleanup', 0));
    WITH expired AS (
      SELECT k."id"
      FROM "public"."idempotency_keys" k
      WHERE k."expiresAt" <= now()
      ORDER BY k."expiresAt", k."id"
      LIMIT p_limit
    )
    DELETE FROM "public"."idempotency_keys" k
    USING expired
    WHERE k."id" = expired."id"
      AND k."expiresAt" <= now();
    GET DIAGNOSTICS v_deleted = ROW_COUNT;
    RETURN v_deleted;
  END;
  $$;

GRANT SELECT, DELETE ON "public"."idempotency_keys" TO core_lookup;

GRANT CREATE ON SCHEMA "public" TO core_lookup;
ALTER FUNCTION "public"."idempotency_keys_cleanup_expired"(integer) OWNER TO core_lookup;
REVOKE CREATE ON SCHEMA "public" FROM core_lookup;
REVOKE ALL ON FUNCTION "public"."idempotency_keys_cleanup_expired"(integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION "public"."idempotency_keys_cleanup_expired"(integer) TO core_app;
