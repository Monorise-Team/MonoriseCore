-- Zaproszenia pracowników (ADR-0021, ADR-0037): uprawnienia roli aplikacji, ograniczenia spójności,
-- RLS oraz wąskie wyszukiwanie zaproszenia po skrócie tokenu ponad granicą firm.

-- ── Uprawnienia roli aplikacji ─────────────────────────────────────────────────────────────────────
-- Domyślne uprawnienia schematu dały core_app także DELETE; zaproszeń aplikacja nie usuwa
-- (zamiast usuwania ustawia status REVOKED, EXPIRED albo ACCEPTED).
REVOKE ALL ON "public"."invitations" FROM core_app;
GRANT SELECT, INSERT, UPDATE ON "public"."invitations" TO core_app;

-- ── Ograniczenia spójności i co najwyżej jedno zaproszenie PENDING na konto ───────────────────────
CREATE UNIQUE INDEX "invitations_accountId_pending_key"
  ON "public"."invitations" ("accountId")
  WHERE "status" = 'PENDING';

ALTER TABLE "public"."invitations"
  ADD CONSTRAINT "invitations_status_accepted_consistency"
  CHECK (
    ("status" = 'ACCEPTED' AND "acceptedAt" IS NOT NULL)
    OR ("status" <> 'ACCEPTED' AND "acceptedAt" IS NULL)
  );

-- ── RLS: pełna izolacja firm ───────────────────────────────────────────────────────────────────────
ALTER TABLE "public"."invitations" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "public"."invitations" FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON "public"."invitations"
  USING ("organizationId" = "public"."current_organization_id"())
  WITH CHECK ("organizationId" = "public"."current_organization_id"());

-- ── Wąskie wyszukiwanie zaproszenia ponad granicą firm ─────────────────────────────────────────────
-- Podczas akceptacji zaproszenia znany jest wyłącznie token z linku (firma nie jest jeszcze znana).
-- Funkcja należy do roli core_lookup (BYPASSRLS) i zwraca wyłącznie identyfikatory firmy i zaproszenia.
GRANT SELECT ON "public"."invitations" TO core_lookup;

CREATE FUNCTION "public"."invitation_by_token_hash"(p_token_hash text)
  RETURNS TABLE (organization_id uuid, invitation_id uuid)
  LANGUAGE sql STABLE SECURITY DEFINER
  SET search_path = pg_catalog, public
  AS $$
    SELECT i."organizationId", i."id"
    FROM "public"."invitations" i
    WHERE i."tokenHash" = p_token_hash
  $$;

GRANT CREATE ON SCHEMA "public" TO core_lookup;
ALTER FUNCTION "public"."invitation_by_token_hash"(text) OWNER TO core_lookup;
REVOKE CREATE ON SCHEMA "public" FROM core_lookup;
REVOKE ALL ON FUNCTION "public"."invitation_by_token_hash"(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION "public"."invitation_by_token_hash"(text) TO core_app;
