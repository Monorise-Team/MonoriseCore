-- Transakcyjna kolejka wysyłki poczty (MonoriseCore#60, ADR-0037):
-- 1. Tabela public.mail_outbox przechowuje wyłącznie referencję do zasobu (nigdy treści wiadomości ani
--    jawnego tokenu aktywacyjnego) i jest zapisywana w tej samej transakcji co zmiana zaproszenia.
-- 2. Złożony klucz obcy (organizationId, invitationId) -> invitations(organizationId, id) pilnuje granicy firmy.
-- 3. RLS + FORCE RLS z polityką tenant_isolation; rola core_app bez DELETE (sprząta funkcja SECURITY DEFINER).
-- 4. Funkcje mail_outbox_claim (atomowe pobieranie z dzierżawą i FOR UPDATE SKIP LOCKED) oraz
--    mail_outbox_cleanup (usuwanie starych wierszy SENT/CANCELLED) należą do roli core_lookup.

-- CreateEnum
CREATE TYPE "public"."MailKind" AS ENUM ('INVITATION');

-- CreateEnum
CREATE TYPE "public"."MailStatus" AS ENUM ('PENDING', 'SENT', 'FAILED', 'CANCELLED');

-- CreateIndex (wymagany przez złożony klucz obcy z mail_outbox do invitations)
CREATE UNIQUE INDEX "invitations_organizationId_id_key"
  ON "public"."invitations"("organizationId", "id");

-- CreateTable
CREATE TABLE "public"."mail_outbox" (
    "id" UUID NOT NULL,
    "organizationId" UUID NOT NULL,
    "kind" "public"."MailKind" NOT NULL,
    "invitationId" UUID NOT NULL,
    "status" "public"."MailStatus" NOT NULL DEFAULT 'PENDING',
    "attempts" INTEGER NOT NULL DEFAULT 0,
    "nextAttemptAt" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lockedUntil" TIMESTAMPTZ(3),
    "lastAttemptAt" TIMESTAMPTZ(3),
    "sentAt" TIMESTAMPTZ(3),
    "failedAt" TIMESTAMPTZ(3),
    "lastError" TEXT,
    "createdAt" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "mail_outbox_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "mail_outbox_status_nextAttemptAt_idx"
  ON "public"."mail_outbox"("status", "nextAttemptAt");

-- CreateIndex
CREATE INDEX "mail_outbox_organizationId_invitationId_idx"
  ON "public"."mail_outbox"("organizationId", "invitationId");

-- AddForeignKey
ALTER TABLE "public"."mail_outbox"
  ADD CONSTRAINT "mail_outbox_organizationId_fkey"
  FOREIGN KEY ("organizationId") REFERENCES "public"."organizations"("id")
  ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "public"."mail_outbox"
  ADD CONSTRAINT "mail_outbox_organizationId_invitationId_fkey"
  FOREIGN KEY ("organizationId", "invitationId") REFERENCES "public"."invitations"("organizationId", "id")
  ON DELETE CASCADE ON UPDATE CASCADE;

-- ── Ograniczenia spójności ─────────────────────────────────────────────────────────────────────────
ALTER TABLE "public"."mail_outbox"
  ADD CONSTRAINT "mail_outbox_attempts_nonnegative"
  CHECK ("attempts" >= 0);

ALTER TABLE "public"."mail_outbox"
  ADD CONSTRAINT "mail_outbox_status_sent_consistency"
  CHECK (
    ("status" = 'SENT' AND "sentAt" IS NOT NULL)
    OR ("status" <> 'SENT' AND "sentAt" IS NULL)
  );

ALTER TABLE "public"."mail_outbox"
  ADD CONSTRAINT "mail_outbox_status_failed_consistency"
  CHECK (
    ("status" = 'FAILED' AND "failedAt" IS NOT NULL)
    OR ("status" <> 'FAILED' AND "failedAt" IS NULL)
  );

ALTER TABLE "public"."mail_outbox"
  ADD CONSTRAINT "mail_outbox_last_error_length"
  CHECK ("lastError" IS NULL OR char_length("lastError") <= 500);

-- ── Uprawnienia roli aplikacji ─────────────────────────────────────────────────────────────────────
-- Domyślne uprawnienia schematu dały core_app także DELETE; tu zawężamy je do odczytu, kolejkowania
-- i aktualizacji statusu (stare wiersze SENT/CANCELLED sprząta wyłącznie mail_outbox_cleanup).
REVOKE ALL ON "public"."mail_outbox" FROM core_app;
GRANT SELECT, INSERT, UPDATE ON "public"."mail_outbox" TO core_app;

-- ── RLS: pełna izolacja firm ───────────────────────────────────────────────────────────────────────
ALTER TABLE "public"."mail_outbox" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "public"."mail_outbox" FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON "public"."mail_outbox"
  USING ("organizationId" = "public"."current_organization_id"())
  WITH CHECK ("organizationId" = "public"."current_organization_id"());

-- ── Pobieranie zadań do wysyłki ponad granicą firm ─────────────────────────────────────────────────
-- Funkcja należy do roli core_lookup (BYPASSRLS), bo worker obsługuje kolejkę wszystkich firm.
-- Atomowo rezerwuje porcję zadań PENDING gotowych do wysyłki (FOR UPDATE SKIP LOCKED), ustawia
-- dzierżawę lockedUntil, podbija attempts oraz lastAttemptAt i zwraca wyłącznie referencje.
CREATE FUNCTION "public"."mail_outbox_claim"(
  p_limit integer,
  p_lease_ms integer,
  p_now timestamptz DEFAULT now()
)
  RETURNS TABLE (
    "id" uuid,
    "organizationId" uuid,
    "kind" "public"."MailKind",
    "invitationId" uuid,
    "attempts" integer
  )
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER
  SET search_path = pg_catalog, public
  AS $$
  DECLARE
    v_now timestamptz := COALESCE(p_now, now());
  BEGIN
    IF p_limit IS NULL OR p_limit < 1 OR p_limit > 1000 THEN
      RAISE EXCEPTION 'p_limit musi być w zakresie 1..1000';
    END IF;
    IF p_lease_ms IS NULL OR p_lease_ms < 1 OR p_lease_ms > 86400000 THEN
      RAISE EXCEPTION 'p_lease_ms musi być w zakresie 1..86400000';
    END IF;

    RETURN QUERY
    WITH candidates AS (
      SELECT m."id"
      FROM "public"."mail_outbox" m
      WHERE m."status" = 'PENDING'
        AND m."nextAttemptAt" <= v_now
        AND (m."lockedUntil" IS NULL OR m."lockedUntil" < v_now)
      ORDER BY m."nextAttemptAt" ASC, m."id" ASC
      LIMIT p_limit
      FOR UPDATE SKIP LOCKED
    ),
    claimed AS (
      UPDATE "public"."mail_outbox" m
      SET "lockedUntil" = v_now + (p_lease_ms * interval '1 millisecond'),
          "attempts" = m."attempts" + 1,
          "lastAttemptAt" = v_now,
          "updatedAt" = v_now
      FROM candidates
      WHERE m."id" = candidates."id"
      RETURNING m."id", m."organizationId", m."kind", m."invitationId", m."attempts", m."nextAttemptAt"
    )
    SELECT c."id", c."organizationId", c."kind", c."invitationId", c."attempts"
    FROM claimed c
    ORDER BY c."nextAttemptAt" ASC, c."id" ASC;
  END;
  $$;

-- ── Sprzątanie starych zadań SENT i CANCELLED ponad granicą firm ───────────────────────────────────
-- Usuwa wyłącznie wysłane (SENT) i anulowane (CANCELLED) wiersze starsze niż p_before.
-- Wiersze PENDING i FAILED pozostają nienaruszone.
CREATE FUNCTION "public"."mail_outbox_cleanup"(p_before timestamptz)
  RETURNS integer
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER
  SET search_path = pg_catalog, public
  AS $$
  DECLARE
    v_deleted integer := 0;
  BEGIN
    IF p_before IS NULL THEN
      RAISE EXCEPTION 'p_before nie może być NULL';
    END IF;

    PERFORM pg_advisory_xact_lock(hashtextextended('mail_outbox:cleanup', 0));

    DELETE FROM "public"."mail_outbox" m
    WHERE (m."status" = 'SENT' AND COALESCE(m."sentAt", m."updatedAt") < p_before)
       OR (m."status" = 'CANCELLED' AND m."updatedAt" < p_before);

    GET DIAGNOSTICS v_deleted = ROW_COUNT;
    RETURN v_deleted;
  END;
  $$;

GRANT SELECT, DELETE ON "public"."mail_outbox" TO core_lookup;
GRANT UPDATE ("lockedUntil", "attempts", "lastAttemptAt", "updatedAt") ON "public"."mail_outbox" TO core_lookup;

GRANT CREATE ON SCHEMA "public" TO core_lookup;
ALTER FUNCTION "public"."mail_outbox_claim"(integer, integer, timestamptz) OWNER TO core_lookup;
ALTER FUNCTION "public"."mail_outbox_cleanup"(timestamptz) OWNER TO core_lookup;
REVOKE CREATE ON SCHEMA "public" FROM core_lookup;
REVOKE ALL ON FUNCTION "public"."mail_outbox_claim"(integer, integer, timestamptz) FROM PUBLIC;
REVOKE ALL ON FUNCTION "public"."mail_outbox_cleanup"(timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION "public"."mail_outbox_claim"(integer, integer, timestamptz) TO core_app;
GRANT EXECUTE ON FUNCTION "public"."mail_outbox_cleanup"(timestamptz) TO core_app;
