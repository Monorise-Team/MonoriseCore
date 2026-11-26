-- Moduł powiadomień platformy Monorise — etap 1 (MonoriseCore#86, ADR-0048, ADR-0037):
-- 1. Tabela public.notifications (RLS + FORCE RLS, złożony klucz unikalny (organizationId, id),
--    CHECKi długości tytułu/treści i spójności statusu z sentAt oraz skipReason).
-- 2. Tabela public.notification_preferences (RLS + FORCE RLS, złożony klucz obcy do accounts,
--    unikalność (organizationId, accountId, category, channel); brak wiersza oznacza enabled = true).
-- 3. Rozszerzenie public.mail_outbox o rodzaj NOTIFICATION i złożony klucz obcy (organizationId, notificationId)
--    do notifications(organizationId, id) z ograniczeniem CHECK pilnującym dokładnie jednej referencji zgodnej z kind.
-- 4. Zaktualizowana funkcja public.mail_outbox_claim (SECURITY DEFINER, właściciel core_lookup) zwracająca notificationId.

-- CreateEnum
CREATE TYPE "public"."NotificationStatus" AS ENUM ('QUEUED', 'SENT', 'SKIPPED', 'FAILED');

-- CreateEnum
CREATE TYPE "public"."NotificationSkipReason" AS ENUM ('PREFERENCE_OFF', 'NO_ACCESS');

-- CreateEnum
CREATE TYPE "public"."NotificationChannel" AS ENUM ('EMAIL', 'PUSH');

-- CreateTable: notifications
CREATE TABLE "public"."notifications" (
    "id" UUID NOT NULL,
    "organizationId" UUID NOT NULL,
    "product" TEXT NOT NULL,
    "category" TEXT NOT NULL,
    "recipientAccountId" UUID NOT NULL,
    "title" TEXT NOT NULL,
    "body" TEXT NOT NULL,
    "actionUrl" TEXT,
    "status" "public"."NotificationStatus" NOT NULL DEFAULT 'QUEUED',
    "skipReason" "public"."NotificationSkipReason",
    "createdAt" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "sentAt" TIMESTAMPTZ(3),

    CONSTRAINT "notifications_pkey" PRIMARY KEY ("id")
);

-- CreateIndex (wymagany przez złożony klucz obcy z mail_outbox do notifications)
CREATE UNIQUE INDEX "notifications_organizationId_id_key"
  ON "public"."notifications"("organizationId", "id");

CREATE INDEX "notifications_organizationId_idx"
  ON "public"."notifications"("organizationId");

CREATE INDEX "notifications_organizationId_recipientAccountId_idx"
  ON "public"."notifications"("organizationId", "recipientAccountId");

-- AddForeignKey
ALTER TABLE "public"."notifications"
  ADD CONSTRAINT "notifications_organizationId_fkey"
  FOREIGN KEY ("organizationId") REFERENCES "public"."organizations"("id")
  ON DELETE CASCADE ON UPDATE CASCADE;

-- Ograniczenia spójności notifications
ALTER TABLE "public"."notifications"
  ADD CONSTRAINT "notifications_title_length"
  CHECK (char_length("title") BETWEEN 1 AND 200);

ALTER TABLE "public"."notifications"
  ADD CONSTRAINT "notifications_body_length"
  CHECK (char_length("body") BETWEEN 1 AND 4000);

ALTER TABLE "public"."notifications"
  ADD CONSTRAINT "notifications_status_sent_consistency"
  CHECK (
    ("status" = 'SENT' AND "sentAt" IS NOT NULL)
    OR ("status" <> 'SENT' AND "sentAt" IS NULL)
  );

ALTER TABLE "public"."notifications"
  ADD CONSTRAINT "notifications_status_skip_reason_consistency"
  CHECK (
    ("status" = 'SKIPPED' AND "skipReason" IS NOT NULL)
    OR ("status" <> 'SKIPPED' AND "skipReason" IS NULL)
  );

-- Uprawnienia roli aplikacji dla notifications (bez DELETE — historia powiadomień)
REVOKE ALL ON "public"."notifications" FROM core_app;
GRANT SELECT, INSERT, UPDATE ON "public"."notifications" TO core_app;

-- RLS dla notifications
ALTER TABLE "public"."notifications" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "public"."notifications" FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON "public"."notifications"
  USING ("organizationId" = "public"."current_organization_id"())
  WITH CHECK ("organizationId" = "public"."current_organization_id"());

-- CreateTable: notification_preferences
CREATE TABLE "public"."notification_preferences" (
    "id" UUID NOT NULL,
    "organizationId" UUID NOT NULL,
    "accountId" UUID NOT NULL,
    "category" TEXT NOT NULL,
    "channel" "public"."NotificationChannel" NOT NULL DEFAULT 'EMAIL',
    "enabled" BOOLEAN NOT NULL DEFAULT true,
    "updatedAt" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "notification_preferences_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "notification_preferences_org_account_category_channel_key"
  ON "public"."notification_preferences"("organizationId", "accountId", "category", "channel");

CREATE INDEX "notification_preferences_organizationId_idx"
  ON "public"."notification_preferences"("organizationId");

-- AddForeignKey
ALTER TABLE "public"."notification_preferences"
  ADD CONSTRAINT "notification_preferences_organizationId_fkey"
  FOREIGN KEY ("organizationId") REFERENCES "public"."organizations"("id")
  ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "public"."notification_preferences"
  ADD CONSTRAINT "notification_preferences_organizationId_accountId_fkey"
  FOREIGN KEY ("organizationId", "accountId") REFERENCES "public"."accounts"("organizationId", "id")
  ON DELETE CASCADE ON UPDATE CASCADE;

-- Uprawnienia roli aplikacji dla notification_preferences
REVOKE ALL ON "public"."notification_preferences" FROM core_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON "public"."notification_preferences" TO core_app;

-- RLS dla notification_preferences
ALTER TABLE "public"."notification_preferences" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "public"."notification_preferences" FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON "public"."notification_preferences"
  USING ("organizationId" = "public"."current_organization_id"())
  WITH CHECK ("organizationId" = "public"."current_organization_id"());

-- ── Rozszerzenie mail_outbox o NOTIFICATION ────────────────────────────────────────────────────────
-- Najpierw usuwamy mail_outbox_claim (zależy od typu MailKind i zmienia RETURNS TABLE o notificationId),
-- następnie tworzymy nowy typ enum zamiast ALTER TYPE ADD VALUE, żeby CHECK poniżej mógł użyć 'NOTIFICATION'
-- w tej samej transakcji migracji bez błędu PostgreSQL 55P04.
DROP FUNCTION "public"."mail_outbox_claim"(integer, integer);

CREATE TYPE "public"."MailKind_new" AS ENUM ('INVITATION', 'NOTIFICATION');

ALTER TABLE "public"."mail_outbox"
  ALTER COLUMN "kind" TYPE "public"."MailKind_new"
  USING ("kind"::text::"public"."MailKind_new");

DROP TYPE "public"."MailKind";
ALTER TYPE "public"."MailKind_new" RENAME TO "MailKind";

ALTER TABLE "public"."mail_outbox"
  ALTER COLUMN "invitationId" DROP NOT NULL,
  ADD COLUMN "notificationId" UUID;

CREATE INDEX "mail_outbox_organizationId_notificationId_idx"
  ON "public"."mail_outbox"("organizationId", "notificationId");

-- Złożony klucz obcy (organizationId, notificationId) -> notifications(organizationId, id) pilnuje granicy firmy
-- mimo że sprawdzenia FK pomijają RLS.
ALTER TABLE "public"."mail_outbox"
  ADD CONSTRAINT "mail_outbox_organizationId_notificationId_fkey"
  FOREIGN KEY ("organizationId", "notificationId") REFERENCES "public"."notifications"("organizationId", "id")
  ON DELETE CASCADE ON UPDATE CASCADE;

-- Dokładnie jedna referencja zgodna z rodzajem zadania (INVITATION albo NOTIFICATION)
ALTER TABLE "public"."mail_outbox"
  ADD CONSTRAINT "mail_outbox_kind_reference_consistency"
  CHECK (
    ("kind" = 'INVITATION' AND "invitationId" IS NOT NULL AND "notificationId" IS NULL)
    OR ("kind" = 'NOTIFICATION' AND "notificationId" IS NOT NULL AND "invitationId" IS NULL)
  );

-- ── Zaktualizowana funkcja mail_outbox_claim (z notificationId) ────────────────────────────────────
CREATE FUNCTION "public"."mail_outbox_claim"(
  p_limit integer,
  p_lease_ms integer
)
  RETURNS TABLE (
    "id" uuid,
    "organizationId" uuid,
    "kind" "public"."MailKind",
    "invitationId" uuid,
    "notificationId" uuid,
    "attempts" integer
  )
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER
  SET search_path = pg_catalog, public
  AS $$
  DECLARE
    v_now timestamptz := now();
  BEGIN
    IF p_limit IS NULL OR p_limit < 1 OR p_limit > 1000 THEN
      RAISE EXCEPTION 'p_limit musi być w zakresie 1..1000';
    END IF;
    IF p_lease_ms IS NULL OR p_lease_ms < 1 OR p_lease_ms > 3600000 THEN
      RAISE EXCEPTION 'p_lease_ms musi być w zakresie 1..3600000';
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
      RETURNING m."id", m."organizationId", m."kind", m."invitationId", m."notificationId", m."attempts", m."nextAttemptAt"
    )
    SELECT c."id", c."organizationId", c."kind", c."invitationId", c."notificationId", c."attempts"
    FROM claimed c
    ORDER BY c."nextAttemptAt" ASC, c."id" ASC;
  END;
  $$;

GRANT CREATE ON SCHEMA "public" TO core_lookup;
ALTER FUNCTION "public"."mail_outbox_claim"(integer, integer) OWNER TO core_lookup;
REVOKE CREATE ON SCHEMA "public" FROM core_lookup;
REVOKE ALL ON FUNCTION "public"."mail_outbox_claim"(integer, integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION "public"."mail_outbox_claim"(integer, integer) TO core_app;
