-- Kanał zdarzeń dla produktów (MonoriseCore#53; do czasu EventBridge i SQS z ADR-0045).
-- Zdarzenie dostaje numer `sequence` dopiero przy wysyłce, w kolejności wysyłki. Numer nadaje jeden
-- wysyłający naraz (blokada doradcza do końca transakcji), więc produkt czytający `sequence > X`
-- nigdy nie pominie zdarzenia, które zostanie zatwierdzone później z niższym numerem.

CREATE SEQUENCE "public"."outbox_events_sequence_seq" AS bigint;

ALTER TABLE "public"."outbox_events" ADD COLUMN "sequence" BIGINT;

CREATE UNIQUE INDEX "outbox_events_sequence_key" ON "public"."outbox_events" ("sequence");

-- Dla aplikacji zdarzenia są tylko do dopisywania: wysyła je (numer i publishedAt) wyłącznie funkcja poniżej.
-- Ręczne oznaczenie „wysłane” bez numeru ukryłoby zdarzenie przed kanałem na zawsze.
REVOKE UPDATE ON "public"."outbox_events" FROM core_app;
DROP POLICY outbox_events_tenant_update ON "public"."outbox_events";

-- Wysłane zdarzenie ma numer, a niewysłane nie ma żadnego
ALTER TABLE "public"."outbox_events"
  ADD CONSTRAINT "outbox_events_sequence_when_published"
  CHECK (("sequence" IS NULL) = ("publishedAt" IS NULL));

-- ── Wysyłka: kolejna porcja niewysłanych zdarzeń dostaje numery ────────────────────────────────────
-- Funkcja należy do roli core_lookup (BYPASSRLS), bo wysyła zdarzenia wszystkich firm. Zmienia wyłącznie
-- `sequence` i `publishedAt`, zwraca liczbę wysłanych zdarzeń.
CREATE FUNCTION "public"."outbox_publish_pending"(p_limit integer)
  RETURNS integer
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER
  SET search_path = pg_catalog, public
  AS $$
  DECLARE
    v_row record;
    v_count integer := 0;
  BEGIN
    IF p_limit IS NULL OR p_limit < 1 OR p_limit > 1000 THEN
      RAISE EXCEPTION 'p_limit musi być w zakresie 1..1000';
    END IF;
    -- Jeden wysyłający naraz, do końca transakcji (także między instancjami Core API)
    PERFORM pg_advisory_xact_lock(hashtextextended('outbox_events:publish', 0));
    FOR v_row IN
      SELECT o."id"
      FROM "public"."outbox_events" o
      WHERE o."publishedAt" IS NULL
      ORDER BY o."occurredAt", o."id"
      LIMIT p_limit
      FOR UPDATE
    LOOP
      UPDATE "public"."outbox_events"
        SET "sequence" = nextval('"public"."outbox_events_sequence_seq"'),
            "publishedAt" = clock_timestamp()
        WHERE "id" = v_row."id";
      v_count := v_count + 1;
    END LOOP;
    RETURN v_count;
  END;
  $$;

-- ── Odczyt kanału przez produkt ────────────────────────────────────────────────────────────────────
-- Tylko wysłane zdarzenia firm, które mają aktywny dostęp do produktu (bez zdarzeń platformy).
-- Zwraca wyłącznie pola koperty; produkt sprawdza Core API (klient zarejestrował produkt, zakres tokenu).
CREATE FUNCTION "public"."product_event_feed"(p_product_id uuid, p_after bigint, p_limit integer)
  RETURNS TABLE (
    "sequence" bigint,
    "id" uuid,
    "organizationId" uuid,
    "type" text,
    "version" integer,
    "resourceType" text,
    "resourceId" text,
    "resourceVersion" integer,
    "payload" jsonb,
    "occurredAt" timestamptz
  )
  LANGUAGE sql STABLE SECURITY DEFINER
  SET search_path = pg_catalog, public
  AS $$
    SELECT o."sequence", o."id", o."organizationId", o."type", o."version", o."resourceType",
           o."resourceId", o."resourceVersion", o."payload", o."occurredAt"
    FROM "public"."outbox_events" o
    WHERE o."sequence" > p_after
      AND o."organizationId" IS NOT NULL
      AND EXISTS (
        SELECT 1
        FROM "public"."entitlements" e
        WHERE e."organizationId" = o."organizationId"
          AND e."productId" = p_product_id
          AND e."status" = 'ACTIVE'
          AND e."startsAt" <= now()
          AND (e."endsAt" IS NULL OR e."endsAt" > now())
      )
    ORDER BY o."sequence"
    LIMIT LEAST(GREATEST(p_limit, 1), 500)
  $$;

GRANT USAGE, UPDATE ON SEQUENCE "public"."outbox_events_sequence_seq" TO core_lookup;
GRANT SELECT ON "public"."outbox_events", "public"."entitlements" TO core_lookup;
GRANT UPDATE ("sequence", "publishedAt") ON "public"."outbox_events" TO core_lookup;

GRANT CREATE ON SCHEMA "public" TO core_lookup;
ALTER FUNCTION "public"."outbox_publish_pending"(integer) OWNER TO core_lookup;
ALTER FUNCTION "public"."product_event_feed"(uuid, bigint, integer) OWNER TO core_lookup;
REVOKE CREATE ON SCHEMA "public" FROM core_lookup;
REVOKE ALL ON FUNCTION "public"."outbox_publish_pending"(integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION "public"."product_event_feed"(uuid, bigint, integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION "public"."outbox_publish_pending"(integer) TO core_app;
GRANT EXECUTE ON FUNCTION "public"."product_event_feed"(uuid, bigint, integer) TO core_app;
