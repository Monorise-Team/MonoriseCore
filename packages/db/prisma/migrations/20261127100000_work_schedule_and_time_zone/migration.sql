-- Harmonogram pracy pracownika, domyślny harmonogram firmy i strefa czasowa firmy (MonoriseCore#91):
-- 1. Organization.timeZone: TEXT NOT NULL DEFAULT 'Europe/Warsaw' (istniejące firmy dostają 'Europe/Warsaw'),
--    CHECK pilnuje niepustej nazwy do 64 znaków (dokładną walidację IANA wykonuje kontrakt Zod).
-- 2. Organization.defaultWorkSchedule: nullable JSONB (istniejące firmy mają NULL — brak domyślnego harmonogramu),
--    CHECK pilnuje typu object, wyłącznie kluczy ISO "1".."7" oraz całkowitych wartości minut 0..1440.
-- 3. Employee.workSchedule: nullable JSONB (istniejący pracownicy mają NULL — brak ustawionego harmonogramu),
--    CHECK pilnuje typu object, wyłącznie kluczy ISO "1".."7" oraz całkowitych wartości minut 0..1440.
-- Tabele organizations i employees mają już włączone i wymuszone RLS (20261123000001_rls).

ALTER TABLE "public"."organizations"
  ADD COLUMN "timeZone" TEXT NOT NULL DEFAULT 'Europe/Warsaw',
  ADD COLUMN "defaultWorkSchedule" JSONB;

ALTER TABLE "public"."organizations"
  ADD CONSTRAINT "organizations_timeZone_non_empty"
  CHECK (btrim("timeZone") <> '' AND char_length("timeZone") <= 64);

ALTER TABLE "public"."organizations"
  ADD CONSTRAINT "organizations_defaultWorkSchedule_valid"
  CHECK (
    CASE
      WHEN "defaultWorkSchedule" IS NULL THEN true
      WHEN jsonb_typeof("defaultWorkSchedule") <> 'object' THEN false
      WHEN ("defaultWorkSchedule" - ARRAY['1', '2', '3', '4', '5', '6', '7']::text[]) <> '{}'::jsonb THEN false
      ELSE
        (CASE
          WHEN NOT ("defaultWorkSchedule" ? '1') THEN true
          WHEN jsonb_typeof("defaultWorkSchedule" -> '1') <> 'number' THEN false
          ELSE ("defaultWorkSchedule" ->> '1')::numeric = trunc(("defaultWorkSchedule" ->> '1')::numeric)
            AND ("defaultWorkSchedule" ->> '1')::numeric BETWEEN 0 AND 1440
        END)
        AND (CASE
          WHEN NOT ("defaultWorkSchedule" ? '2') THEN true
          WHEN jsonb_typeof("defaultWorkSchedule" -> '2') <> 'number' THEN false
          ELSE ("defaultWorkSchedule" ->> '2')::numeric = trunc(("defaultWorkSchedule" ->> '2')::numeric)
            AND ("defaultWorkSchedule" ->> '2')::numeric BETWEEN 0 AND 1440
        END)
        AND (CASE
          WHEN NOT ("defaultWorkSchedule" ? '3') THEN true
          WHEN jsonb_typeof("defaultWorkSchedule" -> '3') <> 'number' THEN false
          ELSE ("defaultWorkSchedule" ->> '3')::numeric = trunc(("defaultWorkSchedule" ->> '3')::numeric)
            AND ("defaultWorkSchedule" ->> '3')::numeric BETWEEN 0 AND 1440
        END)
        AND (CASE
          WHEN NOT ("defaultWorkSchedule" ? '4') THEN true
          WHEN jsonb_typeof("defaultWorkSchedule" -> '4') <> 'number' THEN false
          ELSE ("defaultWorkSchedule" ->> '4')::numeric = trunc(("defaultWorkSchedule" ->> '4')::numeric)
            AND ("defaultWorkSchedule" ->> '4')::numeric BETWEEN 0 AND 1440
        END)
        AND (CASE
          WHEN NOT ("defaultWorkSchedule" ? '5') THEN true
          WHEN jsonb_typeof("defaultWorkSchedule" -> '5') <> 'number' THEN false
          ELSE ("defaultWorkSchedule" ->> '5')::numeric = trunc(("defaultWorkSchedule" ->> '5')::numeric)
            AND ("defaultWorkSchedule" ->> '5')::numeric BETWEEN 0 AND 1440
        END)
        AND (CASE
          WHEN NOT ("defaultWorkSchedule" ? '6') THEN true
          WHEN jsonb_typeof("defaultWorkSchedule" -> '6') <> 'number' THEN false
          ELSE ("defaultWorkSchedule" ->> '6')::numeric = trunc(("defaultWorkSchedule" ->> '6')::numeric)
            AND ("defaultWorkSchedule" ->> '6')::numeric BETWEEN 0 AND 1440
        END)
        AND (CASE
          WHEN NOT ("defaultWorkSchedule" ? '7') THEN true
          WHEN jsonb_typeof("defaultWorkSchedule" -> '7') <> 'number' THEN false
          ELSE ("defaultWorkSchedule" ->> '7')::numeric = trunc(("defaultWorkSchedule" ->> '7')::numeric)
            AND ("defaultWorkSchedule" ->> '7')::numeric BETWEEN 0 AND 1440
        END)
    END
  );

ALTER TABLE "public"."employees"
  ADD COLUMN "workSchedule" JSONB;

ALTER TABLE "public"."employees"
  ADD CONSTRAINT "employees_workSchedule_valid"
  CHECK (
    CASE
      WHEN "workSchedule" IS NULL THEN true
      WHEN jsonb_typeof("workSchedule") <> 'object' THEN false
      WHEN ("workSchedule" - ARRAY['1', '2', '3', '4', '5', '6', '7']::text[]) <> '{}'::jsonb THEN false
      ELSE
        (CASE
          WHEN NOT ("workSchedule" ? '1') THEN true
          WHEN jsonb_typeof("workSchedule" -> '1') <> 'number' THEN false
          ELSE ("workSchedule" ->> '1')::numeric = trunc(("workSchedule" ->> '1')::numeric)
            AND ("workSchedule" ->> '1')::numeric BETWEEN 0 AND 1440
        END)
        AND (CASE
          WHEN NOT ("workSchedule" ? '2') THEN true
          WHEN jsonb_typeof("workSchedule" -> '2') <> 'number' THEN false
          ELSE ("workSchedule" ->> '2')::numeric = trunc(("workSchedule" ->> '2')::numeric)
            AND ("workSchedule" ->> '2')::numeric BETWEEN 0 AND 1440
        END)
        AND (CASE
          WHEN NOT ("workSchedule" ? '3') THEN true
          WHEN jsonb_typeof("workSchedule" -> '3') <> 'number' THEN false
          ELSE ("workSchedule" ->> '3')::numeric = trunc(("workSchedule" ->> '3')::numeric)
            AND ("workSchedule" ->> '3')::numeric BETWEEN 0 AND 1440
        END)
        AND (CASE
          WHEN NOT ("workSchedule" ? '4') THEN true
          WHEN jsonb_typeof("workSchedule" -> '4') <> 'number' THEN false
          ELSE ("workSchedule" ->> '4')::numeric = trunc(("workSchedule" ->> '4')::numeric)
            AND ("workSchedule" ->> '4')::numeric BETWEEN 0 AND 1440
        END)
        AND (CASE
          WHEN NOT ("workSchedule" ? '5') THEN true
          WHEN jsonb_typeof("workSchedule" -> '5') <> 'number' THEN false
          ELSE ("workSchedule" ->> '5')::numeric = trunc(("workSchedule" ->> '5')::numeric)
            AND ("workSchedule" ->> '5')::numeric BETWEEN 0 AND 1440
        END)
        AND (CASE
          WHEN NOT ("workSchedule" ? '6') THEN true
          WHEN jsonb_typeof("workSchedule" -> '6') <> 'number' THEN false
          ELSE ("workSchedule" ->> '6')::numeric = trunc(("workSchedule" ->> '6')::numeric)
            AND ("workSchedule" ->> '6')::numeric BETWEEN 0 AND 1440
        END)
        AND (CASE
          WHEN NOT ("workSchedule" ? '7') THEN true
          WHEN jsonb_typeof("workSchedule" -> '7') <> 'number' THEN false
          ELSE ("workSchedule" ->> '7')::numeric = trunc(("workSchedule" ->> '7')::numeric)
            AND ("workSchedule" ->> '7')::numeric BETWEEN 0 AND 1440
        END)
    END
  );
