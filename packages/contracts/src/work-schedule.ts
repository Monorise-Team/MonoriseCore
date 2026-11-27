import { z } from "zod";

/** Numery dni tygodnia według ISO 8601 (`"1"` = poniedziałek, …, `"7"` = niedziela). */
export const WORK_SCHEDULE_DAYS = ["1", "2", "3", "4", "5", "6", "7"] as const;
export type IsoWeekday = (typeof WORK_SCHEDULE_DAYS)[number];

/** Maksymalna liczba minut pracy w jednym dniu (24 h). */
export const WORK_SCHEDULE_MAX_DAY_MINUTES = 1440;

/** Pełny etat tygodniowo w minutach (5 × 8 h = 40 h = 2400 min). */
export const WORK_SCHEDULE_FULL_TIME_MINUTES = 2400;

/** Domyślna strefa czasowa IANA dla firm (ADR / MonoriseCore#91). */
export const DEFAULT_ORGANIZATION_TIME_ZONE = "Europe/Warsaw";

/** Maksymalna długość identyfikatora strefy czasowej IANA. */
export const MAX_TIME_ZONE_LENGTH = 64;

export const WorkScheduleDayMinutes = z
  .number()
  .int("Liczba minut pracy w dniu musi być liczbą całkowitą")
  .min(0, "Liczba minut pracy w dniu nie może być ujemna")
  .max(
    WORK_SCHEDULE_MAX_DAY_MINUTES,
    `Liczba minut pracy w dniu może wynosić co najwyżej ${WORK_SCHEDULE_MAX_DAY_MINUTES}`,
  );

/**
 * Harmonogram pracy pracownika: liczba minut pracy w poszczególne dni tygodnia ISO (`"1"` = poniedziałek,
 * …, `"7"` = niedziela), wartości całkowite `0–1440`. Brak klucza oznacza dzień wolny, a `null` w polu
 * `Employee.workSchedule` oznacza nieustawiony harmonogram.
 */
export const WorkSchedule = z
  .object({
    "1": WorkScheduleDayMinutes.optional(),
    "2": WorkScheduleDayMinutes.optional(),
    "3": WorkScheduleDayMinutes.optional(),
    "4": WorkScheduleDayMinutes.optional(),
    "5": WorkScheduleDayMinutes.optional(),
    "6": WorkScheduleDayMinutes.optional(),
    "7": WorkScheduleDayMinutes.optional(),
  })
  .strict();
export type WorkSchedule = z.infer<typeof WorkSchedule>;

/** Suma minut pracy w tygodniu wynikająca z harmonogramu (`null`, gdy harmonogram nie jest ustawiony). */
export function workScheduleWeeklyMinutes(schedule: WorkSchedule): number;
export function workScheduleWeeklyMinutes(schedule: null | undefined): null;
export function workScheduleWeeklyMinutes(schedule: WorkSchedule | null | undefined): number | null;
export function workScheduleWeeklyMinutes(schedule: WorkSchedule | null | undefined): number | null {
  if (schedule == null) return null;
  let total = 0;
  for (const day of WORK_SCHEDULE_DAYS) {
    const minutes = schedule[day];
    if (minutes !== undefined) {
      total += minutes;
    }
  }
  return total;
}

/**
 * Wyliczony wymiar etatu (`FTE = suma minut / 2400`), nigdy nieprzechowywany w bazie.
 * Przykłady: Anna 5 × 480 min → `1`, Jan 3 × 240 min → `0.3`.
 */
export function workScheduleFte(schedule: WorkSchedule): number;
export function workScheduleFte(schedule: null | undefined): null;
export function workScheduleFte(schedule: WorkSchedule | null | undefined): number | null;
export function workScheduleFte(schedule: WorkSchedule | null | undefined): number | null {
  const weeklyMinutes = workScheduleWeeklyMinutes(schedule);
  if (weeklyMinutes === null) return null;
  return weeklyMinutes / WORK_SCHEDULE_FULL_TIME_MINUTES;
}

/** Porównuje dwa harmonogramy pracy według wartości dla dni `"1".."7"` (niezależnie od kolejności kluczy). */
export function workScheduleEquals(a: WorkSchedule | null, b: WorkSchedule | null): boolean {
  if (a === b) return true;
  if (a === null || b === null) return false;
  for (const day of WORK_SCHEDULE_DAYS) {
    if (a[day] !== b[day]) return false;
  }
  return true;
}

/**
 * Efektywny harmonogram pracy pracownika: indywidualny harmonogram pracownika, gdy jest ustawiony
 * (nie-`null`), w przeciwnym razie domyślny harmonogram firmy, albo `null`, gdy oba są nieustawione.
 */
export function effectiveWorkSchedule(
  employeeSchedule: WorkSchedule | null | undefined,
  organizationDefault: WorkSchedule | null | undefined,
): WorkSchedule | null {
  return employeeSchedule ?? organizationDefault ?? null;
}

const SUPPORTED_IANA_TIME_ZONES: ReadonlySet<string> = new Set([...Intl.supportedValuesOf("timeZone"), "UTC"]);

/** Identyfikatory IANA z podziałem na region i miasto/alias (odrzuca stałe przesunięcia typu `+02:00` i skróty typu `EST`). */
const IANA_REGION_ZONE_REGEX = /^[A-Z][A-Za-z0-9_+-]*(?:\/[A-Z][A-Za-z0-9_+-]*)+$/;

/**
 * Sprawdza, czy podana wartość jest poprawnym identyfikatorem strefy czasowej IANA (np. `Europe/Warsaw`,
 * `America/New_York`, `UTC`, `Europe/Kyiv`). Odrzuca stałe przesunięcia (`+02:00`), skróty (`EST`, `CET`),
 * niepoprawną wielkość liter oraz nieznane strefy.
 */
export function isValidIanaTimeZone(value: string): boolean {
  if (SUPPORTED_IANA_TIME_ZONES.has(value)) return true;
  if (!IANA_REGION_ZONE_REGEX.test(value)) return false;
  try {
    new Intl.DateTimeFormat("en-US", { timeZone: value });
    return true;
  } catch {
    return false;
  }
}

/** Identyfikator strefy czasowej IANA firmy (np. `Europe/Warsaw`). */
export const TimeZone = z
  .string()
  .trim()
  .min(1, "Strefa czasowa nie może być pusta")
  .max(MAX_TIME_ZONE_LENGTH, `Nazwa strefy czasowej może mieć co najwyżej ${MAX_TIME_ZONE_LENGTH} znaków`)
  .refine(isValidIanaTimeZone, "Podaj poprawną strefę czasową IANA (np. Europe/Warsaw)");
export type TimeZone = z.infer<typeof TimeZone>;
