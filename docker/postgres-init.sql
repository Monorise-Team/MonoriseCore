-- Baza monorise_core i jej role (ADR-0037, 04-data/multi-tenancy.md):
-- - core_owner jest właścicielem tabel i uruchamia migracje,
-- - core_app to rola aplikacji: nie jest właścicielem tabel i nie ma BYPASSRLS, więc RLS obowiązuje ją zawsze,
-- - core_lookup (bez logowania) jest właścicielem kilku wąskich funkcji SECURITY DEFINER, które muszą
--   zajrzeć ponad granicą firm (np. dane do tokenu po identyfikatorze konta); tylko ona omija RLS.
-- Hasła tylko do pracy lokalnej i CI; na AWS role i hasła zakłada infrastruktura.
CREATE ROLE core_owner LOGIN PASSWORD 'core_owner';
CREATE ROLE core_app LOGIN PASSWORD 'core_app';
CREATE ROLE core_lookup NOLOGIN BYPASSRLS;
GRANT core_lookup TO core_owner;
CREATE DATABASE monorise_core OWNER core_owner;
-- Osobna baza testów lokalnych, żeby testy nie mieszały danych (i kluczy podpisujących) z pracą w przeglądarce
CREATE DATABASE monorise_core_test OWNER core_owner;
\connect monorise_core
CREATE EXTENSION IF NOT EXISTS citext;
\connect monorise_core_test
CREATE EXTENSION IF NOT EXISTS citext;
