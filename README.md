# MonoriseCore

Serwer platformy Monorise: logowanie (`auth.monorise.studio`), firmy, pracownicy, role i uprawnienia (`api.monorise.studio`). Produkty Monorise logują swoich użytkowników przez Core.

## Uruchomienie lokalne

Potrzebne: Node 24, pnpm 11, Docker oraz token do paczek `@monorise-team/*` z GitHub Packages:

```bash
export GITHUB_PACKAGES_TOKEN=$(gh auth token)   # po gh auth refresh -s read:packages
pnpm install
pnpm setup:env      # pliki .env.local z losowym sekretem i adresami lokalnej bazy
pnpm db:up          # PostgreSQL i Mailpit w Dockerze (kontenery monorise-core-*)
pnpm db:migrate
pnpm dev
```

- logowanie i zakładanie firmy: http://localhost:3100,
- Core API: http://localhost:3200/core/v1/health,
- maile (potwierdzenie adresu): http://localhost:8125.

Lokalnie domenę firmy można potwierdzić bez rekordu DNS (przycisk „Potwierdź bez DNS”).

## Logowanie produktów przez Core

Produkty logują użytkowników przez Core w OAuth 2.1 (kod autoryzacji z PKCE). Przykład: Anna otwiera AvenMail, trafia na ekran logowania Core, a po zalogowaniu wraca do AvenMail z kodem, który serwer AvenMail wymienia na token dla swojego API.

Lokalnie aplikacje Monorise rejestruje polecenie:

```bash
pnpm oauth:seed     # klienci OAuth AvenMail i TimoTime, ich API oraz wpisy w rejestrze produktów
```

Sekrety nowych klientów poufnych (serwery AvenMail i TimoTime) trafiają do `apps/auth/.data/oauth-clients.json`, poza repozytorium; w bazie zostaje tylko ich skrót. Ponowne uruchomienie niczego nie psuje i nie zmienia istniejących sekretów.

| Klient             | Rodzaj                   | Powrót po zalogowaniu                                                                        |
| ------------------ | ------------------------ | -------------------------------------------------------------------------------------------- |
| `avenmail-web`     | poufny (serwer AvenMail) | `http://aven-mail.localhost:3000/api/auth/callback`                                          |
| `avenmail-desktop` | publiczny (Tauri)        | `http://127.0.0.1/oauth/callback` (dowolny port, RFC 8252)                                   |
| `avenmail-mobile`  | publiczny (Expo)         | `avenmail://oauth/callback`, lokalnie też `exp://127.0.0.1:8081/--/oauth/callback` (Expo Go) |
| `timotime-web`     | poufny (serwer TimoTime) | `http://timo-time.localhost:3300/api/auth/callback`                                          |
| `timotime-mobile`  | publiczny (Expo)         | `timotime://oauth/callback`, lokalnie też `exp://127.0.0.1:8081/--/oauth/callback` (Expo Go) |

Token dostępu jest ważny 5 minut, a token odświeżania (zakres `offline_access`) 30 dni. Rejestrowanie aplikacji przez HTTP jest wyłączone. Poufni klienci produktów (`avenmail-web`, `timotime-web`) mogą dodatkowo pobierać 5-minutowy token maszynowy (`grant_type=client_credentials`) wyłącznie z zakresem `core:permissions.register` dla zasobu Core API; klienci publiczni nigdy nie dostają tego grantu, a przepływ użytkownika w przeglądarce nie przyjmuje tego zakresu.

## Struktura firmy i Owner (etap 1 dziedziny Core)

Każda firma ma jednego Ownera (`Organization.ownerAccountId`, ustawianego przy samorejestracji; `GET /core/v1/me` zwraca `account.isOwner`). Drzewo jednostek organizacyjnych (`OrganizationUnit`: `BRANCH`, `DEPARTMENT`, `TEAM`) i przypisania pracowników (`UnitMembership`: `MEMBER`, `LEADER`) są chronione przez RLS, klucze złożone wewnątrz firmy i wyzwalacz blokujący cykle.

Dostępne endpointy Core API (`/core/v1`):

- `GET /core/v1/me`, `GET /core/v1/organization` — konto (z `isOwner`), pracownik i firma,
- `GET /core/v1/employees`, `POST /core/v1/employees` — stronicowana lista i dodawanie pracowników,
- `GET /core/v1/units`, `POST /core/v1/units`, `PATCH /core/v1/units/{unitId}` — stronicowane drzewo jednostek (filtrowanie `?status=`, zmiana nazwy, przenoszenie z kontrolą cykli, archiwizacja bez aktywnych dzieci),
- `GET /core/v1/units/{unitId}/members`, `PUT /core/v1/units/{unitId}/members/{employeeId}`, `DELETE /core/v1/units/{unitId}/members/{employeeId}` — stronicowani członkowie jednostek.

Endpointy listowe (`/employees`, `/units`, `/units/{unitId}/members`, `/permissions`, `/roles`, `/role-assignments`) przyjmują parametry `?limit=` (1–100, domyślnie 50) i `?cursor=` (kursor po `id`) oraz zwracają `meta.nextCursor` (`null` na ostatniej stronie). Odczyty (poza filtrowaniem widoczności przypisań) działają dla każdego aktywnego konta firmy; operacje zapisu wymagają odpowiednich uprawnień `core.*` w wymaganym zakresie albo roli Ownera.

## Role, gotowe szablony, przypisania i przekazanie Ownera (etap 2b dziedziny Core)

System ról i uprawnień w Core korzysta bezpośrednio ze wspólnej biblioteki `@monorise-team/permissions` (ADR-0033, ADR-0034, ADR-0035):

- **Gotowe role (szablony)**: współdzielone między firmami (`organizationId = null`, unikalny klucz `<produkt>.<nazwa>`). Przy starcie Core API automatycznie rejestruje szablon platformy `core.company_admin` („Administrator firmy”, wszystkie uprawnienia `core.*`, wpis audytu `role_templates.registered` przy zmianach). Produkty wysyłają swoje szablony tym samym tokenem maszynowym co manifest uprawnień (`PUT /core/v1/products/{productKey}/role-templates`, zakres `core:permissions.register`, wpis audytu `product.role_templates.registered`). Zmiany szablonów od produktów **nie podbijają** `authzRevision` kont w firmach — wchodzą w życie najpóźniej w ciągu 5 minut wraz z odświeżeniem pamięci podręcznej.
- **Role firmowe i kopiowanie**: uprawnienie `core.roles.manage` (zakres `ORGANIZATION`) pozwala tworzyć role firmowe od zera, kopiować szablony lub własne role (`copiedFromRoleId`), edytować aktywne role firmy i je archiwizować (archiwizacja wymaga braku przypisań, inaczej `409 CONFLICT`). Gotowych szablonów firmy nie mogą edytować ani archiwizować (`403`).
- **Przypisania z zakresem i delegowanie**: przypisanie wiąże konto z rolą w zakresie `ORGANIZATION`, `UNIT` (obejmuje jednostkę i całe jej poddrzewo) albo `RESOURCE`, opcjonalnie na czas określony (`validFrom`, `validUntil`). Nadanie i odebranie roli wymaga roli Ownera albo jednocześnie uprawnienia `core.roles.assign` obejmującego docelowy zakres (`RESOURCE` i `ORGANIZATION` wymagają zakresu całej firmy) oraz posiadania każdego uprawnienia tej roli w tym zakresie (`canDelegate`). Konta z `core.roles.assign` lub `core.roles.manage` (w dowolnym zakresie) oraz Owner widzą wszystkie przypisania firmy; pozostałe konta widzą wyłącznie własne.
- **Egzekwowanie w Core API i `authzRevision`**: zarządzanie pracownikami wymaga `core.employees.manage` (`ORGANIZATION`), a struktura firmy — `core.structure.manage` na odpowiedniej jednostce (albo `ORGANIZATION` dla jednostek głównych). Każde nadanie/odebranie przypisania, zmiana uprawnień roli firmy i przekazanie Ownera zwiększa `accounts.authzRevision` zainteresowanych kont i zapisuje wpis w `audit_log`.
- **Przekazanie Ownera**: `PUT /core/v1/organization/owner` dostępne wyłącznie dla bieżącego Ownera; przekazuje rolę aktywnemu kontu tej samej firmy (`organization.owner.transferred` z `{ from, to }`). Poprzedni Owner zachowuje tylko uprawnienia wynikające z przypisanych ról.

Endpointy etapu 2b (`/core/v1`):

- `GET /core/v1/roles`, `GET /core/v1/roles/{roleId}`, `POST /core/v1/roles`, `PATCH /core/v1/roles/{roleId}`, `DELETE /core/v1/roles/{roleId}` — przegląd, tworzenie, kopiowanie, edycja i archiwizacja ról,
- `GET /core/v1/role-assignments`, `POST /core/v1/role-assignments`, `DELETE /core/v1/role-assignments/{assignmentId}` — lista, nadawanie i odbieranie przypisań ról,
- `PUT /core/v1/organization/owner` — przekazanie roli Ownera,
- `PUT /core/v1/products/{productKey}/role-templates` — maszynowa rejestracja gotowych ról produktu.

## Rejestr uprawnień produktów i dziennik zdarzeń (etap 2a dziedziny Core)

Produkty deklarują swoje uprawnienia w kodzie za pomocą `definePermissions` z `@monorise-team/permissions` (ADR-0036), a Core utrzymuje ich rejestr w tabelach `products` i `permissions` (bez RLS, bez prawa `DELETE` dla `core_app`; wyzwalacz i ograniczenia `CHECK` pilnują zgodności prefiksu klucza z produktem):

- **Uprawnienia platformy (`core.*`)**: zdefiniowane w `@core/contracts` (`CORE_PERMISSIONS`) i rejestrowane automatycznie przy starcie Core API (`productId = null`, aktor `SYSTEM`).
- **Rejestracja manifestu produktu**: podczas wdrożenia serwer produktu pobiera z `POST /api/auth/oauth2/token` token maszynowy (`grant_type=client_credentials`, `scope=core:permissions.register`, `resource=<CORE_API_URL>`, bez `org_id`) i wysyła tablicę manifestu (1–500 wpisów) na `PUT /core/v1/products/{productKey}/permissions`. Core sprawdza, czy `client_id` tokenu zgadza się z `products.registrationClientId`, idempotentnie dodaje nowe klucze, aktualizuje opisy, wycofuje brakujące klucze przez `deprecatedAt` (nigdy ich nie usuwa) i przywraca ponownie obecne, zwracając podsumowanie `{ added, updated, deprecated, restored, unchanged }`. Tokeny maszynowe i tokeny użytkowników są ściśle rozdzielone.
- **Przeglądanie uprawnień**: `GET /core/v1/permissions` (dowolne aktywne konto firmy) z filtrami `?product=<klucz|core>`, `?includeDeprecated=true|false` (domyślnie `false`) oraz stronicowaniem kursorowym.

**Centralny dziennik zdarzeń (`audit_log`, ADR-0039)** działa w trybie tylko dopisywania:

- `core_app` ma na tabeli `audit_log` wyłącznie `SELECT` i `INSERT`, a wyzwalacz `BEFORE UPDATE` blokuje modyfikację wpisów nawet dla roli właściciela tabel (`core_owner`). Usunięcie firmy kaskadowo usuwa jej wpisy (ADR-0041).
- RLS odcina firmy od cudzych wpisów i od wpisów platformy (`organizationId = null`); zapisy firmowe wymagają `withOrganization`, a platformowe (rejestracja uprawnień) działają bez kontekstu firmy.
- Zapisy w Core API (`employee.created`, `unit.created`, `unit.updated`, `unit.member.set`, `unit.member.removed`) zapisują wpis w tej samej transakcji bez danych osobowych w `metadata`, a rejestracja uprawnień zapisuje wpis `product.permissions.registered` tylko wtedy, gdy manifest coś zmienił.

## Opis API (OpenAPI)

Opis Core API w standardzie OpenAPI 3.1 znajduje się w [openapi/core-api.json](openapi/core-api.json) i jest serwowany na żywo pod `GET /core/v1/openapi.json` (bez tokenu, jako czysty dokument JSON — wyjątek od koperty `{ data, meta, error }`). Plik powstaje automatycznie z katalogu ścieżek (`apps/api/src/routes.ts`) oraz schematów Zod (`@core/contracts`) i stanowi jedyne źródło prawdy do generowania typowanego klienta `@monorise-team/sdk`.

Po każdej zmianie ścieżek lub schematów Core API odśwież i sprawdź plik:

```bash
pnpm openapi                                 # generuje openapi/core-api.json z kodu
pnpm openapi:check                           # sprawdza, czy plik w repo jest aktualny
pnpm exec redocly lint openapi/core-api.json # walidacja składni i reguł OpenAPI
```

Kontrole `pnpm openapi:check` oraz `redocly lint` są częścią `pnpm check` (i CI).

## Licencja

Repozytorium jest publiczne, ale nie jest open source: wszelkie prawa zastrzeżone (zob. [LICENSE](LICENSE)).
