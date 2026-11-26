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

Sekrety nowych klientów poufnych (serwery AvenMail, TimoTime i MonorisePortal) trafiają do `apps/auth/.data/oauth-clients.json`, poza repozytorium; w bazie zostaje tylko ich skrót. Ponowne uruchomienie niczego nie psuje i nie zmienia istniejących sekretów.

| Klient             | Rodzaj                   | Powrót po zalogowaniu                                                                            |
| ------------------ | ------------------------ | ------------------------------------------------------------------------------------------------ |
| `avenmail-web`     | poufny (serwer AvenMail) | `http://aven-mail.localhost:3000/api/auth/callback`                                              |
| `avenmail-desktop` | publiczny (Tauri)        | `http://127.0.0.1/oauth/callback` (dowolny port, RFC 8252)                                       |
| `avenmail-mobile`  | publiczny (Expo)         | `avenmail://oauth/callback`, lokalnie też `exp://127.0.0.1:8081/--/oauth/callback` (Expo Go)     |
| `timotime-web`     | poufny (serwer TimoTime) | `http://timo-time.localhost:3300/api/auth/callback`                                              |
| `timotime-mobile`  | publiczny (Expo)         | `timotime://oauth/callback`, lokalnie też `exp://127.0.0.1:8081/--/oauth/callback` (Expo Go)     |
| `monorise-portal`  | poufny (serwer Portalu)  | `http://portal.localhost:3400/api/auth/callback` (zmienna `CORE_PORTAL_WEB_URL`); tylko Core API |

Token dostępu jest ważny 5 minut, a token odświeżania (zakres `offline_access`) 30 dni. Token odświeżania jest jednorazowy: przez 20 sekund po użyciu ten sam stary token dostaje tę samą odpowiedź (dwa żądania przeglądarki naraz), a później jego ponowne użycie unieważnia wszystkie tokeny tej osoby w tej aplikacji. Nieaktywne konto albo wstrzymana firma dostaje przy odświeżaniu odmowę `invalid_grant`, więc aplikacja kończy sesję. Rejestrowanie aplikacji przez HTTP jest wyłączone. Poufni klienci produktów (`avenmail-web`, `timotime-web`) mogą dodatkowo pobierać 5-minutowy token maszynowy (`grant_type=client_credentials`) z zakresami `core:permissions.register`, `core:permissions.read` oraz `core:directory.read` dla zasobu Core API; klienci publiczni nigdy nie dostają tego grantu, a przepływ użytkownika w przeglądarce nie przyjmuje tych zakresów.

## Struktura firmy i Owner (etap 1 dziedziny Core)

Każda firma ma jednego Ownera (`Organization.ownerAccountId`, ustawianego przy samorejestracji; `GET /core/v1/me` zwraca `account.isOwner`). Drzewo jednostek organizacyjnych (`OrganizationUnit`: `BRANCH`, `DEPARTMENT`, `TEAM`) i przypisania pracowników (`UnitMembership`: `MEMBER`, `LEADER`) są chronione przez RLS, klucze złożone wewnątrz firmy i wyzwalacz blokujący cykle.

Dostępne endpointy Core API (`/core/v1`):

- `GET /core/v1/me`, `GET /core/v1/organization` — konto (z `isOwner`), pracownik i firma,
- `GET /core/v1/employees`, `POST /core/v1/employees`, `PATCH /core/v1/employees/{employeeId}`, `POST /core/v1/employees/{employeeId}/deactivate`, `POST /core/v1/employees/{employeeId}/reactivate` — stronicowana lista, dodawanie, edycja danych (z weryfikacją domeny `workEmail` i synchronizacją nazwy konta logowania) oraz wyłączanie i przywracanie kont logowania pracowników (z natychmiastowym usunięciem sesji i tokenów OAuth oraz zachowaniem przypisań ról i `AppAccess`),
- `GET /core/v1/units`, `POST /core/v1/units`, `PATCH /core/v1/units/{unitId}` — stronicowane drzewo jednostek (filtrowanie `?status=`, zmiana nazwy, przenoszenie z kontrolą cykli, archiwizacja bez aktywnych dzieci),
- `GET /core/v1/units/{unitId}/members`, `PUT /core/v1/units/{unitId}/members/{employeeId}`, `DELETE /core/v1/units/{unitId}/members/{employeeId}` — stronicowani członkowie jednostek.

Endpointy listowe (`/employees`, `/invitations`, `/units`, `/units/{unitId}/members`, `/permissions`, `/roles`, `/role-assignments`, `/entitlements`, `/app-access`, `/audit-log`) przyjmują parametry `?limit=` (1–100, domyślnie 50) i `?cursor=` oraz zwracają `meta.nextCursor` (`null` na ostatniej stronie). Odczyty (poza zaproszeniami, dziennikiem zdarzeń oraz filtrowaniem widoczności przypisań i dostępu do aplikacji) działają dla każdego aktywnego konta firmy; operacje zapisu wymagają odpowiednich uprawnień `core.*` w wymaganym zakresie albo roli Ownera.

Operacje tworzące (`POST`) przyjmują opcjonalny nagłówek `Idempotency-Key` (1–255 drukowalnych znaków ASCII, ważny 24 godziny, izolowany per firma i wywołujący w tabeli `idempotency_keys` z RLS): powtórzone żądanie z tym samym kluczem i treścią zwraca zapisaną odpowiedź z nagłówkiem `Idempotency-Replayed: true` bez powtarzania zapisu ani efektów ubocznych (np. wysyłki e-maila), a użycie tego samego klucza z inną treścią zwraca `409 CONFLICT`; nieprawidłowy nagłówek zwraca `400 VALIDATION_FAILED`, a odpowiedzi błędów nie są zapisywane. Wygasłe klucze usuwa okresowo funkcja bazy `idempotency_keys_cleanup_expired` (`CORE_IDEMPOTENCY_CLEANUP_INTERVAL_MS`, domyślnie co godzinę, `0` wyłącza).

## Zaproszenia pracowników (konto `INVITED` i aktywacja)

Konta pracowników powstają wyłącznie z zaproszenia (ADR-0021). Adres e-mail musi należeć do zweryfikowanej domeny firmy (`OrganizationDomain.status = VERIFIED`); darmowe skrzynki pocztowe (ADR-0019) i zajęte adresy są odrzucane (`422` / `409` bez zdradzania innych firm).

- **Tworzenie zaproszenia (`POST /core/v1/invitations`)**: wymaga roli Ownera albo uprawnienia `core.employees.manage` w zakresie całej firmy (`ORGANIZATION`). Przyjmuje `{ email, firstName?, lastName?, employeeId? }` (bez `employeeId` tworzy pracownika z `workEmail = email`; z `employeeId` wymaga pracownika firmy bez konta). Tworzy konto logowania bez hasła (`emailVerified = false`), konto firmy w statusie `INVITED`, zaproszenie `PENDING` ważne 7 dni (w bazie wyłącznie skrót SHA-256 tokenu, co najwyżej jedno zaproszenie `PENDING` na konto) i wysyła wiadomość e-mail z linkiem `${CORE_AUTH_URL}/invite?token=<token>`. Token nigdy nie jest zwracany w odpowiedzi API ani zapisywany w dzienniku zdarzeń.
- **Lista, ponowne wysłanie i cofnięcie**:
  - `GET /core/v1/invitations` (`?status=`, `?limit=`, `?cursor=`) — lista zaproszeń firmy (wymaga `core.employees.manage` w zakresie `ORGANIZATION` lub Ownera); wygasłe wiersze `PENDING` są raportowane jako `EXPIRED`,
  - `POST /core/v1/invitations/{invitationId}/resend` — ponowne wysłanie zaproszenia w statusie `PENDING`, `EXPIRED` lub `REVOKED` (dopóki konto ma status `INVITED`); generuje nowy token i 7-dniowy termin ważności, unieważniając poprzedni link, oraz ustawia status `PENDING`,
  - `DELETE /core/v1/invitations/{invitationId}` — cofa oczekujące zaproszenie (`PENDING` → `REVOKED`, `204`); konto pozostaje w statusie `INVITED`, a zaproszenie można później wysłać ponownie przez `/resend`.
- **Aktywacja konta (`apps/auth`)**: strona `/invite?token=<token>` wyszukuje firmę i zaproszenie przez wąską funkcję bazy `invitation_by_token_hash` (SECURITY DEFINER, zwraca wyłącznie `organization_id` i `invitation_id`), pokazuje nazwę firmy, adres e-mail i formularz ustawienia hasła (12–128 znaków, ADR-0024). Nieznane, wygasłe (oznaczane jako `EXPIRED`), cofnięte lub zużyte linki pokazują jednolity komunikat bez zdradzania szczegółów. `POST /api/invitations/accept` w jednej transakcji zapisuje hasło (hashowane mechanizmem Better Auth), ustawia `emailVerified = true`, zmienia konto na `ACTIVE`, zaproszenie na `ACCEPTED` (`acceptedAt`), zapisuje wpis audytu `invitation.accepted` i przekierowuje na `/sign-in` bez automatycznego logowania. Konto `INVITED` nie może się zalogować przed aktywacją.
- **CLI dla pilotażu i testów lokalnych** (aktor `SYSTEM`, `metadata.source = "cli"`, `invitedByAccountId = null`):

```bash
pnpm invitation:create -- --organization acme.com --email jan@acme.com --first-name Jan --last-name Kowalski
```

Wiadomość trafia na skonfigurowany serwer SMTP (`CORE_SMTP_URL`, lokalnie Mailpit pod `http://localhost:8125`). Wyłącznie gdy `CORE_SMTP_URL` ma wartość `memory` albo wskazuje na `localhost`, polecenie dodatkowo wypisuje link aktywacyjny na standardowe wyjście.

## Dostęp do aplikacji, migawka uprawnień dla produktów i zdarzenia (etap 3 dziedziny Core)

Dostęp pracownika do produktu działa dwustopniowo (ADR-0035, ADR-0051, ADR-0052):

- **Dostęp firmy do produktu (`Entitlement`)**: tabela `entitlements` (ścisła izolacja odczytu RLS: firma czyta wyłącznie własne wpisy przez `GET /core/v1/entitlements`, a bez kontekstu firmy `core_app` nie widzi żadnych wierszy; zapis wymaga kontekstu firmy i transakcyjnej flagi operatora Core). Aktywny dostęp oznacza `status = ACTIVE` oraz `startsAt <= teraz` i brak albo przyszłe `endsAt`. Do czasu powstania MonoriseAdmin dostępy przyznaje i kończy CLI Core (audyt z aktorem `SYSTEM` i `metadata.source = "cli"`):

```bash
pnpm entitlement:grant -- --organization acme.com --product timotime --ends-at 2027-12-31T23:59:59Z
pnpm entitlement:end   -- --organization acme.com --product timotime
```

- **Włączanie aplikacji pracownikowi (`AppAccess`)**: Owner firmy ma domyślny dostęp do każdego produktu, do którego firma ma aktywny `Entitlement` (bez wpisu `AppAccess`). Pozostałym aktywnym kontom aplikacje włącza Owner albo konto z uprawnieniem `core.app_access.manage` (dodanym do `CORE_PERMISSIONS` i szablonu `core.company_admin`) w zakresie jednostek pracownika (pracownik bez jednostek wymaga zakresu `ORGANIZATION`). Cofnięcie (`DELETE /core/v1/app-access/{appAccessId}`) oznacza wiersz jako `REVOKED` (historia), a ponowne włączenie tworzy nowy wiersz `ACTIVE`.
  - `GET /core/v1/entitlements` — stronicowana lista dostępów firmy do produktów (dla każdego aktywnego konta),
  - `GET /core/v1/app-access` (`?accountId=`, `?product=`, `?includeRevoked=`) — Owner i konta z `core.app_access.manage` widzą wszystkie wpisy firmy, pozostali tylko własne,
  - `POST /core/v1/app-access` (`{ accountId, product }`) — włącza aplikację aktywnemu kontu (`409` przy braku aktywnego `Entitlement`, nieaktywnym koncie lub duplikacie),
  - `DELETE /core/v1/app-access/{appAccessId}` — wyłącza aplikację (`204`, ustawia `REVOKED`).
- **Migawka uprawnień dla serwerów produktów (`GET /core/v1/products/{productKey}/permission-snapshot?organizationId=<uuid>&accountId=<uuid>`)**: endpoint maszynowy dla poufnego klienta produktu (`grant_type=client_credentials`, zakres `core:permissions.read`, zgodność `client_id` z `products.registrationClientId`). Zwraca obiekt zgodny z `permissionSnapshotSchema` z `@monorise-team/permissions`: `products` zawiera `[productKey]` wyłącznie gdy firma ma aktywny `Entitlement` i konto jest Ownerem albo ma aktywny `AppAccess` (dla kont `INVITED`/`DEACTIVATED` zwraca puste `products` i `grants`), `grants` zawiera wyłącznie nie-wycofane uprawnienia tego produktu z niezarchiwizowanych ról (nigdy `core.*`), a `units` pełne drzewo jednostek firmy (łącznie z `ARCHIVED`). Serwer produktu używa tego endpointu z `createPermissionCache`:

```ts
import { can, createPermissionCache } from "@monorise-team/permissions";

const permissions = createPermissionCache({
  load: async ({ organizationId, accountId }) => {
    const token = await getCoreMachineToken("core:permissions.read");
    const url = `${CORE_API_URL}/core/v1/products/timotime/permission-snapshot?organizationId=${organizationId}&accountId=${accountId}`;
    const res = await fetch(url, { headers: { Authorization: `Bearer ${token}` } });
    return (await res.json()).data;
  },
});

const snapshot = await permissions.get({ organizationId, accountId, authzRevision });
const allowed = can(snapshot, "timotime.entries.approve", { unitIds: [employeeUnitId] });
```

- **Katalog pracowników i jednostek dla serwerów produktów**: endpointy maszynowe wymagające tokenu `client_credentials` z zakresem `core:directory.read`, zgodności klienta produktu (`registrationClientId`) oraz aktywnego dostępu firmy (`Entitlement`, inaczej `403`, a dla nieznanej firmy `404`), działające przez RLS ze standardowym stronicowaniem kursorowym:
  - `GET /core/v1/products/{productKey}/directory/unit-members?organizationId=<uuid>&unitId=<uuid>` (powtarzalny parametr `unitId`, maks. 100; brak = wszystkie jednostki) — zwraca `{ unitId, employeeId, accountId, role }`,
  - `GET /core/v1/products/{productKey}/directory/employees?organizationId=<uuid>&employeeId=<uuid>` (powtarzalny parametr `employeeId`, maks. 100; brak = wszyscy pracownicy) — zwraca minimalne dane `{ id, accountId, firstName, lastName, status }` (bez służbowego e-maila i stanowiska).

- **Zdarzenia outbox (`outbox_events`, ADR-0045)**: każde podbicie `accounts.authzRevision` (nadanie/odebranie roli, zmiana uprawnień roli firmowej, archiwizacja roli, przekazanie Ownera, wyłączenie/przywrócenie konta pracownika, włączenie/wyłączenie `AppAccess` oraz zmiana `Entitlement`) w tej samej transakcji zapisuje zdarzenie `organization.permissions.changed` (budowane przez `@monorise-team/events`) w tabeli `outbox_events` (`resourceType = "account"`, `resourceId = accountId`, `resourceVersion = authzRevision`, `publishedAt = null`). Dla aplikacji (`core_app`) zdarzenia są tylko do dopisywania.
- **Kanał zdarzeń dla produktów (do czasu EventBridge i SQS z ADR-0045)**: Core API co sekundę wysyła oczekujące zdarzenia funkcją bazy `outbox_publish_pending`, która nadaje im kolejne numery `sequence` w kolejności wysyłki (jeden wysyłający naraz dzięki blokadzie doradczej, także przy kilku instancjach; `CORE_OUTBOX_PUBLISH_INTERVAL_MS`, domyślnie `1000`, `0` wyłącza). Serwer produktu pobiera je tokenem `client_credentials` z zakresem `core:events.read`: `GET /core/v1/products/{productKey}/events?cursor=<numer>&limit=` zwraca koperty `@monorise-team/events` z polem `sequence` w rosnącej kolejności, wyłącznie dla firm z aktywnym dostępem do produktu. Produkt zapamiętuje numer ostatnio przetworzonego zdarzenia i pyta o kolejne (`createEventFeedPoller` w `@monorise-team/events`); `meta.nextCursor` jest równy numerowi ostatniego zdarzenia przy pełnej stronie, a `null`, gdy produkt jest na bieżąco. Klienci produktów dostają zakres po `pnpm oauth:seed`.

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
- Zapisy w Core API (`employee.created`, `employee.updated`, `account.deactivated`, `account.reactivated`, `unit.created`, `unit.updated`, `unit.member.set`, `unit.member.removed`) zapisują wpis w tej samej transakcji bez danych osobowych w `metadata`, a rejestracja uprawnień zapisuje wpis `product.permissions.registered` tylko wtedy, gdy manifest coś zmienił.
- **Odczyt dziennika firmy (`GET /core/v1/audit-log`)**: wymaga roli Ownera albo uprawnienia `core.audit.read` w zakresie całej firmy (`ORGANIZATION`, domyślnie w `core.company_admin`). Zwraca wpisy od najnowszych (`createdAt DESC, id DESC`, złożony kursor) z oknem retencji 730 dni, filtrami (`actorAccountId`, `actorType`, `action`, `resourceType`, `resourceId`, `from`, `to`), rozwiązaną nazwą aktora (`actorDisplayName`), polską etykietą akcji (`actionLabel`) oraz oczyszczonym polem `metadata` (bez tokenów, sekretów, haseł i skrótów; `actorOperatorId` nigdy nie jest zwracany).

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
