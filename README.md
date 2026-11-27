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
- maile (potwierdzenie adresu, zmiana hasła, zaproszenia): http://localhost:8125.

Lokalnie domenę firmy można potwierdzić bez rekordu DNS (przycisk „Potwierdź bez DNS”, sterowany zmienną `CORE_DEV_TRUST_DOMAINS=1` w `apps/auth` i `apps/api`).

## Zmienne środowiskowe

Polecenie `pnpm setup:env` tworzy lokalne pliki `.env.local` (istniejących nie nadpisuje) ze wspólnym sekretem `CORE_DOMAIN_VERIFICATION_SECRET` dla `apps/auth` i `apps/api`.

### `apps/auth`

| Zmienna                           | Wymagana                           | Opis                                                                                                                                                                                                                      |
| --------------------------------- | ---------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `BETTER_AUTH_SECRET`              | tak                                | Sekret sesji i podpisów Better Auth (nigdy nie trafia do `apps/api`).                                                                                                                                                     |
| `CORE_DOMAIN_VERIFICATION_SECRET` | na prod. tak (poza prod. zalecana) | Wspólny z `apps/api` sekret HMAC-SHA256 do rekordów DNS TXT weryfikacji domen (na produkcji wymagany, po przycięciu spacji min. 32 znaki, bez fallbacku); poza produkcją `apps/auth` może wrócić do `BETTER_AUTH_SECRET`. |
| `BETTER_AUTH_URL`                 | nie                                | Publiczny adres serwera logowania (`iss` tokenów JWT, domyślnie `http://localhost:3100`).                                                                                                                                 |
| `CORE_DATABASE_URL`               | tak                                | Połączenie PostgreSQL roli `core_app` (bez uprawnień właściciela i `BYPASSRLS`).                                                                                                                                          |
| `CORE_TOKEN_AUDIENCE`             | nie                                | Odbiorcy tokenów JWT rozdzieleni przecinkami (domyślnie `http://localhost:3200`).                                                                                                                                         |
| `CORE_SMTP_URL`                   | nie                                | Transport poczty (`smtp://…` albo `memory`, domyślnie `memory`).                                                                                                                                                          |
| `CORE_MAIL_FROM`                  | nie                                | Nadawca wiadomości e-mail (domyślnie `Monorise <no-reply@monorise.studio>`).                                                                                                                                              |
| `CORE_DEV_TRUST_DOMAINS`          | nie                                | `1` wyłącznie gdy `NODE_ENV` ma wartość `development` lub `test` — włącza potwierdzanie głównej domeny bez DNS (`trustLocally: true`).                                                                                    |

### `apps/api`

| Zmienna                                 | Wymagana            | Opis                                                                                                                                                                                                                                       |
| --------------------------------------- | ------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `CORE_DATABASE_URL`                     | tak                 | Połączenie PostgreSQL roli `core_app` (wszystkie dane firm przez RLS).                                                                                                                                                                     |
| `CORE_DOMAIN_VERIFICATION_SECRET`       | tak                 | Wspólny z `apps/auth` sekret HMAC-SHA256 do wyliczania rekordów DNS TXT weryfikacji domen firmy (na produkcji wymagany, po przycięciu spacji min. 32 znaki).                                                                               |
| `CORE_AUTH_ISSUER`                      | tak                 | Wystawca tokenów JWT (`iss`, np. `http://localhost:3100`).                                                                                                                                                                                 |
| `CORE_AUTH_JWKS_URL`                    | tak                 | Adres kluczy publicznych JWKS serwera logowania.                                                                                                                                                                                           |
| `CORE_AUTH_URL`                         | nie                 | Adres serwera logowania do linków zaproszeń (domyślnie `CORE_AUTH_ISSUER`).                                                                                                                                                                |
| `CORE_API_AUDIENCE`                     | tak                 | Oczekiwany odbiorca tokenów JWT (`aud`, np. `http://localhost:3200`).                                                                                                                                                                      |
| `CORE_API_URL`                          | na prod. `https://` | Publiczny adres Core API używany do budowania linków wypisania RFC 8058 (domyślnie `CORE_API_AUDIENCE`); na produkcji wymagany jako poprawny adres `https://` bez danych logowania i parametrów zapytania.                                 |
| `CORE_SMTP_URL`                         | nie                 | Transport poczty kanału logowania dla zaproszeń (`smtp://…` albo `memory`).                                                                                                                                                                |
| `CORE_MAIL_FROM`                        | nie                 | Nadawca wiadomości kanału logowania (domyślnie `Monorise <no-reply@monorise.studio>`).                                                                                                                                                     |
| `CORE_NOTIFICATIONS_SMTP_URL`           | na prod. tak        | Osobny transport SMTP kanału powiadomień produktów (`smtp://…`, `smtps://…` albo lokalnie `memory`); na produkcji wymagany poprawny adres `smtp://`/`smtps://` (`memory` odrzucane przy starcie), poza produkcją wraca do `CORE_SMTP_URL`. |
| `CORE_NOTIFICATIONS_FROM`               | na prod. tak        | Nadawca wiadomości kanału powiadomień; na produkcji wymagany przy starcie i bez znaków CR/LF, poza produkcją wraca do `CORE_MAIL_FROM`.                                                                                                    |
| `CORE_NOTIFICATIONS_UNSUBSCRIBE_SECRET` | na prod. tak        | Sekret HMAC-SHA256 (na produkcji wymagany, po przycięciu spacji min. 32 znaki) do podpisywania tokenów jednoklikowego wypisania RFC 8058; w `development` i `test` wyprowadzany z `CORE_DOMAIN_VERIFICATION_SECRET`.                       |
| `CORE_DEV_TRUST_DOMAINS`                | nie                 | `1` wyłącznie gdy `NODE_ENV` ma wartość `development` lub `test` — włącza lokalne potwierdzanie domen (`trustLocally: true`) w `POST .../verify`.                                                                                          |
| `CORE_OUTBOX_PUBLISH_INTERVAL_MS`       | nie                 | Odstęp wysyłki zdarzeń outbox w ms (domyślnie `1000`, `0` wyłącza).                                                                                                                                                                        |
| `CORE_MAIL_OUTBOX_INTERVAL_MS`          | nie                 | Odstęp pracy workera transakcyjnej kolejki poczty (`mail_outbox`) w ms (domyślnie `1000`, `0` wyłącza).                                                                                                                                    |
| `CORE_IDEMPOTENCY_CLEANUP_INTERVAL_MS`  | nie                 | Odstęp sprzątania wygasłych kluczy `Idempotency-Key` w ms (domyślnie 1 godzina, `0` wyłącza).                                                                                                                                              |

## Logowanie i zmiana hasła (`apps/auth`)

Ekran logowania (`/sign-in`) pozwala zalogować się adresem e-mail i hasłem, założyć firmę (`/sign-up`) albo rozpocząć zmianę zapomnianego hasła („Nie pamiętam hasła” → `/forgot-password`).

- **Jednolita odpowiedź bez wyroczni czasowej**: formularz `/forgot-password` zawsze pokazuje ten sam komunikat niezależnie od tego, czy konto istnieje. Wiadomości logowania (potwierdzenie adresu e-mail przy rejestracji oraz reset hasła) są wysyłane od razu w tle z 3 szybkimi próbami (`0 s`, `2 s`, `5 s`, limit 30 s na próbę i krótsze limity gniazda SMTP), poza kolejką `mail_outbox` (ta służy wyłącznie do zaproszeń). Endpoint żądania resetu chroni wbudowany limit częstotliwości Better Auth.
- **Jednorazowy link i unieważnienie sesji**: link na `/reset-password?token=…` jest ważny 30 minut i działa raz. Po ustawieniu nowego hasła (12–128 znaków) kończone są wszystkie sesje Better Auth oraz tokeny dostępu i odświeżania OAuth (`revokeUserAuthTokens`), a do dziennika firmy trafia wpis `account.password_reset` (bez haseł i tokenów).

## Logowanie produktów przez Core

Produkty logują użytkowników przez Core w OAuth 2.1 (kod autoryzacji z PKCE). Przykład: Anna otwiera AvenMail, trafia na ekran logowania Core, a po zalogowaniu wraca do AvenMail z kodem, który serwer AvenMail wymienia na token dla swojego API.

Lokalnie aplikacje Monorise rejestruje polecenie:

```bash
pnpm oauth:seed     # klienci OAuth AvenMail, TimoTime i KivoTasks, ich API oraz wpisy w rejestrze produktów
```

Sekrety nowych klientów poufnych (serwery AvenMail, TimoTime, KivoTasks i MonorisePortal) trafiają do `apps/auth/.data/oauth-clients.json`, poza repozytorium; w bazie zostaje tylko ich skrót. Ponowne uruchomienie niczego nie psuje i nie zmienia istniejących sekretów.

| Klient             | Rodzaj                    | Powrót po zalogowaniu                                                                            |
| ------------------ | ------------------------- | ------------------------------------------------------------------------------------------------ |
| `avenmail-web`     | poufny (serwer AvenMail)  | `http://aven-mail.localhost:3000/api/auth/callback`                                              |
| `avenmail-desktop` | publiczny (Tauri)         | `http://127.0.0.1/oauth/callback` (dowolny port, RFC 8252)                                       |
| `avenmail-mobile`  | publiczny (Expo)          | `avenmail://oauth/callback`, lokalnie też `exp://127.0.0.1:8081/--/oauth/callback` (Expo Go)     |
| `timotime-web`     | poufny (serwer TimoTime)  | `http://timo-time.localhost:3300/api/auth/callback`                                              |
| `kivotasks-web`    | poufny (serwer KivoTasks) | `http://kivotasks.localhost:3500/api/auth/callback`                                              |
| `timotime-mobile`  | publiczny (Expo)          | `timotime://oauth/callback`, lokalnie też `exp://127.0.0.1:8081/--/oauth/callback` (Expo Go)     |
| `monorise-portal`  | poufny (serwer Portalu)   | `http://portal.localhost:3400/api/auth/callback` (zmienna `CORE_PORTAL_WEB_URL`); tylko Core API |

Token dostępu jest ważny 5 minut, a token odświeżania (zakres `offline_access`) 30 dni. Token odświeżania jest jednorazowy: przez 20 sekund po użyciu ten sam stary token dostaje tę samą odpowiedź (dwa żądania przeglądarki naraz), a później jego ponowne użycie unieważnia wszystkie tokeny tej osoby w tej aplikacji. Nieaktywne konto albo wstrzymana firma dostaje przy odświeżaniu odmowę `invalid_grant`, więc aplikacja kończy sesję. Rejestrowanie aplikacji przez HTTP jest wyłączone. Poufni klienci produktów (`avenmail-web`, `timotime-web`, `kivotasks-web`) mogą dodatkowo pobierać 5-minutowy token maszynowy (`grant_type=client_credentials`) z zakresami `core:permissions.register`, `core:permissions.read`, `core:directory.read` oraz `core:events.read` dla zasobu Core API, a klienci produktów korzystających z modułu powiadomień (`timotime-web`, `kivotasks-web`) dodatkowo z zakresem `core:notifications.send`; klienci publiczni nigdy nie dostają tego grantu, a przepływ użytkownika w przeglądarce nie przyjmuje tych zakresów.

## Struktura firmy i Owner (etap 1 dziedziny Core)

Każda firma ma jednego Ownera (`Organization.ownerAccountId`, ustawianego przy samorejestracji; `GET /core/v1/me` zwraca `account.isOwner`). Drzewo jednostek organizacyjnych (`OrganizationUnit`: `BRANCH`, `DEPARTMENT`, `TEAM`) i przypisania pracowników (`UnitMembership`: `MEMBER`, `LEADER`) są chronione przez RLS, klucze złożone wewnątrz firmy i wyzwalacz blokujący cykle.

Dostępne endpointy Core API (`/core/v1`):

- `GET /core/v1/me`, `GET /core/v1/organization`, `PATCH /core/v1/organization` — konto (z `isOwner`), pracownik (z `workSchedule` oraz wyliczonym `effectiveWorkSchedule`) oraz odczyt i zmiana nazwy, strefy czasowej firmy (`timeZone`, domyślnie `Europe/Warsaw`, walidowana jako poprawna strefa IANA) i domyślnego harmonogramu pracy firmy (`defaultWorkSchedule`, opcjonalny obiekt JSONB albo `null`; wymaga `core.organization.manage` w zakresie `ORGANIZATION` albo Ownera),
- `POST /core/v1/organization/domains`, `POST /core/v1/organization/domains/{domainId}/verify`, `PUT /core/v1/organization/domains/{domainId}/primary`, `DELETE /core/v1/organization/domains/{domainId}` — zarządzanie domenami e-mail firmy (limit 20 domen, weryfikacja DNS TXT lub lokalne `trustLocally`, atomowa zmiana głównej domeny, blokada usunięcia głównej, ostatniej zweryfikowanej i używanej domeny; wymaga `core.organization.manage` w zakresie `ORGANIZATION` albo Ownera; w `GET /core/v1/organization` oraz na stronie `/account` w `apps/auth` instrukcje DNS TXT dla domen `PENDING`/`FAILED` widzą wyłącznie konta z tym uprawnieniem albo Owner; `POST /api/organization/domain/verify` w `apps/auth` egzekwuje te same uprawnienia).
  - **Zasada „wygrywa weryfikacja”**: wiele firm może mieć tę samą domenę jako niezweryfikowane roszczenie (`PENDING`/`FAILED`, unikalne w obrębie jednej firmy), natomiast globalnie unikalna jest wyłącznie domena `VERIFIED`. Kto pierwszy udowodni rekord DNS TXT, przejmuje domenę, a funkcja bazy `organization_domains_release_competing_claims` (`SECURITY DEFINER`, `core_lookup`) usuwa w tej samej transakcji niezweryfikowane, niegłówne roszczenia innych firm. Wyjątek: niezweryfikowana **główna** domena innej firmy (samorejestracja w toku) nie jest usuwana po cichu — przy późniejszej próbie weryfikacji tamta firma dostaje wyraźny błąd `409 CONFLICT`. Każde rozpoznanie właściciela domeny (`domain_owner`, samorejestracja, zaproszenia, `workEmail`, CLI) uznaje wyłącznie domeny `VERIFIED`. Potwierdzenie głównej domeny lub ustawienie zweryfikowanej domeny jako głównej w Core API przenosi firmę z `PENDING_VERIFICATION` do `ACTIVE` z wpisem audytu `organization.activated` (nigdy nie odblokowuje `SUSPENDED` ani `OFFBOARDING`). Przy zmianie `CORE_DOMAIN_VERIFICATION_SECRET` sprawdzanie rekordu TXT akceptuje zarówno zapisany skrót (`verificationTokenHash`), jak i wartość wyliczoną z bieżącego sekretu. Darmowe skrzynki pocztowe oraz ich subdomeny (np. `gmail.com`, `mail.gmail.com`, `pm.me`, `tuta.com`, `tutanota.com`, `wp.pl`, `onet.pl`) są odrzucane zarówno przy rejestracji, jak i przy dodawaniu domeny.
- `GET /core/v1/employees`, `POST /core/v1/employees`, `PATCH /core/v1/employees/{employeeId}`, `POST /core/v1/employees/{employeeId}/deactivate`, `POST /core/v1/employees/{employeeId}/reactivate` — stronicowana lista, dodawanie, edycja danych (w tym harmonogramu pracy `workSchedule`, z weryfikacją domeny `workEmail` i synchronizacją nazwy konta logowania) oraz wyłączanie i przywracanie kont logowania pracowników (z natychmiastowym usunięciem sesji i tokenów OAuth oraz zachowaniem przypisań ról i `AppAccess`).
  - **Harmonogram pracy (`Employee.workSchedule`, `Organization.defaultWorkSchedule`) i strefa czasowa firmy (`Organization.timeZone`)**:
    - `Employee.workSchedule` i `Organization.defaultWorkSchedule` to opcjonalne obiekty JSONB (domyślnie `null` = nieustawiony), w których kluczami są dni tygodnia ISO (`"1"` = poniedziałek, …, `"7"` = niedziela), a wartościami liczby całkowite minut pracy `0–1440`; brak klucza oznacza dzień wolny (np. Anna pełny etat: `{"1":480,"2":480,"3":480,"4":480,"5":480}`, Jan 12 h/tydz.: `{"1":240,"2":240,"3":240}`). Poprawność pilnują jednocześnie schemat Zod `WorkSchedule` oraz ograniczenia `CHECK` bazy (`employees_workSchedule_valid`, `organizations_defaultWorkSchedule_valid`). Wymiar etatu (`FTE = suma minut / 2400`) nie jest zapisywany w bazie — wyliczają go pomocniki `workScheduleWeeklyMinutes` i `workScheduleFte` z `@core/contracts`. Efektywny harmonogram pracownika wyznacza pomocnik `effectiveWorkSchedule(employeeSchedule, organizationDefault)` (indywidualny harmonogram pracownika, gdy jest ustawiony, inaczej domyślny harmonogram firmy, inaczej `null`) i jest zwracany w `GET /core/v1/me` oraz w katalogu produktu (`effectiveWorkSchedule` obok surowego `workSchedule`).
    - `Organization.timeZone` to wymagany tekst IANA (`NOT NULL DEFAULT 'Europe/Warsaw'`, walidowany w `@core/contracts` schematem `TimeZone` opartym o `Intl.supportedValuesOf('timeZone')` i `Intl.DateTimeFormat`, odrzucającym stałe przesunięcia typu `+02:00` i skróty typu `EST`). Zmiany trafiają do istniejących wpisów audytu `employee.updated` i `organization.updated`.
- `GET /core/v1/units`, `POST /core/v1/units`, `PATCH /core/v1/units/{unitId}` — stronicowane drzewo jednostek (filtrowanie `?status=`, zmiana nazwy, przenoszenie z kontrolą cykli, archiwizacja bez aktywnych dzieci),
- `GET /core/v1/units/{unitId}/members`, `PUT /core/v1/units/{unitId}/members/{employeeId}`, `DELETE /core/v1/units/{unitId}/members/{employeeId}` — stronicowani członkowie jednostek.

Endpointy listowe (`/employees`, `/invitations`, `/units`, `/units/{unitId}/members`, `/permissions`, `/roles`, `/role-assignments`, `/entitlements`, `/app-access`, `/audit-log`) przyjmują parametry `?limit=` (1–100, domyślnie 50) i `?cursor=` oraz zwracają `meta.nextCursor` (`null` na ostatniej stronie). Odczyty (poza zaproszeniami, dziennikiem zdarzeń oraz filtrowaniem widoczności przypisań i dostępu do aplikacji) działają dla każdego aktywnego konta firmy; operacje zapisu wymagają odpowiednich uprawnień `core.*` w wymaganym zakresie albo roli Ownera.

Operacje tworzące (`POST`) przyjmują opcjonalny nagłówek `Idempotency-Key` (1–255 drukowalnych znaków ASCII, ważny 24 godziny, izolowany per firma i wywołujący w tabeli `idempotency_keys` z RLS): powtórzone żądanie z tym samym kluczem i treścią zwraca zapisaną odpowiedź z nagłówkiem `Idempotency-Replayed: true` bez powtarzania zapisu ani efektów ubocznych (np. wysyłki e-maila), a użycie tego samego klucza z inną treścią zwraca `409 CONFLICT`; nieprawidłowy nagłówek zwraca `400 VALIDATION_FAILED`, a odpowiedzi błędów nie są zapisywane. Wygasłe klucze usuwa okresowo funkcja bazy `idempotency_keys_cleanup_expired` (`CORE_IDEMPOTENCY_CLEANUP_INTERVAL_MS`, domyślnie co godzinę, `0` wyłącza).

## Zaproszenia pracowników (konto `INVITED` i aktywacja)

Konta pracowników powstają wyłącznie z zaproszenia (ADR-0021). Adres e-mail musi należeć do zweryfikowanej domeny firmy (`OrganizationDomain.status = VERIFIED`); darmowe skrzynki pocztowe (ADR-0019) i zajęte adresy są odrzucane (`422` / `409` bez zdradzania innych firm).

- **Tworzenie zaproszenia (`POST /core/v1/invitations`)**: wymaga roli Ownera albo uprawnienia `core.employees.manage` w zakresie całej firmy (`ORGANIZATION`). Przyjmuje `{ email, firstName?, lastName?, employeeId? }` (bez `employeeId` tworzy pracownika z `workEmail = email`; z `employeeId` wymaga pracownika firmy bez konta). Tworzy konto logowania bez hasła (`emailVerified = false`), konto firmy w statusie `INVITED`, zaproszenie `PENDING` ważne 7 dni (w bazie wyłącznie skrót SHA-256 losowego tokenu, co najwyżej jedno zaproszenie `PENDING` na konto) oraz wpis w transakcyjnej kolejce poczty `mail_outbox` (`PENDING`). Wiadomość e-mail nie jest wysyłana w trakcie transakcji bazy — wysyła ją dopiero worker po `COMMIT` (generując jednorazowy token z linkiem `${CORE_AUTH_URL}/invite?token=<token>` w chwili wysyłki), dzięki czemu awaria SMTP nie wycofuje zaproszenia i żaden link nie opuszcza serwera przed zatwierdzeniem transakcji. Token nigdy nie jest zwracany w odpowiedzi API ani zapisywany w bazie czy dzienniku zdarzeń.
- **Transakcyjna kolejka poczty (`mail_outbox`, `CORE_MAIL_OUTBOX_INTERVAL_MS`)**:
  - Tabela `mail_outbox` (chroniona przez RLS, z częściowym indeksem `mail_outbox_pending_claim_idx` wyłącznie dla wierszy `PENDING`) obsługuje rodzaje `INVITATION` (złożony FK do `invitations`) oraz `NOTIFICATION` (złożony FK do `notifications`, z ograniczeniem `CHECK` pilnującym dokładnie jednej referencji zgodnej z `kind`) i przechowuje wyłącznie referencję do zasobu (nigdy treści wiadomości ani jawnego tokenu). Worker Core API uruchamia się domyślnie co `1000` ms (`CORE_MAIL_OUTBOX_INTERVAL_MS`, `0` wyłącza) i jest budzony natychmiast po zatwierdzeniu utworzenia lub ponowienia zaproszenia albo zakolejkowania powiadomienia.
  - Zadania pobiera atomowo funkcja bazy `mail_outbox_claim` (`SECURITY DEFINER`, `core_lookup`, `FOR UPDATE SKIP LOCKED`, zawsze według zegara bazy `now()`, dzierżawa 90 s odnawiana na starcie każdego zadania). Pojedyncze `sendMail()` ma twardy limit czasu całkowitego 30 s (`MAIL_SEND_DEADLINE_MS`) oraz krótsze limity gniazda (`SMTP_TIMEOUTS`), a każda zmiana wiersza jest ogrodzona warunkiem `status = 'PENDING' AND attempts = job.attempts`, więc spóźniony worker po wygaśnięciu dzierżawy nie nadpisze nowszej próby. Przy chwilowym błędzie SMTP worker ponawia wysyłkę z wykładniczym opóźnieniem `30 s × 2^(attempts − 1)` (maksymalnie 1 godzina) do 8 prób, po czym oznacza zadanie jako `FAILED` (wewnętrzny komunikat błędu `lastError` ma zanonimizowane dane logowania z URL i wartości `token=`, jest przycinany do 500 znaków i nigdy nie trafia do API). Dostarczanie ma semantykę _at-least-once_: po wygaśnięciu dzierżawy kolejna próba generuje nowy token (unieważniając poprzedni link).
  - Odpowiedzi zaproszeń (`GET /core/v1/invitations`, utworzenie i ponowienie) zawierają pole `delivery`: `{ status, attempts, lastAttemptAt, sentAt }` z najnowszego zadania tego zaproszenia (`status: null` dla starszych zaproszeń bez wpisu w kolejce).
  - Raz na godzinę worker porcjowo sprząta zadania starsze niż 30 dni (według `now()` bazy) funkcją `mail_outbox_cleanup` (`SECURITY DEFINER`, `core_lookup`): usuwa stare `SENT`, `CANCELLED` oraz zastąpione nowszym zadaniem `FAILED` (dzięki czemu `delivery` nigdy nie cofa się z `SENT` do `FAILED`), zachowując jedyne/najnowsze `FAILED` do diagnostyki.
- **Lista, ponowne wysłanie i cofnięcie**:
  - `GET /core/v1/invitations` (`?status=`, `?limit=`, `?cursor=`) — lista zaproszeń firmy wraz z `delivery` (wymaga `core.employees.manage` w zakresie `ORGANIZATION` lub Ownera); wygasłe wiersze `PENDING` są raportowane jako `EXPIRED`,
  - `POST /core/v1/invitations/{invitationId}/resend` — ponowne wysłanie zaproszenia w statusie `PENDING`, `EXPIRED` lub `REVOKED` (dopóki konto ma status `INVITED`); natychmiast unieważnia poprzedni link (nowy losowy skrót w bazie), ustawia nowy 7-dniowy termin ważności i status `PENDING`, anuluje poprzednie oczekujące zadania w `mail_outbox` (`CANCELLED`) i kolejkuje nową wysyłkę,
  - `DELETE /core/v1/invitations/{invitationId}` — cofa oczekujące zaproszenie (`PENDING` → `REVOKED`, `204`) i anuluje jego oczekujące zadania w `mail_outbox` (`CANCELLED`); konto pozostaje w statusie `INVITED`, a zaproszenie można później wysłać ponownie przez `/resend`.
- **Aktywacja konta (`apps/auth`)**: strona `/invite?token=<token>` wyszukuje firmę i zaproszenie przez wąską funkcję bazy `invitation_by_token_hash` (SECURITY DEFINER, zwraca wyłącznie `organization_id` i `invitation_id`), pokazuje nazwę firmy, adres e-mail i formularz ustawienia hasła (12–128 znaków, ADR-0024). Nieznane, wygasłe (oznaczane jako `EXPIRED`), cofnięte lub zużyte linki pokazują jednolity komunikat bez zdradzania szczegółów. `POST /api/invitations/accept` w jednej transakcji zapisuje hasło (hashowane mechanizmem Better Auth), ustawia `emailVerified = true`, zmienia konto na `ACTIVE`, zaproszenie na `ACCEPTED` (`acceptedAt`), zapisuje wpis audytu `invitation.accepted` i przekierowuje na `/sign-in` bez automatycznego logowania. Konto `INVITED` nie może się zalogować przed aktywacją.
- **CLI dla pilotażu i testów lokalnych** (aktor `SYSTEM`, `metadata.source = "cli"`, `invitedByAccountId = null`):

```bash
pnpm invitation:create -- --organization acme.com --email jan@acme.com --first-name Jan --last-name Kowalski
```

Polecenie tworzy zaproszenie (zapisując zadanie w `mail_outbox`) i od razu dostarcza je w tym samym procesie na skonfigurowany serwer SMTP (`CORE_SMTP_URL`, lokalnie Mailpit pod `http://localhost:8125`). Wyłącznie gdy `CORE_SMTP_URL` ma wartość `memory` albo wskazuje na `localhost` i wysyłka się powiodła, polecenie dodatkowo wypisuje link aktywacyjny na standardowe wyjście.

## Moduł powiadomień (ADR-0048, etap 1)

Wszystkie automatyczne wiadomości e-mail produktów Monorise przechodzą przez jeden wspólny moduł powiadomień Core. Produkty zlecają jedynie powiadomienie, a Core sprawdza uprawnienia i ustawienia odbiorcy, renderuje jeden spójny układ (tekst i HTML z kodowaniem wszystkich danych produktu) i wysyła wiadomość osobnym kanałem poczty (`CORE_NOTIFICATIONS_SMTP_URL`, `CORE_NOTIFICATIONS_FROM`), dzięki czemu problemy z przypomnieniami nigdy nie wpływają na e-maile logowania.

- **Stały katalog kategorii (`@core/contracts`, `NOTIFICATION_CATEGORIES`)**:
  - `security`, `account` — kanał `login`, obowiązkowe (`optional = false`, nie można ich wyłączyć, produkty nie mogą ich zlecać),
  - `timotime.reminders` (produkt `timotime`) oraz `kivotasks.assignments` (produkt `kivotasks`) — kanał `notifications`, opcjonalne (`optional = true`, domyślnie włączone; brak wiersza w `notification_preferences` oznacza `enabled = true`).
- **Tabele z RLS (`ENABLE` + `FORCE`)**:
  - `notifications` — historia powiadomień (`QUEUED | SENT | SKIPPED | FAILED`, opcjonalny `skipReason`: `PREFERENCE_OFF | NO_ACCESS`, złożony klucz unikalny `(organizationId, id)` dla klucza obcego z `mail_outbox`, bez `DELETE` dla `core_app`),
  - `notification_preferences` — ustawienia kont w firmie dla `(organizationId, accountId, category, channel)` (`EMAIL`, zarezerwowane `PUSH`) ze złożonym kluczem obcym do `accounts(organizationId, id)`.
- **Endpointy Core API (`/core/v1`)**:
  - `POST /core/v1/organizations/{organizationId}/notifications` — maszynowy endpoint produktu (`client_credentials`, zakres `core:notifications.send`, obsługa `Idempotency-Key`). Weryfikuje własność kategorii przez produkt klienta (`403`), aktywny status firmy (firmy `SUSPENDED` i `DELETED` dostają `403`) oraz aktywny `Entitlement` firmy (`403`), a także origin `actionUrl` zgodny z `uri` klienta OAuth (`422`; odrzuca białe znaki, znaki sterujące i ukośniki odwrotne, wymaga `https:` poza lokalnym `http:`, zapisuje i renderuje zkanonizowany `URL.href`). Gdy odbiorca nie jest aktywnym pracownikiem firmy z aktywnym kontem i dostępem do produktu (Owner albo aktywny `AppAccess`), zwraca `202` ze statusem `SKIPPED` i powodem `NO_ACCESS` (bez zdradzania szczegółów); wyłączona kategoria daje `202` `SKIPPED` / `PREFERENCE_OFF`; w przeciwnym razie zapisuje `notifications` (`QUEUED`) i zadanie `mail_outbox` (`NOTIFICATION`) w jednej transakcji i odpowiada `202 { id, status, skipReason }`.
  - `GET /core/v1/me/notification-preferences` — kategorie kanału `login` (zawsze włączone, nieopcjonalne) oraz kategorie produktów, do których bieżąca firma ma aktywny `Entitlement`, z bieżącym stanem `enabled`.
  - `PUT /core/v1/me/notification-preferences/{category}` (`{ enabled }`) — przełącza opcjonalną kategorię na kanale `EMAIL` i dopisuje wpis audytu `notification.preference_changed` wyłącznie przy faktycznej zmianie wartości; dla kategorii obowiązkowych (`security`, `account`) i nieznanych zwraca `422 VALIDATION_FAILED`.
  - `GET /core/v1/notifications/unsubscribe/{token}` — publiczna strona HTML potwierdzenia wypisania otwierana z linku w stopce wiadomości (bez zmiany stanu na `GET`, żeby skanery linków nie wyłączały powiadomień); pokazuje nazwę kategorii i firmy oraz przycisk „Wyłącz powiadomienia” w formularzu wysyłającym `POST` na ten sam adres z `List-Unsubscribe=One-Click`. Nieprawidłowy, zmanipulowany albo nieaktywny link zwraca neutralną stronę HTML ze statusem `404` („Ten link jest nieaktualny.”). Wszystkie odpowiedzi HTML ustawiają restrykcyjne nagłówki (`Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; form-action 'self'`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store`).
  - `POST /core/v1/notifications/unsubscribe/{token}` — publiczne jednoklikowe wypisanie (RFC 8058; przyjmuje `application/x-www-form-urlencoded` i `multipart/form-data` do 16 KiB oraz puste żądania; nieobsługiwany `Content-Type` daje `422`). Token to `base64url(payload)` + HMAC-SHA256 z `CORE_NOTIFICATIONS_UNSUBSCRIBE_SECRET` porównywany w stałym czasie (`timingSafeEqual`); błędny, zmanipulowany albo należący do nieaktywnego konta token zwraca `404`. Wyłącza kategorię na kanale `EMAIL` (bezpiecznie przy równoczesnych kliknięciach), zapisuje wpis audytu `notification.preference_changed` tylko przy zmianie i odpowiada HTML dla przeglądarki (`Accept: text/html`) albo JSON dla klientów jednoklikowych. Tokeny wypisania są cenzurowane w logach HTTP i komunikatach `mail_outbox.lastError`.
- **Dostarczanie przez worker `mail_outbox`**: w chwili wysyłki worker ponownie sprawdza status firmy (`SUSPENDED`/`DELETED` → `SKIPPED`/`NO_ACCESS`), dostęp i preferencję odbiorcy (wyłączona kategoria zamyka zadanie jako `CANCELLED` i oznacza powiadomienie `SKIPPED` / `PREFERENCE_OFF` bez wysyłki), dołącza nagłówki `List-Unsubscribe` i `List-Unsubscribe-Post: List-Unsubscribe=One-Click`, ponawia z tym samym backoffem, dzierżawą i limitem 8 prób co zaproszenia, oznaczając powiadomienie jako `SENT` (z `sentAt`) po sukcesie albo `FAILED` po ostatniej nieudanej próbie.

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

- **Katalog firmy, pracowników i jednostek dla serwerów produktów**: endpointy maszynowe wymagające tokenu `client_credentials` z zakresem `core:directory.read`, zgodności klienta produktu (`registrationClientId`) oraz aktywnego dostępu firmy (`Entitlement`, inaczej `403`, a dla nieznanej firmy `404`), działające przez RLS (listy ze standardowym stronicowaniem kursorowym):
  - `GET /core/v1/products/{productKey}/directory/organization?organizationId=<uuid>` — zwraca podstawowe dane firmy `{ id, name, status, timeZone, defaultWorkSchedule }` (bez danych domenowych),
  - `GET /core/v1/products/{productKey}/directory/unit-members?organizationId=<uuid>&unitId=<uuid>` (powtarzalny parametr `unitId`, maks. 100; brak = wszystkie jednostki) — zwraca `{ unitId, employeeId, accountId, role, workSchedule, effectiveWorkSchedule }`,
  - `GET /core/v1/products/{productKey}/directory/employees?organizationId=<uuid>&employeeId=<uuid>` (powtarzalny parametr `employeeId`, maks. 100; brak = wszyscy pracownicy) — zwraca minimalne dane `{ id, accountId, firstName, lastName, status, workSchedule, effectiveWorkSchedule }` (bez służbowego e-maila i stanowiska).

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
