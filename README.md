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
pnpm oauth:seed     # klienci OAuth AvenMail i TimoTime oraz ich API jako odbiorcy tokenów
```

Sekrety nowych klientów poufnych (serwery AvenMail i TimoTime) trafiają do `apps/auth/.data/oauth-clients.json`, poza repozytorium; w bazie zostaje tylko ich skrót. Ponowne uruchomienie niczego nie psuje i nie zmienia istniejących sekretów.

| Klient             | Rodzaj                   | Powrót po zalogowaniu                                                                        |
| ------------------ | ------------------------ | -------------------------------------------------------------------------------------------- |
| `avenmail-web`     | poufny (serwer AvenMail) | `http://aven-mail.localhost:3000/api/auth/callback`                                          |
| `avenmail-desktop` | publiczny (Tauri)        | `http://127.0.0.1/oauth/callback` (dowolny port, RFC 8252)                                   |
| `avenmail-mobile`  | publiczny (Expo)         | `avenmail://oauth/callback`, lokalnie też `exp://127.0.0.1:8081/--/oauth/callback` (Expo Go) |
| `timotime-web`     | poufny (serwer TimoTime) | `http://timo-time.localhost:3300/api/auth/callback`                                          |
| `timotime-mobile`  | publiczny (Expo)         | `timotime://oauth/callback`                                                                  |

Token dostępu jest ważny 5 minut, a token odświeżania (zakres `offline_access`) 30 dni. Rejestrowanie aplikacji przez HTTP jest wyłączone.

## Struktura firmy i Owner (etap 1 dziedziny Core)

Każda firma ma jednego Ownera (`Organization.ownerAccountId`, ustawianego przy samorejestracji; `GET /core/v1/me` zwraca `account.isOwner`). Drzewo jednostek organizacyjnych (`OrganizationUnit`: `BRANCH`, `DEPARTMENT`, `TEAM`) i przypisania pracowników (`UnitMembership`: `MEMBER`, `LEADER`) są chronione przez RLS, klucze złożone wewnątrz firmy i wyzwalacz blokujący cykle.

Dostępne endpointy Core API (`/core/v1`):

- `GET /core/v1/me`, `GET /core/v1/organization` — konto (z `isOwner`), pracownik i firma,
- `GET /core/v1/employees`, `POST /core/v1/employees` — stronicowana lista i dodawanie pracowników,
- `GET /core/v1/units`, `POST /core/v1/units`, `PATCH /core/v1/units/{unitId}` — stronicowane drzewo jednostek (filtrowanie `?status=`, zmiana nazwy, przenoszenie z kontrolą cykli, archiwizacja bez aktywnych dzieci),
- `GET /core/v1/units/{unitId}/members`, `PUT /core/v1/units/{unitId}/members/{employeeId}`, `DELETE /core/v1/units/{unitId}/members/{employeeId}` — stronicowani członkowie jednostek.

Endpointy listowe (`/employees`, `/units`, `/units/{unitId}/members`) przyjmują parametry `?limit=` (1–100, domyślnie 50) i `?cursor=` (kursor kursorowy po `id`) oraz zwracają `meta.nextCursor` (`null` na ostatniej stronie). Odczyty działają dla każdego aktywnego konta firmy; operacje zapisu wymagają roli Ownera do czasu wdrożenia ról i uprawnień (etap 2).

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
