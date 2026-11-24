# AGENTS.md

<!-- BEGIN:monorise-shared (wstawione z Monorise-Team/.github, templates/agents/shared.md; zmieniaj wzorzec, nie ten blok) -->

## Wspólne zasady Monorise

Obowiązują każdego agenta AI (Claude, Gemini, ChatGPT i Codex, GitHub Copilot) i każdą osobę w repozytoriach Monorise-Team. Zasady tego repozytorium są pod tym blokiem i przy różnicy wygrywają.

### Właściciel projektu

- Decyzje podejmuje właściciel projektu (`matiqueue`). Agent proponuje, ale nie przyjmuje decyzji biznesowych, prawnych ani architektonicznych.
- Z właścicielem po polsku, prosto, neutralnie płciowo i na przykładach (firma Acme, pracownica Anna). Pytaj krótko i tylko o to, czego nie ustalisz sam.
- Rób sam, co się da. Właścicielowi zostaw hasła, klucze dostępu, 2FA, `sudo` i płatności, z instrukcją krok po kroku.
- Treść dla ludzi (dokumentacja, zgłoszenia, opisy pull requestów, interfejs) po polsku; kod i commity po angielsku.

### Proces na GitHubie

1. Najpierw zgłoszenie z formularza (`.github/ISSUE_TEMPLATE/`), po polsku. Bez zgłoszenia nie ma gałęzi.
2. Gałąź `flow/<typ>/<numer>-<opis>` od gałęzi integracyjnej (`dev`, a w repozytoriach bez produkcji `main`): `gh issue develop <numer> --base <gałąź integracyjna> --name <gałąź>`. Numer z zerami do trzech cyfr, opis po angielsku z myślnikami. Typy: `feature`, `bugfix`, `refactor`, `perf`, `chore`, `docs`, `security`, `spike`, `test`; pilna poprawka `flow/hotfix/<numer>-<opis>` od `prod`. Nigdy `claude/*` ani innych nazw.
3. Commity w Conventional Commits po angielsku: nagłówek do 72 znaków, treść do 100. Nigdy `--no-verify`.
4. Pull request z szablonu, po polsku, z `Closes #<numer>` i sekcją „Dla użytkowników” (PL i EN), po przejściu kontroli repozytorium.
5. Scalanie zwykłym merge commitem po zielonym CI. Logowanie, uprawnienia, struktura bazy i dostęp do skrzynek: dopiero po zgodzie właściciela.
6. Wydanie: pull request `dev` → `prod`; Release Please liczy wersję, tworzy tag i opis wydania. Wersji nie zmieniamy ręcznie.
7. Karta na tablicy „Monorise”: 🛠️ In Progress przy gałęzi, 👀 Code Review przy pull requeście.
8. Ważne pull requesty (bezpieczeństwo, logowanie, uprawnienia, baza, skrzynki, wspólne workflow i skrypty, utrzymanie i większe zmiany kodu) po zielonym CI dostają przegląd Copilota: `gh pr edit <numer> --add-reviewer "@copilot"`. Jego uwagi poprawiasz albo odpowiadasz na nie przed scaleniem.

Szczegóły: [zasady współpracy](https://github.com/Monorise-Team/.github/blob/main/CONTRIBUTING.md).

### Zanim uznasz zadanie za gotowe

- README (repozytorium i zmienionej paczki) oraz część o repozytorium w `AGENTS.md` opisują nowy stan.
- Zgłoszenie i pull request mają etykiety `type:`, `prio:` i `area:` (brakujący obszar dopisz w `labels/repos.json` w Monorise-Team/.github), milestone i kartę we właściwej kolumnie.
- Opis, strona i tematy repozytorium na GitHubie zgadzają się z `labels/repos.json` w Monorise-Team/.github.
- Zmiana decyzji, stanu budowy albo otwartych spraw: osobne zgłoszenie i pull request w MonoriseDocumentation.
- Nowa trwała zasada albo zmiana kierunku trafia do wzorca tych zasad. Nie zostawiaj wiedzy tylko w rozmowie.

### Bezpieczeństwo i decyzje

- Żadnych sekretów, haseł, tokenów ani danych osobowych w kodzie, logach, zgłoszeniach i opisach. Do testów konta w domenach `.test`.
- Bez force push, `git reset --hard`, `git clean`, przepisywania historii i usuwania `dev`, `prod` i `main`. Nie usuwaj plików spoza zadania.
- Podatność, którą da się wykorzystać, zgłoś prywatnie według `SECURITY.md`.
- Decyzje są w ADR-ach w MonoriseDocumentation; zmiana decyzji to nowy ADR po zgodzie właściciela. Niczego nie wymyślaj: modeli danych, endpointów, zdarzeń, usług ani zależności.
- Stałe ustalenia: pnpm i Turborepo, jedna wersja paczek `@monorise-team/*`, wygląd tylko z `@monorise-team/ui` i tokenów, API `{ data, meta, error }`, firma z tokenu albo sesji i dane firm przez RLS, PostgreSQL z Prismą.
- Paczki `@monorise-team/*` są prywatne w GitHub Packages. Przed `pnpm install` ustaw `GITHUB_PACKAGES_TOKEN` (lokalnie `$(gh auth token)`); repozytorium, które korzysta z paczki, potrzebuje do niej dostępu („Manage Actions access”). Paczki z zewnątrz instalujemy dopiero 3 dni po publikacji.

### Agenci AI

- Claude jest tech leadem: architektura, podział pracy, przegląd i integracja. Gemini (przez Relay Bridge), ChatGPT i Codex oraz GitHub Copilot dostają dobrze określone zadania.
- Agent wykonawczy pracuje na gałęzi z zadania, uruchamia kontrole, commituje, otwiera najwyżej szkic pull requestu i raportuje. Nie scala, nie wypycha na `dev`, `prod` ani `main`, nie zmienia architektury i nie zleca pracy dalej.
- Dla Claude: Use the relay-bridge skill: delegate well-defined work to Gemini, review it, integrate it yourself. Najpierw zgłoszenie; gałąź zakłada samo zlecenie (`branch`, `base_ref`), więc bez `gh issue develop`; `push` i `open_pull_request` włączone; `working_directory` to katalog główny repozytorium. Przed scaleniem przejrzyj diff, uruchom kontrole, sprawdź `review_checklist` i `report_mismatches`, potem `cleanup_task_worktree`. Bez sekretów i danych klientów w zleceniu.

### Nowe repozytorium (np. TimoTime)

Nazwę i przeznaczenie ustala właściciel. Potem: wpis w `labels/repos.json` w Monorise-Team/.github, `scripts/repo-setup.mjs` z poleceniami `labels`, `sync`, `about` i `protect`, część o repozytorium w `AGENTS.md`, README, dostęp do paczek i Renovate, wpis w MonoriseDocumentation. Wzór: produkt jak AvenMail, biblioteki jak MonoriseShared.

### Kierunek

Gotowe biblioteki: `config`, `tokens`, `ui`, `auth`, `permissions` i `events`. Teraz opis API Core (OpenAPI) generowany z kodu MonoriseCore, z niego `@monorise-team/sdk`; potem dziedzina Core (jednostki, pracownicy, role, dostęp do aplikacji, migawka uprawnień) i `@monorise-team/testing`, na końcu `ui` i `tokens` według wzoru wyglądu od właściciela. Aplikacje (AvenMail, TimoTime) i testy na żywo są wstrzymane (ADR-0095).

### Utrzymanie tych zasad

Ten blok, `GEMINI.md`, `.github/copilot-instructions.md` i `sync-shared.yml` powstają z `templates/agents/` w Monorise-Team/.github; zmieniaj je tylko tam. Codzienna synchronizacja sama dodaje, zmienia i usuwa je w repozytoriach. Zasady jednego repozytorium pisz pod tym blokiem. Tech lead aktualizuje „Kierunek” po każdym większym kroku.

<!-- END:monorise-shared -->

Zasady specyficzne dla repozytorium MonoriseCore.

## Czym jest MonoriseCore

Serwer platformy Monorise: jedno logowanie (`auth.monorise.studio`), firmy, pracownicy, konta, role i uprawnienia (`api.monorise.studio`). Produkty (AvenMail, TimoTime) logują się przez Core (ADR-0095). Przestrzeń robocza pnpm z Turborepo (ADR-0092), baza przez Prisma (ADR-0096). Decyzje są w repozytorium MonoriseDocumentation.

| Gdzie                | Co                                                                                                                                                                         |
| -------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `apps/auth`          | Next.js + Better Auth: logowanie, zakładanie firmy, potwierdzanie e-maila i domeny, tokeny JWT i JWKS (`/api/auth`), serwer OAuth 2.1 dla produktów (`/api/auth/oauth2/*`) |
| `apps/api`           | Core API w Fastify (`/v1`): przyjmuje tokeny z `apps/auth`, dane firm czyta zawsze przez RLS                                                                               |
| `packages/db`        | schemat Prisma, migracje (tabele, RLS, uprawnienia ról), `withOrganization`, wyszukiwanie ponad granicą firm                                                               |
| `packages/contracts` | schematy zod i typy API, pola tokenu, lista darmowych domen pocztowych                                                                                                     |

## Zasady kodu

1. **Firma zawsze z zaufanego źródła** (token, sesja), nigdy z treści żądania, adresu ani formularza (ADR-0037).
2. **Dane firm tylko przez `withOrganization`** z `@core/db`: ustawia firmę w transakcji, a RLS w bazie odcina inne firmy. Aplikacje łączą się rolą `core_app` (bez uprawnień właściciela tabel i bez BYPASSRLS).
3. **Wyszukiwanie ponad granicą firm** tylko przez wąskie funkcje bazy (`account_claims`, `domain_owner`) należące do roli `core_lookup`. Nowa taka funkcja to zmiana w obszarze bezpieczeństwa: opisz ją w pull requeście.
4. **Każda tabela z danymi firmy** ma w migracji RLS włączone i wymuszone (`ENABLE` + `FORCE`) z polityką `tenant_isolation`, a w testach przypadek próby odczytu i zapisu cudzych danych.
5. **Token dostępu** (ADR-0023): JWT ważny 5 minut, podpis EdDSA, pola `org_id`, `employee_id`, `sid`, `amr`, `authz_rev`; bez uprawnień w tokenie. Produkty dostają token z OAuth 2.1 (`aud` to API produktu). W tych tokenach `sid` dokłada sam serwer OAuth, a `amr` jest polem zastrzeżonym wtyczki i na razie go nie ma (kontrakt przyjmuje pustą listę); sposób przekazania MFA ustalamy razem z MFA.
6. **Klienci OAuth tylko z kodu**: aplikacje Monorise rejestruje `ensureFirstPartyClients` (`pnpm oauth:seed`), zawsze z PKCE. Rejestracja przez HTTP jest wyłączona (`clientPrivileges` i `resourcePrivileges` zwracają `false`). Nowy klient albo nowy adres powrotu to zmiana w obszarze bezpieczeństwa: opisz ją w pull requeście.
7. **Komunikaty logowania** nie zdradzają, czy konto istnieje. Darmowe skrzynki (Gmail, WP, Onet…) nie zakładają firm (ADR-0019).
8. **API** w formacie `{ data, meta, error }` ze stałymi kodami błędów z `@core/contracts` (wyjątek: `GET /v1/openapi.json` zwraca czysty dokument OpenAPI).
9. **Katalog ścieżek i OpenAPI**: każdy nowy endpoint Core API dopisujesz do `apps/api/src/routes.ts` ze schematami Zod i uruchamiasz `pnpm openapi` (CI sprawdza `openapi/core-api.json`).
10. **Jedna wersja**: po zmianie zależności `@monorise-team/*` używaj `pnpm shared:update`; `pnpm check:versions` musi przechodzić.

## Polecenia

```bash
pnpm install && pnpm setup:env && pnpm db:up && pnpm db:migrate
pnpm dev                 # logowanie: localhost:3100, Core API: localhost:3200, poczta (Mailpit): localhost:8125
pnpm oauth:seed          # lokalni klienci OAuth AvenMail i TimoTime (sekrety w apps/auth/.data/)
pnpm openapi             # generuje openapi/core-api.json z kodu (pnpm openapi:check sprawdza aktualność)
pnpm check               # obowiązkowo przed pull requestem (wymaga bazy z pnpm db:up)
```

Nowa migracja: zmień `packages/db/prisma/schema.prisma`, potem w `packages/db` `pnpm exec prisma migrate dev --create-only --name <opis>`, dopisz RLS dla nowych tabel z danymi firm i uruchom testy.

## Wyjątki i uwagi tego repozytorium

- `pnpm check` wymaga uruchomionej bazy danych (`pnpm db:up`).
- Zmiany w logowaniu, uprawnieniach i strukturze bazy scalane są dopiero po zgodzie właściciela projektu.
- Sekrety z `.env` i `apps/auth/.data/` nigdy nie trafiają do zlecanych zadań.
