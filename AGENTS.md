# AGENTS.md

Instrukcje dla agentów AI (i ludzi) pracujących w repozytorium MonoriseCore.

## Czym jest MonoriseCore

Serwer platformy Monorise: jedno logowanie (`auth.monorise.studio`), firmy, pracownicy, konta, role i uprawnienia (`api.monorise.studio`). Produkty (AvenMail, TimoTime) logują się przez Core (ADR-0095). Przestrzeń robocza pnpm z Turborepo (ADR-0092), baza przez Prisma (ADR-0096). Decyzje są w repozytorium MonoriseDocumentation.

| Gdzie                | Co                                                                                                                                                                         |
| -------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `apps/auth`          | Next.js + Better Auth: logowanie, zakładanie firmy, potwierdzanie e-maila i domeny, tokeny JWT i JWKS (`/api/auth`), serwer OAuth 2.1 dla produktów (`/api/auth/oauth2/*`) |
| `apps/api`           | Core API w Fastify (`/v1`): przyjmuje tokeny z `apps/auth`, dane firm czyta zawsze przez RLS                                                                               |
| `packages/db`        | schemat Prisma, migracje (tabele, RLS, uprawnienia ról), `withOrganization`, wyszukiwanie ponad granicą firm                                                               |
| `packages/contracts` | schematy zod i typy API, pola tokenu, lista darmowych domen pocztowych                                                                                                     |

## Proces pracy (zawsze)

1. **Najpierw zgłoszenie** z formularza (`.github/ISSUE_TEMPLATE/`), po polsku, z sekcjami `### Obszar`, `### Priorytet`, `### Nakład pracy`.
2. **Gałąź** `flow/<typ>/<numer>-<opis>` od aktualnego `dev`, zakładana poleceniem `gh issue develop <numer> --base dev --name <gałąź>`. Pilna poprawka produkcji: `flow/hotfix/<numer>-<opis>` od `prod`. Nigdy `claude/*` ani innych nazw spoza konwencji.
3. **Commity** po angielsku w formacie Conventional Commits; hooki sprawdzają lint, formatowanie, typy i wersje. Nigdy `--no-verify`.
4. **Pull request** do `dev` z szablonu (sekcja „Dla użytkowników” PL i EN), z `Closes #<numer>`. Scalamy zwykłym scaleniem, nigdy przez squash. Zmiany w logowaniu, uprawnieniach i strukturze bazy przegląda właściciel projektu.
5. **Wydanie**: pull request `dev` → `prod`; Release Please liczy wersję. Wersji nie zmieniamy ręcznie.

## Zasady kodu

1. **Firma zawsze z zaufanego źródła** (token, sesja), nigdy z treści żądania, adresu ani formularza (ADR-0037).
2. **Dane firm tylko przez `withOrganization`** z `@core/db`: ustawia firmę w transakcji, a RLS w bazie odcina inne firmy. Aplikacje łączą się rolą `core_app` (bez uprawnień właściciela tabel i bez BYPASSRLS).
3. **Wyszukiwanie ponad granicą firm** tylko przez wąskie funkcje bazy (`account_claims`, `domain_owner`) należące do roli `core_lookup`. Nowa taka funkcja to zmiana w obszarze bezpieczeństwa: opisz ją w pull requeście.
4. **Każda tabela z danymi firmy** ma w migracji RLS włączone i wymuszone (`ENABLE` + `FORCE`) z polityką `tenant_isolation`, a w testach przypadek próby odczytu i zapisu cudzych danych.
5. **Token dostępu** (ADR-0023): JWT ważny 5 minut, podpis EdDSA, pola `org_id`, `employee_id`, `sid`, `amr`, `authz_rev`; bez uprawnień w tokenie. Produkty dostają token z OAuth 2.1 (`aud` to API produktu). W tych tokenach `sid` dokłada sam serwer OAuth, a `amr` jest polem zastrzeżonym wtyczki i na razie go nie ma (kontrakt przyjmuje pustą listę); sposób przekazania MFA ustalamy razem z MFA.
6. **Klienci OAuth tylko z kodu**: aplikacje Monorise rejestruje `ensureFirstPartyClients` (`pnpm oauth:seed`), zawsze z PKCE. Rejestracja przez HTTP jest wyłączona (`clientPrivileges` i `resourcePrivileges` zwracają `false`). Nowy klient albo nowy adres powrotu to zmiana w obszarze bezpieczeństwa: opisz ją w pull requeście.
7. **Komunikaty logowania** nie zdradzają, czy konto istnieje. Darmowe skrzynki (Gmail, WP, Onet…) nie zakładają firm (ADR-0019).
8. **API** w formacie `{ data, meta, error }` ze stałymi kodami błędów z `@core/contracts`.
9. **Wygląd** tylko z `@monorise-team/ui` i tokenów (ADR-0091); teksty interfejsu po polsku.
10. **Jedna wersja**: po zmianie zależności `@monorise-team/*` używaj `pnpm shared:update`; `pnpm check:versions` musi przechodzić.

## Polecenia

```bash
pnpm install && pnpm setup:env && pnpm db:up && pnpm db:migrate
pnpm dev                 # logowanie: localhost:3100, Core API: localhost:3200, poczta (Mailpit): localhost:8125
pnpm oauth:seed          # lokalni klienci OAuth AvenMail i TimoTime (sekrety w apps/auth/.data/)
pnpm check               # obowiązkowo przed pull requestem (wymaga bazy z pnpm db:up)
```

Nowa migracja: zmień `packages/db/prisma/schema.prisma`, potem w `packages/db` `pnpm exec prisma migrate dev --create-only --name <opis>`, dopisz RLS dla nowych tabel z danymi firm i uruchom testy.
