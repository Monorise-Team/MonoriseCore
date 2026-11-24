# CLAUDE.md

Zasady pracy w tym repozytorium są wspólne dla wszystkich agentów i opisane w @AGENTS.md.

Dodatkowo dla Claude:

- Rozmawiaj z właścicielem projektu po polsku, prostym językiem i na przykładach (firma Acme, pracownica Anna). Pytaj tylko o to, czego nie da się ustalić samodzielnie.
- Po każdej zmianie uruchom `pnpm check` (z bazą z `pnpm db:up`) i popraw błędy przed commitem.
- Zmiany ekranów logowania sprawdzaj w przeglądarce pod `localhost:3100` w trybie jasnym i ciemnym oraz w wąskim oknie; maile z logowania są w Mailpit pod `localhost:8125`.
- Nigdy nie wpisuj prawdziwych haseł; do testów służą konta w domenach `.test`.

## Relay Bridge

Use the relay-bridge skill: delegate well-defined work to Gemini, review it, integrate it yourself.

- Zlecaj Gemini pracę dobrze określoną: funkcję, testy, poprawkę ze znaną przyczyną, dokumentację. Architektura, decyzje, przegląd i scalanie zostają po Twojej stronie.
- Najpierw zgłoszenie z formularza. Gałąź zakłada samo zlecenie (`branch: flow/<typ>/<numer>-<opis>`, `base_ref: dev`), więc przy pracy zleconej pomijasz `gh issue develop`. Zlecenie dostaje `push: true` i `open_pull_request: true`.
- `working_directory` to katalog główny tego repozytorium (`git rev-parse --show-toplevel`).
- Nie przekazuj w zleceniu sekretów z `.env` ani z `apps/auth/.data/`.
- Przed integracją przejrzyj diff, uruchom `pnpm check` (z bazą z `pnpm db:up`) w katalogu roboczym zlecenia i sprawdź `review_checklist` oraz `report_mismatches`.
- Pull request uzupełnij z szablonu (`Closes #<numer>`), oznacz jako gotowy i scal zwykłym scaleniem po zielonym CI. Zmiany w logowaniu, uprawnieniach i strukturze bazy scalasz dopiero po zgodzie właściciela projektu.
- Po scaleniu usuń katalog roboczy zlecenia (`cleanup_task_worktree`).
- Agent, który dostał zlecenie przez Relay Bridge, nie zleca dalej: wykonuje zadanie i raportuje.
