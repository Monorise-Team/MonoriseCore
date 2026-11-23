# CLAUDE.md

Zasady pracy w tym repozytorium są wspólne dla wszystkich agentów i opisane w @AGENTS.md.

Dodatkowo dla Claude:

- Rozmawiaj z właścicielem projektu po polsku, prostym językiem i na przykładach (firma Acme, pracownica Anna). Pytaj tylko o to, czego nie da się ustalić samodzielnie.
- Po każdej zmianie uruchom `pnpm check` (z bazą z `pnpm db:up`) i popraw błędy przed commitem.
- Zmiany ekranów logowania sprawdzaj w przeglądarce pod `localhost:3100` w trybie jasnym i ciemnym oraz w wąskim oknie; maile z logowania są w Mailpit pod `localhost:8125`.
- Nigdy nie wpisuj prawdziwych haseł; do testów służą konta w domenach `.test`.
