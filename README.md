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
- Core API: http://localhost:3200/v1/health,
- maile (potwierdzenie adresu): http://localhost:8125.

Lokalnie domenę firmy można potwierdzić bez rekordu DNS (przycisk „Potwierdź bez DNS”).

## Licencja

Repozytorium jest publiczne, ale nie jest open source: wszelkie prawa zastrzeżone (zob. [LICENSE](LICENSE)).
