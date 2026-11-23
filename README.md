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

## Logowanie produktów przez Core

Produkty logują użytkowników przez Core w OAuth 2.1 (kod autoryzacji z PKCE). Przykład: Anna otwiera AvenMail, trafia na ekran logowania Core, a po zalogowaniu wraca do AvenMail z kodem, który serwer AvenMail wymienia na token dla swojego API.

Lokalnie aplikacje Monorise rejestruje polecenie:

```bash
pnpm oauth:seed     # klienci OAuth AvenMail i TimoTime oraz ich API jako odbiorcy tokenów
```

Sekrety nowych klientów poufnych (serwery AvenMail i TimoTime) trafiają do `apps/auth/.data/oauth-clients.json`, poza repozytorium; w bazie zostaje tylko ich skrót. Ponowne uruchomienie niczego nie psuje i nie zmienia istniejących sekretów.

| Klient             | Rodzaj                   | Powrót po zalogowaniu                               |
| ------------------ | ------------------------ | --------------------------------------------------- |
| `avenmail-web`     | poufny (serwer AvenMail) | `http://aven-mail.localhost:3000/api/auth/callback` |
| `avenmail-desktop` | publiczny (Tauri)        | `studio.monorise.avenmail://oauth/callback`         |
| `avenmail-mobile`  | publiczny (Expo)         | `avenmail://oauth/callback`                         |
| `timotime-web`     | poufny (serwer TimoTime) | `http://timo-time.localhost:3300/api/auth/callback` |
| `timotime-mobile`  | publiczny (Expo)         | `timotime://oauth/callback`                         |

Token dostępu jest ważny 5 minut, a token odświeżania (zakres `offline_access`) 30 dni. Rejestrowanie aplikacji przez HTTP jest wyłączone.

## Licencja

Repozytorium jest publiczne, ale nie jest open source: wszelkie prawa zastrzeżone (zob. [LICENSE](LICENSE)).
