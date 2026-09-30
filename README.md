# Chameleon CITP VPN

Chameleon — VPN-клиент и серверная часть для работы в сетях с фильтрацией трафика. Клиент сам выбирает рабочий способ подключения (AUTO), держит соединение при смене сети и не уводит российские сайты в туннель.

Текущие версии: **Android 4.5.1**, **Windows 4.5.0**.

- Ветка `main` — полный проект: клиенты, ядро, серверы, протокол, инструменты, документация.
- Ветка `app/chameleon-4.5` — только исходники клиентского приложения 4.5 (Android + Windows + общее ядро).

## Содержание

- [Возможности](#возможности)
- [Как это устроено](#как-это-устроено)
- [Структура репозитория](#структура-репозитория)
- [Сборка](#сборка)
- [Своя инсталляция](#своя-инсталляция)
- [Безопасность и приватность](#безопасность-и-приватность)
- [Что не входит в репозиторий](#что-не-входит-в-репозиторий)
- [Участие и лицензия](#участие-и-лицензия)

## Возможности

- **AUTO-режим.** Клиент пробует несколько транспортов и держится за тот, который реально проходит в текущей сети. Результаты сеансов учитываются при следующем выборе.
- **Несколько протоколов.** CITP (TCP, TTLS, WebSocket, CDN-канал), KS (UDP) и ChaosSync. Переключение без действий пользователя.
- **Раздельная маршрутизация.** Российские адреса идут напрямую, остальное — через VPN.
- **Аутентифицированный DNS.** Ответы о выборе узла подписываются (канонический MAC v2) и проверяются клиентом; при ошибке проверки тихого отката нет.
- **Сдержанный фоновый трафик.** Маскирующий трафик ограничен по объёму и времени.
- **Обновления внутри приложения.** Вкладка «Обновления» на Android и Windows сверяет SHA-256 пакета перед установкой.
- **Минимум данных.** Телеметрия — только технические счётчики без содержимого трафика и адресов назначения.

## Как это устроено

```
 Клиент (Android / Windows)
   │  CITP / KS / ChaosSync, выбор AUTO
   ▼
 Входной узел ── цепочка CITP ──► Выходной узел ──► Интернет
   ▲
   │  подписанные ответы о выборе узла (DNS v2), бюллетень состояния сети
```

- Клиент получает адреса и ключи узлов из **личного ключа доступа**, поэтому в коде приложения их нет.
- Входной узел принимает клиентов, выходной выпускает трафик в интернет; между ними — аутентифицированная цепочка.
- Спецификация протокола: [`protocol/overview.md`](protocol/overview.md), [`protocol/wire-format.md`](protocol/wire-format.md), [`protocol/dns-binding.md`](protocol/dns-binding.md), инварианты — [`protocol/INVARIANTS.md`](protocol/INVARIANTS.md).

> **Совместимость.** DNS-аутентификация v2 не принимает старые MAC. Клиенты и все узлы цепочки (входной и выходной) обновляются вместе.

## Структура репозитория

| Каталог | Что внутри |
|---|---|
| `android/` | Приложение Android (Kotlin, VpnService), Gradle-проект |
| `desktop/Chameleon.Windows/` | Интерфейс Windows (WPF, .NET 10) |
| `mobilecore/` | Ядро для Android (gomobile): туннель, AUTO, раздельная маршрутизация |
| `cmd/chamd/` | Служба-ядро Windows: брокер, Wintun, AUTO, DNS |
| `cmd/cham-server/`, `cmd/cham-client/`, `cmd/cham-keygen/` | Сервер и консольный клиент CITP, генерация ключей |
| `cmd/ks-vpn/`, `cmd/ks-hub/`, `cmd/ks-admin/` | Протокол KS: клиент, хаб, консоль управления |
| `cmd/chaossync-*` | Сервер, клиент и самопроверка ChaosSync |
| `cmd/cdt-*` | Экспериментальный транспорт CDT и утилиты к нему |
| `cmd/vpn-web/`, `cmd/vpn-observer/`, `cmd/chaos-metrics/` | Сайт активации, наблюдатель за доступностью, метрики |
| `internal/` | Общие библиотеки: `chameleon` (CITP), `chaossync`, активация, IPC, телеметрия |
| `protocol/` | Спецификации, модель угроз, TLA+-модели, эталонный парсер |
| `docs/` | Описание подсистем (CDT, KS, ChaosSync, метрики), заметки к выпускам |
| `packaging/` | Установщик NSIS, лицензии сторонних компонентов |
| `scripts/` | Сборка релизов и проверки безопасности |
| `services/` | Примеры systemd-юнитов и бот выдачи ключей |
| `tools/` | Диагностика и лабораторные утилиты (fieldtest, probe, профилировщик и др.) |
| `workers/cham-bridge/` | Cloudflare Worker — WebSocket-мост к узлу |
| `test/e2e/` | Сквозные тесты |
| `examples/` | Примеры конфигураций клиента и сервера |

## Сборка

Требования: Go 1.26+, для Android — gomobile, Android SDK 34 и Gradle 8.7, для Windows — .NET 10 SDK и NSIS 3.

```bash
git clone <repository-url> chameleon && cd chameleon

# всё Go-ядро, серверы и утилиты
go build ./...
go vet ./...
go test ./internal/... ./cmd/... ./mobilecore

# сервер для Linux
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags '-s -w' ./cmd/cham-server

# ядро Windows
GOOS=windows GOARCH=amd64 go build -trimpath -ldflags '-H=windowsgui' ./cmd/chamd

# Android: библиотека ядра + APK
gomobile bind -target=android -androidapi 23 -o android/app/libs/mobilecore.aar ./mobilecore
cd android && gradle assembleRelease

# интерфейс Windows
dotnet publish desktop/Chameleon.Windows -c Release -r win-x64
```

`make build`, `make test`, `make vet` и `make security` делают то же самое через Makefile. APK и установщик подписываются вашими собственными ключами — в репозитории их нет.

## Своя инсталляция

Все адреса, порты, ключи и токены реальной инсталляции заменены заглушками; логика кода не менялась.

| Заглушка | Где | Что указать |
|---|---|---|
| `vpn.example.com` | `internal/clientactivation`, `cmd/chamd`, `android/…`, `desktop/…` | домен сайта активации и обновлений |
| `your_activation_bot` | `desktop/…`, `packaging/windows/*.txt` | Telegram-бот выдачи ключей |
| `203.0.113.x`, `your-node.example.com` | тесты, `examples/` | адреса ваших узлов |
| `<port>` в документации, `ksprobe.Port`, `PortBase` ChaosSync | `docs/`, `internal/ksprobe`, `internal/chaossync` | порты ваших узлов |
| `<ws-token>`, `your-account` | `workers/cham-bridge/wrangler.toml` | токен WS-фронта узла и аккаунт Cloudflare |

Быстрый старт сервера:

```bash
cham-server -genkey -keyfile server.key   # ключ узла (покажет публичный ключ)
cham-server -keyfile server.key -allowfile clients.txt -listen 0.0.0.0:<port>
```

Пример конфигурации — [`examples/server.example.yaml`](examples/server.example.yaml), клиента — [`examples/client.example.json`](examples/client.example.json).

## Безопасность и приватность

- Модель угроз: [`THREAT_MODEL.md`](THREAT_MODEL.md) и [`protocol/security/`](protocol/security).
- Сообщить об уязвимости: [`SECURITY.md`](SECURITY.md). Пожалуйста, не публикуйте детали в открытых issue.
- Секреты в репозиторий не коммитятся; проверка — `make security` (gitleaks + govulncheck).
- CI в GitHub Actions только собирает и тестирует код на стандартных раннерах GitHub; доступа к серверам проекта у него нет.

## Что не входит в репозиторий

- приватные и публичные ключи узлов, токены, пароли, ключи подписи;
- реальные IP-адреса, домены, порты и пути серверов;
- скрипты развёртывания на конкретные серверы, рабочие журналы, сырые результаты экспериментов;
- собранные бинарные файлы и сторонние библиотеки (`.jar`, `.aar`, `.dll`).

## Участие и лицензия

Как предложить изменения — [`CONTRIBUTING.md`](CONTRIBUTING.md). Лицензия — MIT, см. [`LICENSE`](LICENSE), примечания — [`LICENSE-NOTICE.md`](LICENSE-NOTICE.md) и [`packaging/THIRD-PARTY-NOTICES.txt`](packaging/THIRD-PARTY-NOTICES.txt).
