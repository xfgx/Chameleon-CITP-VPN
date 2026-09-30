# Chameleon — исходники клиентского приложения (4.5)

Эта ветка содержит **только исходники самого приложения Chameleon**: клиент Android, клиент Windows, общее ядро на Go и документацию протокола. Серверная инфраструктура, служебные скрипты, эксперименты и рабочие заметки сюда не входят.

Версии: Android **4.5.1**, Windows **4.5.0**.

## Состав

| Каталог | Что внутри |
|---|---|
| `android/` | Приложение Android (Kotlin, VpnService), Gradle-проект |
| `desktop/Chameleon.Windows/` | Интерфейс Windows (WPF, .NET), встроенная вкладка «Обновления» |
| `mobilecore/` | Ядро для Android (gomobile): туннель, AUTO-выбор протокола, split-tunnel РФ |
| `cmd/chamd/` | Служба-ядро Windows: брокер, Wintun, AUTO-режим, DNS |
| `cmd/ks-vpn/` | Клиент протокола KS |
| `cmd/cham-client/`, `cmd/cham-keygen/`, `cmd/vpn-service-setup/` | Консольный клиент CITP, генерация ключей, установка службы |
| `internal/` | Общие библиотеки: протокол CITP (`chameleon`), `chaossync`, активация, IPC, телеметрия без содержимого трафика |
| `packaging/` | Установщик NSIS, скрипты проверки, лицензии сторонних компонентов |
| `protocol/` | Спецификации: wire-format, инварианты, модель угроз, TLA+-модель |
| `docs/` | Заметки к выпускам клиента |

## Сборка

Требования: Go 1.26+, gomobile, Android SDK 34 + Gradle 8.7, .NET 8 SDK, NSIS 3.

```bash
# ядро и консольные утилиты
go build ./...
go test ./internal/... ./cmd/chamd ./cmd/ks-vpn ./mobilecore

# ядро Windows
GOOS=windows GOARCH=amd64 go build -trimpath -ldflags '-H=windowsgui' ./cmd/chamd

# библиотека ядра для Android
gomobile bind -target=android -androidapi 23 -o android/app/libs/mobilecore.aar ./mobilecore
cd android && gradle assembleRelease

# интерфейс Windows
dotnet publish desktop/Chameleon.Windows -c Release -r win-x64
```

Подпись APK и установщика выполняется вашими собственными ключами; ключи и пароли в репозиторий не кладутся.

## Настройка под свою инсталляцию

Все адреса, порты и ключи реальной инсталляции из этой ветки удалены и заменены заглушками. Логика кода не менялась. Перед сборкой укажите свои значения:

| Заглушка | Где | Что указать |
|---|---|---|
| `vpn.example.com` | `internal/clientactivation`, `cmd/chamd`, `android/…/ActivationClient.kt`, `MainActivity.kt`, `AndroidManifest.xml`, `desktop/…/Updater.cs`, `Services.cs` | домен вашего сайта активации и обновлений |
| `your_activation_bot` | `desktop/…/MainWindow.xaml.cs`, `packaging/windows/*.txt` | имя вашего Telegram-бота выдачи ключей |
| `ksprobe.Port`, `chaossync PortBase`, `PeerPort` в `client.example.json` | `internal/ksprobe`, `internal/chaossync/cdt.go`, `packaging/windows` | порты ваших узлов |
| `-connect` у `cham-client` | `cmd/cham-client` | адрес и порт вашей ноды |

Адреса и ключи серверов клиент получает из личного ключа доступа (выдаётся ботом), поэтому в коде их нет.

## Что удалено при публикации

- приватные и публичные ключи узлов, токены, пароли, сертификаты подписи;
- IP-адреса, домены, порты и пути реальных серверов;
- рабочие заметки и журналы, серверные скрипты развёртывания, админ-панели, бот, эксперименты;
- ссылки на внутреннюю инфраструктуру и сторонние ресурсы в документации.

В коде оставлены только публичные сервисы, без которых функции не работают: DNS-over-HTTPS-резолверы, OONI, RIPEstat, crt.sh, проверочные адреса связности.

## Лицензия

См. `LICENSE`, `LICENSE-NOTICE.md` и `packaging/THIRD-PARTY-NOTICES.txt`.
