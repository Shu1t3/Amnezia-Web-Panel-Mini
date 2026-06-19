# Amnezia Web Panel Mini

Веб-панель для управления VPN-серверами и протоколами **AmneziaWG**, **WireGuard**, **Telemt (MTProxy)** и сервисами **AmneziaDNS**, **AdGuard Home**, **SOCKS5** на удалённых Ubuntu-серверах.

## Протоколы

| Протокол | Описание |
|----------|----------|
| **AmneziaWG (awg2)** | Протокол на базе WireGuard с обфускацией S3/S4 для обхода DPI |
| **WireGuard** | Стандартный высокопроизводительный VPN-протокол |
| **Telemt** | Telegram MTProxy с эмуляцией TLS |
| **AmneziaDNS** | DNS-over-TLS резолвер на базе Unbound (порт 53) |
| **AdGuard Home** | DNS-блокировщик рекламы (два режима: замена DNS / параллельно) |
| **SOCKS5** | SOCKS5-прокси на базе 3proxy с авторизацией |

## Возможности

- Управление серверами: добавление, редактирование, удаление, проверка, перезагрузка, очистка
- Установка и удаление протоколов на серверах через Docker
- Управление пользователями с ролями (admin, support, user)
- Создание и управление VPN-подключениями с привязкой к пользователям
- Генерация конфигураций, VPN-ссылок (`vpn://`) и QR-кодов
- Telegram-бот для получения конфигураций по команде
- Интерфейс на русском, английском, французском, китайском и персидском языках
- Тёмная и светлая темы

## Требования

- **Go 1.21+**
- SSH-доступ к целевым серверам (Ubuntu 20.04/22.04/24.04)
- Docker на целевых серверах (устанавливается автоматически при необходимости)

## Установка

### Из исходников

```bash
git clone https://github.com/PRVTPRO/Amnezia-Web-Panel.git
cd Amnezia-Web-Panel
go build -o panel ./cmd/panel
./panel
```

### Docker Compose

```bash
docker compose up -d
```

Данные хранятся в Docker-томе `amnezia_data` (файл `/data/panel.db` внутри контейнера).

### Готовый образ

```bash
docker pull prvtpro/amnezia-panel:latest
docker run -d -p 8000:8000 -v panel_data:/data prvtpro/amnezia-panel:latest
```

## Первый вход

- **Логин**: `admin`
- **Пароль**: `admin`

> Сразу после первого входа измените пароль в разделе **Пользователи**.

## Переменные окружения

| Переменная | Описание | По умолчанию |
|---|---|---|
| `PORT` | Порт HTTP-сервера | `8000` |
| `DB_PATH` | Путь к файлу SQLite | `./db.sqlite3` |
| `TELEGRAM_BOT_TOKEN` | Токен Telegram-бота (также хранится в БД) | — |

## Структура проекта

```
cmd/panel/main.go             # Точка входа
internal/
├── bot/telegram_bot.go       # Telegram-бот
├── database/
│   ├── schema.sql            # SQL-схема
│   ├── query.sql             # Запросы sqlc
│   └── *.go                  # Сгенерированный код
├── handlers/
│   ├── routes.go             # Маршруты и middleware
│   ├── auth.go               # Аутентификация (сессии)
│   ├── servers.go            # CRUD серверов
│   ├── connections.go        # CRUD подключений
│   ├── users.go              # CRUD пользователей
│   ├── protocols.go          # Установка/удаление протоколов
│   └── i18n.go               # Переводы
├── managers/
│   ├── awg_manager.go        # AmneziaWG
│   ├── wireguard_manager.go  # WireGuard
│   ├── telemt_manager.go     # Telemt (MTProxy)
│   ├── dns_manager.go        # AmneziaDNS
│   ├── adguard_manager.go    # AdGuard Home
│   ├── socks5_manager.go     # SOCKS5
│   ├── ssh_manager.go        # SSH/SFTP
│   └── utils.go              # Генерация ключей, MTU, Docker
└── models/models.go          # Структуры данных
protocol_telemt/              # Docker-контекст для Telemt
templates/                    # Pongo2-шаблоны (8 шт.)
static/                       # CSS, JS, favicon
translations/                 # en, ru, fr, zh, fa
Dockerfile                    # Многоэтапная сборка (golang:alpine → alpine)
docker-compose.yml
sqlc.yaml                     # Конфигурация sqlc
```

## Стек технологий

- **Язык**: Go
- **Веб-фреймворк**: Fiber v2
- **Шаблоны**: Pongo2 (Django-style)
- **БД**: SQLite (modernc.org/sqlite, чистый Go)
- **SSH**: golang.org/x/crypto/ssh + pkg/sftp
- **Telegram**: telebot.v3
- **Генерация кода БД**: sqlc

## Лицензия

GNU General Public License v3.0 — см. [LICENSE](LICENSE).
