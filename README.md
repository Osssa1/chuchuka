# Telegram-бот: информация по IP, доменам, BIN, криптокошелькам и номерам

Бот выдаёт информацию по IP через **ipapi.is**, по доменам через WHOIS, по BIN через **HandyAPI**, по криптокошелькам — баланс и транзакции через **Etherscan**, **BlockCypher** и **TronGrid** (ETH, BTC, TRON), по номерам телефонов — оператор через **Numverify**.

## Возможности

- Команда `/ip <адрес>` — информация по указанному IP
- Можно просто отправить в чат IP (`8.8.8.8`), домен (`example.com`), BIN (`535316`), адрес кошелька (`0x...`, `1...`, `T...`) или номер (`+79161234567`)
- Поддержка IPv4 и IPv6
- Поиск по BIN: схема карты (Visa/Mastercard и др.), тип, банк-эмитент, страна
- Поиск по криптокошельку: баланс, количество транзакций, метки (биржи, миксеры). Кнопка «TX отчёт» — выгрузка всех транзакций в файл (ETH, BTC, TRON)
- Поиск по номеру: оператор связи, тип линии (мобильный/стационарный), страна, регион
- DNS lookup: A, AAAA, MX, NS, TXT, CNAME записи домена

## Установка

1. Создайте бота в Telegram через [@BotFather](https://t.me/botfather) и скопируйте выданный токен.

2. Установите зависимости:

```bash
cd xseo_ip_bot
pip install -r requirements.txt
```

3. Задайте переменные окружения и запустите бота:

**Windows (PowerShell):**
```powershell
$env:TELEGRAM_BOT_TOKEN="ваш_токен_от_BotFather"
$env:HANDYAPI_KEY="ваш_ключ_handyapi"   # для поиска по BIN (получить на handyapi.com)
python bot.py
```

**Windows (CMD):**
```cmd
set TELEGRAM_BOT_TOKEN=ваш_токен_от_BotFather
python bot.py
```

**Linux/macOS:**
```bash
export TELEGRAM_BOT_TOKEN="ваш_токен_от_BotFather"
python bot.py
```

## Команды бота

| Команда | Описание |
|--------|----------|
| `/start` | Приветствие и краткая инструкция |
| `/help`  | Справка по командам |
| `/ip 8.8.8.8` | Информация по указанному IP |
| `/domain example.com` | WHOIS по домену |
| `/dns example.com` | DNS записи (A, MX, NS, TXT и др.) |
| `/bin 535316` | Поиск по BIN карты (6–8 цифр) |
| `/wallet 0x...` | Криптокошелёк (ETH/BTC/TRON): баланс, TX, метки |
| `/phone +79161234567` | Оператор по номеру телефона |

Можно отправить в чат без команд: `8.8.8.8`, `example.com`, `535316`, `0x...` / `1...` / `T...` или `+79161234567`.

## Зависимости

- `python-telegram-bot` — работа с Telegram Bot API
- `requests` — запросы к API
- `whois` — резервный WHOIS по доменам
- `dnspython` — DNS lookup

## API

- [ipapi.is](https://ipapi.is/) — IP-геолокация (бесплатно, до 1000 запросов/день)
- [HandyAPI](https://www.handyapi.com/bin-list) — BIN lookup (нужен ключ в ip_service.py)
- [Etherscan](https://etherscan.io/apis) — ETH баланс и транзакции (нужен ключ в ETHERSCAN_KEY)
- [BlockCypher](https://www.blockcypher.com/dev/) — BTC баланс и транзакции (без ключа)
- [TronGrid](https://developers.tron.network) — TRON баланс и транзакции (без ключа)
- [Numverify](https://numverify.com/) — оператор по номеру (1000 бесплатных запросов/мес)
- dnspython — DNS lookup (A, AAAA, MX, NS, TXT, CNAME) без API
