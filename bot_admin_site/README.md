# Администрирование бота (Django)

Управление списком пользователей, которым разрешён доступ к боту.

## Запуск

```bash
cd bot_admin_site
python manage.py migrate
python manage.py createsuperuser   # логин/пароль для входа в /admin/
python manage.py runserver
```

Откройте http://127.0.0.1:8000/admin/ и войдите под суперпользователем.

## Управление доступом

- В разделе **«Разрешённые пользователи»** (bot_admin) добавляйте записи: **Telegram ID** (обязательно), при желании — username и заметку.
- Снимите галочку **«Доступ разрешён»**, чтобы временно отключить пользователя.
- Telegram ID можно узнать через бота @userinfobot в Telegram.

## Подключение бота к Django

URL API задаётся **переменной окружения** `BOT_ALLOWED_LIST_URL` (в `bot.py` значение по умолчанию только для локальной отладки):

```bash
export BOT_ALLOWED_LIST_URL="https://ВАШ-ДОМЕН/api/allowed-ids/"
export TELEGRAM_BOT_TOKEN="…"
```

Для **кнопок Web App** адрес должен быть **`https://`** и содержать `/api/` — тогда бот откроет:

- `https://ВАШ-ДОМЕН/webapp/consent/` для согласия на ПД;
- `https://ВАШ-ДОМЕН/webapp/cabinet/` для кабинета пользователя.

При `http://` остаётся сценарий с полным текстом политики в чате, а кабинетная кнопка не показывается.

На сервере Django должен видеть тот же **`TELEGRAM_BOT_TOKEN`**, что и бот (проверка подписи `initData` в `/api/webapp-consent/` и `/api/webapp-profile/`). В корне репозитория (рядом с каталогом `bot_admin_site`) должен лежать файл **`POLICY_PERSONAL_DATA.md`**.

### Автоматизация деплоя (Linux)

В каталоге **`deploy/`** в корне репозитория:

- `env.example` — шаблон `/etc/xseo/environment`;
- `xseo-django-gunicorn.service.example`, `xseo-bot.service.example` — unit-файлы systemd;
- `nginx-site.conf.example` — обратный прокси на Gunicorn (TLS — certbot);
- `SERVER_SETUP.sh` — установка venv, `migrate`, копирование unit-файлов (запуск от root после правки путей в начале скрипта или через `DEPLOY_ROOT=...`).

Кратко: клонировать репо в `/opt/xseo_ip_bot`, выполнить `bash deploy/SERVER_SETUP.sh`, отредактировать созданный `/etc/xseo/environment`, настроить nginx + certbot, `systemctl start xseo-django-gunicorn xseo-bot`.

После этого бот при старте и по таймеру подгружает список разрешённых из Django. Если URL не задан или Django недоступен, используется список `ALLOWED_USER_IDS` из `bot.py`.
