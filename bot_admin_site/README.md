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

В `bot.py` укажите URL API:

```python
BOT_ALLOWED_LIST_URL = "http://127.0.0.1:8000/api/allowed-ids/"
```

После этого бот при старте и каждые 5 минут подгружает список разрешённых из Django. Если URL не задан или Django недоступен, используется список `ALLOWED_USER_IDS` из `bot.py`.
