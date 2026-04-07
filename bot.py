# -*- coding: utf-8 -*-
"""
Telegram-бот: информация по IP через API ipapi.is.
Команды: /start, /help, /ip <адрес>, или просто отправить IP в чат.
"""

import asyncio
import logging
import os
import re
import uuid
from typing import Optional

# Токен бота берём из переменной окружения, чтобы не хранить секрет в репозитории.
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")

# Доступ к боту: список Telegram user_id. Пустой список = доступ всем.
# Узнать свой id: напишите боту @userinfobot в Telegram.
ALLOWED_USER_IDS: list[int] = [

]
# Если задан — бот подгружает список доступа из Django и объединяет с ALLOWED_USER_IDS (см. bot_admin_site).
BOT_ALLOWED_LIST_URL: str = os.environ.get("BOT_ALLOWED_LIST_URL", "http://127.0.0.1:8000/api/allowed-ids/")

import requests
from telegram import Update, BotCommand, InlineKeyboardButton, InlineKeyboardMarkup, InputFile
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    CallbackQueryHandler,
    ContextTypes,
    filters,
)

from io import BytesIO

from ip_service import (
    get_ip_info,
    get_domain_info,
    get_dns_info,
    get_dns_report_file,
    get_bin_info,
    get_email_info,
    get_phone_info,
    get_username_info,
    get_wallet_info,
    get_wallet_tx_report_file,
    get_spravka_word,
    detect_lookup_type,
    _validate_domain,
    _validate_email,
    _validate_phone,
    _validate_username,
    _validate_wallet,
    _detect_wallet_chains,
    _normalize_email,
    _normalize_phone,
    _normalize_username,
)

logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO,
)
logger = logging.getLogger(__name__)

# Дисклеймер / предупреждение об использовании
DISCLAIMER_TEXT = (
    "📋 <b>Предупреждение об использовании</b>\n\n"
    "🔍 <b>Источники информации.</b> Данный бот является OSINT-инструментом и осуществляет "
    "поиск информации исключительно в общедоступных источниках (открытые данные соцсетей, "
    "WHOIS-сервисы, публичные реестры, СМИ). Мы не подключаемся к закрытым базам данных, "
    "не используем нелегальные утечки и не нарушаем защиту компьютерной информации.\n\n"
    "⚖️ <b>Достоверность сведений.</b> Информация предоставляется «как есть». Она может быть "
    "неполной, устаревшей или ошибочной, так как собирается автоматически. Мы не гарантируем "
    "её точность и не рекомендуем использовать её для действий, которые могут затронуть права "
    "и законные интересы третьих лиц.\n\n"
    "🎯 <b>Цель использования.</b> Сервис создан для личных и семейных нужд, а также для общего "
    "развития (reconnaissance, обучение). Любое использование данных в противоправных целях "
    "(сталкинг, мошенничество, вмешательство в частную жизнь) запрещено.\n\n"
    "⚠️ <b>Ответственность.</b> Вводя запрос, вы принимаете на себя полную ответственность за "
    "дальнейшее использование полученной информации. Администрация бота не несёт ответственности "
    "за любые прямые или косвенные убытки, возникшие в результате использования сервиса или "
    "данных, полученных с его помощью."
)

# Кнопка под дисклеймером — показать команды
DISCLAIMER_KEYBOARD = InlineKeyboardMarkup(
    [[InlineKeyboardButton("📌 Показать команды", callback_data="show_commands")]]
)

# Краткий текст о обработке ПД (запас, если файл политики недоступен)
POLICY_VERSION = "1.0"
PRIVACY_SHORT = (
    "📄 <b>Обработка персональных данных</b>\n\n"
    "При использовании бота обрабатываются: Telegram ID, при необходимости — username и ФИО. "
    "Цели: управление доступом, учёт обращений, формирование справок для уполномоченных лиц. "
    "Срок хранения данных обращений — не более 12 месяцев. "
    "Полный текст политики: команда /privacy."
)
# Вводное сообщение перед текстом правил при первом входе
POLICY_INTRO = "📋 <b>Прочитайте правила обработки персональных данных</b>\n\n"
# Контакт оператора для запросов по ПД (дублируется из политики, чтобы показывать в боте)
OPERATOR_CONTACT_EMAIL = "mo.cyber.osint@gmail.com"
# Путь к файлу политики (рядом с bot.py)
POLICY_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "POLICY_PERSONAL_DATA.md")
# Лимит длины одного сообщения в Telegram
TELEGRAM_MESSAGE_MAX = 4096

# Полный текст политики ПД для команды /privacy и при первом входе (в формате Telegram HTML)
FULL_POLICY_FOR_TELEGRAM = (
    "📋 <b>Прочитайте правила обработки персональных данных</b>\n\n"
    "<i>В соответствии с Законом Республики Беларусь от 7 мая 2021 г. № 99-З «О персональных данных»</i>\n\n"
    "<b>1. Оператор</b>\n\n"
    "Оператором персональных данных является владелец (администратор) Telegram-бота и сервиса учёта обращений "
    "(далее — оператор). Контакт для запросов по персональным данным: mo.cyber.osint@gmail.com.\n\n"
    "<b>2. Цели обработки</b>\n\n"
    "Обработка персональных данных осуществляется в целях:\n\n"
    "• управления доступом к функционалу бота (проверка разрешённых пользователей);\n"
    "• учёта обращений к боту и обеспечения безопасности сервиса;\n"
    "• формирования справок по запросам уполномоченных лиц (в рамках служебного использования).\n\n"
    "Обработка ограничена указанными целями; сбор данных «про запас» не осуществляется.\n\n"
    "<b>3. Состав обрабатываемых персональных данных</b>\n\n"
    "• <b>Telegram ID</b> — уникальный идентификатор пользователя в мессенджере (необходим для проверки доступа и учёта обращений).\n"
    "• <b>Username в Telegram</b> — при наличии и при необходимости для идентификации и учёта.\n"
    "• <b>ФИО</b> — только для разрешённых пользователей, при внесении в список доступа администратором; используется для управления доступом и учёта.\n"
    "• <b>Служебная заметка</b> — краткая пометка администратора (например, должность, подразделение) только для целей управления доступом; объём ограничен.\n\n"
    "Данные, вводимые пользователем в бот (IP, домен, BIN, номер телефона, адрес кошелька и т.д.), обрабатываются для формирования ответа и справки; "
    "при необходимости они могут сохраняться в составе сформированных документов в соответствии с внутренними правилами оператора. "
    "Обработка таких данных в боте направлена на исполнение запроса пользователя и не является избыточной относительно заявленных целей.\n\n"
    "<b>4. Правовые основания</b>\n\n"
    "• Согласие субъекта персональных данных (при первом использовании бота после добавления в список разрешённых пользователей).\n"
    "• В случаях, предусмотренных законодательством, — исполнение договора или законные интересы оператора при соблюдении ограничений Закона о персональных данных.\n\n"
    "<b>5. Сроки хранения</b>\n\n"
    "• <b>Данные учёта обращений (посещений бота):</b> не более <b>12 (двенадцати) месяцев</b> с даты последнего обращения; по истечении срока записи удаляются или обезличиваются автоматически.\n"
    "• <b>Данные разрешённого пользователя (Telegram ID, username, ФИО, заметка):</b> хранятся до отзыва доступа или отзыва согласия на обработку ПД; "
    "после снятия доступа или запроса на удаление — не более <b>90 дней</b> (для исполнения запроса на удаление и аудита), далее — удаление или обезличивание.\n"
    "• <b>Сведения о факте и дате согласия:</b> хранятся в течение срока действия согласия и не более срока, указанного выше для данных разрешённого пользователя.\n\n"
    "Конкретные сроки могут быть уточнены в актуальной версии политики (см. дату/версию документа).\n\n"
    "<b>6. Передача данных третьим лицам</b>\n\n"
    "Персональные данные не передаются третьим лицам, за исключением случаев, предусмотренных законодательством РБ "
    "(по запросу уполномоченных государственных органов и т.п.).\n\n"
    "<b>7. Права субъекта персональных данных</b>\n\n"
    "В соответствии с Законом РБ о персональных данных вы имеете право:\n\n"
    "• <b>Получить сведения</b> о том, какие ваши персональные данные обрабатываются оператором (в т.ч. через команду бота или по запросу оператору).\n"
    "• <b>Потребовать уточнение (исправление)</b> неточных данных.\n"
    "• <b>Потребовать удаление</b> персональных данных или отозвать согласие на обработку; в этом случае использование бота может быть прекращено.\n"
    "• <b>Обжаловать</b> действия оператора в порядке, установленном законодательством РБ.\n\n"
    "Реализация прав: через команду бота (например, /privacy — краткая информация и запрос на удаление) или по контакту оператора, указанному в п. 1.\n\n"
    "<b>8. Изменение политики</b>\n\n"
    "Актуальная версия политики публикуется в репозитории проекта и/или по ссылке, указанной в боте. "
    "При существенных изменениях пользователям может быть направлено уведомление или предложено повторное согласие (например, при следующем входе в бот).\n\n"
    "—\n\n"
    "<i>Дата актуальной версии: 2026-03-09. Версия документа: 1.0.</i>"
)

# Кнопки согласия при первом входе (под текстом правил)
CONSENT_KEYBOARD = InlineKeyboardMarkup([
    [InlineKeyboardButton("✅ Принимаю правила", callback_data="privacy_accept")],
    [InlineKeyboardButton("❌ Не принимаю", callback_data="privacy_decline")],
])
# Кнопка запроса удаления ПД (в /privacy)
PRIVACY_DELETE_KEYBOARD = InlineKeyboardMarkup([
    [InlineKeyboardButton("🗑 Запросить удаление моих данных", callback_data="privacy_request_delete")],
])
PRIVACY_DELETE_CONFIRM_KEYBOARD = InlineKeyboardMarkup([
    [
        InlineKeyboardButton("Да, удалить данные", callback_data="privacy_confirm_delete"),
        InlineKeyboardButton("Отмена", callback_data="privacy_cancel_delete"),
    ],
])

# Кнопки (callback_data до 64 байт)
DNS_REPORT_PREFIX = "dns_report:"
WALLET_TX_PREFIX = "wtx:"
SPRAVKA_PREFIX = "spravka:"

_spravka_cache: dict[str, tuple[str, str]] = {}


def _policy_file_path() -> str:
    """Путь к POLICY_PERSONAL_DATA.md: рядом с bot.py или в текущей рабочей папке."""
    path_by_module = os.path.join(os.path.dirname(os.path.abspath(__file__)), "POLICY_PERSONAL_DATA.md")
    if os.path.isfile(path_by_module):
        return path_by_module
    path_by_cwd = os.path.join(os.getcwd(), "POLICY_PERSONAL_DATA.md")
    if os.path.isfile(path_by_cwd):
        return path_by_cwd
    return path_by_module


def _load_policy_for_telegram() -> str:
    """
    Загружает текст политики из POLICY_PERSONAL_DATA.md и приводит к виду для Telegram (HTML).
    Если файла нет или текст слишком длинный — возвращает краткий PRIVACY_SHORT.
    """
    path = _policy_file_path()
    if not os.path.isfile(path):
        logger.debug("Файл политики не найден: %s", path)
        return PRIVACY_SHORT
    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = f.read()
    except Exception as e:
        logger.warning("Не удалось прочитать файл политики: %s", e)
        return PRIVACY_SHORT
    # Сначала помечаем **...** плейсхолдерами, потом экранируем, потом вставляем <b>
    _OPEN, _CLOSE = "\x00B1\x01", "\x00B2\x01"

    def esc(s: str) -> str:
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    def apply_bold_and_esc(s: str) -> str:
        s = re.sub(r"\*\*([^*]+)\*\*", _OPEN + r"\1" + _CLOSE, s)
        s = esc(s)
        return s.replace(_OPEN, "<b>").replace(_CLOSE, "</b>")

    lines = raw.split("\n")
    out = []
    for line in lines:
        s = line.rstrip()
        if s.startswith("## "):
            out.append("\n<b>" + esc(s[3:]) + "</b>")
        elif s.startswith("# "):
            out.append("\n<b>" + esc(s[2:]) + "</b>")
        elif s == "---":
            out.append("\n")
        elif s.startswith("- "):
            out.append("\n• " + apply_bold_and_esc(s[2:]))
        elif s.startswith("*") and s.endswith("*") and len(s) > 1 and s[1] != "*":
            out.append("\n<i>" + esc(s[1:-1]) + "</i>")
        elif s:
            out.append("\n" + apply_bold_and_esc(s))
    body = "".join(out).strip()
    intro_plus = POLICY_INTRO + body
    if len(intro_plus) > TELEGRAM_MESSAGE_MAX - 200:
        return PRIVACY_SHORT
    return intro_plus


def _spravka_cb(lookup_type: str, value: str, context: "ContextTypes.DEFAULT_TYPE") -> str:
    """Callback_data для кнопки Справка (лимит 64 байта)."""
    raw = f"{SPRAVKA_PREFIX}{lookup_type}:{value}"
    if len(raw.encode("utf-8")) <= 64:
        return raw
    key = str(uuid.uuid4())[:8]
    _spravka_cache[key] = (lookup_type, value)
    return f"{SPRAVKA_PREFIX}{key}"


def _domain_result_keyboard(domain: str, context: "ContextTypes.DEFAULT_TYPE") -> InlineKeyboardMarkup:
    """Клавиатура под результатом поиска по домену: DNS отчёт + Справка."""
    dns_cb = f"{DNS_REPORT_PREFIX}{domain}"[:64]
    spravka_cb = _spravka_cb("domain", domain, context)
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("📥 DNS отчёт (файл)", callback_data=dns_cb)],
        [InlineKeyboardButton("📄 Справка (Word)", callback_data=spravka_cb)],
    ])


def _spravka_only_keyboard(lookup_type: str, value: str, context: "ContextTypes.DEFAULT_TYPE") -> InlineKeyboardMarkup:
    """Клавиатура только с кнопкой Справка."""
    cb = _spravka_cb(lookup_type, value, context)
    return InlineKeyboardMarkup([[InlineKeyboardButton("📄 Справка (Word)", callback_data=cb)]])


# Кэш для TX-отчётов (callback_data лимит 64 байта, длинные адреса не влезают)
_wallet_tx_cache: dict[str, tuple[str, str]] = {}


def _wallet_result_keyboard(address: str, context: "ContextTypes.DEFAULT_TYPE") -> Optional[InlineKeyboardMarkup]:
    """Клавиатура под результатом поиска по кошельку: TX отчёты + Справка."""
    chains = _detect_wallet_chains(address)
    if not chains:
        return None
    buttons = []
    for chain in chains:
        cb_raw = f"{WALLET_TX_PREFIX}{chain}:{address}"
        if len(cb_raw.encode("utf-8")) <= 64:
            cb = cb_raw
        else:
            key = str(uuid.uuid4())[:8]
            _wallet_tx_cache[key] = (address, chain)
            cb = f"{WALLET_TX_PREFIX}{key}"
        label = {"eth": "ETH", "btc": "BTC", "tron": "TRON"}.get(chain, chain)
        buttons.append(InlineKeyboardButton(f"📥 TX отчёт ({label})", callback_data=cb))
    spravka_cb = _spravka_cb("wallet", address, context)
    return InlineKeyboardMarkup([
        buttons,
        [InlineKeyboardButton("📄 Справка (Word)", callback_data=spravka_cb)],
    ])

# Текст со списком команд (для кнопки под дисклеймером и для /help)
COMMANDS_TEXT = (
    "Просто введи IP, домен, BIN, кошелёк или номер в чат:\n"
    "• 8.8.8.8 — информация по IP\n"
    "• example.com — информация о домене\n"
    "• 535316 — информация по BIN карты\n"
    "• user@example.com — email OSINT\n"
    "• @username — поиск username по площадкам\n"
    "• 0x... / 1... / T... — криптокошелёк (ETH, BTC, TRON)\n"
    "• +79161234567 — оператор по номеру\n\n"
    "Команды: /start, /help, /privacy (политика ПД), /ip, /domain, /dns, /bin, /email, /user, /wallet, /phone"
)


def _get_visit_url() -> str:
    """URL для регистрации обращений к боту (Django)."""
    if not BOT_ALLOWED_LIST_URL:
        return ""
    return BOT_ALLOWED_LIST_URL.rstrip("/").replace("allowed-ids", "seen-user") + "/"


def _get_api_base() -> str:
    """Базовый URL API (без суффикса allowed-ids)."""
    if not BOT_ALLOWED_LIST_URL:
        return ""
    return BOT_ALLOWED_LIST_URL.rstrip("/").rsplit("/", 1)[0] + "/"


def _post_consent_sync(telegram_id: int, version: str = "1.0") -> bool:
    """Фиксация согласия на обработку ПД в Django. Возвращает True при успехе."""
    base = _get_api_base()
    if not base:
        return False
    try:
        r = requests.post(
            base + "consent/",
            json={"telegram_id": telegram_id, "version": version},
            timeout=5,
        )
        return r.status_code == 200 and r.json().get("ok") is True
    except Exception as e:
        logger.debug("consent api failed: %s", e)
        return False


def _get_my_data_sync(telegram_id: int) -> Optional[dict]:
    """Получение данных по telegram_id из Django (для /privacy)."""
    base = _get_api_base()
    if not base:
        return None
    try:
        r = requests.get(base + "my-data/", params={"telegram_id": telegram_id}, timeout=5)
        if r.status_code != 200:
            return None
        return r.json()
    except Exception as e:
        logger.debug("my-data api failed: %s", e)
        return None


def _post_request_deletion_sync(telegram_id: int) -> dict:
    """Запрос на удаление ПД в Django. Возвращает ответ API."""
    base = _get_api_base()
    if not base:
        return {"ok": False}
    try:
        r = requests.post(
            base + "request-deletion/",
            json={"telegram_id": telegram_id},
            timeout=5,
        )
        return r.json() if r.status_code == 200 else {"ok": False}
    except Exception as e:
        logger.debug("request-deletion api failed: %s", e)
        return {"ok": False}


def _get_spravka_profile_sync(telegram_id: int) -> Optional[dict]:
    """Получение сохранённого профиля для справки из Django."""
    base = _get_api_base()
    if not base:
        return None
    try:
        r = requests.get(base + "spravka-profile/", params={"telegram_id": telegram_id}, timeout=5)
        if r.status_code != 200:
            return None
        data = r.json()
        return data.get("profile") or None
    except Exception as e:
        logger.debug("spravka-profile api failed: %s", e)
        return None


def _save_spravka_profile_sync(
    telegram_id: int,
    position: str,
    unit: str,
    rank: str,
    signature_name: str,
) -> bool:
    """Сохранение/обновление профиля для справки в Django."""
    base = _get_api_base()
    if not base:
        return False
    try:
        r = requests.post(
            base + "spravka-profile/save/",
            json={
                "telegram_id": telegram_id,
                "position": position,
                "unit": unit,
                "rank": rank,
                "signature_name": signature_name,
            },
            timeout=5,
        )
        return r.status_code == 200 and r.json().get("ok") is True
    except Exception as e:
        logger.debug("spravka-profile-save api failed: %s", e)
        return False


def _record_visit_sync(telegram_id: int, username: str) -> None:
    """Синхронно отправляет в Django факт обращения пользователя (без блокировки бота)."""
    url = _get_visit_url()
    if not url:
        return
    try:
        requests.post(
            url,
            json={"telegram_id": telegram_id, "telegram_username": username or ""},
            timeout=5,
        )
    except Exception as e:
        logger.debug("record visit failed: %s", e)


def _get_allowed_user_ids(context: "ContextTypes.DEFAULT_TYPE") -> list[int]:
    """Список разрешённых telegram_id: из Django API (если настроен) + ALLOWED_USER_IDS из кода."""
    result = set(ALLOWED_USER_IDS)
    if BOT_ALLOWED_LIST_URL:
        ids = (context.application.bot_data or {}).get("allowed_user_ids")
        if ids is not None:
            result |= set(ids)
    return list(result)


def _get_consent_required_ids(context: "ContextTypes.DEFAULT_TYPE") -> set[int]:
    """Telegram_id, которым нужно дать согласие на обработку ПД (нет consent_at в Django)."""
    if not BOT_ALLOWED_LIST_URL:
        return set()
    ids = (context.application.bot_data or {}).get("consent_required_ids")
    if ids is None:
        return set()
    return set(ids)


async def _refresh_allowed_ids(context: "ContextTypes.DEFAULT_TYPE") -> None:
    """Загрузка списка разрешённых и списка «согласие требуется» из Django API."""
    if not BOT_ALLOWED_LIST_URL:
        return
    try:
        r = requests.get(BOT_ALLOWED_LIST_URL, timeout=10)
        r.raise_for_status()
        data = r.json()
        ids = set(int(x) for x in data.get("allowed_ids", [])) | set(ALLOWED_USER_IDS)
        context.application.bot_data["allowed_user_ids"] = list(ids)
        consent_required = set(int(x) for x in data.get("consent_required_ids", []))
        context.application.bot_data["consent_required_ids"] = list(consent_required)
        logger.info("Обновлён список доступа из Django: %s записей, без согласия: %s", len(ids), len(consent_required))
    except Exception as e:
        logger.warning("Не удалось загрузить список доступа из Django: %s", e)


async def _check_allowed(
    update: Update, context: ContextTypes.DEFAULT_TYPE, *, require_consent: bool = True
) -> bool:
    """
    Проверка доступа: список разрешённых и (если require_consent) наличие согласия на обработку ПД.
    Возвращает False, если доступ запрещён (сообщение уже отправлено).
    """
    user = update.effective_user
    # Если JobQueue не настроен (нет фонового обновления),
    # перед каждой проверкой доступа обновляем список из Django.
    if BOT_ALLOWED_LIST_URL and not getattr(context.application, "job_queue", None):
        await _refresh_allowed_ids(context)
    if user and _get_visit_url():
        asyncio.create_task(
            asyncio.to_thread(_record_visit_sync, user.id, (user.username or "").strip())
        )
    allowed = _get_allowed_user_ids(context)
    if not allowed:
        return True
    if not user or user.id not in allowed:
        try:
            if update.callback_query:
                await update.callback_query.answer("Доступ к боту ограничен.", show_alert=True)
                await update.callback_query.message.reply_text("Доступ к боту ограничен.")
            else:
                await update.effective_chat.send_message("Доступ к боту ограничен.")
        except Exception:
            pass
        return False
    if require_consent and user.id in _get_consent_required_ids(context):
        msg = (
            "Для использования бота необходимо принять политику обработки персональных данных. "
            "Нажмите /start."
        )
        try:
            if update.callback_query:
                await update.callback_query.answer(msg, show_alert=True)
                await update.callback_query.message.reply_text(msg)
            else:
                await update.effective_chat.send_message(msg)
        except Exception:
            pass
        return False
    return True


def _allowed_only(func=None, *, require_consent: bool = True):
    """Декоратор: только для разрешённых; при require_consent=True требуется согласие на обработку ПД."""
    def decorator(f):
        async def wrapper(update: Update, context: ContextTypes.DEFAULT_TYPE):
            if not await _check_allowed(update, context, require_consent=require_consent):
                return
            return await f(update, context)
        return wrapper
    if func is not None:
        return decorator(func)
    return decorator


async def post_init(app: Application) -> None:
    """Устанавливает список команд; при включённом Django — загружает список доступа и consent_required."""
    if BOT_ALLOWED_LIST_URL:
        try:
            r = requests.get(BOT_ALLOWED_LIST_URL, timeout=10)
            r.raise_for_status()
            data = r.json()
            from_django = {int(x) for x in data.get("allowed_ids", [])}
            merged = list(from_django | set(ALLOWED_USER_IDS))
            app.bot_data["allowed_user_ids"] = merged
            app.bot_data["consent_required_ids"] = list(
                int(x) for x in data.get("consent_required_ids", [])
            )
            logger.info(
                "Список доступа загружен из Django: %s записей, без согласия: %s",
                len(merged), len(app.bot_data["consent_required_ids"]),
            )
        except Exception as e:
            logger.warning("Не удалось загрузить список доступа из Django при старте: %s", e)
    await app.bot.set_my_commands(
        [
            BotCommand("start", "Главная"),
            BotCommand("help", "Справка"),
            BotCommand("privacy", "Политика ПД и ваши данные"),
            BotCommand("ip", "Информация по IP"),
            BotCommand("domain", "Поиск по домену"),
            BotCommand("dns", "DNS записи домена"),
            BotCommand("bin", "Поиск по BIN карты"),
            BotCommand("email", "OSINT по email"),
            BotCommand("user", "Username search"),
            BotCommand("wallet", "Криптокошелёк (ETH/BTC/TRON)"),
            BotCommand("phone", "Оператор по номеру"),
        ]
    )


@_allowed_only(require_consent=False)
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user = update.effective_user
    if user and user.id in _get_consent_required_ids(context):
        await update.message.reply_text(
            FULL_POLICY_FOR_TELEGRAM,
            parse_mode="HTML",
            reply_markup=CONSENT_KEYBOARD,
        )
        return
    await update.message.reply_text(
        "👋 Привет!\n\n"
        "Я помогу узнать информацию по IP, доменам, BIN, email, username, криптокошелькам и номерам телефонов. "
        "Просто введи нужные данные в чат или выбери команду из меню.\n\n"
        "Обработка персональных данных: /privacy",
    )
    await update.message.reply_text(
        DISCLAIMER_TEXT,
        parse_mode="HTML",
        reply_markup=DISCLAIMER_KEYBOARD,
    )


@_allowed_only
async def help_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text(COMMANDS_TEXT)


@_allowed_only
async def show_commands_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Обработка нажатия кнопки «Показать команды» под дисклеймером."""
    await update.callback_query.answer()
    await update.callback_query.message.reply_text(COMMANDS_TEXT)


@_allowed_only(require_consent=False)
async def privacy_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Политика ПД (полный текст), сведения о хранимых данных и запрос на удаление."""
    user = update.effective_user
    if not user:
        return
    # Первым сообщением — полный текст политики (фиксированный формат для Telegram)
    await update.message.reply_text(FULL_POLICY_FOR_TELEGRAM, parse_mode="HTML")
    data = await asyncio.get_event_loop().run_in_executor(
        None, _get_my_data_sync, user.id
    )
    if data:
        lines = ["📋 <b>Данные по вашему аккаунту:</b>"]
        au = data.get("allowed_user")
        if au:
            lines.append(f"• Разрешённый пользователь: да, активен: {au.get('is_active', False)}")
            if au.get("consent_at"):
                lines.append(f"• Согласие на обработку ПД: {au['consent_at'][:10]}")
            lines.append(f"• Обновлено: {au.get('updated_at', '')[:10]}")
        v = data.get("visitor")
        if v:
            lines.append(f"• Обращения: первое {v.get('first_seen', '')[:10]}, последнее {v.get('last_seen', '')[:10]}")
        if not au and not v:
            lines.append("• Записей не найдено.")
        lines.append("")
        lines.append(f"Для исправления неточных данных или отзыва согласия обратитесь к оператору: {OPERATOR_CONTACT_EMAIL}")
        await update.message.reply_text(
            "\n".join(lines),
            parse_mode="HTML",
            reply_markup=PRIVACY_DELETE_KEYBOARD,
        )
    else:
        await update.message.reply_text(
            "Сведения о данных недоступны (сервис учёта отключён или временно недоступен). "
            f"Для запросов по ПД обратитесь к оператору: {OPERATOR_CONTACT_EMAIL}",
            reply_markup=PRIVACY_DELETE_KEYBOARD,
        )


async def privacy_accept_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Пользователь нажал «Принимаю» — фиксируем согласие в Django и обновляем кэш."""
    if not update.callback_query or not update.effective_user:
        return
    if not await _check_allowed(update, context, require_consent=False):
        return
    user = update.effective_user
    ok = await asyncio.get_event_loop().run_in_executor(
        None, _post_consent_sync, user.id, POLICY_VERSION
    )
    if ok and context.application.bot_data.get("consent_required_ids") is not None:
        consent_list = context.application.bot_data["consent_required_ids"]
        if user.id in consent_list:
            context.application.bot_data["consent_required_ids"] = [
                x for x in consent_list if x != user.id
            ]
    await update.callback_query.answer("Согласие зафиксировано.", show_alert=True)
    await update.callback_query.edit_message_text(
        "✅ Согласие на обработку персональных данных принято. Нажмите /start для продолжения."
    )


async def privacy_decline_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Пользователь нажал «Не принимаю»."""
    if not await _check_allowed(update, context, require_consent=False):
        return
    await update.callback_query.answer("Без согласия использование бота невозможно.", show_alert=True)
    await update.callback_query.edit_message_text(
        "❌ Без согласия на обработку персональных данных использование бота невозможно."
    )


async def privacy_request_delete_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Кнопка «Запросить удаление» — запрос подтверждения."""
    if not await _check_allowed(update, context, require_consent=False):
        return
    await update.callback_query.answer()
    await update.callback_query.message.reply_text(
        "Подтвердите удаление всех ваших данных. Доступ к боту будет отключён.",
        reply_markup=PRIVACY_DELETE_CONFIRM_KEYBOARD,
    )


async def privacy_confirm_delete_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Подтверждение удаления ПД — вызов API и ответ пользователю."""
    user = update.effective_user
    if not user:
        await update.callback_query.answer("Ошибка.", show_alert=True)
        return
    result = await asyncio.get_event_loop().run_in_executor(
        None, _post_request_deletion_sync, user.id
    )
    await update.callback_query.answer()
    if result.get("ok"):
        await update.callback_query.edit_message_text(
            "✅ Запрос выполнен. Ваши данные удалены, доступ к боту отключён. "
            "Для повторного доступа обратитесь к администратору."
        )
    else:
        await update.callback_query.message.reply_text(
            "Не удалось выполнить запрос. Обратитесь к администратору."
        )


async def privacy_cancel_delete_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Отмена запроса на удаление."""
    await update.callback_query.answer("Отменено.")
    try:
        await update.callback_query.message.delete()
    except Exception:
        pass


@_allowed_only
async def ip_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not context.args:
        await _ip_prompt(update)
        return
    ip = " ".join(context.args).strip()
    status_msg = await update.message.reply_text("Проверяю информацию по IP…")
    loop = asyncio.get_event_loop()
    text = await loop.run_in_executor(None, get_ip_info, ip)
    if len(text) > 4000:
        text = text[:3997] + "..."
    await update.message.reply_text(
        text,
        parse_mode="HTML",
        reply_markup=_spravka_only_keyboard("ip", ip, context),
    )
    try:
        await status_msg.delete()
    except Exception:
        pass


async def _ip_prompt(update: Update) -> None:
    """Подсказка ввести IP (для /ip без аргумента)."""
    await update.message.reply_text("Укажите IP-адрес: /ip 8.8.8.8")


@_allowed_only
async def domain_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Поиск информации по домену."""
    if not context.args:
        await update.message.reply_text("Укажите домен: /domain example.com")
        return
    domain = context.args[0].strip().lower()
    if not _validate_domain(domain):
        await update.message.reply_text("Неверный формат домена. Пример: /domain example.com")
        return
    status_msg = await update.message.reply_text("Проверяю информацию по домену…")
    loop = asyncio.get_event_loop()
    text = await loop.run_in_executor(None, get_domain_info, domain)
    if len(text) > 4000:
        text = text[:3997] + "..."
    await update.message.reply_text(
        text,
        parse_mode="HTML",
        reply_markup=_domain_result_keyboard(domain, context),
    )
    try:
        await status_msg.delete()
    except Exception:
        pass


@_allowed_only
async def wallet_tx_report_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """По нажатию кнопки «TX отчёт» — отправляет файл с транзакциями кошелька."""
    query = update.callback_query
    if not query.data or not query.data.startswith(WALLET_TX_PREFIX):
        return
    rest = query.data[len(WALLET_TX_PREFIX):].strip()
    parts = rest.split(":")
    if len(parts) >= 2 and parts[0] in ("eth", "btc", "tron"):
        chain, address = parts[0], ":".join(parts[1:]).strip()
    else:
        # Кэш по ключу (длинный адрес)
        address, chain = _wallet_tx_cache.get(parts[0] if parts else "", (None, None))
        if not address or not chain:
            await query.answer("Сессия истекла. Повторите запрос.", show_alert=True)
            return
    if chain not in ("eth", "btc", "tron") or not address:
        await query.answer("Неверные параметры", show_alert=True)
        return
    await query.answer("Формирую отчёт по транзакциям…")
    try:
        content, filename = await asyncio.get_event_loop().run_in_executor(
            None, get_wallet_tx_report_file, address, chain
        )
        doc = InputFile(BytesIO(content), filename=filename)
        await query.message.reply_document(
            document=doc,
            caption=f"📥 TX отчёт: {chain.upper()} — {address[:20]}…",
        )
    except ValueError as e:
        await query.message.reply_text(str(e))
    except Exception as e:
        logger.warning("wallet_tx_report failed: %s", e)
        await query.message.reply_text("Не удалось сформировать TX-отчёт.")


# Ключ в user_data: мастер справки — dict с lookup_type, value, case_num, position, unit, rank, step
PENDING_SPRAVKA_KEY = "pending_spravka"

# Должности, подразделения, звания для справки (callback_data: spravka_wiz:pos:0 и т.д.)
SPRAVKA_POSITIONS = ["Следователь", "Старший следователь", "Следователь по ОВД"]
SPRAVKA_UNITS = [
    "СУ УСК",
    "ОЦРПС УСК",
    "Березинский РОСК", "Борисовский РОСК", "Вилейский РОСК", "Воложинский РОСК",
    "Дзержинский РОСК", "Жодинский ГОСК", "Клецкий РОСК", "Копыльский РОСК",
    "Крупский РОСК", "Логойский РОСК", "Любанский РОСК", "Минский РОСК",
    "Молодечненский РОСК", "Мядельский РОСК", "Несвижский РОСК", "Пуховичский РОСК",
    "Слуцкий РОСК", "Смолевичский РОСК", "Солигорский РОСК", "Стародорожский РОСК",
    "Столбцовский РОСК", "Узденский РОСК", "Червенский РОСК",
]
SPRAVKA_RANKS = [
    "младший лейтенант юстиции",
    "лейтенант юстиции",
    "старший лейтенант юстиции",
    "капитан юстиции",
    "майор юстиции",
    "подполковник юстиции",
]

SPRAVKA_WIZ_PREFIX = "spravka_wiz:"
SPRAVKA_PROFILE_CHOICE_USE = "use"
SPRAVKA_PROFILE_CHOICE_NEW = "new"


def _spravka_position_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([
        [InlineKeyboardButton(t, callback_data=f"{SPRAVKA_WIZ_PREFIX}pos:{i}")]
        for i, t in enumerate(SPRAVKA_POSITIONS)
    ])


def _spravka_profile_choice_keyboard(profile: dict) -> InlineKeyboardMarkup:
    """Клавиатура выбора: использовать весь сохранённый профиль или ввести новый."""
    pos = (profile.get("position") or "").strip()
    unit = (profile.get("unit") or "").strip()
    rank = (profile.get("rank") or "").strip()
    name = (profile.get("signature_name") or "").strip()
    summary_parts = [part for part in (pos, unit, rank, name) if part]
    summary = "; ".join(summary_parts) if summary_parts else "сохранённые данные"
    text_use = f"Применить сохранённые ({summary})"
    text_new = "Ввести новый профиль"
    return InlineKeyboardMarkup(
        [
            [InlineKeyboardButton(text_use[:64], callback_data=f"{SPRAVKA_WIZ_PREFIX}profile:{SPRAVKA_PROFILE_CHOICE_USE}")],
            [InlineKeyboardButton(text_new, callback_data=f"{SPRAVKA_WIZ_PREFIX}profile:{SPRAVKA_PROFILE_CHOICE_NEW}")],
        ]
    )


def _spravka_profile_is_complete(profile: Optional[dict]) -> bool:
    """Есть ли в профиле полный набор реквизитов для справки."""
    if not profile:
        return False
    return all(
        (profile.get(key) or "").strip()
        for key in ("position", "unit", "rank", "signature_name")
    )


async def _finish_spravka_flow(
    chat,
    context: ContextTypes.DEFAULT_TYPE,
    pending: dict,
    user,
) -> None:
    """Сохраняет профиль и отправляет готовую справку."""
    lookup_type = pending["lookup_type"]
    value = pending["value"]
    case_num = pending.get("case_num") or ""
    position = pending.get("position") or ""
    unit = pending.get("unit") or ""
    rank = pending.get("rank") or ""
    name = pending.get("signature_name") or ""
    context.user_data.pop(PENDING_SPRAVKA_KEY, None)
    status_msg = await chat.send_message("Формирую справку…")
    try:
        if user:
            await asyncio.get_event_loop().run_in_executor(
                None,
                _save_spravka_profile_sync,
                user.id,
                position,
                unit,
                rank,
                name,
            )
        content, filename = await asyncio.get_event_loop().run_in_executor(
            None,
            lambda: get_spravka_word(
                lookup_type,
                value,
                case_num=case_num or None,
                position=position or None,
                unit=unit or None,
                rank=rank or None,
                signature_name=name or None,
            ),
        )
        doc = InputFile(BytesIO(content), filename=filename)
        await chat.send_document(
            document=doc,
            caption=f"📄 Справка: {lookup_type} — {value[:30]}{'…' if len(value) > 30 else ''}",
        )
    except ValueError as e:
        await chat.send_message(str(e))
    except RuntimeError as e:
        await chat.send_message(str(e))
    except Exception as e:
        logger.warning("spravka failed: %s", e)
        await chat.send_message("Не удалось сформировать справку.")
    try:
        await status_msg.delete()
    except Exception:
        pass


def _spravka_unit_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([
        [InlineKeyboardButton(t, callback_data=f"{SPRAVKA_WIZ_PREFIX}unit:{i}")]
        for i, t in enumerate(SPRAVKA_UNITS)
    ])


def _spravka_rank_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([
        [InlineKeyboardButton(t, callback_data=f"{SPRAVKA_WIZ_PREFIX}rank:{i}")]
        for i, t in enumerate(SPRAVKA_RANKS)
    ])


@_allowed_only
async def spravka_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """По нажатию «Справка (Word)» — запуск мастера: номер дела → должность → подразделение → звание → ФИО."""
    query = update.callback_query
    if not query.data or not query.data.startswith(SPRAVKA_PREFIX):
        return
    rest = query.data[len(SPRAVKA_PREFIX):].strip()
    parts = rest.split(":")
    if len(parts) >= 2 and parts[0] in ("ip", "domain", "dns", "bin", "email", "phone", "wallet"):
        lookup_type, value = parts[0], ":".join(parts[1:]).strip()
    else:
        lookup_type, value = _spravka_cache.get(parts[0] if parts else "", (None, None))
        if not lookup_type or not value:
            await query.answer("Сессия истекла. Повторите запрос.", show_alert=True)
            return
    if not lookup_type or not value:
        await query.answer("Ошибка параметров", show_alert=True)
        return
    await query.answer()
    context.user_data[PENDING_SPRAVKA_KEY] = {
        "lookup_type": lookup_type,
        "value": value,
        "step": "case_num",
    }
    await query.message.reply_text("Введите номер уголовного дела:")


@_allowed_only
async def spravka_wizard_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Обработка выбора реквизитов и сохранённого профиля в мастере справки."""
    query = update.callback_query
    if not query.data or not query.data.startswith(SPRAVKA_WIZ_PREFIX):
        return
    pending = context.user_data.get(PENDING_SPRAVKA_KEY)
    if not pending or not isinstance(pending, dict):
        await query.answer("Сессия справки истекла. Начните заново с кнопки «Справка (Word)».", show_alert=True)
        return
    rest = query.data[len(SPRAVKA_WIZ_PREFIX):].strip()
    parts = rest.split(":")
    if len(parts) != 2:
        await query.answer()
        return
    kind, value = parts[0], parts[1]
    await query.answer()
    chat = query.message.chat
    try:
        await query.message.delete()
    except Exception:
        pass

    if kind == "profile":
        # Выбор: использовать весь сохранённый профиль или ввести заново
        if value == SPRAVKA_PROFILE_CHOICE_USE:
            user = update.effective_user
            profile = None
            if user:
                profile = await asyncio.get_event_loop().run_in_executor(
                    None, _get_spravka_profile_sync, user.id
                )
            if not _spravka_profile_is_complete(profile):
                pending["step"] = "position"
                context.user_data[PENDING_SPRAVKA_KEY] = pending
                await chat.send_message("Выберите должность:", reply_markup=_spravka_position_keyboard())
                return
            pending["position"] = (profile.get("position") or "").strip()
            pending["unit"] = (profile.get("unit") or "").strip()
            pending["rank"] = (profile.get("rank") or "").strip()
            pending["signature_name"] = (profile.get("signature_name") or "").strip()
            context.user_data[PENDING_SPRAVKA_KEY] = pending
            await _finish_spravka_flow(chat, context, pending, update.effective_user)
            return
        elif value == SPRAVKA_PROFILE_CHOICE_NEW:
            pending.pop("position", None)
            pending.pop("unit", None)
            pending.pop("rank", None)
            pending.pop("signature_name", None)
            pending["step"] = "position"
            context.user_data[PENDING_SPRAVKA_KEY] = pending
            await chat.send_message("Выберите должность:", reply_markup=_spravka_position_keyboard())
            return
        else:
            await query.answer()
            return

    try:
        idx = int(value)
    except ValueError:
        await query.answer()
        return

    if kind == "pos" and 0 <= idx < len(SPRAVKA_POSITIONS):
        pending["position"] = SPRAVKA_POSITIONS[idx]
        pending["step"] = "unit"
        context.user_data[PENDING_SPRAVKA_KEY] = pending
        await chat.send_message("Выберите следственное подразделение:", reply_markup=_spravka_unit_keyboard())
    elif kind == "unit" and 0 <= idx < len(SPRAVKA_UNITS):
        pending["unit"] = SPRAVKA_UNITS[idx]
        pending["step"] = "rank"
        context.user_data[PENDING_SPRAVKA_KEY] = pending
        await chat.send_message("Выберите звание:", reply_markup=_spravka_rank_keyboard())
    elif kind == "rank" and 0 <= idx < len(SPRAVKA_RANKS):
        pending["rank"] = SPRAVKA_RANKS[idx]
        pending["step"] = "name"
        context.user_data[PENDING_SPRAVKA_KEY] = pending
        await chat.send_message('Введите ФИО в формате "И.И.Иванов":')


@_allowed_only
async def dns_report_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """По нажатию кнопки «DNS отчёт» — отправляет файл с DNS-записями."""
    query = update.callback_query
    if not query.data or not query.data.startswith(DNS_REPORT_PREFIX):
        return
    domain = query.data[len(DNS_REPORT_PREFIX):].strip()
    if not domain:
        await query.answer("Домен не указан", show_alert=True)
        return

    await query.answer("Формирую DNS-отчёт…")

    try:
        content, filename = await asyncio.get_event_loop().run_in_executor(
            None, get_dns_report_file, domain
        )
        doc = InputFile(BytesIO(content), filename=filename)
        await query.message.reply_document(
            document=doc,
            caption=f"📥 DNS отчёт: {domain}",
        )
    except ValueError as e:
        await query.message.reply_text(str(e))
    except RuntimeError as e:
        await query.message.reply_text(str(e))
    except Exception as e:
        logger.warning("dns_report failed: %s", e)
        await query.message.reply_text("Не удалось сформировать DNS-отчёт.")


@_allowed_only
async def dns_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """DNS записи домена."""
    if not context.args:
        await update.message.reply_text("Укажите домен: /dns example.com")
        return
    domain = context.args[0].strip().lower()
    if not _validate_domain(domain):
        await update.message.reply_text("Неверный формат домена. Пример: /dns example.com")
        return
    status_msg = await update.message.reply_text("Получаю DNS записи…")
    loop = asyncio.get_event_loop()
    text = await loop.run_in_executor(None, get_dns_info, domain)
    if len(text) > 4000:
        text = text[:3997] + "..."
    await update.message.reply_text(
        text,
        parse_mode="HTML",
        reply_markup=_spravka_only_keyboard("dns", domain, context),
    )
    try:
        await status_msg.delete()
    except Exception:
        pass


@_allowed_only
async def bin_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Поиск по BIN через HandyAPI."""
    if not context.args:
        await update.message.reply_text(
            "Укажите BIN (6–8 цифр карты): /bin 535316"
        )
        return
    bin_val = "".join(c for c in context.args[0] if c.isdigit())[:8]
    if len(bin_val) < 6:
        await update.message.reply_text(
            "BIN должен содержать 6–8 цифр. Пример: /bin 535316"
        )
        return
    status_msg = await update.message.reply_text("Проверяю информацию по BIN…")
    loop = asyncio.get_event_loop()
    text = await loop.run_in_executor(None, get_bin_info, bin_val)
    if len(text) > 4000:
        text = text[:3997] + "..."
    await update.message.reply_text(
        text,
        parse_mode="HTML",
        reply_markup=_spravka_only_keyboard("bin", bin_val, context),
    )
    try:
        await status_msg.delete()
    except Exception:
        pass


@_allowed_only
async def email_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """OSINT по email."""
    if not context.args:
        await update.message.reply_text("Укажите email: /email user@example.com")
        return
    email = _normalize_email("".join(context.args))
    if not _validate_email(email):
        await update.message.reply_text("Неверный формат email. Пример: /email user@example.com")
        return
    status_msg = await update.message.reply_text("Проверяю информацию по email…")
    loop = asyncio.get_event_loop()
    text = await loop.run_in_executor(None, get_email_info, email)
    if len(text) > 4000:
        text = text[:3997] + "..."
    await update.message.reply_text(
        text,
        parse_mode="HTML",
        reply_markup=_spravka_only_keyboard("email", email, context),
    )
    try:
        await status_msg.delete()
    except Exception:
        pass


@_allowed_only
async def user_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Username search."""
    if not context.args:
        await update.message.reply_text("Укажите username: /user durov или /user @durov")
        return
    username = _normalize_username("".join(context.args))
    if not _validate_username(username):
        await update.message.reply_text("Неверный формат username. Пример: /user durov")
        return
    status_msg = await update.message.reply_text("Проверяю username по площадкам…")
    loop = asyncio.get_event_loop()
    text = await loop.run_in_executor(None, get_username_info, username)
    if len(text) > 4000:
        text = text[:3997] + "..."
    await update.message.reply_text(text, parse_mode="HTML")
    try:
        await status_msg.delete()
    except Exception:
        pass


@_allowed_only
async def wallet_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Поиск по криптокошельку (ETH, BTC, TRON)."""
    if not context.args:
        await update.message.reply_text(
            "Укажите адрес: /wallet 0x... (ETH) или 1.../bc1... (BTC) или T... (TRON)"
        )
        return
    addr = context.args[0].strip()
    if not _validate_wallet(addr):
        await update.message.reply_text(
            "Неверный формат. Поддерживаются: ETH (0x...), BTC (1..., 3..., bc1...), TRON (T...)"
        )
        return
    status_msg = await update.message.reply_text("Проверяю кошелёк…")
    loop = asyncio.get_event_loop()
    text = await loop.run_in_executor(None, get_wallet_info, addr)
    if len(text) > 4000:
        text = text[:3997] + "..."
    reply_markup = _wallet_result_keyboard(addr, context)
    await update.message.reply_text(
        text,
        parse_mode="HTML",
        reply_markup=reply_markup,
    )
    try:
        await status_msg.delete()
    except Exception:
        pass


@_allowed_only
async def phone_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Поиск оператора по номеру через Numverify."""
    if not context.args:
        await update.message.reply_text(
            "Укажите номер (с кодом страны): /phone +79161234567"
        )
        return
    raw = "".join(context.args)
    if not _validate_phone(raw):
        await update.message.reply_text(
            "Неверный формат. Укажите 10–15 цифр с кодом страны: /phone +79161234567"
        )
        return
    phone_val = _normalize_phone(raw)
    status_msg = await update.message.reply_text("Проверяю информацию по номеру…")
    loop = asyncio.get_event_loop()
    text = await loop.run_in_executor(None, get_phone_info, phone_val)
    if len(text) > 4000:
        text = text[:3997] + "..."
    await update.message.reply_text(
        text,
        parse_mode="HTML",
        reply_markup=_spravka_only_keyboard("phone", phone_val, context),
    )
    try:
        await status_msg.delete()
    except Exception:
        pass


@_allowed_only
async def message_ip_or_domain(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Обработка ввода: один IP, домен, BIN, кошелёк или номер — без команд. Либо шаги мастера справки."""
    pending = context.user_data.get(PENDING_SPRAVKA_KEY)
    text = (update.message.text or "").strip()

    if pending is not None:
        if isinstance(pending, tuple):
            lookup_type, value = pending
            pending = {"lookup_type": lookup_type, "value": value, "step": "case_num"}
        step = pending.get("step")
        if step == "case_num":
            pending["case_num"] = text
            pending["step"] = "profile_choice"
            context.user_data[PENDING_SPRAVKA_KEY] = pending
            # Пробуем получить полный сохранённый профиль и предложить выбор
            user = update.effective_user
            profile = None
            if user:
                profile = await asyncio.get_event_loop().run_in_executor(
                    None, _get_spravka_profile_sync, user.id
                )
            if _spravka_profile_is_complete(profile):
                await update.message.reply_text(
                    "Найден ранее сохранённый профиль для справки.\n"
                    "Выберите: применить его целиком или ввести новые значения.",
                    reply_markup=_spravka_profile_choice_keyboard(profile),
                )
            else:
                pending["step"] = "position"
                context.user_data[PENDING_SPRAVKA_KEY] = pending
                await update.message.reply_text(
                    "Выберите должность:", reply_markup=_spravka_position_keyboard()
                )
            return
        if step == "name":
            pending["signature_name"] = text
            context.user_data[PENDING_SPRAVKA_KEY] = pending
            await _finish_spravka_flow(update.message.chat, context, pending, update.effective_user)
            return

    raw = text
    lookup_type, value = detect_lookup_type(raw)
    if not lookup_type:
        return

    status_texts = {
        "ip": "Проверяю информацию по IP…",
        "domain": "Проверяю информацию по домену…",
        "bin": "Проверяю информацию по BIN…",
        "email": "Проверяю информацию по email…",
        "user": "Проверяю username по площадкам…",
        "wallet": "Проверяю кошелёк…",
        "phone": "Проверяю информацию по номеру…",
    }
    handlers = {
        "ip": get_ip_info,
        "domain": get_domain_info,
        "bin": get_bin_info,
        "email": get_email_info,
        "user": get_username_info,
        "wallet": get_wallet_info,
        "phone": get_phone_info,
    }

    status_msg = await update.message.reply_text(status_texts.get(lookup_type, "Проверяю…"))
    loop = asyncio.get_event_loop()
    text = await loop.run_in_executor(None, handlers[lookup_type], value)

    if len(text) > 4000:
        text = text[:3997] + "..."

    if lookup_type == "domain":
        reply_markup = _domain_result_keyboard(value, context)
    elif lookup_type == "wallet":
        reply_markup = _wallet_result_keyboard(value, context)
    elif lookup_type == "user":
        reply_markup = None
    else:
        reply_markup = _spravka_only_keyboard(lookup_type, value, context)
    await update.message.reply_text(
        text,
        parse_mode="HTML",
        reply_markup=reply_markup,
    )
    try:
        await status_msg.delete()
    except Exception:
        pass


def main() -> None:
    if not TELEGRAM_BOT_TOKEN:
        print("Введите токен бота в bot.py (TELEGRAM_BOT_TOKEN).")
        return

    app = (
        Application.builder()
        .token(TELEGRAM_BOT_TOKEN)
        .post_init(post_init)
        .build()
    )
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("help", help_cmd))
    app.add_handler(CommandHandler("privacy", privacy_cmd))
    app.add_handler(CallbackQueryHandler(show_commands_callback, pattern="^show_commands$"))
    app.add_handler(CallbackQueryHandler(privacy_accept_callback, pattern="^privacy_accept$"))
    app.add_handler(CallbackQueryHandler(privacy_decline_callback, pattern="^privacy_decline$"))
    app.add_handler(CallbackQueryHandler(privacy_request_delete_callback, pattern="^privacy_request_delete$"))
    app.add_handler(CallbackQueryHandler(privacy_confirm_delete_callback, pattern="^privacy_confirm_delete$"))
    app.add_handler(CallbackQueryHandler(privacy_cancel_delete_callback, pattern="^privacy_cancel_delete$"))
    app.add_handler(CallbackQueryHandler(dns_report_callback, pattern="^dns_report:"))
    app.add_handler(CallbackQueryHandler(wallet_tx_report_callback, pattern="^wtx:"))
    app.add_handler(CallbackQueryHandler(spravka_callback, pattern="^spravka:"))
    app.add_handler(CallbackQueryHandler(spravka_wizard_callback, pattern="^spravka_wiz:"))
    app.add_handler(CommandHandler("ip", ip_command))
    app.add_handler(CommandHandler("domain", domain_command))
    app.add_handler(CommandHandler("dns", dns_command))
    app.add_handler(CommandHandler("bin", bin_command))
    app.add_handler(CommandHandler("email", email_command))
    app.add_handler(CommandHandler("user", user_command))
    app.add_handler(CommandHandler("wallet", wallet_command))
    app.add_handler(CommandHandler("phone", phone_command))
    app.add_handler(
        MessageHandler(filters.TEXT & ~filters.COMMAND, message_ip_or_domain)
    )

    if BOT_ALLOWED_LIST_URL and app.job_queue:
        # Периодически обновляем список разрешённых пользователей и статусы согласия
        # из Django-админки, чтобы не нужно было перезапускать бота.
        # Интервал 10 секунд: достаточно часто, но без лишней нагрузки.
        app.job_queue.run_repeating(_refresh_allowed_ids, interval=10, first=5)

    logger.info("Бот запущен")
    app.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()
