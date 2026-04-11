# -*- coding: utf-8 -*-
import hashlib
import hmac
import json
import os
from pathlib import Path
from typing import Optional, Tuple
from urllib.parse import parse_qsl

from django.conf import settings
from django.http import JsonResponse
from django.shortcuts import render
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from .models import AllowedUser, BotVisitor, PersonalDataDeletionRequest, SpravkaProfile


def _policy_markdown_text() -> str:
    """Текст политики из файла в корне репозитория (на уровень выше bot_admin_site)."""
    repo_root = Path(settings.BASE_DIR).resolve().parent
    path = repo_root / "POLICY_PERSONAL_DATA.md"
    if not path.is_file():
        return ""
    try:
        return path.read_text(encoding="utf-8")
    except Exception:
        return ""


def _verify_telegram_webapp_init_data(init_data: str, bot_token: str) -> Optional[dict]:
    """
    Проверка подписи initData Telegram Web App.
    https://core.telegram.org/bots/webapps#validating-data-received-via-the-mini-app
    """
    if not init_data or not bot_token:
        return None
    try:
        pairs = dict(parse_qsl(init_data, keep_blank_values=True))
    except Exception:
        return None
    recv_hash = pairs.pop("hash", None)
    if not recv_hash:
        return None
    data_check_string = "\n".join(f"{k}={pairs[k]}" for k in sorted(pairs.keys()))
    secret_key = hmac.new(
        b"WebAppData", bot_token.encode("utf-8"), hashlib.sha256
    ).digest()
    calc_hash = hmac.new(
        secret_key, data_check_string.encode("utf-8"), hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(calc_hash, recv_hash):
        return None
    user_raw = pairs.get("user")
    if not user_raw:
        return None
    try:
        user = json.loads(user_raw)
    except json.JSONDecodeError:
        return None
    return user


def _request_json(request) -> dict:
    """Безопасно декодирует JSON body; пустое тело -> пустой dict."""
    if not request.body:
        return {}
    try:
        return json.loads(request.body.decode("utf-8"))
    except (AttributeError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("invalid json") from exc


def _webapp_user_from_request(request, body: Optional[dict] = None) -> Tuple[Optional[dict], Optional[JsonResponse]]:
    """
    Возвращает пользователя Telegram из подписанного initData Telegram Web App.
    Не доверяет telegram_id из фронтенда: идентичность вычисляется только на сервере.
    """
    bot_token = os.environ.get("TELEGRAM_BOT_TOKEN", "")
    if not bot_token:
        return None, JsonResponse({"error": "TELEGRAM_BOT_TOKEN not configured on server"}, status=500)

    init_data = ""
    if body is not None:
        init_data = body.get("init_data") or body.get("initData") or ""
    if not init_data:
        init_data = (
            request.headers.get("X-Telegram-Init-Data", "")
            or request.GET.get("init_data", "")
            or request.GET.get("initData", "")
        )
    if not init_data:
        return None, JsonResponse({"error": "init_data required"}, status=400)

    user = _verify_telegram_webapp_init_data(init_data, bot_token)
    if not user:
        return None, JsonResponse({"error": "invalid init_data"}, status=403)
    try:
        user["id"] = int(user.get("id"))
    except (TypeError, ValueError):
        return None, JsonResponse({"error": "invalid user id"}, status=400)
    return user, None


def _spravka_profile_payload(profile: Optional[SpravkaProfile]) -> Optional[dict]:
    if not profile:
        return None
    return {
        "position": profile.position,
        "unit": profile.unit,
        "rank": profile.rank,
        "signature_name": profile.signature_name,
        "updated_at": profile.updated_at.isoformat(),
    }


def _allowed_user_payload(user: Optional[AllowedUser], fallback_user: Optional[dict] = None) -> dict:
    fallback_user = fallback_user or {}
    return {
        "telegram_id": user.telegram_id if user else int(fallback_user.get("id", 0) or 0),
        "telegram_username": (user.telegram_username if user else "") or fallback_user.get("username") or "",
        "fio": user.fio if user else "",
        "is_active": bool(user.is_active) if user else False,
        "consent_at": user.consent_at.isoformat() if user and user.consent_at else None,
        "consent_version": user.consent_version if user else "",
        "updated_at": user.updated_at.isoformat() if user else None,
    }


@require_http_methods(["GET"])
def webapp_consent_page(request):
    """Страница mini app: политика ПД и согласие (открывается из бота через Web App)."""
    policy = _policy_markdown_text()
    return render(
        request,
        "bot_admin/webapp_consent.html",
        {
            "policy_text": policy,
            "policy_version": os.environ.get("POLICY_VERSION", "1.0"),
        },
    )


@require_http_methods(["GET"])
def webapp_cabinet_page(request):
    """Страница mini app: кабинет пользователя, данные подгружаются из Django API."""
    return render(request, "bot_admin/webapp_cabinet.html")


@csrf_exempt
@require_http_methods(["POST"])
def webapp_consent_api(request):
    """
    POST /api/webapp-consent/
    Тело: {"init_data": "<строка из Telegram.WebApp.initData>", "version": "1.0"}
    Проверяет подпись, фиксирует согласие для user.id из init_data.
    """
    try:
        body = _request_json(request)
        version = (body.get("version") or os.environ.get("POLICY_VERSION", "1.0")).strip()[:32]
    except ValueError:
        return JsonResponse({"error": "invalid json"}, status=400)
    user, error = _webapp_user_from_request(request, body)
    if error:
        return error
    telegram_id = user["id"]
    updated = AllowedUser.objects.filter(
        telegram_id=telegram_id, is_active=True, consent_at__isnull=True
    ).update(consent_at=timezone.now(), consent_version=version)
    return JsonResponse({"ok": True, "updated": updated > 0, "telegram_id": telegram_id})


@require_http_methods(["GET"])
def allowed_ids_api(request):
    """
    GET /api/allowed-ids/
    Возвращает список telegram_id с доступом и список id, которым нужно дать согласие на обработку ПД.
    """
    active = AllowedUser.objects.filter(is_active=True)
    ids = list(active.values_list("telegram_id", flat=True))
    consent_required_ids = list(
        active.filter(consent_at__isnull=True).values_list("telegram_id", flat=True)
    )
    return JsonResponse({
        "allowed_ids": ids,
        "consent_required_ids": consent_required_ids,
    })


@csrf_exempt
@require_http_methods(["POST"])
def seen_user_api(request):
    """
    POST /api/seen-user/
    Тело: {"telegram_id": 123, "telegram_username": "optional"}
    Создаёт или обновляет запись об обращении пользователя к боту (уникально по telegram_id).
    """
    try:
        body = json.loads(request.body or "{}")
        telegram_id = int(body.get("telegram_id"))
    except (ValueError, TypeError, KeyError):
        return JsonResponse({"error": "telegram_id required (integer)"}, status=400)
    username = (body.get("telegram_username") or "").strip()[:128]
    visitor, created = BotVisitor.objects.get_or_create(
        telegram_id=telegram_id,
        defaults={"telegram_username": username},
    )
    if not created:
        visitor.telegram_username = username or visitor.telegram_username
        visitor.save()
    return JsonResponse({"ok": True, "created": created})


@csrf_exempt
@require_http_methods(["POST"])
def consent_api(request):
    """
    POST /api/consent/
    Тело: {"telegram_id": 123, "version": "1.0"}
    Фиксирует согласие субъекта на обработку ПД.
    """
    try:
        body = json.loads(request.body or "{}")
        telegram_id = int(body.get("telegram_id"))
    except (ValueError, TypeError, KeyError):
        return JsonResponse({"error": "telegram_id required (integer)"}, status=400)
    version = (body.get("version") or "1.0").strip()[:32]
    updated = AllowedUser.objects.filter(
        telegram_id=telegram_id, is_active=True, consent_at__isnull=True
    ).update(consent_at=timezone.now(), consent_version=version)
    return JsonResponse({"ok": True, "updated": updated > 0})


@require_http_methods(["GET"])
def my_data_api(request):
    """
    GET /api/my-data/?telegram_id=123
    Возвращает данные, хранящиеся по данному telegram_id (для реализации права субъекта на доступ).
    Вызывается только ботом от имени пользователя.
    """
    try:
        telegram_id = int(request.GET.get("telegram_id", 0))
    except (ValueError, TypeError):
        return JsonResponse({"error": "telegram_id required (integer)"}, status=400)
    data = {"telegram_id": telegram_id, "allowed_user": None, "visitor": None}
    au = AllowedUser.objects.filter(telegram_id=telegram_id).first()
    if au:
        data["allowed_user"] = {
            "telegram_username": au.telegram_username or "",
            "fio": au.fio or "",
            "note": "(служебная заметка)",
            "is_active": au.is_active,
            "consent_at": au.consent_at.isoformat() if au.consent_at else None,
            "consent_version": au.consent_version or "",
            "created_at": au.created_at.isoformat(),
            "updated_at": au.updated_at.isoformat(),
        }
    v = BotVisitor.objects.filter(telegram_id=telegram_id).first()
    if v:
        data["visitor"] = {
            "telegram_username": v.telegram_username or "",
            "first_seen": v.first_seen.isoformat(),
            "last_seen": v.last_seen.isoformat(),
        }
    return JsonResponse(data)


@csrf_exempt
@require_http_methods(["POST"])
def request_deletion_api(request):
    """
    POST /api/request-deletion/
    Тело: {"telegram_id": 123}
    Удаляет все упоминания пользователя: BotVisitor, AllowedUser и записи PersonalDataDeletionRequest с этим telegram_id.
    В админке Django после этого не остаётся записей о данном пользователе.
    """
    try:
        body = json.loads(request.body or "{}")
        telegram_id = int(body.get("telegram_id"))
    except (ValueError, TypeError, KeyError):
        return JsonResponse({"error": "telegram_id required (integer)"}, status=400)
    n_visitor, _ = BotVisitor.objects.filter(telegram_id=telegram_id).delete()
    n_allowed, _ = AllowedUser.objects.filter(telegram_id=telegram_id).delete()
    n_requests, _ = PersonalDataDeletionRequest.objects.filter(telegram_id=telegram_id).delete()
    n_profiles, _ = SpravkaProfile.objects.filter(telegram_id=telegram_id).delete()
    return JsonResponse({
        "ok": True,
        "visitor_deleted": n_visitor > 0,
        "allowed_user_deleted": n_allowed > 0,
        "deletion_requests_deleted": n_requests > 0,
        "profiles_deleted": n_profiles > 0,
    })


@require_http_methods(["GET"])
def spravka_profile_api(request):
    """
    GET /api/spravka-profile/?telegram_id=123
    Возвращает сохранённые реквизиты для справки (должность, подразделение, звание, ФИО)
    по telegram_id. Используется ботом для предложения «использовать сохранённые данные».
    """
    try:
        telegram_id = int(request.GET.get("telegram_id", 0))
    except (ValueError, TypeError):
        return JsonResponse({"error": "telegram_id required (integer)"})
    profile = SpravkaProfile.objects.filter(telegram_id=telegram_id).first()
    if not profile:
        return JsonResponse({"profile": None})
    return JsonResponse({
        "profile": {
            "telegram_id": profile.telegram_id,
            "position": profile.position,
            "unit": profile.unit,
            "rank": profile.rank,
            "signature_name": profile.signature_name,
            "updated_at": profile.updated_at.isoformat(),
        }
    })


@csrf_exempt
@require_http_methods(["POST"])
def spravka_profile_save_api(request):
    """
    POST /api/spravka-profile/
    Тело: {"telegram_id": 123, "position": "...", "unit": "...", "rank": "...", "signature_name": "..."}
    Создаёт или обновляет профиль для справки.
    """
    try:
        body = json.loads(request.body or "{}")
        telegram_id = int(body.get("telegram_id"))
    except (ValueError, TypeError, KeyError):
        return JsonResponse({"error": "telegram_id required (integer)"}, status=400)
    position = (body.get("position") or "").strip()[:255]
    unit = (body.get("unit") or "").strip()[:255]
    rank = (body.get("rank") or "").strip()[:255]
    signature_name = (body.get("signature_name") or "").strip()[:255]
    profile, created = SpravkaProfile.objects.update_or_create(
        telegram_id=telegram_id,
        defaults={
            "position": position,
            "unit": unit,
            "rank": rank,
            "signature_name": signature_name,
        },
    )
    return JsonResponse({
        "ok": True,
        "created": created,
        "profile": {
            "telegram_id": profile.telegram_id,
            "position": profile.position,
            "unit": profile.unit,
            "rank": profile.rank,
            "signature_name": profile.signature_name,
            "updated_at": profile.updated_at.isoformat(),
        },
    })


@csrf_exempt
@require_http_methods(["GET", "POST"])
def webapp_profile_api(request):
    """
    API mini app кабинета.
    GET: возвращает данные текущего пользователя по initData.
    POST: сохраняет редактируемые поля профиля в SpravkaProfile для текущего пользователя.
    """
    body = None
    if request.method == "POST":
        try:
            body = _request_json(request)
        except ValueError:
            return JsonResponse({"error": "invalid json"}, status=400)

    user, error = _webapp_user_from_request(request, body)
    if error:
        return error

    telegram_id = user["id"]
    allowed_user = AllowedUser.objects.filter(telegram_id=telegram_id, is_active=True).first()
    if not allowed_user:
        return JsonResponse({"error": "access denied"}, status=403)

    if request.method == "GET":
        profile = SpravkaProfile.objects.filter(telegram_id=telegram_id).first()
        return JsonResponse({
            "ok": True,
            "account": _allowed_user_payload(allowed_user, user),
            "profile": _spravka_profile_payload(profile),
        })

    position = (body.get("position") or "").strip()[:255]
    unit = (body.get("unit") or "").strip()[:255]
    rank = (body.get("rank") or "").strip()[:255]
    signature_name = (body.get("signature_name") or "").strip()[:255]

    profile, created = SpravkaProfile.objects.update_or_create(
        telegram_id=telegram_id,
        defaults={
            "position": position,
            "unit": unit,
            "rank": rank,
            "signature_name": signature_name,
        },
    )
    return JsonResponse({
        "ok": True,
        "created": created,
        "account": _allowed_user_payload(allowed_user, user),
        "profile": _spravka_profile_payload(profile),
    })
