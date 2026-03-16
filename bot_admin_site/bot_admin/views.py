# -*- coding: utf-8 -*-
import json
from django.http import JsonResponse
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from .models import AllowedUser, BotVisitor, PersonalDataDeletionRequest, SpravkaProfile


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
