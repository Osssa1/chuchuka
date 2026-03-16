# -*- coding: utf-8 -*-
from django.contrib import admin, messages
from .models import AllowedUser, BotVisitor, PersonalDataDeletionRequest, SpravkaProfile


@admin.register(AllowedUser)
class AllowedUserAdmin(admin.ModelAdmin):
    list_display = ("telegram_id", "telegram_username", "fio", "note", "is_active", "consent_at", "created_at")
    list_filter = ("is_active",)
    search_fields = ("telegram_id", "telegram_username", "fio", "note")
    list_editable = ("is_active",)
    readonly_fields = ("created_at", "updated_at")


@admin.action(description="Предоставить доступ к боту")
def grant_bot_access(modeladmin, request, queryset):
    added = 0
    updated = 0
    already = 0
    for visitor in queryset:
        obj, created = AllowedUser.objects.get_or_create(
            telegram_id=visitor.telegram_id,
            defaults={
                "telegram_username": visitor.telegram_username or "",
                "is_active": True,
            },
        )
        if created:
            added += 1
        elif not obj.is_active:
            obj.is_active = True
            obj.telegram_username = visitor.telegram_username or obj.telegram_username
            obj.save()
            updated += 1
        else:
            already += 1
    parts = []
    if added:
        parts.append(f"добавлено: {added}")
    if updated:
        parts.append(f"доступ включён снова: {updated}")
    if already:
        parts.append(f"уже с доступом: {already}")
    modeladmin.message_user(request, "Доступ к боту: " + ", ".join(parts), messages.SUCCESS)


@admin.register(BotVisitor)
class BotVisitorAdmin(admin.ModelAdmin):
    list_display = ("telegram_id", "telegram_username", "first_seen", "last_seen")
    list_filter = ()
    search_fields = ("telegram_id", "telegram_username")
    readonly_fields = ("telegram_id", "telegram_username", "first_seen", "last_seen")
    actions = [grant_bot_access]

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False


@admin.register(PersonalDataDeletionRequest)
class PersonalDataDeletionRequestAdmin(admin.ModelAdmin):
    list_display = ("telegram_id", "status", "requested_at", "processed_at", "note")
    list_filter = ("status",)
    search_fields = ("telegram_id", "note")
    readonly_fields = ("telegram_id", "requested_at")
    date_hierarchy = "requested_at"


@admin.register(SpravkaProfile)
class SpravkaProfileAdmin(admin.ModelAdmin):
    list_display = ("telegram_id", "position", "unit", "rank", "updated_at")
    search_fields = ("telegram_id", "position", "unit", "rank", "signature_name")
