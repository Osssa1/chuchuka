# -*- coding: utf-8 -*-
from django.db import models


class AllowedUser(models.Model):
    """Пользователь Telegram, которому разрешён доступ к боту."""
    telegram_id = models.BigIntegerField(
        unique=True,
        verbose_name="Telegram ID",
        help_text="Узнать id: @userinfobot в Telegram",
    )
    telegram_username = models.CharField(
        max_length=128,
        blank=True,
        verbose_name="Username в Telegram",
    )
    fio = models.CharField(
        max_length=255,
        blank=True,
        verbose_name="ФИО",
        help_text="Фамилия Имя Отчество",
    )
    note = models.CharField(
        max_length=255,
        blank=True,
        verbose_name="Заметка",
    )
    is_active = models.BooleanField(
        default=True,
        verbose_name="Доступ разрешён",
    )
    consent_at = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name="Дата согласия на обработку ПД",
        help_text="Заполняется при принятии пользователем политики в боте",
    )
    consent_version = models.CharField(
        max_length=32,
        default="1.0",
        blank=True,
        verbose_name="Версия политики при согласии",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Разрешённый пользователь"
        verbose_name_plural = "Разрешённые пользователи"
        ordering = ["-created_at"]

    def __str__(self):
        name = self.fio.strip() or self.telegram_username or f"ID {self.telegram_id}"
        return f"{name}" + (" (неактивен)" if not self.is_active else "")


class BotVisitor(models.Model):
    """Уникальный пользователь Telegram, который хотя бы раз обратился к боту."""
    telegram_id = models.BigIntegerField(
        unique=True,
        db_index=True,
        verbose_name="Telegram ID",
    )
    telegram_username = models.CharField(
        max_length=128,
        blank=True,
        verbose_name="Username в Telegram",
    )
    first_seen = models.DateTimeField(verbose_name="Первое обращение", auto_now_add=True)
    last_seen = models.DateTimeField(verbose_name="Последнее обращение", auto_now=True)

    class Meta:
        verbose_name = "Обращение к боту"
        verbose_name_plural = "Обращения к боту (уникальные пользователи)"
        ordering = ["-last_seen"]

    def __str__(self):
        name = self.telegram_username or f"ID {self.telegram_id}"
        return name


class PersonalDataDeletionRequest(models.Model):
    """Запрос субъекта на удаление персональных данных (учёт для соответствия Закону о ПД)."""
    STATUS_PENDING = "pending"
    STATUS_DONE = "done"
    STATUS_REJECTED = "rejected"
    STATUS_CHOICES = [
        (STATUS_PENDING, "Ожидает обработки"),
        (STATUS_DONE, "Выполнено"),
        (STATUS_REJECTED, "Отклонено"),
    ]
    telegram_id = models.BigIntegerField(verbose_name="Telegram ID", db_index=True)
    requested_at = models.DateTimeField(verbose_name="Дата запроса", auto_now_add=True)
    processed_at = models.DateTimeField(null=True, blank=True, verbose_name="Дата обработки")
    status = models.CharField(
        max_length=16,
        choices=STATUS_CHOICES,
        default=STATUS_PENDING,
        verbose_name="Статус",
    )
    note = models.CharField(
        max_length=255,
        blank=True,
        verbose_name="Пометка администратора",
    )

    class Meta:
        verbose_name = "Запрос на удаление ПД"
        verbose_name_plural = "Запросы на удаление ПД"
        ordering = ["-requested_at"]

    def __str__(self):
        return f"Telegram ID {self.telegram_id} — {self.get_status_display()} ({self.requested_at})"


class SpravkaProfile(models.Model):
    """Сохранённые реквизиты для формирования справки (должность, подразделение, звание, ФИО)."""
    telegram_id = models.BigIntegerField(
        unique=True,
        db_index=True,
        verbose_name="Telegram ID",
    )
    position = models.CharField(
        max_length=255,
        blank=True,
        verbose_name="Должность",
    )
    unit = models.CharField(
        max_length=255,
        blank=True,
        verbose_name="Подразделение",
    )
    rank = models.CharField(
        max_length=255,
        blank=True,
        verbose_name="Специальное звание",
    )
    signature_name = models.CharField(
        max_length=255,
        blank=True,
        verbose_name="ФИО для подписи",
        help_text='Формат "И.И.Иванов"',
    )
    updated_at = models.DateTimeField(auto_now=True, verbose_name="Обновлено")

    class Meta:
        verbose_name = "Профиль для справки"
        verbose_name_plural = "Профили для справок"
        ordering = ["-updated_at"]

    def __str__(self):
        return f"Профиль {self.telegram_id} ({self.position or ''} {self.unit or ''})"
