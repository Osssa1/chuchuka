# -*- coding: utf-8 -*-
"""
Удаление записей неактивных AllowedUser старше 90 дней (ограничение хранения по Закону о ПД).
Запуск: python manage.py cleanup_old_deactivated_users [--days 90]
"""
from django.core.management.base import BaseCommand
from django.utils import timezone
from datetime import timedelta

from bot_admin.models import AllowedUser


class Command(BaseCommand):
    help = "Удаляет неактивных разрешённых пользователей (AllowedUser), деактивированных более N дней назад"

    def add_arguments(self, parser):
        parser.add_argument(
            "--days",
            type=int,
            default=90,
            help="Удалить записи с is_active=False и updated_at старше этого количества дней (по умолчанию 90)",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Только показать, сколько записей будет удалено, без удаления",
        )

    def handle(self, *args, **options):
        days = max(1, options["days"])
        dry_run = options["dry_run"]
        threshold = timezone.now() - timedelta(days=days)
        qs = AllowedUser.objects.filter(is_active=False, updated_at__lt=threshold)
        count = qs.count()
        if dry_run:
            self.stdout.write(
                self.style.WARNING(
                    f"Dry-run: было бы удалено неактивных AllowedUser: {count} (updated_at < {threshold.date()})"
                )
            )
            return
        qs.delete()
        self.stdout.write(self.style.SUCCESS(f"Удалено неактивных записей AllowedUser: {count}"))
