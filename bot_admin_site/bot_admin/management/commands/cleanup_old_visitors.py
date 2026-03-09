# -*- coding: utf-8 -*-
"""
Удаление записей BotVisitor старше заданного срока (ограничение хранения по Закону о ПД).
Запуск: python manage.py cleanup_old_visitors [--months 12]
"""
from django.core.management.base import BaseCommand
from django.utils import timezone
from datetime import timedelta

from bot_admin.models import BotVisitor


class Command(BaseCommand):
    help = "Удаляет записи обращений к боту (BotVisitor) старше N месяцев"

    def add_arguments(self, parser):
        parser.add_argument(
            "--months",
            type=int,
            default=12,
            help="Удалить записи, где last_seen старше этого количества месяцев (по умолчанию 12)",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Только показать, сколько записей будет удалено, без удаления",
        )

    def handle(self, *args, **options):
        months = max(1, options["months"])
        dry_run = options["dry_run"]
        threshold = timezone.now() - timedelta(days=30 * months)
        qs = BotVisitor.objects.filter(last_seen__lt=threshold)
        count = qs.count()
        if dry_run:
            self.stdout.write(
                self.style.WARNING(f"Dry-run: было бы удалено записей: {count} (last_seen < {threshold.date()})")
            )
            return
        qs.delete()
        self.stdout.write(self.style.SUCCESS(f"Удалено записей обращений к боту: {count}"))
