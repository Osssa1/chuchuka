# -*- coding: utf-8 -*-
"""
Единая команда для автоматического удаления ПД по срокам (Закон о ПД).
Последовательно запускает:
  1) cleanup_old_visitors — обращения к боту старше 12 месяцев;
  2) cleanup_old_deactivated_users — неактивные пользователи старше 90 дней.
Удобно вызывать одной задачей по расписанию (cron / Планировщик заданий).
Запуск: python manage.py cleanup_personal_data [--visitor-months 12] [--deactivated-days 90] [--dry-run]
"""
from django.core.management import call_command
from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = "Удаляет устаревшие персональные данные: обращения (12 мес.) и неактивных пользователей (90 дней)"

    def add_arguments(self, parser):
        parser.add_argument(
            "--visitor-months",
            type=int,
            default=12,
            help="Удалить BotVisitor старше N месяцев (по умолчанию 12)",
        )
        parser.add_argument(
            "--deactivated-days",
            type=int,
            default=90,
            help="Удалить неактивных AllowedUser старше N дней (по умолчанию 90)",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Только показать объём удаления, без изменений",
        )

    def handle(self, *args, **options):
        dry_run = options["dry_run"]
        self.stdout.write("Запуск очистки персональных данных (сроки хранения)...")
        call_command(
            "cleanup_old_visitors",
            months=options["visitor_months"],
            dry_run=dry_run,
        )
        call_command(
            "cleanup_old_deactivated_users",
            days=options["deactivated_days"],
            dry_run=dry_run,
        )
        self.stdout.write(self.style.SUCCESS("Очистка завершена."))
