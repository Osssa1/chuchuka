# -*- coding: utf-8 -*-
from django.contrib import admin
from django.urls import path, include

from bot_admin import views as bot_admin_views

urlpatterns = [
    path("admin/", admin.site.urls),
    path("webapp/consent/", bot_admin_views.webapp_consent_page, name="webapp_consent"),
    path("webapp/cabinet/", bot_admin_views.webapp_cabinet_page, name="webapp_cabinet"),
    path("webapp/dashboard/", bot_admin_views.webapp_dashboard_page, name="webapp_dashboard"),
    path("api/", include("bot_admin.urls")),
]
