# -*- coding: utf-8 -*-
from django.urls import path
from . import views

urlpatterns = [
    path("allowed-ids/", views.allowed_ids_api),
    path("seen-user/", views.seen_user_api),
    path("consent/", views.consent_api),
    path("webapp-consent/", views.webapp_consent_api),
    path("webapp-profile/", views.webapp_profile_api),
    path("my-data/", views.my_data_api),
    path("request-deletion/", views.request_deletion_api),
    path("spravka-profile/", views.spravka_profile_api),
    path("spravka-profile/save/", views.spravka_profile_save_api),
]
