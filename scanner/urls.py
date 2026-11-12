from django.urls import path

from . import views

app_name = "scanner"

urlpatterns = [
    path("", views.dashboard, name="dashboard"),
    path("submit/", views.submit_email, name="submit_email"),
    path("email/<int:pk>/", views.email_detail, name="email_detail"),
    path("email/<int:pk>/action/", views.email_action, name="email_action"),
    path("quarantine/", views.quarantine_center, name="quarantine_center"),
    path("alerts/<int:pk>/ack/", views.acknowledge_alert, name="acknowledge_alert"),
    path("model/", views.model_lab, name="model_lab"),
    path("api/emails/<int:pk>/status/", views.api_email_status, name="api_email_status"),
    path("api/scan/", views.api_scan_email, name="api_scan_email"),
    path("api/metrics/", views.api_metrics, name="api_metrics"),
]
