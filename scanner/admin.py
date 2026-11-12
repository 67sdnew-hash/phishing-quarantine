from django.contrib import admin

from .models import EmailReport, QuarantineAlert


@admin.register(EmailReport)
class EmailReportAdmin(admin.ModelAdmin):
    list_display = (
        "ticket_id",
        "subject",
        "sender_email",
        "predicted_label",
        "risk_score",
        "quarantine_status",
        "status",
        "created_at",
    )
    list_filter = ("predicted_label", "quarantine_status", "status", "contains_attachment")
    search_fields = ("sender", "subject", "body", "reported_by")
    readonly_fields = ("created_at", "scanned_at", "celery_task_id")


@admin.register(QuarantineAlert)
class QuarantineAlertAdmin(admin.ModelAdmin):
    list_display = ("title", "severity", "alert_type", "is_acknowledged", "created_at")
    list_filter = ("severity", "alert_type", "is_acknowledged")
    search_fields = ("title", "message")
