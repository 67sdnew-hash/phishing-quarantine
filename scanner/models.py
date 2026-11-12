from django.db import models
from django.utils import timezone


class EmailReport(models.Model):
    """Represents a forwarded/reported email submitted for NLP threat scanning."""

    class ScanStatus(models.TextChoices):
        PENDING = "PENDING", "Pending Scan"
        SCANNING = "SCANNING", "Scanning"
        COMPLETED = "COMPLETED", "Completed"
        FAILED = "FAILED", "Failed"

    class ThreatLabel(models.TextChoices):
        PENDING = "Pending", "Pending"
        SAFE = "Safe", "Safe"
        SPAM = "Spam", "Spam"
        PHISHING = "Phishing", "Phishing"

    class QuarantineStatus(models.TextChoices):
        NONE = "NONE", "Delivered / Clear"
        QUARANTINED = "QUARANTINED", "Quarantined"
        RELEASED = "RELEASED", "Released by Analyst"
        CONFIRMED_THREAT = "CONFIRMED_THREAT", "Confirmed Threat"

    sender = models.CharField(max_length=255)
    sender_display_name = models.CharField(max_length=255, blank=True)
    sender_email = models.CharField(max_length=255, blank=True)
    sender_domain = models.CharField(max_length=255, blank=True)
    reported_by = models.CharField(max_length=255, default="soc-intake@acme-corp.com")
    subject = models.CharField(max_length=500)
    body = models.TextField()
    raw_eml = models.TextField(blank=True)
    contains_attachment = models.BooleanField(default=False)
    attachment_names = models.JSONField(default=list, blank=True)

    status = models.CharField(
        max_length=20,
        choices=ScanStatus.choices,
        default=ScanStatus.PENDING,
        db_index=True,
    )
    celery_task_id = models.CharField(max_length=255, blank=True)

    predicted_label = models.CharField(
        max_length=20,
        choices=ThreatLabel.choices,
        default=ThreatLabel.PENDING,
        db_index=True,
    )
    confidence_score = models.FloatField(default=0.0)
    risk_score = models.FloatField(default=0.0, db_index=True)
    class_probabilities = models.JSONField(default=dict, blank=True)

    extracted_features = models.JSONField(default=dict, blank=True)
    explainability_data = models.JSONField(default=dict, blank=True)

    quarantine_status = models.CharField(
        max_length=25,
        choices=QuarantineStatus.choices,
        default=QuarantineStatus.NONE,
        db_index=True,
    )
    analyst_notes = models.TextField(blank=True)
    reviewed_by = models.CharField(max_length=150, blank=True)
    reviewed_at = models.DateTimeField(null=True, blank=True)

    source_tag = models.CharField(max_length=50, default="manual")
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    scanned_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at", "-id"]

    def __str__(self) -> str:
        return f"[{self.ticket_id}] {self.predicted_label}: {self.subject[:60]}"

    @property
    def ticket_id(self) -> str:
        return f"INC-{self.id:04d}" if self.id else "INC-NEW"

    @property
    def is_high_risk(self) -> bool:
        return self.predicted_label == self.ThreatLabel.PHISHING or self.risk_score >= 65.0

    @property
    def url_count(self) -> int:
        return len(self.extracted_features.get("urls", []))

    @property
    def has_domain_mismatch(self) -> bool:
        return bool(self.extracted_features.get("domain_mismatch", {}).get("detected"))


class QuarantineAlert(models.Model):
    """Simulated SOC quarantine alert triggered by high-risk phishing/malicious URL detections."""

    class Severity(models.TextChoices):
        CRITICAL = "CRITICAL", "Critical"
        HIGH = "HIGH", "High"
        MEDIUM = "MEDIUM", "Medium"
        LOW = "LOW", "Low"

    class AlertType(models.TextChoices):
        AUTO_QUARANTINE = "AUTO_QUARANTINE", "Auto-Quarantine Triggered"
        LOOKALIKE_DOMAIN = "LOOKALIKE_DOMAIN", "Lookalike / Domain Spoofing"
        MALICIOUS_URL = "MALICIOUS_URL", "Malicious / Suspicious URL"
        CREDENTIAL_HARVEST = "CREDENTIAL_HARVEST", "Credential Harvesting Intent"
        BEC_IMPERSONATION = "BEC_IMPERSONATION", "Executive / BEC Impersonation"

    email_report = models.ForeignKey(
        EmailReport,
        on_delete=models.CASCADE,
        related_name="alerts",
    )
    severity = models.CharField(
        max_length=20,
        choices=Severity.choices,
        default=Severity.HIGH,
        db_index=True,
    )
    alert_type = models.CharField(
        max_length=30,
        choices=AlertType.choices,
        default=AlertType.AUTO_QUARANTINE,
    )
    title = models.CharField(max_length=255)
    message = models.TextField()
    triggered_rules = models.JSONField(default=list, blank=True)
    simulated_dispatch_channel = models.CharField(
        max_length=150,
        default="SOC-Slack #phishing-alerts + Exchange Mail Quarantine",
    )
    is_acknowledged = models.BooleanField(default=False, db_index=True)
    acknowledged_by = models.CharField(max_length=150, blank=True)
    acknowledged_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ["-created_at", "-id"]

    def __str__(self) -> str:
        return f"[{self.severity}] {self.title}"

    def acknowledge(self, analyst: str = "SOC Analyst") -> None:
        self.is_acknowledged = True
        self.acknowledged_by = analyst
        self.acknowledged_at = timezone.now()
        self.save(update_fields=["is_acknowledged", "acknowledged_by", "acknowledged_at"])
