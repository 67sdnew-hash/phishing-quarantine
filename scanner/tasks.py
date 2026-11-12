"""Celery background tasks for scanning forwarded emails & raising quarantine alerts."""

from __future__ import annotations

from celery import shared_task
from django.db import transaction
from django.utils import timezone

from .ml.features import parse_sender_identity
from .ml.pipeline import predict_and_explain
from .models import EmailReport, QuarantineAlert


def _determine_alert_details(
    report: EmailReport,
    result: dict,
) -> tuple[str, str, str, list[str]]:
    """Build severity, alert type, title, and triggered rules for a high-risk email."""
    features = result["extracted_features"]
    risk = result["risk_score"]
    mismatch = features.get("domain_mismatch", {})
    mal_urls = [u for u in features.get("urls", []) if u.get("is_malicious")]
    cred_kw = features.get("credential_keywords", [])
    urg_kw = features.get("urgency_keywords", [])

    triggered_rules: list[str] = []
    if mismatch.get("detected"):
        triggered_rules.extend(mismatch.get("reasons", []))
    for u in mal_urls[:3]:
        triggered_rules.append(f"Malicious URL ({u['host'] or u['url']}): {', '.join(u['flags'])}")
    if cred_kw:
        triggered_rules.append(f"Credential/Financial intent: {', '.join(cred_kw[:4])}")
    if urg_kw:
        triggered_rules.append(f"Urgency/Coercion cues: {', '.join(urg_kw[:4])}")
    if report.contains_attachment:
        triggered_rules.append("Attachment included in high-risk message")

    if mismatch.get("detected") and any("webmail" in r.lower() or "ceo" in r.lower() or "cfo" in r.lower() for r in mismatch.get("reasons", [])):
        alert_type = QuarantineAlert.AlertType.BEC_IMPERSONATION
    elif mismatch.get("detected"):
        alert_type = QuarantineAlert.AlertType.LOOKALIKE_DOMAIN
    elif mal_urls:
        alert_type = QuarantineAlert.AlertType.MALICIOUS_URL
    elif cred_kw:
        alert_type = QuarantineAlert.AlertType.CREDENTIAL_HARVEST
    else:
        alert_type = QuarantineAlert.AlertType.AUTO_QUARANTINE

    severity = (
        QuarantineAlert.Severity.CRITICAL
        if (risk >= 84.0 or (mismatch.get("detected") and (mal_urls or cred_kw)))
        else QuarantineAlert.Severity.HIGH
    )

    title = f"{report.ticket_id} Quarantined: {report.subject[:95]}"
    return severity, alert_type, title, triggered_rules


@shared_task(bind=True, name="scanner.scan_email_task")
def scan_email_task(self, email_report_id: int) -> dict:
    """Run TF-IDF + LinearSVC + URL/Domain feature scan on an EmailReport."""
    report = EmailReport.objects.get(pk=email_report_id)
    task_id = getattr(self.request, "id", "") or f"eager-{email_report_id}"

    report.status = EmailReport.ScanStatus.SCANNING
    report.celery_task_id = str(task_id)
    report.save(update_fields=["status", "celery_task_id"])

    try:
        sender_info = parse_sender_identity(report.sender)
        result = predict_and_explain(
            sender=report.sender,
            subject=report.subject,
            body=report.body,
            contains_attachment=report.contains_attachment,
        )

        with transaction.atomic():
            report.sender_display_name = sender_info["display_name"]
            report.sender_email = sender_info["email"]
            report.sender_domain = sender_info["domain"]
            report.predicted_label = result["predicted_label"]
            report.confidence_score = result["confidence_score"]
            report.risk_score = result["risk_score"]
            report.class_probabilities = result["class_probabilities"]
            report.extracted_features = result["extracted_features"]
            report.explainability_data = result["explainability_data"]
            report.scanned_at = timezone.now()
            report.status = EmailReport.ScanStatus.COMPLETED

            should_quarantine = (
                result["predicted_label"] == EmailReport.ThreatLabel.PHISHING
                or result["risk_score"] >= 65.0
            )
            if should_quarantine:
                report.quarantine_status = EmailReport.QuarantineStatus.QUARANTINED
            elif result["predicted_label"] == EmailReport.ThreatLabel.SPAM and result["risk_score"] >= 45.0:
                report.quarantine_status = EmailReport.QuarantineStatus.QUARANTINED
            else:
                report.quarantine_status = EmailReport.QuarantineStatus.NONE

            report.save()

            # High-risk emails trigger simulated SOC quarantine alerts
            if report.predicted_label == EmailReport.ThreatLabel.PHISHING or report.risk_score >= 65.0:
                severity, alert_type, title, rules = _determine_alert_details(report, result)
                summary = "; ".join(result["explainability_data"].get("summary_reasons", [])) or (
                    f"Classified as {report.predicted_label} with {report.risk_score}/100 risk score."
                )
                QuarantineAlert.objects.create(
                    email_report=report,
                    severity=severity,
                    alert_type=alert_type,
                    title=title,
                    message=summary,
                    triggered_rules=rules,
                )

        return {
            "email_report_id": report.id,
            "ticket_id": report.ticket_id,
            "predicted_label": report.predicted_label,
            "risk_score": report.risk_score,
            "quarantine_status": report.quarantine_status,
        }
    except Exception as exc:
        report.status = EmailReport.ScanStatus.FAILED
        report.analyst_notes = f"Scan error: {exc}"
        report.save(update_fields=["status", "analyst_notes"])
        raise


@shared_task(name="scanner.batch_scan_emails_task")
def batch_scan_emails_task(email_report_ids: list[int]) -> list[dict]:
    """Scan a batch of EmailReport IDs sequentially or via worker queue."""
    results = []
    for report_id in email_report_ids:
        results.append(scan_email_task(report_id))
    return results
