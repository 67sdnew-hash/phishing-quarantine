"""Views for the Phishing Email & Malicious URL Quarantine System."""

from __future__ import annotations

import csv
import io
import json

from django.conf import settings
from django.contrib import messages
from django.db.models import Avg, Count, Q
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_GET, require_POST

from .ml.pipeline import get_model_metrics, train_and_save_model
from .models import EmailReport, QuarantineAlert
from .parsers import SAMPLE_PRESETS, parse_raw_eml
from .tasks import batch_scan_emails_task, scan_email_task


def _dashboard_stats() -> dict:
    total_emails = EmailReport.objects.count()
    phishing_count = EmailReport.objects.filter(predicted_label=EmailReport.ThreatLabel.PHISHING).count()
    spam_count = EmailReport.objects.filter(predicted_label=EmailReport.ThreatLabel.SPAM).count()
    safe_count = EmailReport.objects.filter(predicted_label=EmailReport.ThreatLabel.SAFE).count()
    quarantined_count = EmailReport.objects.filter(
        quarantine_status=EmailReport.QuarantineStatus.QUARANTINED
    ).count()
    unack_alerts = QuarantineAlert.objects.filter(is_acknowledged=False).count()
    avg_risk = EmailReport.objects.filter(status=EmailReport.ScanStatus.COMPLETED).aggregate(
        avg=Avg("risk_score")
    )["avg"] or 0.0

    return {
        "total_emails": total_emails,
        "phishing_count": phishing_count,
        "spam_count": spam_count,
        "safe_count": safe_count,
        "quarantined_count": quarantined_count,
        "unack_alerts": unack_alerts,
        "avg_risk": round(float(avg_risk), 1),
    }


def dashboard(request: HttpRequest) -> HttpResponse:
    """SOC Triage Dashboard with KPIs, threat breakdown, recent alerts, and filterable email queue."""
    label_filter = request.GET.get("label", "all")
    quarantine_filter = request.GET.get("quarantine", "all")
    query = request.GET.get("q", "").strip()

    reports = EmailReport.objects.all()
    if label_filter in ("Phishing", "Spam", "Safe", "Pending"):
        reports = reports.filter(predicted_label=label_filter)
    if quarantine_filter in ("QUARANTINED", "RELEASED", "CONFIRMED_THREAT", "NONE"):
        reports = reports.filter(quarantine_status=quarantine_filter)
    if query:
        reports = reports.filter(
            Q(subject__icontains=query)
            | Q(sender__icontains=query)
            | Q(reported_by__icontains=query)
            | Q(body__icontains=query)
        )

    stats = _dashboard_stats()
    recent_alerts = QuarantineAlert.objects.select_related("email_report").filter(
        is_acknowledged=False
    )[:4]
    metrics = get_model_metrics()

    # Compute top extracted threat signals across scanned emails for the overview widget
    url_flagged_count = 0
    domain_mismatch_count = 0
    urgency_flagged_count = 0
    for r in EmailReport.objects.filter(status=EmailReport.ScanStatus.COMPLETED).only("extracted_features"):
        ef = r.extracted_features or {}
        if ef.get("malicious_url_count", 0) > 0:
            url_flagged_count += 1
        if ef.get("domain_mismatch", {}).get("detected"):
            domain_mismatch_count += 1
        if ef.get("urgency_keywords"):
            urgency_flagged_count += 1

    total_safe = max(stats["total_emails"], 1)
    context = {
        "active_nav": "dashboard",
        "stats": stats,
        "reports": reports[:60],
        "recent_alerts": recent_alerts,
        "metrics": metrics,
        "label_filter": label_filter,
        "quarantine_filter": quarantine_filter,
        "query": query,
        "signal_stats": {
            "malicious_urls": url_flagged_count,
            "domain_mismatch": domain_mismatch_count,
            "urgency_cues": urgency_flagged_count,
        },
        "pct": {
            "phishing": round(stats["phishing_count"] * 100 / total_safe, 1),
            "spam": round(stats["spam_count"] * 100 / total_safe, 1),
            "safe": round(stats["safe_count"] * 100 / total_safe, 1),
        },
        "celery_eager": settings.CELERY_TASK_ALWAYS_EAGER,
    }
    return render(request, "scanner/dashboard.html", context)


def submit_email(request: HttpRequest) -> HttpResponse:
    """Forward & ingest suspicious emails (Manual form, Raw .eml parser, or Bulk CSV)."""
    if request.method == "POST":
        mode = request.POST.get("mode", "manual")

        if mode == "manual":
            sender = request.POST.get("sender", "").strip()
            reported_by = request.POST.get("reported_by", "employee@acme-corp.com").strip() or "employee@acme-corp.com"
            subject = request.POST.get("subject", "").strip()
            body = request.POST.get("body", "").strip()
            contains_attachment = request.POST.get("contains_attachment") == "on"
            attachment_name = request.POST.get("attachment_name", "").strip()

            if not sender or not subject or not body:
                messages.error(request, "Sender, Subject, and Email Body are required to run a scan.")
            else:
                report = EmailReport.objects.create(
                    sender=sender,
                    reported_by=reported_by,
                    subject=subject,
                    body=body,
                    contains_attachment=contains_attachment,
                    attachment_names=[attachment_name] if attachment_name else [],
                    source_tag="manual-forward",
                )
                task = scan_email_task.delay(report.id)
                report.refresh_from_db()
                messages.success(
                    request,
                    f"{report.ticket_id} scanned (Task {str(task.id)[:10]}): Classified as {report.predicted_label} "
                    f"(Risk {report.risk_score}/100).",
                )
                return redirect("scanner:email_detail", pk=report.pk)

        elif mode == "raw_eml":
            raw_eml = request.POST.get("raw_eml", "").strip()
            reported_by = request.POST.get("reported_by", "employee@acme-corp.com").strip() or "employee@acme-corp.com"
            uploaded = request.FILES.get("eml_file")
            if uploaded:
                raw_eml = uploaded.read().decode("utf-8", errors="replace")

            if not raw_eml:
                messages.error(request, "Please paste raw email headers/body or upload a .eml file.")
            else:
                parsed = parse_raw_eml(raw_eml)
                report = EmailReport.objects.create(
                    sender=parsed["sender"],
                    reported_by=reported_by,
                    subject=parsed["subject"],
                    body=parsed["body"],
                    raw_eml=raw_eml,
                    contains_attachment=parsed["contains_attachment"],
                    attachment_names=parsed["attachment_names"],
                    source_tag="eml-import",
                )
                scan_email_task.delay(report.id)
                report.refresh_from_db()
                messages.success(
                    request,
                    f"Parsed .eml into {report.ticket_id} — Verdict: {report.predicted_label} "
                    f"(Risk {report.risk_score}/100).",
                )
                return redirect("scanner:email_detail", pk=report.pk)

        elif mode == "bulk_csv":
            csv_file = request.FILES.get("csv_file")
            if not csv_file:
                messages.error(request, "Please upload a CSV file with sender, subject, body columns.")
            else:
                content = csv_file.read().decode("utf-8", errors="replace")
                reader = csv.DictReader(io.StringIO(content))
                created_ids: list[int] = []
                for row in list(reader)[:50]:
                    sender = (row.get("sender") or "").strip()
                    subject = (row.get("subject") or "").strip()
                    body = (row.get("body") or "").strip()
                    if not (sender and subject and body):
                        continue
                    att_raw = str(row.get("contains_attachment", "")).strip().lower()
                    contains_att = att_raw in ("true", "1", "yes")
                    rep = EmailReport.objects.create(
                        sender=sender,
                        reported_by="bulk-ingest@acme-corp.com",
                        subject=subject,
                        body=body,
                        contains_attachment=contains_att,
                        source_tag="csv-batch",
                    )
                    created_ids.append(rep.id)

                if created_ids:
                    batch_scan_emails_task.delay(created_ids)
                    messages.success(
                        request,
                        f"Queued and scanned {len(created_ids)} email(s) via Celery batch pipeline.",
                    )
                    return redirect("scanner:dashboard")
                messages.error(request, "No valid rows found in CSV (requires sender, subject, body columns).")

    context = {
        "active_nav": "submit",
        "presets_json": json.dumps(SAMPLE_PRESETS),
        "presets": SAMPLE_PRESETS,
        "stats": _dashboard_stats(),
    }
    return render(request, "scanner/submit_email.html", context)


def email_detail(request: HttpRequest, pk: int) -> HttpResponse:
    """Explainable NLP Investigation Console for a single email report."""
    report = get_object_or_404(EmailReport, pk=pk)
    alerts = report.alerts.all()
    features = report.extracted_features or {}
    explain = report.explainability_data or {}

    context = {
        "active_nav": "dashboard",
        "report": report,
        "alerts": alerts,
        "features": features,
        "explain": explain,
        "stats": _dashboard_stats(),
    }
    return render(request, "scanner/email_detail.html", context)


@require_POST
def email_action(request: HttpRequest, pk: int) -> HttpResponse:
    """SOC Analyst actions: release from quarantine, confirm threat, re-scan, or save notes."""
    report = get_object_or_404(EmailReport, pk=pk)
    action = request.POST.get("action", "")
    notes = request.POST.get("analyst_notes", "").strip()
    analyst = request.POST.get("analyst", "SOC Analyst").strip() or "SOC Analyst"

    if notes:
        report.analyst_notes = notes

    if action == "release":
        report.quarantine_status = EmailReport.QuarantineStatus.RELEASED
        report.reviewed_by = analyst
        report.reviewed_at = timezone.now()
        report.save()
        report.alerts.filter(is_acknowledged=False).update(
            is_acknowledged=True,
            acknowledged_by=analyst,
            acknowledged_at=timezone.now(),
        )
        messages.success(request, f"{report.ticket_id} released from quarantine and marked cleared.")
    elif action == "confirm_threat":
        report.quarantine_status = EmailReport.QuarantineStatus.CONFIRMED_THREAT
        report.reviewed_by = analyst
        report.reviewed_at = timezone.now()
        report.save()
        report.alerts.filter(is_acknowledged=False).update(
            is_acknowledged=True,
            acknowledged_by=analyst,
            acknowledged_at=timezone.now(),
        )
        messages.warning(request, f"{report.ticket_id} confirmed as malicious threat; sender domain logged.")
    elif action == "rescan":
        report.save(update_fields=["analyst_notes"])
        scan_email_task.delay(report.id)
        messages.info(request, f"{report.ticket_id} re-scanned with current TF-IDF + LinearSVC model.")
    elif action == "save_notes":
        report.save(update_fields=["analyst_notes"])
        messages.success(request, "Analyst investigation notes updated.")

    return redirect("scanner:email_detail", pk=pk)


def quarantine_center(request: HttpRequest) -> HttpResponse:
    """Quarantine Vault & Simulated SOC Alerts Center."""
    severity_filter = request.GET.get("severity", "all")
    ack_filter = request.GET.get("ack", "all")

    alerts = QuarantineAlert.objects.select_related("email_report").all()
    if severity_filter in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        alerts = alerts.filter(severity=severity_filter)
    if ack_filter == "unack":
        alerts = alerts.filter(is_acknowledged=False)
    elif ack_filter == "ack":
        alerts = alerts.filter(is_acknowledged=True)

    quarantined_emails = EmailReport.objects.filter(
        quarantine_status__in=[
            EmailReport.QuarantineStatus.QUARANTINED,
            EmailReport.QuarantineStatus.CONFIRMED_THREAT,
        ]
    )

    context = {
        "active_nav": "quarantine",
        "alerts": alerts[:60],
        "quarantined_emails": quarantined_emails[:40],
        "severity_filter": severity_filter,
        "ack_filter": ack_filter,
        "stats": _dashboard_stats(),
    }
    return render(request, "scanner/quarantine_center.html", context)


@require_POST
def acknowledge_alert(request: HttpRequest, pk: int) -> HttpResponse:
    """Acknowledge a simulated quarantine alert."""
    alert = get_object_or_404(QuarantineAlert, pk=pk)
    alert.acknowledge(analyst="SOC Lead")
    messages.success(request, f"Alert '{alert.title[:60]}' acknowledged.")
    next_url = request.POST.get("next") or "scanner:quarantine_center"
    if next_url.startswith("/"):
        return redirect(next_url)
    return redirect(next_url)


def model_lab(request: HttpRequest) -> HttpResponse:
    """ML Model Performance, Confusion Matrix, and Global Explainability Lab."""
    if request.method == "POST":
        metrics = train_and_save_model()
        messages.success(
            request,
            f"Retrained TF-IDF + LinearSVC on {metrics['dataset_rows']} samples "
            f"(5-Fold CV Accuracy: {metrics['cv_accuracy']}%, Macro F1: {metrics['macro_f1']}%).",
        )
        return redirect("scanner:model_lab")

    metrics = get_model_metrics()
    # Format confusion matrix with row labels for crisp template display
    classes = metrics.get("classes", ["Phishing", "Safe", "Spam"])
    cm_raw = metrics.get("confusion_matrix", [])
    cm_rows = [
        {"label": cls, "counts": row}
        for cls, row in zip(classes, cm_raw)
    ]

    context = {
        "active_nav": "model",
        "metrics": metrics,
        "cm_rows": cm_rows,
        "stats": _dashboard_stats(),
    }
    return render(request, "scanner/model_lab.html", context)


@require_GET
def api_email_status(request: HttpRequest, pk: int) -> JsonResponse:
    """JSON polling endpoint for Celery scan status & results."""
    report = get_object_or_404(EmailReport, pk=pk)
    return JsonResponse(
        {
            "id": report.id,
            "ticket_id": report.ticket_id,
            "status": report.status,
            "predicted_label": report.predicted_label,
            "confidence_score": report.confidence_score,
            "risk_score": report.risk_score,
            "quarantine_status": report.quarantine_status,
            "celery_task_id": report.celery_task_id,
        }
    )


@csrf_exempt
@require_POST
def api_scan_email(request: HttpRequest) -> JsonResponse:
    """REST JSON API to ingest and scan an email payload."""
    try:
        payload = json.loads(request.body.decode("utf-8"))
    except json.JSONDecodeError:
        return JsonResponse({"error": "Invalid JSON payload"}, status=400)

    sender = str(payload.get("sender", "")).strip()
    subject = str(payload.get("subject", "")).strip()
    body = str(payload.get("body", "")).strip()
    contains_attachment = bool(payload.get("contains_attachment", False))
    reported_by = str(payload.get("reported_by", "api-gateway@acme-corp.com")).strip()

    if not sender or not subject or not body:
        return JsonResponse(
            {"error": "Fields 'sender', 'subject', and 'body' are required."},
            status=400,
        )

    report = EmailReport.objects.create(
        sender=sender,
        reported_by=reported_by,
        subject=subject,
        body=body,
        contains_attachment=contains_attachment,
        source_tag="rest-api",
    )
    task = scan_email_task.delay(report.id)
    report.refresh_from_db()

    return JsonResponse(
        {
            "id": report.id,
            "ticket_id": report.ticket_id,
            "task_id": str(task.id),
            "status": report.status,
            "predicted_label": report.predicted_label,
            "confidence_score": report.confidence_score,
            "risk_score": report.risk_score,
            "class_probabilities": report.class_probabilities,
            "quarantine_status": report.quarantine_status,
            "domain_mismatch": report.extracted_features.get("domain_mismatch", {}),
            "urls": report.extracted_features.get("urls", []),
            "summary_reasons": report.explainability_data.get("summary_reasons", []),
        },
        status=201,
    )


@require_GET
def api_metrics(request: HttpRequest) -> JsonResponse:
    """Return SOC dashboard stats and ML model metrics."""
    return JsonResponse(
        {
            "soc_stats": _dashboard_stats(),
            "model_metrics": get_model_metrics(),
        }
    )
