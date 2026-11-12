"""Management command to train the ML model and seed realistic SOC queue data."""

from __future__ import annotations

import pandas as pd
from django.conf import settings
from django.core.management.base import BaseCommand

from scanner.ml.pipeline import train_and_save_model
from scanner.models import EmailReport, QuarantineAlert
from scanner.tasks import scan_email_task


class Command(BaseCommand):
    help = "Train the TF-IDF + LinearSVC model on data/emails.csv and seed initial SOC triage emails."

    def add_arguments(self, parser):
        parser.add_argument(
            "--reset",
            action="store_true",
            help="Clear existing EmailReport and QuarantineAlert records before seeding.",
        )
        parser.add_argument(
            "--count",
            type=int,
            default=18,
            help="Number of representative emails from emails.csv to seed into the SOC queue.",
        )

    def handle(self, *args, **options):
        self.stdout.write("Training TF-IDF + LinearSVC phishing classifier...")
        metrics = train_and_save_model()
        self.stdout.write(
            self.style.SUCCESS(
                f"Model trained on {metrics['dataset_rows']} emails | "
                f"5-fold CV Accuracy: {metrics['cv_accuracy']}% | Macro F1: {metrics['macro_f1']}%"
            )
        )

        if options["reset"]:
            QuarantineAlert.objects.all().delete()
            EmailReport.objects.all().delete()
            self.stdout.write("Cleared existing EmailReport and QuarantineAlert tables.")

        if EmailReport.objects.exists() and not options["reset"]:
            self.stdout.write("SOC database already populated; skipping seed (use --reset to re-seed).")
            return

        df = pd.read_csv(settings.DATA_CSV_PATH)
        # Pick a balanced, compelling mix of Phishing, Spam, and Safe emails
        per_class = max(2, options["count"] // 3)
        phishing_rows = df[df["label"] == "Phishing"].head(per_class + 1)
        spam_rows = df[df["label"] == "Spam"].head(per_class)
        safe_rows = df[df["label"] == "Safe"].head(per_class)
        sample_df = pd.concat([phishing_rows, spam_rows, safe_rows]).reset_index(drop=True)

        reporters = [
            "priya.nair@acme-corp.com",
            "alex.rivera@acme-corp.com",
            "marcus.reid@acme-corp.com",
            "hannah.lee@acme-corp.com",
            "finance.ap@acme-corp.com",
        ]

        created_count = 0
        for idx, row in sample_df.iterrows():
            report = EmailReport.objects.create(
                sender=str(row["sender"]),
                reported_by=reporters[idx % len(reporters)],
                subject=str(row["subject"]),
                body=str(row["body"]),
                contains_attachment=bool(row["contains_attachment"]),
                attachment_names=["document_review.html"] if bool(row["contains_attachment"]) else [],
                source_tag="dataset-seed",
            )
            scan_email_task.delay(report.id)
            created_count += 1

        alert_count = QuarantineAlert.objects.count()
        self.stdout.write(
            self.style.SUCCESS(
                f"Seeded {created_count} scanned emails and generated {alert_count} simulated quarantine alerts."
            )
        )
