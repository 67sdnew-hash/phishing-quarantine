import json
from django.test import Client, TestCase
from django.urls import reverse

from scanner.ml.features import analyze_url, extract_email_features
from scanner.ml.pipeline import predict_and_explain, train_and_save_model
from scanner.models import EmailReport, QuarantineAlert
from scanner.parsers import parse_raw_eml
from scanner.tasks import scan_email_task


class FeatureAndMLPipelineTests(TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.metrics = train_and_save_model()

    def test_model_cv_accuracy_is_high(self):
        self.assertGreaterEqual(self.metrics["cv_accuracy"], 85.0)
        self.assertEqual(self.metrics["dataset_rows"], 143)

    def test_url_analysis_detects_ip_and_typosquat(self):
        ip_res = analyze_url("http://185.220.101.44/vpn-reset")
        self.assertTrue(ip_res["is_ip_url"])
        self.assertTrue(ip_res["is_malicious"])
        self.assertGreaterEqual(ip_res["risk_score"], 50)

        typo_res = analyze_url("http://micr0soft-verify-login.xyz/auth/reset")
        self.assertEqual(typo_res["typosquat_brand"], "Microsoft")
        self.assertTrue(typo_res["has_suspicious_tld"])
        self.assertTrue(typo_res["is_malicious"])

    def test_sender_domain_mismatch_detection(self):
        feats = extract_email_features(
            sender="CEO Sarah Jenkins <s.jenkins.corp@gmail.com>",
            subject="Urgent confidential wire transfer needed before 3 PM",
            body="Please process an urgent vendor wire transfer of $18,500 immediately.",
            contains_attachment=False,
        )
        self.assertTrue(feats["domain_mismatch"]["detected"])
        self.assertTrue(feats["domain_mismatch"]["is_free_webmail"])
        self.assertIn("urgent", feats["urgency_keywords"])
        self.assertIn("wire transfer", feats["credential_keywords"])

    def test_predict_and_explain_phishing_vs_safe(self):
        phish = predict_and_explain(
            sender="Microsoft Account Team <security@micr0soft-verify-login.xyz>",
            subject="URGENT: Unusual sign-in activity detected",
            body="Your account will be suspended within 24 hours unless you verify your identity at http://micr0soft-verify-login.xyz/auth/reset",
            contains_attachment=False,
        )
        self.assertEqual(phish["predicted_label"], "Phishing")
        self.assertGreaterEqual(phish["risk_score"], 65.0)
        body_highlights = [s for s in phish["explainability_data"]["body_segments"] if s.get("highlight")]
        self.assertTrue(any(s.get("category") == "malicious-url" for s in body_highlights))

        safe = predict_and_explain(
            sender="GitHub <notifications@github.com>",
            subject="[acme-corp/backend-api] Pull request #418 merged",
            body="All 142 unit tests passed in CI on branch main.",
            contains_attachment=False,
        )
        self.assertEqual(safe["predicted_label"], "Safe")
        self.assertLess(safe["risk_score"], 40.0)


class CeleryAndWebWorkflowTests(TestCase):
    def setUp(self):
        self.client = Client()

    def test_raw_eml_parser(self):
        raw = (
            "From: IT Helpdesk <support@it-portal-update.tk>\n"
            "Reply-To: attacker@evil.ru\n"
            "Subject: VPN Password Expires Today\n\n"
            "Reset immediately at http://185.220.101.44/vpn-reset"
        )
        parsed = parse_raw_eml(raw)
        self.assertEqual(parsed["subject"], "VPN Password Expires Today")
        self.assertIn("support@it-portal-update.tk", parsed["sender"])
        self.assertIn("Reply-To=attacker@evil.ru", parsed["body"])

    def test_scan_task_quarantines_phishing_and_raises_alert(self):
        report = EmailReport.objects.create(
            sender="PayPal Security <service@paypal-resolution-center.top>",
            subject="Account Limited: Verify your billing details immediately",
            body="Verify your bank card and SSN within 12 hours: https://bit.ly/3xPayPalVerify",
            contains_attachment=False,
        )
        scan_email_task.delay(report.id)
        report.refresh_from_db()

        self.assertEqual(report.status, EmailReport.ScanStatus.COMPLETED)
        self.assertEqual(report.predicted_label, EmailReport.ThreatLabel.PHISHING)
        self.assertEqual(report.quarantine_status, EmailReport.QuarantineStatus.QUARANTINED)
        self.assertGreaterEqual(QuarantineAlert.objects.filter(email_report=report).count(), 1)

    def test_views_and_rest_api(self):
        resp = self.client.post(
            reverse("scanner:api_scan_email"),
            data=json.dumps(
                {
                    "sender": "Okta SSO Support <noreply@okta-auth-verify.com>",
                    "subject": "New MFA device registered - Was this you?",
                    "body": "Revoke device immediately at http://okta-auth-verify.com/revoke-mfa",
                    "contains_attachment": False,
                }
            ),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 201)
        data = resp.json()
        self.assertEqual(data["predicted_label"], "Phishing")
        report_id = data["id"]

        for url_name, kwargs in [
            ("scanner:dashboard", {}),
            ("scanner:submit_email", {}),
            ("scanner:email_detail", {"pk": report_id}),
            ("scanner:quarantine_center", {}),
            ("scanner:model_lab", {}),
            ("scanner:api_metrics", {}),
        ]:
            page_resp = self.client.get(reverse(url_name, kwargs=kwargs))
            self.assertEqual(page_resp.status_code, 200)

        # Analyst releases email from quarantine
        rel_resp = self.client.post(
            reverse("scanner:email_action", kwargs={"pk": report_id}),
            data={"action": "release", "analyst_notes": "Verified test payload"},
        )
        self.assertEqual(rel_resp.status_code, 302)
        report = EmailReport.objects.get(pk=report_id)
        self.assertEqual(report.quarantine_status, EmailReport.QuarantineStatus.RELEASED)
