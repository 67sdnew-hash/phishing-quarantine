"""Email parsing utilities (.eml / raw forwarded headers) and demo threat presets."""

from __future__ import annotations

import re
from email import policy
from email.parser import Parser
from html import unescape
from typing import Any


def _strip_html(html_text: str) -> str:
    text = re.sub(r"<(script|style)[^>]*>.*?</\1>", " ", html_text, flags=re.I | re.S)
    text = re.sub(r"<br\s*/?>", "\n", text, flags=re.I)
    text = re.sub(r"<[^>]+>", " ", text)
    text = unescape(text)
    return re.sub(r"[ \t]+", " ", text).strip()


def parse_raw_eml(raw_text: str) -> dict[str, Any]:
    """Parse raw RFC-822 email text into sender, subject, body, and attachment metadata."""
    msg = Parser(policy=policy.default).parsestr(raw_text)
    sender = str(msg.get("From", "") or "").strip()
    reply_to = str(msg.get("Reply-To", "") or "").strip()
    subject = str(msg.get("Subject", "") or "").strip()

    body_parts: list[str] = []
    attachment_names: list[str] = []

    if msg.is_multipart():
        for part in msg.walk():
            disposition = str(part.get_content_disposition() or "").lower()
            filename = part.get_filename()
            if filename:
                attachment_names.append(filename)
            if disposition == "attachment":
                continue
            ctype = part.get_content_type()
            try:
                payload = part.get_content()
            except Exception:
                payload_bytes = part.get_payload(decode=True) or b""
                payload = payload_bytes.decode("utf-8", errors="replace")
            if ctype == "text/plain" and isinstance(payload, str):
                body_parts.append(payload)
            elif ctype == "text/html" and isinstance(payload, str) and not body_parts:
                body_parts.append(_strip_html(payload))
    else:
        try:
            payload = msg.get_content()
        except Exception:
            payload_bytes = msg.get_payload(decode=True) or b""
            payload = payload_bytes.decode("utf-8", errors="replace")
        if msg.get_content_type() == "text/html" and isinstance(payload, str):
            body_parts.append(_strip_html(payload))
        elif isinstance(payload, str):
            body_parts.append(payload)

    body = "\n".join(p.strip() for p in body_parts if p and p.strip()).strip()
    if reply_to and reply_to.lower() != sender.lower():
        body = f"[Header Notice: Reply-To={reply_to}]\n{body}"

    return {
        "sender": sender or "unknown@external-sender.invalid",
        "subject": subject or "(No Subject)",
        "body": body or raw_text.strip(),
        "contains_attachment": len(attachment_names) > 0,
        "attachment_names": attachment_names,
    }


SAMPLE_PRESETS: list[dict[str, Any]] = [
    {
        "id": "microsoft-phish",
        "name": "Microsoft 365 Lookalike Phish",
        "badge": "Phishing",
        "sender": "Microsoft Account Team <security@micr0soft-verify-login.xyz>",
        "reported_by": "priya.nair@acme-corp.com",
        "subject": "URGENT: Unusual sign-in activity detected on your Microsoft 365 account",
        "body": (
            "Dear Employee, We detected an unauthorized sign-in attempt from Moscow, Russia. "
            "Your corporate email account will be suspended within 24 hours unless you verify your identity immediately. "
            "Click here to confirm your credentials: http://micr0soft-verify-login.xyz/auth/reset"
        ),
        "contains_attachment": False,
        "attachment_names": [],
    },
    {
        "id": "bec-wire",
        "name": "Executive BEC Wire Fraud",
        "badge": "Phishing",
        "sender": "CEO Sarah Jenkins <s.jenkins.corp@gmail.com>",
        "reported_by": "finance.ap@acme-corp.com",
        "subject": "Urgent confidential wire transfer needed before 3 PM",
        "body": (
            "Hi, I am currently stuck in a board meeting and cannot take calls. "
            "I need you to process an urgent vendor wire transfer of $18,500 immediately. "
            "Reply to this email for the routing details and keep this confidential."
        ),
        "contains_attachment": False,
        "attachment_names": [],
    },
    {
        "id": "vpn-ip-phish",
        "name": "Direct-IP VPN Credential Harvest",
        "badge": "Phishing",
        "sender": "IT Helpdesk <support@it-portal-update.tk>",
        "reported_by": "alex.rivera@acme-corp.com",
        "subject": "Action Required: Your corporate VPN password expires today",
        "body": (
            "Hello, Your enterprise VPN and SSO password expires in 2 hours. "
            "Failure to update your password will result in immediate account lockout. "
            "Please log in now at http://185.220.101.44/vpn-reset to keep your access."
        ),
        "contains_attachment": False,
        "attachment_names": [],
    },
    {
        "id": "promo-spam",
        "name": "Aggressive Crypto / Promo Spam",
        "badge": "Spam",
        "sender": "Crypto Wealth Daily <newsletter@crypto-moon-signals.io>",
        "reported_by": "marketing@acme-corp.com",
        "subject": "Make $5,000 a week trading Bitcoin automatically!",
        "body": (
            "Join 40,000 investors using our AI trading bot to double their portfolio every month. "
            "Zero experience required. Claim your free VIP spot today! Limited seats left! Unsubscribe anytime."
        ),
        "contains_attachment": False,
        "attachment_names": [],
    },
    {
        "id": "safe-github",
        "name": "Legitimate GitHub CI Notification",
        "badge": "Safe",
        "sender": "GitHub <notifications@github.com>",
        "reported_by": "dave.chen@acme-corp.com",
        "subject": "[acme-corp/backend-api] Pull request #418 merged by dave-chen",
        "body": (
            "Dave Chen merged pull request #418 (Fix pagination offset in /api/orders) into main. "
            "All 142 unit tests passed in CI."
        ),
        "contains_attachment": False,
        "attachment_names": [],
    },
]
