"""Domain, URL, sender-mismatch, and urgency feature extraction for PhishGuard."""

from __future__ import annotations

import ipaddress
import re
from email.utils import parseaddr
from typing import Any
from urllib.parse import urlparse

import numpy as np
from sklearn.base import BaseEstimator, TransformerMixin

URL_REGEX = re.compile(
    r"(https?://[^\s<>\"'\)\]]+|www\.[^\s<>\"'\)\]]+)",
    re.IGNORECASE,
)

SUSPICIOUS_TLDS = {
    "xyz", "tk", "top", "click", "ru", "info", "ml", "ga", "cf", "gq",
    "work", "loan", "pw", "cc", "su", "buzz", "surf", "monster",
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "cutt.ly", "rb.gy", "shorturl.at", "tiny.cc",
}

FREE_WEBMAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "aol.com",
    "protonmail.com", "mail.com", "gmx.com", "yandex.com",
}

CREDENTIAL_PATH_KEYWORDS = (
    "login", "auth", "verify", "reset", "billing", "password", "mfa",
    "sso", "wallet", "kyc", "token", "unlock", "confirm", "checkpoint",
    "payroll", "cancel", "refund", "claim", "sign", "dns", "console",
    "quarantine", "release", "card", "download", "update",
)

BRAND_OFFICIAL_DOMAINS: dict[str, tuple[str, ...]] = {
    "microsoft": ("microsoft.com", "office.com", "office365.com", "live.com", "microsoftonline.com"),
    "office 365": ("microsoft.com", "office.com", "office365.com"),
    "o365": ("microsoft.com", "office.com", "office365.com"),
    "teams": ("microsoft.com", "teams.microsoft.com"),
    "google": ("google.com", "gmail.com"),
    "paypal": ("paypal.com",),
    "docusign": ("docusign.com", "docusign.net"),
    "okta": ("okta.com",),
    "apple": ("apple.com", "icloud.com"),
    "chase": ("chase.com", "jpmorgan.com"),
    "bank of america": ("bankofamerica.com",),
    "wells fargo": ("wellsfargo.com",),
    "american express": ("americanexpress.com", "amex.com"),
    "amex": ("americanexpress.com", "amex.com"),
    "amazon": ("amazon.com", "aws.amazon.com"),
    "aws": ("amazon.com", "aws.amazon.com"),
    "github": ("github.com",),
    "gitlab": ("gitlab.com", "mg.gitlab.com"),
    "slack": ("slack.com",),
    "zoom": ("zoom.us", "zoom.com"),
    "dhl": ("dhl.com",),
    "fedex": ("fedex.com",),
    "usps": ("usps.com",),
    "dropbox": ("dropbox.com",),
    "adobe": ("adobe.com",),
    "stripe": ("stripe.com",),
    "netflix": ("netflix.com",),
    "servicenow": ("servicenow.com",),
    "workday": ("workday.com", "myworkday.com"),
    "cisco": ("cisco.com",),
    "salesforce": ("salesforce.com",),
    "atlassian": ("atlassian.com", "atlassian.net"),
    "jira": ("atlassian.com", "atlassian.net"),
    "confluence": ("atlassian.com", "atlassian.net"),
    "quickbooks": ("intuit.com", "quickbooks.intuit.com"),
    "intuit": ("intuit.com",),
    "cloudflare": ("cloudflare.com", "notify.cloudflare.com"),
    "adp": ("adp.com",),
    "binance": ("binance.com",),
    "norton": ("norton.com", "nortonlifelock.com"),
    "geek squad": ("bestbuy.com", "geeksquad.com"),
    "twilio": ("twilio.com",),
    "linkedin": ("linkedin.com",),
    "irs": ("irs.gov",),
}

INTERNAL_CORPORATE_DOMAINS = ("acme-corp.com", "acme-corp.atlassian.net")

INTERNAL_ROLE_KEYWORDS = (
    "ceo", "cfo", "hr ", "hr-", "payroll", "it helpdesk", "helpdesk",
    "it security", "internal audit", "tax department", "admin",
)

TYPOSQUAT_PATTERNS = (
    (re.compile(r"micr0soft|mircosoft|micros0ft", re.I), "Microsoft"),
    (re.compile(r"g00gle|go0gle|goog1e", re.I), "Google"),
    (re.compile(r"app1e|appl3", re.I), "Apple"),
    (re.compile(r"sa1esforce|salesf0rce", re.I), "Salesforce"),
    (re.compile(r"netf1ix|netfiix", re.I), "Netflix"),
    (re.compile(r"wellsfarg0|we11sfargo", re.I), "Wells Fargo"),
    (re.compile(r"linkedln|1inkedin", re.I), "LinkedIn"),
    (re.compile(r"paypa1|p4ypal", re.I), "PayPal"),
    (re.compile(r"amaz0n|arnazon", re.I), "Amazon"),
)

URGENCY_PHRASES = [
    "urgent",
    "immediately",
    "asap",
    "within 24 hours",
    "within 12 hours",
    "within 48 hours",
    "expires today",
    "expires in",
    "expiring in",
    "expiring today",
    "deadline today",
    "action required",
    "action needed",
    "will be suspended",
    "has been locked",
    "will be terminated",
    "account lockout",
    "permanently disabled",
    "disciplinary suspension",
    "final notice",
    "respond asap",
    "right now",
    "avoid contract cancellation",
    "avoid account cancellation",
    "avoid late penalties",
    "keep this confidential",
    "temporarily held",
    "paused",
    "frozen",
    "revoked",
]

CREDENTIAL_FINANCIAL_PHRASES = [
    "verify your identity",
    "confirm your credentials",
    "verify your billing",
    "verify your account",
    "re-authenticate",
    "re-enter your",
    "log in using your work credentials",
    "username and password",
    "corporate password",
    "network password",
    "banking pin",
    "bank card",
    "card pin",
    "cvv",
    "routing number",
    "social security",
    "ssn",
    "w-2",
    "wire transfer",
    "gift cards",
    "enable macros",
    "rotate keys",
    "api key compromised",
    "personal access token",
    "crypto withdrawal",
    "direct deposit",
    "unpaid customs fee",
    "redelivery fee",
]

SPAM_PROMO_PHRASES = [
    "unsubscribe",
    "% off",
    "off everything",
    "flash sale",
    "clearance",
    "free trial",
    "welcome bonus",
    "free spins",
    "grand prize winner",
    "congratulations",
    "order now",
    "limited time",
    "limited seats",
    "risk-free",
    "guaranteed",
    "buy 2 get",
    "no prescription needed",
    "click here to shop",
    "100% free",
    "make $",
    "earn $",
]


def parse_sender_identity(sender: str) -> dict[str, str]:
    """Parse display name, email address, and domain from a sender string."""
    display_name, email_addr = parseaddr(sender or "")
    email_addr = email_addr.strip().lower()
    if not email_addr and "@" in (sender or ""):
        match = re.search(r"[\w.+-]+@[\w.-]+\.[a-zA-Z]{2,}", sender)
        if match:
            email_addr = match.group(0).lower()
    domain = email_addr.split("@", 1)[1] if "@" in email_addr else ""
    return {
        "raw": sender or "",
        "display_name": display_name.strip().strip('"'),
        "email": email_addr,
        "domain": domain,
    }


def _is_ip_address(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _domain_matches_any(domain: str, allowed_domains: tuple[str, ...]) -> bool:
    return any(domain == d or domain.endswith(f".{d}") for d in allowed_domains)


def analyze_url(raw_url: str) -> dict[str, Any]:
    """Extract risk indicators for a single URL found in an email."""
    clean_url = raw_url.rstrip(".,;:!?)\"'")
    normalized = clean_url if clean_url.lower().startswith(("http://", "https://")) else f"http://{clean_url}"
    parsed = urlparse(normalized)
    host = (parsed.hostname or "").lower()
    path_and_query = f"{parsed.path or ''}?{parsed.query or ''}".lower()
    tld = host.rsplit(".", 1)[-1] if "." in host else ""

    flags: list[str] = []
    risk = 0

    is_ip = _is_ip_address(host)
    if is_ip:
        flags.append("Direct IP Host")
        risk += 45

    is_shortener = host in URL_SHORTENERS
    if is_shortener:
        flags.append("URL Shortener")
        risk += 30

    has_suspicious_tld = tld in SUSPICIOUS_TLDS
    if has_suspicious_tld:
        flags.append(f"High-Risk TLD (.{tld})")
        risk += 32

    is_http = normalized.lower().startswith("http://")
    if is_http:
        flags.append("Unencrypted HTTP")
        risk += 12

    typosquat_brand = None
    for pat, brand in TYPOSQUAT_PATTERNS:
        if pat.search(host):
            typosquat_brand = brand
            flags.append(f"Lookalike / Typosquatting ({brand})")
            risk += 45
            break

    if not typosquat_brand:
        for brand, official in BRAND_OFFICIAL_DOMAINS.items():
            brand_slug = brand.replace(" ", "")
            if len(brand_slug) >= 4 and brand_slug in host and not _domain_matches_any(host, official):
                flags.append(f"Brand Spoofing in Domain ({brand.title()})")
                risk += 38
                break

    cred_hits = [kw for kw in CREDENTIAL_PATH_KEYWORDS if kw in path_and_query]
    if cred_hits:
        flags.append(f"Credential/Action Path (/{cred_hits[0]})")
        risk += 18

    if host.count("-") >= 2:
        flags.append("Multi-Hyphen Phishing Pattern")
        risk += 12

    risk = min(100, risk)
    return {
        "url": clean_url,
        "host": host,
        "tld": tld,
        "is_ip_url": is_ip,
        "is_shortener": is_shortener,
        "has_suspicious_tld": has_suspicious_tld,
        "is_insecure_http": is_http,
        "typosquat_brand": typosquat_brand,
        "flags": flags,
        "risk_score": risk,
        "is_malicious": risk >= 35,
    }


def detect_domain_mismatch(sender_info: dict[str, str], subject: str, body: str) -> dict[str, Any]:
    """Detect mismatches between claimed sender identity/brand and actual email domain."""
    display = sender_info["display_name"].lower()
    domain = sender_info["domain"].lower()
    tld = domain.rsplit(".", 1)[-1] if "." in domain else ""
    reasons: list[str] = []
    impersonated_brand = ""

    if not domain:
        return {"detected": False, "reasons": [], "impersonated_brand": "", "suspicious_sender_tld": False}

    for pat, brand in TYPOSQUAT_PATTERNS:
        if pat.search(domain):
            reasons.append(f"Typosquatted domain mimicking {brand} ({domain})")
            impersonated_brand = brand
            break

    for brand, official_domains in BRAND_OFFICIAL_DOMAINS.items():
        if brand in display and not _domain_matches_any(domain, official_domains):
            reasons.append(
                f"Display name claims '{sender_info['display_name']}' but domain '{domain}' is not official ({', '.join(official_domains[:2])})"
            )
            impersonated_brand = impersonated_brand or brand.title()
            break

    if any(role in display for role in INTERNAL_ROLE_KEYWORDS) and not _domain_matches_any(domain, INTERNAL_CORPORATE_DOMAINS):
        if domain in FREE_WEBMAIL_DOMAINS:
            reasons.append(f"Executive/Internal role '{sender_info['display_name']}' sent from free webmail ({domain})")
        else:
            reasons.append(f"Internal role '{sender_info['display_name']}' originates from external domain ({domain})")

    suspicious_sender_tld = tld in SUSPICIOUS_TLDS
    if suspicious_sender_tld and not reasons:
        reasons.append(f"Sender uses high-risk TLD (.{tld}) on domain {domain}")

    # Check if body claims corporate internal authority while sender is external free mail
    if domain in FREE_WEBMAIL_DOMAINS and ("wire transfer" in body.lower() or "gift cards" in body.lower()):
        if not any("free webmail" in r for r in reasons):
            reasons.append(f"Financial request sent from consumer webmail ({domain})")

    return {
        "detected": len(reasons) > 0,
        "reasons": reasons,
        "impersonated_brand": impersonated_brand,
        "suspicious_sender_tld": suspicious_sender_tld,
        "is_free_webmail": domain in FREE_WEBMAIL_DOMAINS,
    }


def extract_email_features(
    sender: str,
    subject: str,
    body: str,
    contains_attachment: bool = False,
) -> dict[str, Any]:
    """Extract comprehensive domain, URL, urgency, credential, and spam signals."""
    sender_info = parse_sender_identity(sender)
    combined_lower = f"{subject}\n{body}".lower()

    raw_urls = URL_REGEX.findall(f"{subject} {body}")
    seen_urls: set[str] = set()
    urls: list[dict[str, Any]] = []
    for raw_url in raw_urls:
        cleaned = raw_url.rstrip(".,;:!?)\"'")
        if cleaned not in seen_urls:
            seen_urls.add(cleaned)
            urls.append(analyze_url(cleaned))

    domain_mismatch = detect_domain_mismatch(sender_info, subject, body)

    urgency_hits = [p for p in URGENCY_PHRASES if p in combined_lower]
    credential_hits = [p for p in CREDENTIAL_FINANCIAL_PHRASES if p in combined_lower]
    spam_hits = [p for p in SPAM_PROMO_PHRASES if p in combined_lower]

    uppercase_words = re.findall(r"\b[A-Z]{3,}\b", f"{subject} {body}")
    exclamation_count = (subject + body).count("!")
    has_currency_bait = bool(re.search(r"(\$|€|£)\s?\d[\d,]*", f"{subject} {body}"))

    max_url_risk = max((u["risk_score"] for u in urls), default=0)
    malicious_url_count = sum(1 for u in urls if u["is_malicious"])

    return {
        "sender_info": sender_info,
        "domain_mismatch": domain_mismatch,
        "urls": urls,
        "url_count": len(urls),
        "malicious_url_count": malicious_url_count,
        "max_url_risk": max_url_risk,
        "urgency_keywords": urgency_hits,
        "credential_keywords": credential_hits,
        "spam_keywords": spam_hits,
        "contains_attachment": bool(contains_attachment),
        "uppercase_token_count": len(uppercase_words),
        "exclamation_count": exclamation_count,
        "has_currency_bait": has_currency_bait,
    }


def features_to_vector(feat: dict[str, Any]) -> list[float]:
    """Convert extracted email signals into a numeric feature vector for scikit-learn."""
    urls = feat["urls"]
    mismatch = feat["domain_mismatch"]
    return [
        1.0 if mismatch["detected"] else 0.0,
        1.0 if mismatch["suspicious_sender_tld"] else 0.0,
        1.0 if mismatch["is_free_webmail"] else 0.0,
        float(min(len(urls), 5)),
        float(min(feat["malicious_url_count"], 5)),
        float(feat["max_url_risk"]) / 100.0,
        1.0 if any(u["is_ip_url"] for u in urls) else 0.0,
        1.0 if any(u["is_shortener"] for u in urls) else 0.0,
        1.0 if any(u["has_suspicious_tld"] for u in urls) else 0.0,
        1.0 if any(u["is_insecure_http"] for u in urls) else 0.0,
        float(min(len(feat["urgency_keywords"]), 6)) / 6.0,
        float(min(len(feat["credential_keywords"]), 6)) / 6.0,
        float(min(len(feat["spam_keywords"]), 6)) / 6.0,
        1.0 if feat["contains_attachment"] else 0.0,
        float(min(feat["exclamation_count"], 6)) / 6.0,
    ]


STRUCTURED_FEATURE_NAMES = [
    "sender_domain_mismatch",
    "sender_suspicious_tld",
    "sender_free_webmail",
    "url_count",
    "malicious_url_count",
    "max_url_risk",
    "has_ip_url",
    "has_url_shortener",
    "has_suspicious_url_tld",
    "has_insecure_http_url",
    "urgency_keyword_density",
    "credential_keyword_density",
    "spam_keyword_density",
    "contains_attachment",
    "exclamation_density",
]


class EmailSignalTransformer(BaseEstimator, TransformerMixin):
    """Scikit-learn transformer computing numeric phishing/spam domain & URL signals."""

    def fit(self, X: Any, y: Any = None) -> "EmailSignalTransformer":
        return self

    def transform(self, X: Any) -> np.ndarray:
        rows = []
        for item in X:
            feat = extract_email_features(
                sender=item.get("sender", ""),
                subject=item.get("subject", ""),
                body=item.get("body", ""),
                contains_attachment=bool(item.get("contains_attachment", False)),
            )
            rows.append(features_to_vector(feat))
        return np.asarray(rows, dtype=np.float64)


def combine_email_text(item: dict[str, Any]) -> str:
    """Create normalized text representation for TF-IDF vectorization."""
    sender = item.get("sender", "")
    subject = item.get("subject", "")
    body = item.get("body", "")
    sender_info = parse_sender_identity(sender)
    domain_tokens = sender_info["domain"].replace(".", " ").replace("-", " ")
    return f"from_domain {domain_tokens} sender {sender} subject {subject} body {body}"


class EmailTextExtractor(BaseEstimator, TransformerMixin):
    """Scikit-learn transformer extracting combined text strings from email dicts."""

    def fit(self, X: Any, y: Any = None) -> "EmailTextExtractor":
        return self

    def transform(self, X: Any) -> list[str]:
        return [combine_email_text(item) for item in X]
