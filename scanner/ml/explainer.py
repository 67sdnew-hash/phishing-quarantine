"""Explainable NLP engine: highlights exact words, n-grams, URLs, and spoof cues."""

from __future__ import annotations

import re
from typing import Any

from .features import URL_REGEX, combine_email_text


def _find_non_overlapping_spans(
    text: str,
    candidates: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Build ordered text segments with highest-priority non-overlapping highlights."""
    if not text:
        return []

    raw_matches: list[tuple[int, int, int, dict[str, Any]]] = []
    for cand in candidates:
        pattern = cand["pattern"]
        priority = cand["priority"]
        for m in pattern.finditer(text):
            if m.start() < m.end():
                raw_matches.append((m.start(), m.end(), priority, cand))

    # Sort by priority desc, then span length desc, then start asc
    raw_matches.sort(key=lambda x: (-x[2], -(x[1] - x[0]), x[0]))

    chosen: list[tuple[int, int, dict[str, Any]]] = []
    for start, end, _prio, cand in raw_matches:
        overlaps = any(not (end <= cs or start >= ce) for cs, ce, _ in chosen)
        if not overlaps:
            chosen.append((start, end, cand))

    chosen.sort(key=lambda x: x[0])

    segments: list[dict[str, Any]] = []
    cursor = 0
    for start, end, cand in chosen:
        if start > cursor:
            segments.append({"text": text[cursor:start], "highlight": False})
        segments.append(
            {
                "text": text[start:end],
                "highlight": True,
                "category": cand["category"],
                "score": cand["score"],
                "reason": cand["reason"],
            }
        )
        cursor = end

    if cursor < len(text):
        segments.append({"text": text[cursor:], "highlight": False})

    return segments


def build_explainability(
    sender: str,
    subject: str,
    body: str,
    contains_attachment: bool,
    extracted_features: dict[str, Any],
    tfidf_vectorizer: Any,
    linear_svc: Any,
    class_labels: list[str],
    predicted_label: str,
) -> dict[str, Any]:
    """Compute LinearSVC white-box token weights and highlighted text spans."""
    sample_dict = {
        "sender": sender,
        "subject": subject,
        "body": body,
        "contains_attachment": contains_attachment,
    }
    combined_text = combine_email_text(sample_dict)
    tfidf_vec = tfidf_vectorizer.transform([combined_text])
    feature_names = tfidf_vectorizer.get_feature_names_out()

    # Determine target class index for contribution scoring (Phishing + predicted class)
    phishing_idx = class_labels.index("Phishing") if "Phishing" in class_labels else 0
    target_idx = class_labels.index(predicted_label) if predicted_label in class_labels else phishing_idx

    svc_coefs = linear_svc.coef_
    nonzero_indices = tfidf_vec.nonzero()[1]

    # Exclude artificial prefix tokens used internally
    ignored_tokens = {"from_domain", "sender", "subject", "body"}

    phishing_contributions: list[dict[str, Any]] = []
    target_contributions: list[dict[str, Any]] = []
    safe_contributions: list[dict[str, Any]] = []

    safe_idx = class_labels.index("Safe") if "Safe" in class_labels else None

    for idx in nonzero_indices:
        term = str(feature_names[idx])
        if term in ignored_tokens or len(term) < 2:
            continue
        val = float(tfidf_vec[0, idx])
        phish_w = round(val * float(svc_coefs[phishing_idx, idx]), 4)
        target_w = round(val * float(svc_coefs[target_idx, idx]), 4)

        if phish_w > 0.02:
            phishing_contributions.append({"term": term, "weight": phish_w})
        if target_w > 0.02:
            target_contributions.append({"term": term, "weight": target_w})
        if safe_idx is not None:
            safe_w = round(val * float(svc_coefs[safe_idx, idx]), 4)
            if safe_w > 0.02:
                safe_contributions.append({"term": term, "weight": safe_w})

    phishing_contributions.sort(key=lambda x: -x["weight"])
    target_contributions.sort(key=lambda x: -x["weight"])
    safe_contributions.sort(key=lambda x: -x["weight"])

    top_phishing_tokens = phishing_contributions[:12]
    top_target_tokens = target_contributions[:12]
    top_safe_tokens = safe_contributions[:8]

    # Build highlight candidates for subject, body, and sender
    candidates: list[dict[str, Any]] = []

    # 1. Malicious / Extracted URLs (highest priority)
    for url_info in extracted_features.get("urls", []):
        u = url_info["url"]
        flags_str = ", ".join(url_info["flags"]) if url_info["flags"] else "External URL"
        candidates.append(
            {
                "pattern": re.compile(re.escape(u), re.IGNORECASE),
                "priority": 100 if url_info["is_malicious"] else 60,
                "category": "malicious-url" if url_info["is_malicious"] else "external-url",
                "score": url_info["risk_score"],
                "reason": f"URL Risk {url_info['risk_score']}/100: {flags_str}",
            }
        )

    # 2. Urgency & Credential / Social engineering phrases
    for phrase in extracted_features.get("urgency_keywords", []):
        candidates.append(
            {
                "pattern": re.compile(r"\b" + re.escape(phrase) + r"\b", re.IGNORECASE),
                "priority": 85,
                "category": "urgency-keyword",
                "score": 80,
                "reason": f"Urgency / Pressure trigger: '{phrase}'",
            }
        )

    for phrase in extracted_features.get("credential_keywords", []):
        candidates.append(
            {
                "pattern": re.compile(r"\b" + re.escape(phrase) + r"\b", re.IGNORECASE),
                "priority": 88,
                "category": "credential-bait",
                "score": 85,
                "reason": f"Credential / Financial bait: '{phrase}'",
            }
        )

    if predicted_label == "Spam":
        for phrase in extracted_features.get("spam_keywords", []):
            candidates.append(
                {
                    "pattern": re.compile(re.escape(phrase), re.IGNORECASE),
                    "priority": 75,
                    "category": "spam-signal",
                    "score": 65,
                    "reason": f"Promotional / Spam indicator: '{phrase}'",
                }
            )

    # 3. Top LinearSVC TF-IDF tokens
    active_tokens = top_phishing_tokens if predicted_label == "Phishing" else top_target_tokens
    nlp_category = "phishing-ngram" if predicted_label == "Phishing" else (
        "spam-signal" if predicted_label == "Spam" else "safe-ngram"
    )
    for tok in active_tokens:
        term = tok["term"]
        if len(term) < 3 or URL_REGEX.match(term):
            continue
        candidates.append(
            {
                "pattern": re.compile(r"\b" + re.escape(term) + r"\b", re.IGNORECASE),
                "priority": 70,
                "category": nlp_category,
                "score": round(tok["weight"] * 100, 1),
                "reason": f"LinearSVC {predicted_label} TF-IDF weight: +{tok['weight']:.3f}",
            }
        )

    # Sender-specific spoof highlight
    sender_candidates: list[dict[str, Any]] = []
    mismatch = extracted_features.get("domain_mismatch", {})
    sender_info = extracted_features.get("sender_info", {})
    if mismatch.get("detected") and sender_info.get("domain"):
        sender_candidates.append(
            {
                "pattern": re.compile(re.escape(sender_info["domain"]), re.IGNORECASE),
                "priority": 95,
                "category": "spoof-indicator",
                "score": 95,
                "reason": "; ".join(mismatch.get("reasons", ["Sender domain mismatch"])),
            }
        )

    sender_segments = _find_non_overlapping_spans(sender, sender_candidates)
    subject_segments = _find_non_overlapping_spans(subject, candidates)
    body_segments = _find_non_overlapping_spans(body, candidates)

    # Human-readable rule summary
    summary_reasons: list[str] = []
    if mismatch.get("detected"):
        summary_reasons.extend(mismatch.get("reasons", []))
    mal_urls = [u for u in extracted_features.get("urls", []) if u["is_malicious"]]
    if mal_urls:
        summary_reasons.append(
            f"Detected {len(mal_urls)} high-risk URL(s): {', '.join(u['host'] or u['url'] for u in mal_urls[:3])}"
        )
    if extracted_features.get("credential_keywords"):
        summary_reasons.append(
            f"Credential/Financial triggers: {', '.join(extracted_features['credential_keywords'][:4])}"
        )
    if extracted_features.get("urgency_keywords"):
        summary_reasons.append(
            f"Urgency/Coercion keywords: {', '.join(extracted_features['urgency_keywords'][:4])}"
        )
    if extracted_features.get("contains_attachment") and predicted_label == "Phishing":
        summary_reasons.append("Contains attachment paired with phishing indicators")
    if predicted_label == "Spam" and extracted_features.get("spam_keywords"):
        summary_reasons.append(
            f"Promotional spam markers: {', '.join(extracted_features['spam_keywords'][:4])}"
        )
    if not summary_reasons and top_safe_tokens and predicted_label == "Safe":
        summary_reasons.append(
            f"Legitimate enterprise/notification patterns ({', '.join(t['term'] for t in top_safe_tokens[:4])})"
        )

    return {
        "sender_segments": sender_segments,
        "subject_segments": subject_segments,
        "body_segments": body_segments,
        "top_phishing_tokens": top_phishing_tokens,
        "top_target_tokens": top_target_tokens,
        "top_safe_tokens": top_safe_tokens,
        "summary_reasons": summary_reasons,
    }
