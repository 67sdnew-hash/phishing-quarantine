"""Scikit-learn TF-IDF + LinearSVC training, evaluation, and inference pipeline."""

from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
from django.conf import settings
from sklearn.calibration import CalibratedClassifierCV
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.model_selection import StratifiedKFold, cross_val_predict
from sklearn.pipeline import FeatureUnion, Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.svm import LinearSVC

from .explainer import build_explainability
from .features import (
    STRUCTURED_FEATURE_NAMES,
    EmailSignalTransformer,
    EmailTextExtractor,
    extract_email_features,
)

_MODEL_LOCK = threading.Lock()
_CACHED_BUNDLE: dict[str, Any] | None = None


def _artifacts_dir() -> Path:
    path = Path(settings.ML_ARTIFACTS_DIR)
    path.mkdir(parents=True, exist_ok=True)
    return path


def _model_path() -> Path:
    return _artifacts_dir() / "phishguard_model.joblib"


def _metrics_path() -> Path:
    return _artifacts_dir() / "metrics.json"


def _build_feature_union() -> FeatureUnion:
    return FeatureUnion(
        transformer_list=[
            (
                "tfidf_text",
                Pipeline(
                    steps=[
                        ("extract", EmailTextExtractor()),
                        (
                            "tfidf",
                            TfidfVectorizer(
                                ngram_range=(1, 2),
                                min_df=1,
                                max_features=6000,
                                sublinear_tf=True,
                                strip_accents="unicode",
                            ),
                        ),
                    ]
                ),
            ),
            (
                "domain_url_signals",
                Pipeline(
                    steps=[
                        ("signals", EmailSignalTransformer()),
                        ("scale", StandardScaler()),
                    ]
                ),
            ),
        ],
        transformer_weights={"tfidf_text": 1.0, "domain_url_signals": 0.45},
    )


def train_and_save_model(csv_path: str | Path | None = None) -> dict[str, Any]:
    """Train TF-IDF + Engineered Signal LinearSVC model on emails.csv and persist artifacts."""
    global _CACHED_BUNDLE

    dataset_path = Path(csv_path) if csv_path else Path(settings.DATA_CSV_PATH)
    df = pd.read_csv(dataset_path)
    df["sender"] = df["sender"].fillna("")
    df["subject"] = df["subject"].fillna("")
    df["body"] = df["body"].fillna("")
    df["contains_attachment"] = df["contains_attachment"].fillna(False).astype(bool)
    df["label"] = df["label"].astype(str).str.strip()

    records = df[["sender", "subject", "body", "contains_attachment"]].to_dict(orient="records")
    y = df["label"].to_numpy()

    # Cross-validation evaluation using identical FeatureUnion + Calibrated LinearSVC
    cv_pipeline = Pipeline(
        steps=[
            ("features", _build_feature_union()),
            (
                "clf",
                CalibratedClassifierCV(
                    estimator=LinearSVC(C=1.2, class_weight="balanced", random_state=42),
                    cv=3,
                    method="sigmoid",
                ),
            ),
        ]
    )
    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    cv_preds = cross_val_predict(cv_pipeline, records, y, cv=skf)

    classes = sorted(list(np.unique(y)))
    cv_accuracy = round(float(accuracy_score(y, cv_preds)) * 100, 2)
    cls_report = classification_report(y, cv_preds, labels=classes, output_dict=True, zero_division=0)
    cm = confusion_matrix(y, cv_preds, labels=classes).tolist()

    # Fit final feature union + raw LinearSVC (for exact white-box coefficients) + CalibratedClassifierCV
    feature_union = _build_feature_union()
    X_full = feature_union.fit_transform(records)

    raw_svc = LinearSVC(C=1.2, class_weight="balanced", random_state=42)
    raw_svc.fit(X_full, y)

    calibrated_svc = CalibratedClassifierCV(
        estimator=LinearSVC(C=1.2, class_weight="balanced", random_state=42),
        cv=5,
        method="sigmoid",
    )
    calibrated_svc.fit(X_full, y)

    tfidf_vectorizer = feature_union.named_transformers["tfidf_text"].named_steps["tfidf"]
    tfidf_vocab_size = len(tfidf_vectorizer.get_feature_names_out())

    # Global top phishing/spam/safe indicators from raw_svc coefficients
    tfidf_names = tfidf_vectorizer.get_feature_names_out()
    svc_classes = list(raw_svc.classes_)
    global_top_tokens: dict[str, list[dict[str, Any]]] = {}
    ignored = {"from_domain", "sender", "subject", "body"}
    for c_idx, label in enumerate(svc_classes):
        coefs = raw_svc.coef_[c_idx, :tfidf_vocab_size]
        top_idx = np.argsort(coefs)[::-1]
        tokens = []
        for idx in top_idx:
            term = str(tfidf_names[idx])
            if term in ignored or len(term) < 3:
                continue
            tokens.append({"term": term, "weight": round(float(coefs[idx]), 4)})
            if len(tokens) >= 15:
                break
        global_top_tokens[label] = tokens

    # Structured signal weights for Phishing class
    phish_c_idx = svc_classes.index("Phishing") if "Phishing" in svc_classes else 0
    struct_coefs = raw_svc.coef_[phish_c_idx, tfidf_vocab_size:]
    structured_weights = [
        {"feature": name, "weight": round(float(w), 4)}
        for name, w in sorted(
            zip(STRUCTURED_FEATURE_NAMES, struct_coefs),
            key=lambda pair: -abs(pair[1]),
        )
    ]

    metrics = {
        "model_name": "TF-IDF (1-2 ngrams) + Domain/URL Signal Fusion -> LinearSVC",
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "dataset_rows": int(len(df)),
        "label_distribution": df["label"].value_counts().to_dict(),
        "classes": classes,
        "cv_folds": 5,
        "cv_accuracy": cv_accuracy,
        "macro_f1": round(float(cls_report["macro avg"]["f1-score"]) * 100, 2),
        "weighted_f1": round(float(cls_report["weighted avg"]["f1-score"]) * 100, 2),
        "per_class": {
            lbl: {
                "precision": round(float(cls_report[lbl]["precision"]) * 100, 2),
                "recall": round(float(cls_report[lbl]["recall"]) * 100, 2),
                "f1": round(float(cls_report[lbl]["f1-score"]) * 100, 2),
                "support": int(cls_report[lbl]["support"]),
            }
            for lbl in classes
        },
        "confusion_matrix": cm,
        "tfidf_vocab_size": tfidf_vocab_size,
        "structured_feature_count": len(STRUCTURED_FEATURE_NAMES),
        "global_top_tokens": global_top_tokens,
        "structured_weights": structured_weights,
    }

    bundle = {
        "feature_union": feature_union,
        "raw_svc": raw_svc,
        "calibrated_svc": calibrated_svc,
        "classes": svc_classes,
    }

    joblib.dump(bundle, _model_path())
    _metrics_path().write_text(json.dumps(metrics, indent=2), encoding="utf-8")

    with _MODEL_LOCK:
        _CACHED_BUNDLE = bundle

    return metrics


def _load_bundle() -> dict[str, Any]:
    global _CACHED_BUNDLE
    with _MODEL_LOCK:
        if _CACHED_BUNDLE is not None:
            return _CACHED_BUNDLE
        if not _model_path().exists():
            train_and_save_model()
        else:
            _CACHED_BUNDLE = joblib.load(_model_path())
        assert _CACHED_BUNDLE is not None
        return _CACHED_BUNDLE


def get_model_metrics() -> dict[str, Any]:
    """Return persisted training metrics, training on demand if missing."""
    if not _metrics_path().exists() or not _model_path().exists():
        return train_and_save_model()
    return json.loads(_metrics_path().read_text(encoding="utf-8"))


def _compute_unified_risk_score(
    predicted_label: str,
    probs: dict[str, float],
    features: dict[str, Any],
) -> float:
    """Compute 0-100 risk score combining ML phishing probability and deterministic IOCs."""
    phish_prob = probs.get("Phishing", 0.0)
    spam_prob = probs.get("Spam", 0.0)

    base = phish_prob * 0.78 + spam_prob * 0.22
    ioc_boost = 0.0
    if features["domain_mismatch"]["detected"]:
        ioc_boost += 12.0
    if features["max_url_risk"] >= 35:
        ioc_boost += min(18.0, features["max_url_risk"] * 0.2)
    if features["credential_keywords"]:
        ioc_boost += min(10.0, len(features["credential_keywords"]) * 3.5)
    if features["urgency_keywords"]:
        ioc_boost += min(8.0, len(features["urgency_keywords"]) * 2.5)

    score = min(99.5, base + ioc_boost)
    if predicted_label == "Phishing":
        score = max(score, 68.0)
    elif predicted_label == "Safe":
        score = min(score, 34.0)
    return round(score, 1)


def predict_and_explain(
    sender: str,
    subject: str,
    body: str,
    contains_attachment: bool = False,
) -> dict[str, Any]:
    """Classify an email, extract URLs/domain/urgency signals, and generate NLP explanations."""
    bundle = _load_bundle()
    feature_union: FeatureUnion = bundle["feature_union"]
    raw_svc: LinearSVC = bundle["raw_svc"]
    calibrated_svc: CalibratedClassifierCV = bundle["calibrated_svc"]
    classes: list[str] = bundle["classes"]

    sample = {
        "sender": sender,
        "subject": subject,
        "body": body,
        "contains_attachment": bool(contains_attachment),
    }

    extracted_features = extract_email_features(
        sender=sender,
        subject=subject,
        body=body,
        contains_attachment=bool(contains_attachment),
    )

    X = feature_union.transform([sample])
    prob_arr = calibrated_svc.predict_proba(X)[0]
    probs = {cls: round(float(p) * 100, 1) for cls, p in zip(classes, prob_arr)}

    # Guardrail: strong multi-IOC phishing signal overrides borderline Safe/Spam
    raw_pred = str(classes[int(np.argmax(prob_arr))])
    phish_ioc_score = (
        (35 if extracted_features["domain_mismatch"]["detected"] else 0)
        + (35 if extracted_features["max_url_risk"] >= 45 else 0)
        + (20 if len(extracted_features["credential_keywords"]) >= 1 else 0)
        + (15 if len(extracted_features["urgency_keywords"]) >= 1 else 0)
    )
    if raw_pred != "Phishing" and phish_ioc_score >= 70 and probs.get("Phishing", 0.0) >= 25.0:
        predicted_label = "Phishing"
        probs["Phishing"] = max(probs.get("Phishing", 0.0), 65.0)
    else:
        predicted_label = raw_pred

    confidence_score = round(probs.get(predicted_label, max(probs.values())), 1)
    risk_score = _compute_unified_risk_score(predicted_label, probs, extracted_features)

    tfidf_vectorizer = feature_union.named_transformers["tfidf_text"].named_steps["tfidf"]
    explainability = build_explainability(
        sender=sender,
        subject=subject,
        body=body,
        contains_attachment=bool(contains_attachment),
        extracted_features=extracted_features,
        tfidf_vectorizer=tfidf_vectorizer,
        linear_svc=raw_svc,
        class_labels=classes,
        predicted_label=predicted_label,
    )

    return {
        "predicted_label": predicted_label,
        "confidence_score": confidence_score,
        "risk_score": risk_score,
        "class_probabilities": probs,
        "extracted_features": extracted_features,
        "explainability_data": explainability,
    }
