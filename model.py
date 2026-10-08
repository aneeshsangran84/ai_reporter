"""
model.py
--------
AI/ML triage engine.

Uses TF-IDF + Random Forest to classify findings into:
  P1 = Critical - Immediate Patch Required
  P2 = Scheduled Maintenance
  P3 = Informational / False Positive / Acceptable Risk

Also computes an "AI Reporter Model Score" combining ML probability,
CVSS, and Nessus severity.
"""

from __future__ import annotations

import numpy as np
import pandas as pd
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier


PRIORITY_SCORE = {
    "P1": 100.0,
    "P2": 60.0,
    "P3": 20.0,
}

PRIORITY_LABELS = {
    "P1": "Critical - Immediate Patch Required",
    "P2": "Scheduled Maintenance",
    "P3": "Informational / False Positive / Acceptable Risk",
}


def _synthetic_training_data():
    """
    Built-in synthetic training data so the model runs without API keys
    or external datasets.
    """
    p1 = [
        "Unauthenticated remote code execution allows an attacker to execute arbitrary commands. Apply emergency patch immediately.",
        "Deserialization flaw in Apache Log4j permits remote code execution and is actively exploited in ransomware campaigns.",
        "Default administrative credentials allow full system compromise. Change credentials and restrict access now.",
        "SQL injection in web application enables authentication bypass and database exfiltration. Emergency remediation required.",
        "Privilege escalation vulnerability allows local user to gain root. Patch immediately.",
        "Command injection in CGI script permits unauthenticated remote command execution.",
        "Critical authentication bypass in VPN appliance allows unauthorized administrative access.",
        "Heap buffer overflow in SMB service may allow remote code execution without authentication.",
        "Path traversal vulnerability exposes sensitive configuration files and credentials.",
        "Missing authentication for critical function allows attacker to modify system settings.",
        "Remote code execution in outdated web framework. Vendor advisory confirms active exploitation.",
        "Wormable vulnerability in server service. Apply emergency security update.",
        "Critical vulnerability in backup software allows arbitrary file upload and execution.",
        "Improper access control allows unauthenticated user to create admin accounts.",
        "Malicious file upload leads to remote code execution on production server.",
    ]

    p2 = [
        "Outdated software version is affected by multiple medium severity issues. Schedule upgrade during maintenance window.",
        "Missing security patches for operating system. Apply monthly patch cycle.",
        "SMB signing is not required, which may allow man-in-the-middle attacks. Enable signing.",
        "TLS 1.0 and TLS 1.1 are enabled. Disable legacy protocols and schedule configuration change.",
        "Information disclosure of software version may aid attackers. Remove banners during next maintenance.",
        "SNMP default community string is in use. Change to strong community string.",
        "Weak password policy allows short passwords. Update domain password policy.",
        "Unnecessary open port detected. Close port if not required.",
        "Missing HTTP security headers. Add headers during next application release.",
        "SSL certificate expires soon. Renew certificate before expiration.",
        "Outdated PHP version supported. Plan upgrade to supported release.",
        "WordPress plugin requires security update. Schedule plugin update.",
        "Database service is exposed to internal network. Restrict access with firewall rules.",
        "Antivirus definitions are outdated. Update definitions and schedule regular updates.",
        "Audit logging is not enabled for critical service. Enable logging in next change window.",
    ]

    p3 = [
        "Informational: service banner is visible. No immediate action required.",
        "Service detection identified an open port. This is expected for the asset.",
        "SSL certificate details are informational. No vulnerability detected.",
        "ICMP timestamp response is enabled. Informational finding.",
        "TCP timestamps are enabled. Low risk informational.",
        "HTTP OPTIONS method is allowed. Informational for this application.",
        "Open port is expected per asset inventory. Acceptable risk.",
        "OS fingerprint information detected. No known vulnerability.",
        "Traceroute information is available. Informational only.",
        "DNS resolution details are informational. No action needed.",
        "Web server version information is informational. Accepted risk.",
        "NTP service is reachable. Informational and expected.",
        "Network device supports deprecated cipher but not exploitable. Accepted risk.",
        "User enumeration is possible but considered low risk. Monitor only.",
        "Directory listing is disabled. Informational check passed.",
    ]

    texts = p1 + p2 + p3
    labels = ["P1"] * len(p1) + ["P2"] * len(p2) + ["P3"] * len(p3)
    return texts, labels


def _combine_text(row) -> str:
    """Combine relevant text fields for NLP feature extraction."""
    parts = []
    for col in ["plugin_name", "synopsis", "description", "solution", "risk_factor"]:
        val = row.get(col, "")
        if val is not None:
            parts.append(str(val))
    return " ".join(parts)


def train_default_model():
    """Train and return the default TF-IDF + Random Forest pipeline."""
    texts, labels = _synthetic_training_data()

    pipeline = Pipeline(
        [
            (
                "tfidf",
                TfidfVectorizer(
                    ngram_range=(1, 2),
                    max_features=5000,
                    stop_words="english",
                ),
            ),
            (
                "clf",
                RandomForestClassifier(
                    n_estimators=250,
                    random_state=42,
                    class_weight="balanced",
                    n_jobs=-1,
                ),
            ),
        ]
    )

    pipeline.fit(texts, labels)
    return pipeline


_MODEL = None


def get_triage_model():
    """Lazy singleton for the triage model."""
    global _MODEL
    if _MODEL is None:
        _MODEL = train_default_model()
    return _MODEL


def triage_findings(df: pd.DataFrame, model=None) -> pd.DataFrame:
    """
    Add AI triage columns to the parsed Nessus DataFrame.

    Added columns:
      ai_priority, ai_confidence, ai_score, ai_reason
    """
    if df is None or df.empty:
        return df.copy() if df is not None else pd.DataFrame()

    work = df.copy()

    for col in [
        "plugin_name", "synopsis", "description", "solution",
        "risk_factor", "severity", "cvss_score", "severity_rank",
    ]:
        if col not in work.columns:
            work[col] = 0 if col in ["cvss_score", "severity_rank"] else ""

    model = model or get_triage_model()

    texts = work.apply(_combine_text, axis=1)

    preds = model.predict(texts)
    proba = model.predict_proba(texts)
    classes = list(model.classes_)

    max_conf = proba.max(axis=1)

    # Weighted ML score: P1=100, P2=60, P3=20
    ml_score = np.zeros(len(work), dtype=float)
    for i, cls in enumerate(classes):
        ml_score += proba[:, i] * PRIORITY_SCORE.get(cls, 0.0)

    cvss = pd.to_numeric(work["cvss_score"], errors="coerce").fillna(0).clip(0, 10)
    sev_rank = pd.to_numeric(work["severity_rank"], errors="coerce").fillna(0).clip(0, 4)

    work["ai_priority"] = preds
    work["ai_confidence"] = max_conf

    # Final score blends ML, CVSS, and Nessus severity
    work["ai_score"] = (
        0.55 * ml_score
        + 0.30 * (cvss / 10.0 * 100.0)
        + 0.15 * (sev_rank / 4.0 * 100.0)
    )

    work["ai_reason"] = [
        f"ML predicted {p} ({c:.0%} confidence); CVSS {v:.1f}; {s} severity"
        for p, c, v, s in zip(
            work["ai_priority"],
            work["ai_confidence"],
            cvss,
            work["severity"],
        )
    ]

    return work.sort_values("ai_score", ascending=False).reset_index(drop=True)
