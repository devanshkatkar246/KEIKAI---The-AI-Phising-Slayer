"""
services/sender_behavior.py

KEIKAI ORGANISATIONAL PHISHING INTELLIGENCE — SENDER BEHAVIOUR MODELING ENGINE

Provides lightweight, explainable sender behavioral modeling and organizational baselines:
1. Synthetic organizational profile management (e.g., Acme Corporation & Corporate Internal)
2. Historical baseline comparison across 6 behavioral dimensions:
   - Sending time anomaly (operational hours vs off-hours)
   - Recipient pattern anomaly (internal team vs mass/unexpected external)
   - Destination domain anomaly (known vendor vs unknown external URL)
   - URL link behavior anomaly (credential link vs rare URL sender)
   - Attachment type anomaly (expected PDF/DOCX vs HTML/EXE/ZIP)
   - Language / intent anomaly (credential/payment request for non-IT role)
3. Transparent anomaly scoring (0-100) distinct from payload threat score
4. Hypothesis generation: POSSIBLE_ACCOUNT_COMPROMISE, SUSPICIOUS_BEHAVIOR, BENIGN_INTERNAL, EXTERNAL_IMPERSONATION, NO_BASELINE_AVAILABLE
"""

import re
import logging
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple

logger = logging.getLogger("keikai.services.sender_behavior")

# Default synthetic organizational baselines for demonstration
ORGANISATION_BASELINES = {
    "org_acme_01": {
        "organisation_id": "org_acme_01",
        "name": "Acme Corporation",
        "trusted_domains": ["acme.example", "acme-corp.example", "corporate.internal", "trusted-vendor.example"],
        "trusted_brands": ["Acme", "Acme Corp"],
        "senders": {
            "finance@acme.example": {
                "role": "Finance & Accounting",
                "allowed_hours": (9, 18),  # 09:00 - 18:00
                "typical_recipients": ["procurement@acme.example", "finance-team@acme.example", "accounts@acme.example"],
                "typical_domains": ["acme.example", "trusted-vendor.example"],
                "url_frequency": "RARE",  # RARE, MEDIUM, HIGH
                "allowed_attachments": ["PDF", "XLSX", "CSV"],
                "typical_intents": ["invoice", "payment", "reimbursement", "budget"],
                "avg_daily_volume": 12
            },
            "hr@acme.example": {
                "role": "Human Resources",
                "allowed_hours": (8, 18),  # 08:00 - 18:00
                "typical_recipients": ["all-staff@acme.example", "careers@acme.example"],
                "typical_domains": ["acme.example", "workday.example"],
                "url_frequency": "MEDIUM",
                "allowed_attachments": ["PDF", "DOCX"],
                "typical_intents": ["policy", "payroll", "benefits", "onboarding"],
                "avg_daily_volume": 25
            },
            "it-security@acme.example": {
                "role": "IT & Information Security",
                "allowed_hours": (0, 24),  # 24/7
                "typical_recipients": ["all-staff@acme.example", "tech@acme.example"],
                "typical_domains": ["acme.example", "okta.example", "microsoft.com"],
                "url_frequency": "HIGH",
                "allowed_attachments": ["PDF"],
                "typical_intents": ["security", "password", "verification", "mfa"],
                "avg_daily_volume": 40
            },
            "alex.rivers@corporate.internal": {
                "role": "Product Manager",
                "allowed_hours": (8, 19),  # 08:00 - 19:00
                "typical_recipients": ["team@corporate.internal", "product@corporate.internal"],
                "typical_domains": ["corporate.internal"],
                "url_frequency": "LOW",
                "allowed_attachments": ["PDF", "ZIP", "DOCX"],
                "typical_intents": ["roadmap", "meeting_notes", "project_update"],
                "avg_daily_volume": 15
            }
        }
    }
}


def parse_sending_hour(received_at: Optional[str]) -> Optional[int]:
    """Extracts sending hour (0-23) from timestamp string."""
    if not received_at:
        return None
    try:
        # Match HH:MM pattern like 'Today, 14:22' or '02:43' or ISO format
        time_match = re.search(r'\b([0-1]?[0-9]|2[0-3]):([0-5][0-9])\b', received_at)
        if time_match:
            return int(time_match.group(1))
        # ISO timestamp format e.g. 2026-09-11T14:22:00
        dt = datetime.fromisoformat(received_at.replace("Z", "+00:00"))
        return dt.hour
    except Exception:
        return None


def extract_sender_email(raw_sender: str) -> str:
    """Extracts clean email address from sender string e.g. 'Finance Dept <finance@acme.example>'."""
    if not raw_sender:
        return ""
    email_match = re.search(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', raw_sender)
    if email_match:
        return email_match.group(0).lower().strip()
    return raw_sender.lower().strip()


def extract_sender_domain(email_str: str) -> str:
    """Extracts domain hostname from email string."""
    if "@" in email_str:
        return email_str.split("@")[-1].strip()
    return ""


def evaluate_sender_behavior(
    sender: str,
    subject: str = "",
    body: str = "",
    received_at: Optional[str] = None,
    extracted_urls: Optional[List[str]] = None,
    extracted_domains: Optional[List[str]] = None,
    content_signals: Optional[Dict[str, bool]] = None,
    org_id: str = "org_acme_01"
) -> Dict[str, Any]:
    """
    Evaluates sender behavior against organizational baseline.
    Returns structured behavioral telemetry, anomaly score, signals, and hypothesis.
    """
    clean_sender = extract_sender_email(sender)
    sender_domain = extract_sender_domain(clean_sender)
    urls = extracted_urls or []
    domains = extracted_domains or []
    signals_map = content_signals or {}

    org_config = ORGANISATION_BASELINES.get(org_id, ORGANISATION_BASELINES["org_acme_01"])
    org_name = org_config["name"]
    trusted_domains = org_config["trusted_domains"]
    senders_catalog = org_config["senders"]

    # Check if sender has a registered profile
    profile = senders_catalog.get(clean_sender)
    
    # Check if sender domain belongs to internal org domain space
    is_internal_domain = any(sender_domain == td or sender_domain.endswith("." + td) for td in trusted_domains)

    if not profile:
        # If internal domain without specific profile, construct default baseline
        if is_internal_domain:
            profile = {
                "role": "Internal Employee",
                "allowed_hours": (8, 19),
                "typical_recipients": [f"all@{sender_domain}"],
                "typical_domains": trusted_domains,
                "url_frequency": "MEDIUM",
                "allowed_attachments": ["PDF", "DOCX"],
                "typical_intents": ["general"],
                "avg_daily_volume": 10
            }
            profile_available = True
            baseline_type = "GENERATED_INTERNAL_BASELINE"
        else:
            # External sender: No organizational baseline available
            return {
                "profile_available": False,
                "sender": clean_sender,
                "sender_domain": sender_domain,
                "organisation": {
                    "id": org_id,
                    "name": org_name
                },
                "anomaly_score": 0,
                "severity": "BENIGN",
                "hypothesis": "NO_BASELINE_AVAILABLE",
                "hypothesis_label": "No Organisational Baseline (External Sender)",
                "confidence": 0.50,
                "signals": [],
                "baseline": None,
                "observed": {
                    "sending_time": received_at or "Unknown",
                    "destination_domains": domains,
                    "urls_present": len(urls) > 0
                },
                "explanation": ["External sender account does not possess an internal organizational behavioral profile."]
            }
    else:
        profile_available = True
        baseline_type = "EXPLICIT_EMPLOYEE_PROFILE"

    # Evaluate Behavioral Anomaly Dimensions
    anomaly_signals = []
    observed_facts = {}
    anomaly_points = 0
    max_anomaly_points = 100

    # 1. Sending-Time Anomaly
    hour = parse_sending_hour(received_at)
    allowed_start, allowed_end = profile["allowed_hours"]
    observed_facts["sending_hour"] = f"{hour:02d}:00" if hour is not None else (received_at or "Unknown")
    observed_facts["allowed_hours"] = f"{allowed_start:02d}:00 - {allowed_end:02d}:00"

    if hour is not None and (allowed_start < allowed_end):
        if hour < allowed_start or hour >= allowed_end:
            anomaly_points += 20
            anomaly_signals.append({
                "feature": "sending_time",
                "severity": "HIGH",
                "evidence": f"Unusual sending time ({hour:02d}:00). Allowed profile hours: {allowed_start:02d}:00–{allowed_end:02d}:00.",
                "observed": f"{hour:02d}:00",
                "baseline": f"{allowed_start:02d}:00–{allowed_end:02d}:00"
            })

    # 2. Destination Domain Anomaly
    unusual_domains = []
    for d in domains:
        d_clean = d.lower().strip()
        is_known = any(d_clean == td or d_clean.endswith("." + td) for td in profile["typical_domains"])
        if not is_known:
            unusual_domains.append(d_clean)

    observed_facts["destination_domains"] = domains
    observed_facts["typical_domains"] = profile["typical_domains"]

    if unusual_domains:
        anomaly_points += 25
        anomaly_signals.append({
            "feature": "destination_domain",
            "severity": "HIGH",
            "evidence": f"Email links to unfamiliar external domain(s): {', '.join(unusual_domains)}. Sender profile expects: {', '.join(profile['typical_domains'])}.",
            "observed": unusual_domains[0],
            "baseline": ", ".join(profile["typical_domains"])
        })

    # 3. URL Link Behavior Anomaly (Credential / Login URL from Low-URL Sender)
    has_credential_url = any(
        any(path in u.lower() for path in ["/login", "/auth", "/verify", "/credential", "/signin"])
        for u in urls
    )
    observed_facts["credential_url_present"] = has_credential_url
    observed_facts["url_frequency_profile"] = profile["url_frequency"]

    if has_credential_url and profile["url_frequency"] in ["RARE", "LOW"]:
        anomaly_points += 30
        anomaly_signals.append({
            "feature": "url_behavior",
            "severity": "CRITICAL",
            "evidence": f"Sender has '{profile['url_frequency']}' link frequency in baseline but sent a credential/login verification URL.",
            "observed": "Credential / Login Link Included",
            "baseline": f"{profile['url_frequency']} URL Usage Profile"
        })

    # 4. Language / Intent Anomaly (Non-IT role requesting passwords/credentials)
    has_cred_intent = signals_map.get("credential_request") or any(
        kw in (subject + " " + body).lower()
        for kw in ["verify password", "renew credentials", "confirm login", "account suspended"]
    )
    observed_facts["credential_intent"] = has_cred_intent
    observed_facts["user_role"] = profile["role"]

    if has_cred_intent and "IT" not in profile["role"]:
        anomaly_points += 20
        anomaly_signals.append({
            "feature": "intent_role_mismatch",
            "severity": "HIGH",
            "evidence": f"Role '{profile['role']}' does not typically send security credential or password verification requests.",
            "observed": "Credential Verification Intent",
            "baseline": f"Role: {profile['role']}"
        })

    # 5. Attachment Anomaly
    has_suspicious_attachment = any(
        kw in (subject + " " + body).lower()
        for kw in ["invoice.exe", "update.html", "script.js", "archive.zip"]
    )
    if has_suspicious_attachment:
        anomaly_points += 15
        anomaly_signals.append({
            "feature": "attachment_type",
            "severity": "MEDIUM",
            "evidence": "Email references atypical executable or HTML attachment payload.",
            "observed": "Executable / HTML Attachment",
            "baseline": ", ".join(profile.get("allowed_attachments", ["PDF"]))
        })

    # Calculate Anomaly Score (0-100)
    anomaly_score = min(100, anomaly_points)

    # Determine Anomaly Severity
    if anomaly_score >= 70:
        severity = "HIGH"
    elif anomaly_score >= 40:
        severity = "MEDIUM"
    elif anomaly_score >= 15:
        severity = "LOW"
    else:
        severity = "BENIGN"

    # Determine Hypothesis
    if anomaly_score >= 50 and is_internal_domain:
        hypothesis = "POSSIBLE_ACCOUNT_COMPROMISE"
        hypothesis_label = "Possible Internal Account Compromise"
        confidence = 0.86
    elif anomaly_score >= 30 and is_internal_domain:
        hypothesis = "SUSPICIOUS_BEHAVIOR"
        hypothesis_label = "Anomalous Internal Sender Activity"
        confidence = 0.72
    elif not is_internal_domain:
        hypothesis = "EXTERNAL_IMPERSONATION"
        hypothesis_label = "External Sender Impersonation"
        confidence = 0.88
    else:
        hypothesis = "BENIGN_INTERNAL"
        hypothesis_label = "Normal Internal Sender Activity"
        confidence = 0.94

    # Build Explainable Reasoning
    explanation = []
    if anomaly_signals:
        for s in anomaly_signals:
            explanation.append(s["evidence"])
    else:
        explanation.append(f"Sender '{clean_sender}' activity aligns with established organizational baseline ({profile['role']}).")

    return {
        "profile_available": True,
        "source_classification": "SIMULATED_ORGANISATIONAL_BASELINE",
        "sender": clean_sender,
        "sender_domain": sender_domain,
        "role": profile["role"],
        "baseline_type": baseline_type,
        "organisation": {
            "id": org_id,
            "name": org_name
        },
        "anomaly_score": anomaly_score,
        "severity": severity,
        "hypothesis": hypothesis,
        "hypothesis_label": hypothesis_label,
        "confidence": round(confidence, 2),
        "signals": anomaly_signals,
        "baseline": {
            "role": profile["role"],
            "allowed_hours": f"{profile['allowed_hours'][0]:02d}:00–{profile['allowed_hours'][1]:02d}:00",
            "typical_domains": profile["typical_domains"],
            "url_frequency": profile["url_frequency"],
            "allowed_attachments": profile.get("allowed_attachments", ["PDF"])
        },
        "observed": observed_facts,
        "explanation": explanation
    }


class SenderTelemetryProvider:
    """
    Abstract interface for organisational sender behavior telemetry providers.
    Allows future integrations (M365, Google Workspace, Mail Gateway, SIEM) without modifying core decision logic.
    """

    def fetch_sender_profile(self, sender_email: str, org_id: str = "org_acme_01") -> Optional[Dict[str, Any]]:
        raise NotImplementedError("Subclasses must implement fetch_sender_profile")

    def get_telemetry_source(self) -> str:
        raise NotImplementedError("Subclasses must implement get_telemetry_source")


class SyntheticSenderTelemetryProvider(SenderTelemetryProvider):
    """
    Default demonstration provider returning synthetic organizational profiles.
    """

    def fetch_sender_profile(self, sender_email: str, org_id: str = "org_acme_01") -> Optional[Dict[str, Any]]:
        org = ORGANISATION_BASELINES.get(org_id, ORGANISATION_BASELINES["org_acme_01"])
        return org.get("senders", {}).get(sender_email.lower())

    def get_telemetry_source(self) -> str:
        return "SIMULATED_ORGANISATIONAL_BASELINE"


def get_sender_behavior_telemetry(sender: str, organisation_id: str = "org_acme_01", **kwargs) -> Dict[str, Any]:
    """
    Convenience wrapper returning sender behavioral telemetry for an organization.
    """
    return evaluate_sender_behavior(sender=sender, org_id=organisation_id, **kwargs)

