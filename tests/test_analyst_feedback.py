"""
tests/test_analyst_feedback.py

Unit tests for Phase 3 Analyst Feedback Loop & Training Signal Dataset:
- Ingestion of analyst labels (CONFIRMED_PHISHING, FALSE_POSITIVE, SUSPICIOUS_NEEDS_REVIEW)
- Feature vector snapshot extraction from investigation telemetry
- Persistence to SQLite database and training signal retrieval
"""

import pytest
from database import init_db, fetch_all_analyst_feedback
from services.feedback_service import record_analyst_decision


@pytest.fixture(autouse=True)
def setup_db():
    init_db()


def test_record_confirmed_phishing_feedback():
    telemetry = {
        "analysis_id": "TEST-EML-001",
        "email_risk_score": 92,
        "domain_risk": 88,
        "visual_risk": 95,
        "payload_risk": 75,
        "domain": "amazon-security-login.example",
        "brand_name": "Amazon",
        "email_signals": {
            "urgency_language": True,
            "credential_request": True,
            "brand_impersonation": True
        },
        "sender_behavior": {
            "anomaly_score": 75,
            "hypothesis": "ANOMALOUS_EXTERNAL_SENDER"
        }
    }

    res = record_analyst_decision(
        case_id="TEST-CASE-001",
        analyst_label="CONFIRMED_PHISHING",
        analysis_id="TEST-EML-001",
        original_verdict="CRITICAL",
        reason_category="credential_harvesting",
        comment="Confirmed phishing landing page requesting user credentials.",
        investigation_telemetry=telemetry
    )

    assert res["status"] == "recorded"
    assert res["analyst_label"] == "CONFIRMED_PHISHING"
    assert res["training_signal_created"] is True
    assert res["training_signal"]["features"]["urgency_signal"] is True
    assert res["training_signal"]["features"]["credential_request_signal"] is True
    assert res["training_signal"]["features"]["email_risk_score"] == 92
    assert res["training_signal"]["features"]["domain_risk_score"] == 88


def test_record_false_positive_feedback():
    telemetry = {
        "email_risk_score": 20,
        "domain_risk": 15,
        "domain": "acme-internal.com",
        "email_signals": {
            "urgency_language": False,
            "credential_request": False
        },
        "sender_behavior": {
            "anomaly_score": 0,
            "hypothesis": "ALIGNS_WITH_BASELINE"
        }
    }

    res = record_analyst_decision(
        case_id="TEST-CASE-002",
        analyst_label="FALSE_POSITIVE",
        original_verdict="LOW",
        comment="Legitimate internal operational email.",
        investigation_telemetry=telemetry
    )

    assert res["status"] == "recorded"
    assert res["analyst_label"] == "FALSE_POSITIVE"
    assert res["training_signal"]["features"]["sender_anomaly_score"] == 0


def test_fetch_all_analyst_feedback_dataset():
    all_feedback = fetch_all_analyst_feedback()
    assert isinstance(all_feedback, list)
    assert len(all_feedback) >= 2
