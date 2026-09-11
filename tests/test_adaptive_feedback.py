"""
tests/test_adaptive_feedback.py

Unit tests for Phase 8 Organisational Feedback & Adaptive Detection Signals:
- Full support for 6 standard feedback types (ANALYST_CONFIRMED_PHISHING, ANALYST_FALSE_POSITIVE, USER_REPORTED_PHISHING, USER_MARKED_SAFE, ANALYST_CONFIRMED_BENIGN, ANALYST_UNCERTAIN)
- Feature vector snapshot capture (risk_score, confidence, sender_anomaly, domain_risk, visual_similarity, redirect_risk, qr_detected, attachment_present, attack_hypothesis)
- Schema versioning (feedback_schema_version, decision_engine_version, feature_schema_version)
- Conflict detection (when user and analyst disagree on same case_id)
- Duplicate submission / poisoning protection
- Dataset export API & statistics generation with RECOMMENDED_SIGNAL_ADJUSTMENTS
"""

import pytest
import uuid
from database import init_db, fetch_all_analyst_feedback
from services.feedback_service import (
    record_analyst_decision,
    get_feedback_training_dataset,
    get_feedback_statistics
)
from services.phishing_decision_engine import evaluate_phishing_decision


@pytest.fixture(autouse=True)
def setup_db():
    init_db()


def test_01_record_analyst_confirmed_phishing():
    case_id = f"TEST-CASE-PHISH-{uuid.uuid4().hex[:6]}"
    telemetry = {
        "risk_score": 88,
        "confidence": 92,
        "sender_behavior": {"anomaly_score": 80, "hypothesis": "EXTERNAL_IMPERSONATION"},
        "domain_intelligence": {"domain_risk": 85, "domain": "paypa1-verify.com"},
        "visual_phishing": {"max_similarity": 94},
        "redirect_signal": {"redirect_risk": 60, "chain_length": 3},
        "payload_inspection": {"qr_detected": True, "attachment_present": False},
        "signals": {"urgency_language": True, "credential_request": True}
    }

    res = record_analyst_decision(
        case_id=case_id,
        analyst_label="ANALYST_CONFIRMED_PHISHING",
        analysis_id="EML-101",
        original_verdict="CRITICAL",
        reason_category="credential_harvesting",
        comment="Confirmed credential phishing page.",
        investigation_telemetry=telemetry,
        actor_id="analyst_sec_01",
        actor_role="ANALYST"
    )

    assert res["status"] == "recorded"
    assert res["analyst_label"] == "ANALYST_CONFIRMED_PHISHING"
    ts = res["training_signal"]
    feats = ts["features"]
    assert feats["risk_score"] == 88
    assert feats["confidence"] == 92
    assert feats["sender_anomaly"] == 80
    assert feats["domain_risk"] == 85
    assert feats["visual_similarity"] == 94
    assert feats["redirect_risk"] == 60
    assert feats["qr_detected"] is True
    assert feats["attack_hypothesis"] == "EXTERNAL_IMPERSONATION"
    assert ts["feedback_schema_version"] == "1.0.0"


def test_02_record_user_reported_phishing_and_user_marked_safe():
    case_id = f"TEST-CASE-USER-{uuid.uuid4().hex[:6]}"
    telemetry = {
        "risk_score": 65,
        "domain_intelligence": {"domain": "suspicious-link.net"},
        "sender_behavior": {"hypothesis": "UNRECOGNIZED_SENDER"}
    }

    res_user = record_analyst_decision(
        case_id=case_id,
        analyst_label="USER_REPORTED_PHISHING",
        comment="Employee reported suspicious email via Outlook button.",
        investigation_telemetry=telemetry,
        actor_id="user_emp_42",
        actor_role="USER"
    )
    assert res_user["status"] == "recorded"
    assert res_user["analyst_label"] == "USER_REPORTED_PHISHING"

    res_safe = record_analyst_decision(
        case_id=f"TEST-CASE-SAFE-{uuid.uuid4().hex[:6]}",
        analyst_label="USER_MARKED_SAFE",
        comment="User marked internal newsletter as safe.",
        investigation_telemetry={"risk_score": 10},
        actor_id="user_emp_99",
        actor_role="USER"
    )
    assert res_safe["analyst_label"] == "USER_MARKED_SAFE"


def test_03_conflicting_feedback_handling():
    case_id = f"TEST-CONFLICT-CASE-{uuid.uuid4().hex[:6]}"
    telemetry = {"risk_score": 50, "domain_intelligence": {"domain": "vendor-portal.com"}}

    # First entry: User reports phishing
    record_analyst_decision(
        case_id=case_id,
        analyst_label="USER_REPORTED_PHISHING",
        comment="User suspicious of vendor link.",
        investigation_telemetry=telemetry,
        actor_id="user_john",
        actor_role="USER"
    )

    # Second entry: Analyst investigates and confirms benign/false positive
    record_analyst_decision(
        case_id=case_id,
        analyst_label="ANALYST_CONFIRMED_BENIGN",
        comment="Analyst verified legitimate corporate vendor domain.",
        investigation_telemetry=telemetry,
        actor_id="analyst_mary",
        actor_role="ANALYST"
    )

    dataset = get_feedback_training_dataset()
    case_records = [r for r in dataset if r["case_id"] == case_id]
    assert len(case_records) == 2
    # Both records should be flagged with has_conflict = True
    assert all(r["has_conflict"] is True for r in case_records)


def test_04_duplicate_submission_poisoning_protection():
    case_id = f"TEST-DUP-{uuid.uuid4().hex[:6]}"
    telemetry = {"risk_score": 75}

    res1 = record_analyst_decision(
        case_id=case_id,
        analyst_label="ANALYST_CONFIRMED_PHISHING",
        investigation_telemetry=telemetry,
        actor_id="analyst_1",
        actor_role="ANALYST"
    )
    assert res1["status"] == "recorded"

    # Exact duplicate submission by same actor and case
    res2 = record_analyst_decision(
        case_id=case_id,
        analyst_label="ANALYST_CONFIRMED_PHISHING",
        investigation_telemetry=telemetry,
        actor_id="analyst_1",
        actor_role="ANALYST"
    )
    # Check that database records for this case did not double-insert
    dataset = get_feedback_training_dataset()
    dup_records = [r for r in dataset if r["case_id"] == case_id and r["actor_id"] == "analyst_1"]
    assert len(dup_records) == 1


def test_05_feedback_dataset_export():
    dataset = get_feedback_training_dataset()
    assert isinstance(dataset, list)
    assert len(dataset) > 0
    first = dataset[0]
    assert "feedback_id" in first
    assert "analyst_label" in first
    assert "features" in first
    assert "feedback_schema_version" in first


def test_06_feedback_statistics_and_recommendations():
    stats = get_feedback_statistics()
    assert "total_feedback" in stats
    assert "confirmed_phishing" in stats
    assert "false_positives" in stats
    assert "labels_by_attack_hypothesis" in stats
    assert "feature_distributions" in stats
    assert "RECOMMENDED_SIGNAL_ADJUSTMENTS" in stats
    assert isinstance(stats["RECOMMENDED_SIGNAL_ADJUSTMENTS"], list)
    assert len(stats["RECOMMENDED_SIGNAL_ADJUSTMENTS"]) > 0


def test_07_phishing_decision_engine_historical_feedback_integration():
    # Insert 5 historical false positive records for a domain
    test_domain = "legit-supplier-portal.com"
    for i in range(5):
        record_analyst_decision(
            case_id=f"TEST-HIST-FP-{i}-{uuid.uuid4().hex[:4]}",
            analyst_label="ANALYST_FALSE_POSITIVE",
            investigation_telemetry={
                "risk_score": 40,
                "domain": test_domain,
                "sender_behavior": {"hypothesis": "NEW_SUPPLIER"}
            },
            actor_id=f"analyst_{i}",
            actor_role="ANALYST"
        )

    # Run decision engine on this domain
    bundle = {
        "email_analysis": {"extracted_domain": test_domain, "threat_signals": []},
        "domain_intelligence": {"domain": test_domain, "domain_risk": 45},
        "sender_behavior": {"anomaly_score": 20, "hypothesis": "NEW_SUPPLIER"}
    }
    decision = evaluate_phishing_decision(bundle)
    
    # Check that historical organizational feedback signal is included in evidence
    signals = [ev["signal"] for ev in decision["contradicting_evidence"]]
    assert "organisational_false_positive_history" in signals
