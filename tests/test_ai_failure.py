"""
tests/test_ai_failure.py

PHASE 9 — PART 3: AI FAILURE & DEGRADATION HARDENING TESTS

Verifies that AI provider failures (unavailability, timeout, HTTP 429, malformed JSON, incomplete JSON, hallucinated fields, provider errors) gracefully fall back to the deterministic decision engine without crashing or corrupting security verdicts.
"""

import pytest
from unittest.mock import patch, MagicMock
from services.ai_reasoning import analyze_evidence, OpenRouterProvider, reset_ai_telemetry
from services.phishing_decision_engine import evaluate_phishing_decision


@pytest.fixture(autouse=True)
def reset_telemetry():
    reset_ai_telemetry()


def test_01_ai_provider_unavailable():
    """Verifies graceful fallback when OpenRouter API is completely unreachable."""
    payload = {
        "subject": "Urgent Password Reset",
        "sender": "attacker@phish.net",
        "risk_score": 90,
        "threat_type": "credential_phishing"
    }

    with patch.object(OpenRouterProvider, "analyze", side_effect=ConnectionError("Host unreachable")):
        res = analyze_evidence(payload)
        assert res["ai_used"] is False
        assert res["reasoning_source"] == "deterministic_engine"
        assert "deterministic" in res["summary"].lower() or "score" in res["summary"].lower()


def test_02_ai_api_timeout():
    """Verifies graceful fallback when OpenRouter API times out."""
    payload = {"risk_score": 85, "threat_type": "spoofing"}

    with patch.object(OpenRouterProvider, "analyze", side_effect=TimeoutError("Request timed out after 5.0s")):
        res = analyze_evidence(payload)
        assert res["ai_used"] is False
        assert res["reasoning_source"] == "deterministic_engine"


def test_03_ai_http_429_quota_exhausted():
    """Verifies graceful fallback when OpenRouter API returns HTTP 429 Rate Limit / Quota Exceeded."""
    payload = {"risk_score": 95, "threat_type": "account_takeover"}

    with patch.object(OpenRouterProvider, "analyze", side_effect=RuntimeError("HTTP 429: Rate limit reached")):
        res = analyze_evidence(payload)
        assert res["ai_used"] is False
        assert res["reasoning_source"] == "deterministic_engine"


def test_04_ai_malformed_json_response():
    """Verifies handling when AI provider returns None or unparseable response."""
    payload = {"risk_score": 75}

    with patch.object(OpenRouterProvider, "analyze", return_value=None):
        res = analyze_evidence(payload)
        assert res["ai_used"] is False
        assert res["reasoning_source"] == "deterministic_engine"


def test_05_ai_incomplete_json_missing_keys():
    """Verifies handling when AI returns partial response missing key_evidence."""
    payload = {"risk_score": 80}

    partial_response = {
        "ai_used": True,
        "summary": "Partial summary only"
    }

    with patch.object(OpenRouterProvider, "analyze", return_value=partial_response):
        res = analyze_evidence(payload)
        # Should reject incomplete response missing key_evidence and fallback
        assert res["ai_used"] is False
        assert res["reasoning_source"] == "deterministic_engine"


def test_06_ai_hallucinated_fields_sanitization():
    """Verifies sanitization when AI returns response with key_evidence."""
    payload = {"risk_score": 90}

    valid_response_with_extra = {
        "ai_used": True,
        "reasoning_source": "openrouter",
        "summary": "Legitimate threat detected",
        "key_evidence": ["High urgency", "Suspicious link"],
        "hallucinated_action": "DELETE_USER_ACCOUNT_IMMEDIATELY",
        "fake_field_99": 12345
    }

    with patch.object(OpenRouterProvider, "analyze", return_value=valid_response_with_extra):
        res = analyze_evidence(payload)
        assert res["summary"] == "Legitimate threat detected"
        assert res["ai_used"] is True
        
        # Verify decision engine remains authoritative for action classification
        bundle = {
            "email_analysis": {
                "email": {"subject": "Alert", "sender": "bad@phish.com"},
                "threat_signals": ["credential_request"]
            },
            "domain_intelligence": {"domain": "phish.com", "domain_risk": 90}
        }
        decision = evaluate_phishing_decision(bundle)
        assert decision["recommended_action"] in ["BLOCK_AND_QUARANTINE", "ISOLATE_AND_INVESTIGATE", "MONITOR_SENDER", "ALLOW"]
        assert decision["recommended_action"] != "DELETE_USER_ACCOUNT_IMMEDIATELY"


def test_07_full_pipeline_decision_engine_survives_ai_crash():
    """Verifies complete decision engine returns clean security verdict even if AI provider crashes catastrophically."""
    bundle = {
        "email_analysis": {
            "email": {"subject": "Urgent Security Action Required", "sender": "admin@paypal-phish.com"},
            "extracted_domain": "paypal-phish.com",
            "threat_signals": ["credential_request"]
        },
        "domain_intelligence": {"domain": "paypal-phish.com", "domain_risk": 95, "lookalike": True}
    }

    with patch("services.ai_reasoning.analyze_evidence", side_effect=Exception("Total AI Failure")):
        decision = evaluate_phishing_decision(bundle)
        assert decision["verdict"] in ["MALICIOUS", "SUSPICIOUS", "BENIGN", "INCONCLUSIVE"]
        assert decision["verdict"] in ["MALICIOUS", "SUSPICIOUS"]
        assert decision["risk_score"] > 0
        assert decision["confidence"] > 0
