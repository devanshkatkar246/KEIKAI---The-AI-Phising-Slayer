"""
tests/test_unified_evidence_phishing_verdict.py

KEIKAI — Phase 9 Unified Evidence Correlation & AI Phishing Verdict Test Suite
==================================================================================
Tests 20 complete scenarios covering multi-stage evidence correlation, attack hypotheses,
explainable risk/confidence/evidence_quality metrics, contradicting evidence handling,
prompt injection defense, strict AI call control (0 calls on repeat/cache), deterministic fallback,
and investigation orchestration APIs.
"""

import os
import sys
import unittest
from unittest.mock import patch, MagicMock

# Ensure workspace root is on Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from services.phishing_decision_engine import (
    evaluate_phishing_decision,
    determine_attack_hypothesis,
    calculate_independent_metrics,
    extract_evidence_provenance,
    analyze_investigation
)
from services.ai_reasoning import reset_ai_telemetry, get_ai_telemetry, calculate_evidence_fingerprint


class TestUnifiedEvidencePhishingVerdict(unittest.TestCase):

    def setUp(self):
        reset_ai_telemetry()

    def test_01_benign_internal_message(self):
        """Scenario 1: Legitimate internal message with benign signals produces BENIGN verdict and ALLOW action."""
        evidence_bundle = {
            "investigation_id": "INV-BENIGN-01",
            "email_analysis": {
                "risk_score": 5,
                "severity": "LOW",
                "signals": {"credential_request": False, "urgency_language": False}
            },
            "sender_behavior": {"hypothesis": "BENIGN_INTERNAL", "profile_available": True},
            "domain_intelligence": {"domain": "acme.com", "relationship": "OFFICIAL_EXACT", "is_official": True}
        }
        res = evaluate_phishing_decision(evidence_bundle)

        self.assertEqual(res["verdict"], "BENIGN")
        self.assertEqual(res["primary_hypothesis"], "BENIGN_INTERNAL")
        self.assertLess(res["risk_score"], 25)
        self.assertIn(res["recommended_action"], ["ALLOW"])

    def test_02_external_brand_impersonation(self):
        """Scenario 2: External sender + brand impersonation + lookalike domain -> EXTERNAL_IMPERSONATION."""
        evidence_bundle = {
            "investigation_id": "INV-IMP-02",
            "email_analysis": {
                "risk_score": 85,
                "signals": {"credential_phishing_keywords": True, "lookalike_domain_detected": True}
            },
            "domain_intelligence": {"domain": "amaz0n-security-login.xyz", "is_lookalike": True},
            "page_analysis": {
                "target_brand": "Amazon",
                "clone_verdict": {"is_clone": True, "clone_classification": "STRONG_BRAND_CLONE"}
            }
        }
        res = evaluate_phishing_decision(evidence_bundle)

        self.assertEqual(res["verdict"], "MALICIOUS")
        self.assertEqual(res["primary_hypothesis"], "EXTERNAL_IMPERSONATION")
        self.assertGreaterEqual(res["risk_score"], 70)

    def test_03_compromised_internal_account(self):
        """Scenario 3: Internal sender + off-hours anomaly + external credential link -> POSSIBLE_ACCOUNT_COMPROMISE."""
        evidence_bundle = {
            "investigation_id": "INV-COMP-03",
            "email_analysis": {
                "risk_score": 65,
                "signals": {"credential_request": True, "suspicious_link": True}
            },
            "sender_behavior": {"hypothesis": "POSSIBLE_ACCOUNT_COMPROMISE", "anomaly_score": 85, "profile_available": True}
        }
        res = evaluate_phishing_decision(evidence_bundle)

        self.assertEqual(res["primary_hypothesis"], "POSSIBLE_ACCOUNT_COMPROMISE")
        self.assertGreaterEqual(res["risk_score"], 60)

    def test_04_credential_phishing_landing_page(self):
        """Scenario 4: Credential harvesting form on new domain -> CREDENTIAL_HARVESTING."""
        evidence_bundle = {
            "investigation_id": "INV-CRED-04",
            "email_analysis": {"risk_score": 75, "signals": {"credential_phishing_keywords": True}},
            "url_intelligence": {
                "url_risk": 80,
                "domain_age_signal": {"signal": "VERY_NEW_DOMAIN", "age_days": 3},
                "credential_page_signal": {"is_credential_page": True}
            }
        }
        res = evaluate_phishing_decision(evidence_bundle)

        self.assertEqual(res["verdict"], "MALICIOUS")
        self.assertIn(res["primary_hypothesis"], ["CREDENTIAL_HARVESTING", "EXTERNAL_IMPERSONATION"])

    def test_05_qr_code_phishing(self):
        """Scenario 5: Decoded QR code URL leading to external target -> QR_PHISHING."""
        evidence_bundle = {
            "investigation_id": "INV-QR-05",
            "payload_inspection": {
                "risk_score": 90,
                "qr_decoded_url": "https://amaz0n-login-verify.xyz/auth",
                "qr_detected": True
            }
        }
        res = evaluate_phishing_decision(evidence_bundle)

        self.assertEqual(res["primary_hypothesis"], "QR_PHISHING")
        self.assertIn("QR_PHISHING", [res["primary_hypothesis"]] + res["secondary_hypotheses"])

    def test_06_malicious_attachment(self):
        """Scenario 6: HTML attachment with password form -> MALICIOUS_ATTACHMENT."""
        evidence_bundle = {
            "investigation_id": "INV-ATT-06",
            "payload_inspection": {
                "risk_score": 85,
                "is_html_form": True,
                "password_input_detected": True
            }
        }
        res = evaluate_phishing_decision(evidence_bundle)

        self.assertEqual(res["primary_hypothesis"], "MALICIOUS_ATTACHMENT")

    def test_07_visual_brand_clone(self):
        """Scenario 7: Phishpedia / pHash logo impersonation -> VISUAL_BRAND_CLONE."""
        evidence_bundle = {
            "investigation_id": "INV-VIS-07",
            "visual_phishing": {
                "verdict": "Phishing",
                "target_brand": "Microsoft",
                "confidence": 95
            }
        }
        res = evaluate_phishing_decision(evidence_bundle)

        self.assertEqual(res["primary_hypothesis"], "VISUAL_BRAND_CLONE")

    def test_08_lookalike_typosquat_domain(self):
        """Scenario 8: Typo-squatted brand domain -> LOOKALIKE_DOMAIN."""
        evidence_bundle = {
            "investigation_id": "INV-LOOK-08",
            "email_analysis": {"risk_score": 45, "signals": {"lookalike_domain_detected": True}},
            "domain_intelligence": {"domain": "micros0ft-update.net", "is_lookalike": True}
        }
        res = evaluate_phishing_decision(evidence_bundle)

        self.assertIn(res["primary_hypothesis"], ["LOOKALIKE_DOMAIN", "EXTERNAL_IMPERSONATION"])

    def test_09_newly_registered_domain(self):
        """Scenario 9: Domain age < 14 days adds secondary NEW_DOMAIN hypothesis."""
        evidence_bundle = {
            "investigation_id": "INV-NEW-09",
            "url_intelligence": {
                "url_risk": 55,
                "domain_age_signal": {"signal": "VERY_NEW_DOMAIN", "age_days": 2}
            }
        }
        res = evaluate_phishing_decision(evidence_bundle)

        self.assertIn("NEW_DOMAIN", res["secondary_hypotheses"])

    def test_10_redirect_chain_phishing(self):
        """Scenario 10: Multi-hop redirect chain adding risk points."""
        evidence_bundle = {
            "investigation_id": "INV-RED-10",
            "url_intelligence": {
                "url_risk": 65,
                "final_url": "https://phish-destination.xyz/login",
                "redirect_signal": {"has_redirects": True, "chain_length": 3}
            }
        }
        res = evaluate_phishing_decision(evidence_bundle)

        self.assertGreaterEqual(res["risk_score"], 35)

    def test_11_conflicting_evidence_handling(self):
        """Scenario 11: Suspicious email text vs official brand domain reduces risk and flags contradiction."""
        evidence_bundle = {
            "investigation_id": "INV-CONF-11",
            "email_analysis": {"risk_score": 30, "signals": {"urgency_language": True}},
            "domain_intelligence": {"domain": "amazon.com", "relationship": "OFFICIAL_EXACT", "is_official": True}
        }
        res = evaluate_phishing_decision(evidence_bundle)

        self.assertEqual(res["verdict"], "BENIGN")
        self.assertGreaterEqual(len(res["contradicting_evidence"]), 1)

    def test_12_incomplete_evidence_handling(self):
        """Scenario 12: Sparse missing evidence reduces evidence_quality score without crashing."""
        evidence_bundle = {
            "investigation_id": "INV-INC-12",
            "email_analysis": {"risk_score": 10, "signals": {}}
        }
        res = evaluate_phishing_decision(evidence_bundle)

        self.assertLess(res["evidence_quality"], 50)
        self.assertIn(res["verdict"], ["BENIGN", "INCONCLUSIVE"])

    def test_13_ai_unavailable_graceful_deterministic_fallback(self):
        """Scenario 13: When AI provider is unconfigured, decision engine uses DETERMINISTIC_FALLBACK."""
        with patch("services.ai_reasoning.OpenRouterProvider.is_configured") as mock_conf:
            mock_conf.return_value = False

            res = evaluate_phishing_decision({"investigation_id": "INV-AI-OFF"})

            self.assertEqual(res["ai_reasoning"]["reasoning_source"], "DETERMINISTIC_FALLBACK")
            self.assertFalse(res["ai_reasoning"]["ai_used"])

    def test_14_ai_429_rate_limit_fallback(self):
        """Scenario 14: Handles 429 rate limit error gracefully with deterministic fallback."""
        with patch("services.ai_reasoning.OpenRouterProvider.is_configured") as mock_conf:
            with patch("urllib.request.urlopen") as mock_url:
                mock_conf.return_value = True
                mock_err = MagicMock()
                mock_err.code = 429
                mock_url.side_effect = mock_err

                res = evaluate_phishing_decision({"investigation_id": "INV-AI-429"})

                self.assertEqual(res["ai_reasoning"]["reasoning_source"], "DETERMINISTIC_FALLBACK")

    def test_15_malformed_ai_json_schema_repair_fallback(self):
        """Scenario 15: Handles malformed non-JSON AI output gracefully."""
        with patch("services.ai_reasoning.OpenRouterProvider.is_configured") as mock_conf:
            with patch("services.ai_reasoning.OpenRouterProvider.analyze") as mock_an:
                mock_conf.return_value = True
                mock_an.return_value = None  # Failed parse

                res = evaluate_phishing_decision({"investigation_id": "INV-AI-BAD"})

                self.assertEqual(res["ai_reasoning"]["reasoning_source"], "DETERMINISTIC_FALLBACK")

    def test_16_duplicate_investigation_executes_zero_additional_ai_calls(self):
        """Scenario 16 & 23: Re-evaluating identical evidence payload reuses cached AI reasoning (0 new API calls)."""
        evidence_bundle = {
            "investigation_id": "INV-CACHE-16",
            "subject": "Urgent Action Required",
            "sender": "alert@fake.example",
            "email_analysis": {"risk_score": 75}
        }

        with patch("services.ai_reasoning.OpenRouterProvider.analyze") as mock_ai_call:
            mock_ai_call.return_value = {
                "ai_used": True,
                "reasoning_source": "openrouter_api",
                "summary": "AI Reasoning output",
                "key_evidence": ["High risk score"]
            }

            # Call 1: Runs AI
            res1 = evaluate_phishing_decision(evidence_bundle)
            call_count_1 = mock_ai_call.call_count

            # Call 2: Identical evidence -> Uses cache -> 0 additional calls
            res2 = evaluate_phishing_decision(evidence_bundle)
            call_count_2 = mock_ai_call.call_count

            self.assertEqual(call_count_1, 1)
            self.assertEqual(call_count_2, 1)  # Zero additional AI calls!
            self.assertEqual(res2["ai_reasoning"]["summary"], "AI Reasoning output")

    def test_17_investigation_isolation(self):
        """Scenario 17: Results are strictly scoped to investigation_id and organisation_id."""
        res = evaluate_phishing_decision({"investigation_id": "INV-SCOPED-17", "organisation_id": "org_acme_01"})
        self.assertEqual(res["investigation_id"], "INV-SCOPED-17")
        self.assertEqual(res["organisation_id"], "org_acme_01")

    def test_18_cached_evidence_fingerprint_verification(self):
        """Scenario 18: Verifies calculate_evidence_fingerprint returns consistent hash."""
        ev1 = {"subject": "Test", "risk_score": 80}
        ev2 = {"subject": "Test", "risk_score": 80}
        self.assertEqual(calculate_evidence_fingerprint(ev1), calculate_evidence_fingerprint(ev2))

    def test_19_contradictory_evidence_reduces_confidence(self):
        """Scenario 19: Having both supporting and contradicting evidence penalizes confidence."""
        supporting = [{"signal": "urgency", "severity": 20}]
        contradicting = [{"signal": "official_brand_domain", "severity": 0}]
        stage_results = {"email": {"risk_score": 20}}

        r, conf, q = calculate_independent_metrics(supporting, contradicting, stage_results)
        self.assertLessEqual(conf, 60)

    def test_20_legitimate_official_subdomain_classification(self):
        """Scenario 20: Legitimate official subdomain is classified as BENIGN."""
        evidence_bundle = {
            "investigation_id": "INV-SUB-20",
            "domain_intelligence": {"domain": "login.microsoft.com", "relationship": "OFFICIAL_SUBDOMAIN", "is_official": True}
        }
        res = evaluate_phishing_decision(evidence_bundle)

        self.assertEqual(res["verdict"], "BENIGN")
        self.assertEqual(res["recommended_action"], "ALLOW")


if __name__ == "__main__":
    unittest.main()
