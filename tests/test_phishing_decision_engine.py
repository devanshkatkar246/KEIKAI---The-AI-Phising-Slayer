"""
Tests for Unified Organisational Phishing Decision Engine (Phase 5)
====================================================================
Verifies multi-stage evidence correlation, independent metric calculations
(risk_score vs confidence vs evidence_quality), attack hypothesis resolution,
evidence provenance tracking, and AI provider fallback safety.
"""

import os
import sys
import unittest
from unittest.mock import patch, MagicMock

# Ensure workspace root is on Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from services.phishing_decision_engine import evaluate_phishing_decision, DECISION_VERSION
from services.ai_reasoning import reset_ai_telemetry, OpenRouterProvider


class TestPhishingDecisionEngine(unittest.TestCase):

    def setUp(self):
        reset_ai_telemetry()

    def test_01_benign_internal_email(self):
        """Scenario 1: Legitimate internal team email matching organizational baseline."""
        evidence_bundle = {
            "email_analysis": {
                "email": {
                    "subject": "Q3 Product Roadmap Review Meeting Notes",
                    "sender": "alex.rivers@corporate.internal"
                },
                "risk_score": 5,
                "severity": "LOW",
                "signals": {}
            },
            "sender_behavior": {
                "profile_available": True,
                "hypothesis": "BENIGN_INTERNAL",
                "anomaly_score": 5
            },
            "domain_intelligence": {
                "domain": "corporate.internal",
                "is_official": True,
                "relationship": "OFFICIAL_EXACT"
            }
        }

        result = evaluate_phishing_decision(evidence_bundle)
        self.assertEqual(result["verdict"], "BENIGN")
        self.assertEqual(result["attack_hypothesis"], "BENIGN_INTERNAL")
        self.assertLess(result["risk_score"], 20)
        self.assertEqual(result["recommended_action"], "ALLOW")
        self.assertTrue(len(result["contradicting_evidence"]) > 0)

    def test_02_external_impersonation(self):
        """Scenario 2: External sender impersonating Amazon from lookalike domain."""
        evidence_bundle = {
            "email_analysis": {
                "email": {
                    "subject": "URGENT: Your Amazon Business Account has been suspended",
                    "sender": "security-alert@amazon-security-login.example"
                },
                "risk_score": 85,
                "severity": "HIGH",
                "signals": {
                    "brand_impersonation": True,
                    "urgency_language": True,
                    "lookalike_domain_detected": True,
                    "credential_request": True
                }
            },
            "domain_intelligence": {
                "domain": "amazon-security-login.example",
                "relationship": "LOOKALIKE",
                "lookalike": True
            }
        }

        result = evaluate_phishing_decision(evidence_bundle)
        self.assertEqual(result["verdict"], "MALICIOUS")
        self.assertEqual(result["attack_hypothesis"], "EXTERNAL_IMPERSONATION")
        self.assertGreaterEqual(result["risk_score"], 70)
        self.assertEqual(result["recommended_action"], "BLOCK_AND_QUARANTINE")

    def test_03_compromised_internal_account(self):
        """Scenario 3: Internal sender (finance@acme.example) off-hours credential verification link."""
        evidence_bundle = {
            "email_analysis": {
                "email": {
                    "subject": "URGENT: Corporate Vendor Account Login Verification Required",
                    "sender": "finance@acme.example"
                },
                "risk_score": 80,
                "severity": "HIGH",
                "signals": {
                    "credential_request": True,
                    "urgency_language": True,
                    "suspicious_domain_mismatch": True
                }
            },
            "sender_behavior": {
                "profile_available": True,
                "hypothesis": "POSSIBLE_ACCOUNT_COMPROMISE",
                "anomaly_score": 85
            },
            "domain_intelligence": {
                "domain": "amazon-security-login.example",
                "relationship": "LOOKALIKE"
            }
        }

        result = evaluate_phishing_decision(evidence_bundle)
        self.assertEqual(result["verdict"], "MALICIOUS")
        self.assertEqual(result["attack_hypothesis"], "POSSIBLE_ACCOUNT_COMPROMISE")
        self.assertGreaterEqual(result["risk_score"], 75)
        self.assertEqual(result["recommended_action"], "BLOCK_AND_QUARANTINE")

    def test_04_credential_phishing(self):
        """Scenario 4: Credential harvesting keywords and password update link."""
        evidence_bundle = {
            "email_analysis": {
                "email": {
                    "subject": "Action Required: Corporate Password Expires Today",
                    "sender": "no-reply@microsoft-update-portal.online"
                },
                "risk_score": 75,
                "severity": "HIGH",
                "signals": {
                    "credential_phishing_keywords": True,
                    "urgency_language": True,
                    "untrusted_tld": True
                }
            }
        }

        result = evaluate_phishing_decision(evidence_bundle)
        self.assertEqual(result["verdict"], "MALICIOUS")
        self.assertEqual(result["attack_hypothesis"], "CREDENTIAL_HARVESTING")

    def test_05_qr_phishing(self):
        """Scenario 5: Decoded QR code credential URL."""
        evidence_bundle = {
            "email_analysis": {
                "email": {
                    "subject": "Security Update QR Code",
                    "sender": "security@company-alert.com"
                },
                "risk_score": 60,
                "severity": "MEDIUM",
                "signals": {}
            },
            "payload_inspection": {
                "qr_decoded_url": "https://microsoft-update-portal.online/login",
                "risk_score": 80
            }
        }

        result = evaluate_phishing_decision(evidence_bundle)
        self.assertEqual(result["verdict"], "MALICIOUS")
        self.assertEqual(result["attack_hypothesis"], "QR_PHISHING")

    def test_06_malicious_attachment(self):
        """Scenario 6: Attachment containing HTML credential harvesting form."""
        evidence_bundle = {
            "payload_inspection": {
                "is_html_form": True,
                "risk_score": 85,
                "has_login_form": True
            }
        }

        result = evaluate_phishing_decision(evidence_bundle)
        self.assertEqual(result["verdict"], "MALICIOUS")
        self.assertEqual(result["attack_hypothesis"], "MALICIOUS_ATTACHMENT")

    def test_07_visual_brand_clone(self):
        """Scenario 7: Visual Phishing / Phishpedia logo clone match."""
        evidence_bundle = {
            "visual_phishing": {
                "verdict": "Phishing",
                "target_brand": "Amazon",
                "confidence": 95.0,
                "overall_status": "CONFIRMED"
            },
            "domain_intelligence": {
                "domain": "amaz0n-security-login.xyz",
                "relationship": "LOOKALIKE"
            }
        }

        result = evaluate_phishing_decision(evidence_bundle)
        self.assertEqual(result["verdict"], "MALICIOUS")
        self.assertEqual(result["attack_hypothesis"], "VISUAL_BRAND_CLONE")

    def test_08_lookalike_domain(self):
        """Scenario 8: Registered typo-squatted lookalike domain."""
        evidence_bundle = {
            "domain_intelligence": {
                "domain": "amaz0n-login.xyz",
                "relationship": "LOOKALIKE",
                "lookalike": True
            }
        }

        result = evaluate_phishing_decision(evidence_bundle)
        self.assertIn(result["verdict"], ["SUSPICIOUS", "MALICIOUS"])
        self.assertEqual(result["attack_hypothesis"], "LOOKALIKE_DOMAIN")

    def test_09_conflicting_evidence(self):
        """Scenario 9: Sender display name mismatch but target is verified official brand domain."""
        evidence_bundle = {
            "email_analysis": {
                "email": {
                    "subject": "Official Acme Security Update",
                    "sender": "support@acme.com"
                },
                "signals": {
                    "urgency_language": True
                }
            },
            "domain_intelligence": {
                "domain": "acme.com",
                "is_official": True,
                "relationship": "OFFICIAL_EXACT"
            }
        }

        result = evaluate_phishing_decision(evidence_bundle)
        self.assertEqual(result["verdict"], "BENIGN")
        self.assertTrue(len(result["contradicting_evidence"]) > 0)
        # Confidence score penalizes conflict cleanly
        self.assertLessEqual(result["confidence"], 85)

    def test_10_missing_sparse_evidence(self):
        """Scenario 10: Sparse evidence (only email subject provided)."""
        evidence_bundle = {
            "email_analysis": {
                "email": {
                    "subject": "Hello"
                }
            }
        }

        result = evaluate_phishing_decision(evidence_bundle)
        self.assertIn(result["verdict"], ["BENIGN", "INCONCLUSIVE"])
        self.assertLess(result["evidence_quality"], 30)

    def test_11_ai_unavailable_fallback(self):
        """Scenario 11: AI provider returns HTTP 429 / is unconfigured -> deterministic engine works 100%."""
        evidence_bundle = {
            "email_analysis": {
                "email": {
                    "subject": "Verify Account",
                    "sender": "admin@phish.xyz"
                },
                "risk_score": 75,
                "severity": "HIGH",
                "signals": {"credential_request": True}
            }
        }

        with patch.object(OpenRouterProvider, "analyze", return_value=None):
            result = evaluate_phishing_decision(evidence_bundle)
            self.assertEqual(result["verdict"], "MALICIOUS")
            self.assertFalse(result["ai_reasoning"]["ai_used"])
            self.assertEqual(result["ai_reasoning"]["reasoning_source"], "deterministic_engine")

    def test_12_malformed_ai_output(self):
        """Scenario 12: OpenRouter returns non-JSON or malformed output -> deterministic fallback."""
        evidence_bundle = {
            "email_analysis": {
                "email": {
                    "subject": "Suspicious Activity",
                    "sender": "alert@domain.xyz"
                },
                "risk_score": 80,
                "signals": {"credential_phishing_keywords": True}
            }
        }

        with patch("urllib.request.urlopen", side_effect=Exception("Invalid JSON response")):
            with patch.dict(os.environ, {"OPENROUTER_API_KEY": "sk-or-testkey"}):
                result = evaluate_phishing_decision(evidence_bundle)
                self.assertEqual(result["verdict"], "MALICIOUS")
                self.assertFalse(result["ai_reasoning"]["ai_used"])
                self.assertEqual(result["ai_reasoning"]["reasoning_source"], "deterministic_engine")


if __name__ == "__main__":
    unittest.main()
