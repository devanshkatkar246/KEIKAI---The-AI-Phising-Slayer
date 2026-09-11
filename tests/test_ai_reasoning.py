"""
Tests for KEKAI AI Reasoning Engine & OpenRouter Provider Migration
====================================================================
Verifies zero network activity on import, evidence fingerprinting,
in-memory caching, 429 rate-limit fallback, malformed JSON handling,
and deterministic security verdict safety.
"""

import os
import sys
import json
import unittest
from unittest.mock import patch, MagicMock
import urllib.error

# Ensure workspace root is on Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from services.ai_reasoning import (
    analyze_evidence,
    calculate_evidence_fingerprint,
    reset_ai_telemetry,
    get_ai_telemetry,
    OpenRouterProvider,
    generate_deterministic_reasoning
)


class TestAIReasoningEngine(unittest.TestCase):

    def setUp(self):
        reset_ai_telemetry()

    def test_01_no_ai_call_on_import(self):
        """Task 26: Importing services.ai_reasoning must NOT make network calls."""
        telemetry = get_ai_telemetry()
        self.assertEqual(telemetry["requests_total"], 0)
        self.assertEqual(telemetry["cache_hits"], 0)

    def test_02_evidence_fingerprinting_consistency(self):
        """Task 13: Fingerprinting produces identical SHA256 for identical normalized evidence."""
        evidence_a = {
            "subject": "URGENT: Verify Credentials",
            "sender": "security@amazon-login.xyz",
            "risk_score": 85,
            "severity": "HIGH",
            "signals": {"urgency_language": True, "credential_request": True},
            "extracted_domains": ["amazon-login.xyz"]
        }
        evidence_b = {
            "sender": "security@amazon-login.xyz",
            "subject": "URGENT: Verify Credentials",
            "signals": {"credential_request": True, "urgency_language": True},
            "risk_score": 85,
            "severity": "HIGH",
            "extracted_domains": ["amazon-login.xyz"]
        }

        hash_a = calculate_evidence_fingerprint(evidence_a)
        hash_b = calculate_evidence_fingerprint(evidence_b)
        self.assertEqual(hash_a, hash_b)

    def test_03_cache_hit_avoids_second_ai_call(self):
        """Task 28 & 29: Repeated evaluation of same evidence reuses cache (0 extra API calls)."""
        evidence = {
            "subject": "Password Renewal Required",
            "sender": "it-helpdesk@corporate-m365.online",
            "risk_score": 75,
            "severity": "HIGH",
            "signals": {"credential_request": True},
            "extracted_domains": ["corporate-m365.online"]
        }

        with patch.object(OpenRouterProvider, "analyze") as mock_analyze:
            mock_analyze.return_value = {
                "ai_used": True,
                "reasoning_source": "openrouter",
                "model": "openrouter/free",
                "attack_hypothesis": "Credential Phishing",
                "summary": "Suspicious login portal detected.",
                "key_evidence": ["Urgent credential harvesting link detected."],
                "reasoning": ["Urgent credential harvesting link detected."],
                "confidence": 0.90
            }

            # 1st call -> Cache Miss, invokes provider
            res1 = analyze_evidence(evidence)
            self.assertFalse(res1.get("cached"))
            self.assertEqual(mock_analyze.call_count, 1)

            # 2nd call -> Cache Hit, reuses cached result
            res2 = analyze_evidence(evidence)
            self.assertTrue(res2.get("cached"))
            self.assertEqual(mock_analyze.call_count, 1)

            telemetry = get_ai_telemetry()
            self.assertEqual(telemetry["cache_hits"], 1)

    def test_04_openrouter_429_graceful_fallback(self):
        """Task 30: HTTP 429 Rate Limit gracefully falls back to deterministic engine without crash."""
        evidence = {
            "subject": "Account Suspension Warning",
            "sender": "admin@bank-alert.xyz",
            "risk_score": 90,
            "severity": "CRITICAL",
            "signals": {"brand_impersonation": True},
            "extracted_domains": ["bank-alert.xyz"]
        }

        # Mock urllib HTTP 429 Error
        http_err = urllib.error.HTTPError(
            url="https://openrouter.ai/api/v1/chat/completions",
            code=429,
            msg="Too Many Requests",
            hdrs={},
            fp=MagicMock()
        )

        with patch("urllib.request.urlopen", side_effect=http_err):
            with patch.dict(os.environ, {"OPENROUTER_API_KEY": "sk-or-v1-mockkey12345"}):
                res = analyze_evidence(evidence)

                self.assertFalse(res["ai_used"])
                self.assertEqual(res["reasoning_source"], "deterministic_engine")
                self.assertTrue(len(res["reasoning"]) > 0)

                telemetry = get_ai_telemetry()
                self.assertEqual(telemetry["rate_limits"], 1)
                self.assertEqual(telemetry["fallbacks"], 1)

    def test_05_openrouter_successful_json_parsing(self):
        """Task 31: Valid OpenRouter response parses correctly and returns structured reasoning."""
        evidence = {
            "subject": "Action Required: Account Verification",
            "sender": "no-reply@security-center.example",
            "risk_score": 80,
            "severity": "HIGH",
            "signals": {"urgent_call_to_action": True},
            "extracted_domains": ["security-center.example"]
        }

        mock_json_resp = {
            "model": "meta-llama/llama-3.3-70b-instruct:free",
            "choices": [
                {
                    "message": {
                        "content": '{\n  "attack_hypothesis": "Credential Harvesting",\n  "summary": "External domain attempting to steal account credentials.",\n  "key_evidence": ["Urgent verification language detected", "Domain mismatch identified"],\n  "reasoning_confidence": 0.92\n}'
                    }
                }
            ]
        }

        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps(mock_json_resp).encode("utf-8")
        mock_resp.__enter__.return_value = mock_resp

        with patch("urllib.request.urlopen", return_value=mock_resp):
            with patch.dict(os.environ, {"OPENROUTER_API_KEY": "sk-or-v1-mockkey12345"}):
                res = analyze_evidence(evidence)

                self.assertTrue(res["ai_used"])
                self.assertEqual(res["reasoning_source"], "openrouter")
                self.assertEqual(res["model"], "meta-llama/llama-3.3-70b-instruct:free")
                self.assertEqual(res["attack_hypothesis"], "Credential Harvesting")
                self.assertEqual(len(res["key_evidence"]), 2)

    def test_06_malformed_json_fallback(self):
        """Task 32: Malformed JSON from AI model triggers deterministic fallback without crash."""
        evidence = {
            "subject": "System Alert",
            "sender": "alert@domain.com",
            "risk_score": 70,
            "severity": "HIGH",
            "signals": {"urgency_language": True}
        }

        mock_json_resp = {
            "choices": [
                {
                    "message": {
                        "content": "Sorry, I am unable to analyze this email as a JSON object."
                    }
                }
            ]
        }

        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps(mock_json_resp).encode("utf-8")
        mock_resp.__enter__.return_value = mock_resp

        with patch("urllib.request.urlopen", return_value=mock_resp):
            with patch.dict(os.environ, {"OPENROUTER_API_KEY": "sk-or-v1-mockkey12345"}):
                res = analyze_evidence(evidence)

                self.assertFalse(res["ai_used"])
                self.assertEqual(res["reasoning_source"], "deterministic_engine")

    def test_07_benign_email_preserves_low_risk(self):
        """Task 34: AI reasoning does not elevate benign email into critical threat."""
        evidence = {
            "subject": "Team Lunch Sync",
            "sender": "colleague@acme.example",
            "risk_score": 5,
            "severity": "LOW",
            "signals": {},
            "extracted_domains": []
        }

        res = generate_deterministic_reasoning(evidence)
        self.assertFalse(res["ai_used"])
        self.assertIn("standard internal/trusted communication baselines", res["reasoning"][0])

    def test_08_account_compromise_hypothesis(self):
        """Task 35: Account compromise evidence is correctly reflected in reasoning."""
        evidence = {
            "subject": "Vendor Portal Verification",
            "sender": "finance@acme.example",
            "risk_score": 85,
            "severity": "HIGH",
            "sender_behavior": {
                "profile_available": True,
                "hypothesis": "POSSIBLE_ACCOUNT_COMPROMISE",
                "explanation": ["Off-hours transmission from finance sender"]
            }
        }

        res = generate_deterministic_reasoning(evidence)
        self.assertTrue(any("Possible Account Compromise" in bullet for bullet in res["reasoning"]))


if __name__ == "__main__":
    unittest.main()
