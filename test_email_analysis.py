"""
test_email_analysis.py — Unit & Integration Test Suite for Email Threat Analysis Pipeline
Runs via standard library unittest without external test runner dependencies.
"""

import unittest
import os
from fastapi.testclient import TestClient
from main import app
from services.email_analysis import (
    normalize_url,
    extract_iocs,
    detect_brand_mentions,
    analyze_security_signals,
    calculate_risk_and_threat_type,
    generate_deterministic_reasoning,
    analyze_email_threat
)


class TestEmailThreatAnalysis(unittest.TestCase):

    def setUp(self):
        self.client = TestClient(app)

    def test_01_url_normalization(self):
        # Test markdown format
        self.assertEqual(normalize_url("[https://example.com/login](https://example.com/login)"), "https://example.com/login")
        # Test angle brackets
        self.assertEqual(normalize_url("<https://example.com/login>"), "https://example.com/login")
        # Test trailing punctuation
        self.assertEqual(normalize_url("https://example.com/login."), "https://example.com/login")
        self.assertEqual(normalize_url("https://example.com/login)"), "https://example.com/login")
        # Test www. prefix
        self.assertEqual(normalize_url("www.example.com/login"), "https://www.example.com/login")
        # Test query strings preserved
        self.assertEqual(normalize_url("https://example.com/auth/login.html?ref=123&type=sec."), "https://example.com/auth/login.html?ref=123&type=sec")

    def test_02_url_extraction(self):
        text = "Please verify your account at [https://amazon-security-login.example/auth/login.html](https://amazon-security-login.example/auth/login.html) or <http://test.com>."
        iocs = extract_iocs(subject="Test", sender="test@example.com", body=text)
        self.assertGreaterEqual(len(iocs["urls"]), 2)
        self.assertIn("https://amazon-security-login.example/auth/login.html", iocs["urls"])
        self.assertNotIn("[https://amazon-security-login.example/auth/login.html](https://amazon-security-login.example/auth/login.html)", iocs["urls"])

    def test_03_domain_extraction(self):
        text = "Visit https://microsoft-update-portal.online/login or http://sub.domain.org/path"
        iocs = extract_iocs(subject="Test", sender="test@example.com", body=text)
        self.assertIn("microsoft-update-portal.online", iocs["domains"])
        self.assertIn("sub.domain.org", iocs["domains"])

    def test_04_email_address_extraction(self):
        text = "Contact support@company.com or billing-team@partner.net for details."
        iocs = extract_iocs(subject="Test", sender="security-alert@fake.com", body=text)
        self.assertIn("security-alert@fake.com", iocs["email_addresses"])
        self.assertIn("support@company.com", iocs["email_addresses"])

    def test_05_urgency_detection(self):
        signals, evidence = analyze_security_signals(
            subject="URGENT: Immediate Action Required",
            sender="alert@domain.com",
            body="Your account access has been temporarily restricted for security reasons. You must verify within 24 hours.",
            iocs={"urls": [], "domains": []}
        )
        self.assertTrue(signals["urgency_language"])
        self.assertTrue(any(e["type"] == "urgency" for e in evidence))

    def test_06_credential_harvesting_detection(self):
        signals, evidence = analyze_security_signals(
            subject="Account Update",
            sender="info@domain.com",
            body="Please click here to verify your credentials and reset password.",
            iocs={"urls": [], "domains": []}
        )
        self.assertTrue(signals["credential_request"])
        self.assertTrue(any(e["type"] == "credential_request" for e in evidence))

    def test_07_sender_domain_mismatch_and_brand_impersonation(self):
        signals, evidence = analyze_security_signals(
            subject="Amazon Security Suspension Notice",
            sender="security-alert@amazon-security-login.example",
            body="We detected unusual activity on your Amazon account. Verify now at https://amazon-security-login.example/login",
            iocs={"urls": ["https://amazon-security-login.example/login"], "domains": ["amazon-security-login.example"]}
        )
        self.assertTrue(signals["brand_impersonation"])
        self.assertTrue(signals["sender_domain_mismatch"])
        self.assertTrue(any(e["type"] == "brand_impersonation" for e in evidence))

    def test_08_phishing_classification_and_risk_scoring(self):
        signals = {
            "brand_impersonation": True,
            "credential_request": True,
            "suspicious_link": True,
            "urgency_language": True,
            "sender_domain_mismatch": True,
            "financial_request": False,
            "attachment_present": False
        }
        risk_score, severity, threat_type, confidence = calculate_risk_and_threat_type(
            signals=signals,
            evidence_list=[],
            iocs={"domains": ["fake-brand.com"]}
        )
        self.assertGreaterEqual(risk_score, 85)
        self.assertEqual(severity, "CRITICAL")
        self.assertTrue("credential" in threat_type or "impersonation" in threat_type)

    def test_09_benign_email_scoring(self):
        signals = {
            "brand_impersonation": False,
            "credential_request": False,
            "suspicious_link": False,
            "urgency_language": False,
            "sender_domain_mismatch": False,
            "financial_request": False,
            "attachment_present": False
        }
        risk_score, severity, threat_type, confidence = calculate_risk_and_threat_type(
            signals=signals,
            evidence_list=[],
            iocs={"domains": ["internal.company"]}
        )
        self.assertEqual(risk_score, 0)
        self.assertEqual(severity, "BENIGN")
        self.assertEqual(threat_type, "benign_email")

    def test_10_malformed_and_empty_email_input(self):
        result = analyze_email_threat(subject=None, sender=None, body=None)
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["risk_score"], 0)
        self.assertEqual(result["severity"], "BENIGN")
        self.assertFalse(result["investigation_ready"])

    def test_11_custom_email_api_endpoint(self):
        payload = {
            "subject": "URGENT: Corporate Password Expiration Notice",
            "sender": "admin@microsoft-update-portal.online",
            "body": "Your Microsoft 365 password expires today. Please renew your credentials at https://microsoft-update-portal.online/login"
        }
        response = self.client.post("/api/email-analyze", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["status"], "success")
        res = data["data"]
        self.assertGreaterEqual(res["risk_score"], 65)
        self.assertIn(res["severity"], ["HIGH", "CRITICAL"])
        self.assertEqual(res["extracted_domain"], "microsoft-update-portal.online")
        self.assertTrue(res["investigation_ready"])
        self.assertEqual(res["investigation_target"]["domain"], "microsoft-update-portal.online")

    def test_13_canonical_url_handoff_regression(self):
        # Regression test for Prompt #5 critical requirement:
        # Ensures email body containing markdown links produces exact clean canonical URL without markdown syntax.
        body_with_markdown = (
            "Dear Customer, please click below to verify:\n"
            "[https://amazon-security-login.example/auth/login.html](https://amazon-security-login.example/auth/login.html)\n"
            "or visit <https://microsoft-update-portal.online/login>."
        )
        result = analyze_email_threat(
            subject="URGENT: Account Suspension Notice",
            sender="security-alert@amazon-security-login.example",
            body=body_with_markdown
        )
        clean_url = result["extracted_url"]
        self.assertEqual(clean_url, "https://amazon-security-login.example/auth/login.html")
        self.assertNotIn("[", clean_url)
        self.assertNotIn("]", clean_url)
        self.assertNotIn("(", clean_url)
        self.assertNotIn(")", clean_url)
        self.assertEqual(result["investigation_target"]["url"], "https://amazon-security-login.example/auth/login.html")

    def test_14_multi_signal_correlation_and_confidence(self):
        result = analyze_email_threat(
            subject="URGENT: Your Amazon Business Account has been suspended",
            sender="security-alert@amazon-security-login.example",
            body="Verify your credentials immediately at https://amazon-security-login.example/auth/login.html"
        )
        self.assertGreaterEqual(result["risk_score"], 80)
        self.assertGreaterEqual(result["confidence"], 0.80)
        self.assertEqual(result["severity"], "CRITICAL")
        self.assertTrue(result["signals"]["brand_impersonation"])
        self.assertTrue(result["signals"]["credential_request"])

    def test_15_source_availability_handling(self):
        # Ensures that missing optional data does not collapse risk score to zero
        result = analyze_email_threat(
            subject="Password Expiration Notice",
            sender="admin@microsoft-update-portal.online",
            body="Please renew password at https://microsoft-update-portal.online/login"
        )
        self.assertGreater(result["risk_score"], 0)
        self.assertIsNotNone(result["extracted_domain"])
        self.assertTrue(result["investigation_ready"])

    def test_16_full_amazon_end_to_end_chain(self):
        payload = {
            "subject": "URGENT: Your Amazon Business Account has been suspended",
            "sender": "security-alert@amazon-security-login.example",
            "body": "Your account access has been restricted. Verify credentials at https://amazon-security-login.example/auth/login.html"
        }
        response = self.client.post("/api/email-analyze", json=payload)
        self.assertEqual(response.status_code, 200)
        res = response.json()["data"]
        self.assertEqual(res["extracted_domain"], "amazon-security-login.example")
        self.assertEqual(res["extracted_url"], "https://amazon-security-login.example/auth/login.html")
        self.assertEqual(res["investigation_target"]["domain"], "amazon-security-login.example")
        self.assertEqual(res["investigation_target"]["url"], "https://amazon-security-login.example/auth/login.html")


if __name__ == "__main__":
    unittest.main()
