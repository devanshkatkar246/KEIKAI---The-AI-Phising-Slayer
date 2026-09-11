"""
test_sender_behavior.py

Unit and integration tests for KEIKAI Organisational Sender Behaviour Engine.
Tests:
1. Account compromise anomaly detection (off-hours + credential URL from low-URL sender)
2. External sender handling (no baseline profile available)
3. Benign internal email handling (normal operational hours + typical domain)
4. FastAPI endpoint POST /api/sender-behavior/analyze
"""

import unittest
from fastapi.testclient import TestClient
from main import app
from services.sender_behavior import evaluate_sender_behavior, parse_sending_hour

class TestSenderBehaviorEngine(unittest.TestCase):

    def setUp(self):
        self.client = TestClient(app)

    def test_parse_sending_hour(self):
        self.assertEqual(parse_sending_hour("Today, 14:22"), 14)
        self.assertEqual(parse_sending_hour("02:43"), 2)
        self.assertEqual(parse_sending_hour("2026-09-11T18:55:00Z"), 18)

    def test_account_compromise_scenario(self):
        res = evaluate_sender_behavior(
            sender="finance@acme.example",
            subject="URGENT: Verify Credentials Immediately",
            body="Please click https://amazon-security-login.example/auth/login.html to verify your account.",
            received_at="02:43",
            extracted_urls=["https://amazon-security-login.example/auth/login.html"],
            extracted_domains=["amazon-security-login.example"]
        )

        self.assertTrue(res["profile_available"])
        self.assertEqual(res["organisation"]["name"], "Acme Corporation")
        self.assertEqual(res["hypothesis"], "POSSIBLE_ACCOUNT_COMPROMISE")
        self.assertGreaterEqual(res["anomaly_score"], 60)
        self.assertGreaterEqual(len(res["signals"]), 2)

    def test_external_sender_no_baseline(self):
        res = evaluate_sender_behavior(
            sender="security-alert@amazon-security-login.example",
            subject="Account Alert",
            body="Verify account at https://amazon-security-login.example",
            extracted_urls=["https://amazon-security-login.example"],
            extracted_domains=["amazon-security-login.example"]
        )

        self.assertFalse(res["profile_available"])
        self.assertEqual(res["hypothesis"], "NO_BASELINE_AVAILABLE")
        self.assertEqual(res["anomaly_score"], 0)

    def test_benign_internal_email(self):
        res = evaluate_sender_behavior(
            sender="alex.rivers@corporate.internal",
            subject="Q3 Product Roadmap Review Meeting Notes",
            body="Hi Team, thanks for joining the roadmap review session.",
            received_at="09:15",
            extracted_urls=[],
            extracted_domains=["corporate.internal"]
        )

        self.assertTrue(res["profile_available"])
        self.assertEqual(res["hypothesis"], "BENIGN_INTERNAL")
        self.assertLess(res["anomaly_score"], 20)

    def test_sender_behavior_api_endpoint(self):
        payload = {
            "sender": "finance@acme.example",
            "subject": "Overdue Payment",
            "body": "Click https://untrusted-domain.com/login",
            "received_at": "03:15",
            "extracted_urls": ["https://untrusted-domain.com/login"],
            "extracted_domains": ["untrusted-domain.com"]
        }

        response = self.client.post("/api/sender-behavior/analyze", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["data"]["hypothesis"], "POSSIBLE_ACCOUNT_COMPROMISE")


if __name__ == "__main__":
    unittest.main()
