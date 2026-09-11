"""
Tests for Pre-Interaction Policy & Enforcement Engine (Phase 6)
===============================================================
Verifies pre-interaction policy enforcement actions (ALLOW, WARN, QUARANTINE,
BLOCK, ANALYST_REVIEW), audit logging, organisation policy customization,
analyst manual overrides, and MessageSourceAdapter normalization.
"""

import os
import sys
import unittest

# Ensure workspace root is on Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from services.message_ingestion import (
    StandardMessageAdapter,
    MessageSourceAdapter,
    ingest_pre_interaction_message
)
from services.policy_engine import (
    evaluate_message_policy,
    get_audit_record,
    list_audit_records,
    set_organisation_policy,
    get_organisation_policy
)


class TestPolicyEngine(unittest.TestCase):

    def test_01_high_risk_quarantine(self):
        """Task 11: High-risk threat message with moderate confidence -> QUARANTINE."""
        msg = ingest_pre_interaction_message({
            "sender": "security-alert@amazon-login.xyz",
            "subject": "Account Suspension Warning",
            "body": "Please verify credentials."
        })
        decision_verdict = {
            "verdict": "MALICIOUS",
            "risk_score": 85,
            "confidence": 65,  # Moderate confidence
            "evidence_quality": 80,
            "attack_hypothesis": "EXTERNAL_IMPERSONATION",
            "primary_reasons": ["Brand impersonation detected"]
        }

        res = evaluate_message_policy(msg, decision_verdict)
        self.assertEqual(res["action"], "QUARANTINE")
        self.assertEqual(res["decision"], "QUARANTINE")
        self.assertIn("audit_id", res)

    def test_02_high_risk_credential_phishing_block(self):
        """Task 11: High-risk credential phishing threat -> BLOCK."""
        msg = ingest_pre_interaction_message({
            "sender": "no-reply@microsoft-update-portal.online",
            "subject": "Action Required: Password Expired",
            "body": "Renew credentials at portal."
        })
        decision_verdict = {
            "verdict": "MALICIOUS",
            "risk_score": 90,
            "confidence": 95,
            "evidence_quality": 85,
            "attack_hypothesis": "CREDENTIAL_HARVESTING",
            "primary_reasons": ["Credential harvesting keywords detected"]
        }

        res = evaluate_message_policy(msg, decision_verdict)
        self.assertEqual(res["action"], "BLOCK")
        self.assertEqual(res["decision"], "BLOCK")

    def test_03_uncertain_evidence_analyst_review(self):
        """Task 11: High risk score with low evidence quality (< 35) -> ANALYST_REVIEW."""
        msg = ingest_pre_interaction_message({
            "sender": "unknown@domain.xyz",
            "subject": "Urgent Alert"
        })
        decision_verdict = {
            "verdict": "MALICIOUS",
            "risk_score": 80,
            "confidence": 50,
            "evidence_quality": 20,  # Low quality (< 35)
            "attack_hypothesis": "CREDENTIAL_HARVESTING",
            "primary_reasons": ["Uncertain payload"]
        }

        res = evaluate_message_policy(msg, decision_verdict)
        self.assertEqual(res["action"], "ANALYST_REVIEW")

    def test_04_benign_internal_allow(self):
        """Task 11: Benign internal message -> ALLOW."""
        msg = ingest_pre_interaction_message({
            "sender": "alex.rivers@corporate.internal",
            "subject": "Meeting Notes",
            "body": "See team wiki."
        })
        decision_verdict = {
            "verdict": "BENIGN",
            "risk_score": 5,
            "confidence": 95,
            "evidence_quality": 80,
            "attack_hypothesis": "BENIGN_INTERNAL",
            "primary_reasons": ["Normal internal communication"]
        }

        res = evaluate_message_policy(msg, decision_verdict)
        self.assertEqual(res["action"], "ALLOW")

    def test_05_medium_risk_warn(self):
        """Task 11: Medium risk message -> WARN."""
        msg = ingest_pre_interaction_message({
            "sender": "info@external-vendor.com",
            "subject": "Vendor Notice",
            "body": "Update billing details."
        })
        decision_verdict = {
            "verdict": "SUSPICIOUS",
            "risk_score": 55,
            "confidence": 80,
            "evidence_quality": 70,
            "attack_hypothesis": "LOOKALIKE_DOMAIN",
            "primary_reasons": ["Medium risk vendor notice"]
        }

        res = evaluate_message_policy(msg, decision_verdict)
        self.assertEqual(res["action"], "WARN")

    def test_06_analyst_override(self):
        """Task 11 & 8: SOC Analyst manual override takes precedence and logs audit event."""
        msg = ingest_pre_interaction_message({
            "sender": "finance@acme.example",
            "subject": "Vendor Verification"
        })
        decision_verdict = {
            "verdict": "MALICIOUS",
            "risk_score": 85,
            "confidence": 90,
            "evidence_quality": 85,
            "attack_hypothesis": "POSSIBLE_ACCOUNT_COMPROMISE"
        }

        # Analyst overrides MALICIOUS to ALLOW with rationale
        override_payload = {
            "override_action": "ALLOW",
            "analyst_id": "soc_analyst_42",
            "rationale": "Verified via secondary out-of-band phone call."
        }

        res = evaluate_message_policy(msg, decision_verdict, policy_override=override_payload)
        self.assertEqual(res["action"], "ALLOW")
        self.assertTrue(res["override"]["is_override"])
        self.assertEqual(res["override"]["analyst_id"], "soc_analyst_42")

    def test_07_custom_organisation_policy(self):
        """Task 11 & 5: Configurable per-organisation policies."""
        org_id = "org_custom_strict"
        set_organisation_policy(org_id, {
            "high_risk_threshold": 60,  # Strict threshold
            "auto_block_enabled": True
        })

        msg = ingest_pre_interaction_message({
            "sender": "alert@suspicious.xyz",
            "subject": "Password Reset",
            "organisation_id": org_id
        })
        decision_verdict = {
            "verdict": "SUSPICIOUS",
            "risk_score": 65,  # Above 60 strict threshold
            "confidence": 90,
            "evidence_quality": 80,
            "attack_hypothesis": "CREDENTIAL_HARVESTING"
        }

        res = evaluate_message_policy(msg, decision_verdict)
        self.assertEqual(res["action"], "BLOCK")

    def test_08_audit_logging_and_retrieval(self):
        """Task 11 & 7: Pre-interaction audit log record creation and retrieval."""
        msg = ingest_pre_interaction_message({
            "sender": "test@audit-log.example",
            "subject": "Audit Trail Test"
        })
        decision_verdict = {
            "verdict": "BENIGN",
            "risk_score": 0,
            "confidence": 90,
            "evidence_quality": 80,
            "attack_hypothesis": "BENIGN_INTERNAL"
        }

        res = evaluate_message_policy(msg, decision_verdict)
        audit_id = res["audit_id"]

        retrieved = get_audit_record(audit_id)
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved["message_id"], msg.message_id)

    def test_09_message_source_adapter_normalization(self):
        """Task 12: MessageSourceAdapter interface & StandardMessageAdapter normalization."""
        adapter = StandardMessageAdapter()
        self.assertTrue(issubclass(StandardMessageAdapter, MessageSourceAdapter))

        raw_input = {
            "from": "user@external.com",
            "to": "target@corporate.com",
            "subject": "Invoice Attached",
            "body": "Check https://amazon-security-login.example for payment details",
            "attachments": [
                {"name": "invoice.html", "content_type": "text/html", "is_html_form": True}
            ]
        }

        norm = adapter.ingest(raw_input)
        self.assertEqual(norm.sender, "user@external.com")
        self.assertIn("https://amazon-security-login.example", norm.urls)
        self.assertEqual(len(norm.attachments_metadata), 1)
        self.assertTrue(norm.attachments_metadata[0].has_html_form)


if __name__ == "__main__":
    unittest.main()
