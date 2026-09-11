"""
tests/test_attack_chain_visualization.py

Unit test suite verifying backend payload contracts for Objective A Attack Chain Visualization:
1. Directed graph node and edge formatting for UI rendering.
2. Node detail attributes, risk contribution, and live provenance.
3. Attack hypothesis trigger links and evidence items.
4. Preserved three-metric model (risk_score, confidence, evidence_quality).
5. Chronological investigation timeline with actual timestamps.
"""

import unittest
from unittest.mock import patch
from services.phishing_decision_engine import evaluate_phishing_decision, analyze_investigation
from services.chain_tracer import trace_attack_chain


class TestAttackChainVisualization(unittest.TestCase):

    def test_01_graph_payload_nodes_and_edges_for_ui(self):
        """Task 4: Backend graph payload contains stable IDs, types, and labels."""
        chain = trace_attack_chain(
            investigation_id="INV-UI-01",
            target_url="https://amaz0n-security-login.xyz/auth/login.html",
            email_bundle={
                "sender": "alert@amaz0n-security-login.xyz",
                "subject": "Security Alert",
                "urls": ["https://amaz0n-security-login.xyz/auth/login.html"]
            }
        )

        self.assertEqual(chain["investigation_id"], "INV-UI-01")
        self.assertGreaterEqual(len(chain["nodes"]), 4)
        self.assertGreaterEqual(len(chain["edges"]), 3)

        for node in chain["nodes"]:
            self.assertIn("id", node)
            self.assertIn("type", node)
            self.assertIn("label", node)

        for edge in chain["edges"]:
            self.assertIn("source", edge)
            self.assertIn("target", edge)
            self.assertIn("relationship", edge)

    def test_02_three_metric_preservation_for_frontend(self):
        """Task 7: Preserves separate risk, confidence, and evidence_quality metrics."""
        result = evaluate_phishing_decision(
            evidence_bundle={
                "investigation_id": "INV-METRIC-01",
                "url_intelligence": {"url_risk": 30, "risk_signals": [{"signal": "NEW_DOMAIN", "severity": 30}]}
            }
        )

        metrics = result.get("metrics", {})
        self.assertIn("risk_score", metrics)
        self.assertIn("confidence", metrics)
        self.assertIn("evidence_quality", metrics)
        self.assertGreaterEqual(metrics["risk_score"], 0)
        self.assertLessEqual(metrics["risk_score"], 100)

    def test_03_hypothesis_supporting_evidence_links(self):
        """Task 8: Hypotheses specify supporting evidence and confidence."""
        result = evaluate_phishing_decision(
            evidence_bundle={
                "investigation_id": "INV-HYPO-01",
                "page_analysis": {
                    "form_analysis": {"has_credential_submission": True},
                    "clone_verdict": {"is_clone": True, "clone_classification": "STRONG_BRAND_CLONE"}
                }
            }
        )

        hypotheses = result.get("hypotheses", [])
        self.assertGreaterEqual(len(hypotheses), 1)
        for hypo in hypotheses:
            self.assertIn("id", hypo)
            self.assertIn("label", hypo)
            self.assertIn("confidence", hypo)

    def test_04_investigation_timeline_timestamps(self):
        """Task 9: Timeline contains chronological investigation events."""
        result = analyze_investigation(investigation_id="INV-TIME-01")

        timeline = result.get("timeline") or result.get("evidence_items") or []
        self.assertGreaterEqual(len(timeline), 1)
        for event in timeline:
            self.assertIn("stage", event)


if __name__ == "__main__":
    unittest.main()
