"""
tests/test_unified_attack_chain_foundation.py

KEIKAI — Phase 1 Unified Attack Chain Foundation Test Suite
==================================================================================
Tests standardized evidence items, node deduplication, directed edge relationships,
cross-stage attack hypotheses, anti-double counting engine, 3-metric model preservation,
and attack chain API output compatibility.
"""

import os
import sys
import unittest
from unittest.mock import patch, MagicMock

# Ensure workspace root is on Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from services.chain_tracer import (
    trace_attack_chain,
    create_evidence_item,
    AttackGraph
)
from services.phishing_decision_engine import (
    evaluate_phishing_decision,
    deduplicate_and_normalize_evidence,
    calculate_independent_metrics,
    analyze_investigation
)


class TestUnifiedAttackChainFoundation(unittest.TestCase):

    def test_01_standardized_evidence_item_creation(self):
        """Task 1: Standardized evidence item captures provenance, stage, severity, and related entities."""
        item = create_evidence_item(
            investigation_id="INV-TEST-01",
            stage="MESSAGE",
            evidence_type="credential_phishing_keywords",
            source="email_analysis",
            value="Password reset keywords detected",
            severity=30,
            confidence=0.85,
            related_entity_ids=["email:MSG-01"]
        )

        self.assertTrue(item["evidence_id"].startswith("ev-message-credential_phishing_keywords-"))
        self.assertEqual(item["investigation_id"], "INV-TEST-01")
        self.assertEqual(item["stage"], "MESSAGE")
        self.assertEqual(item["severity"], 30)
        self.assertEqual(item["confidence"], 0.85)
        self.assertIn("source", item["provenance"])

    def test_02_url_and_domain_node_deduplication(self):
        """Task 2: Attack graph deduplicates normalized URLs and domain nodes across detectors."""
        graph = AttackGraph("INV-TEST-02")

        n1 = graph.get_or_create_url_node("https://amaz0n-security-login.xyz/auth/login.html?ref=email")
        n2 = graph.get_or_create_url_node("https://amaz0n-security-login.xyz/auth/login.html")
        d1 = graph.get_or_create_domain_node("AMAZ0N-SECURITY-LOGIN.XYZ")
        d2 = graph.get_or_create_domain_node("amaz0n-security-login.xyz")

        # URLs with different query params normalize to same base URL node
        self.assertEqual(n1, n2)
        # Domain casing normalizes to same domain node
        self.assertEqual(d1, d2)
        self.assertEqual(len(graph.nodes), 2)

    def test_03_directed_edge_relationship_creation(self):
        """Task 3: Edge creation enforces valid relationship types, confidence scores, and prevents duplicates."""
        graph = AttackGraph("INV-TEST-03")

        u_node = graph.get_or_create_url_node("https://amaz0n-security-login.xyz/login")
        d_node = graph.get_or_create_domain_node("amaz0n-security-login.xyz")

        graph.add_edge(u_node, d_node, "RESOLVES_TO", "URL resolves to domain", confidence=95.0, source_provider="dns")
        # Duplicate edge should be ignored
        graph.add_edge(u_node, d_node, "RESOLVES_TO", "URL resolves to domain", confidence=95.0, source_provider="dns")

        self.assertEqual(len(graph.edges), 1)
        self.assertEqual(graph.edges[0]["relationship"], "RESOLVES_TO")
        self.assertEqual(graph.edges[0]["confidence"], 95.0)

    def test_04_anti_double_counting_engine(self):
        """Task 4: Anti-double counting categorizes evidence and suppresses duplicate severity additions."""
        supporting = [
            {"source": "rdap", "signal": "newly_registered_domain", "severity": 30},
            {"source": "rdap", "signal": "very_new_domain_registration", "severity": 30},  # Duplicate fact from RDAP
            {"source": "page_analyzer", "signal": "visual_brand_clone", "severity": 45},
            {"source": "imagehash", "signal": "strong_brand_clone", "severity": 45}  # Corroborating visual signal
        ]
        contradicting = []

        deduped, groups = deduplicate_and_normalize_evidence(supporting, contradicting)

        # Duplicate RDAP signal should have 0 effective severity
        dup_items = [i for i in deduped if i["evidence_category"] == "DUPLICATE"]
        self.assertEqual(len(dup_items), 1)
        self.assertEqual(dup_items[0]["effective_severity"], 0)

        # Corroborating signal should have reduced effective severity
        corrob_items = [i for i in deduped if i["evidence_category"] == "CORROBORATING"]
        self.assertEqual(len(corrob_items), 1)
        self.assertLess(corrob_items[0]["effective_severity"], 45)

    def test_05_three_metric_model_preservation(self):
        """Task 5: Risk, confidence, and evidence_quality remain distinct unmerged metrics."""
        supporting = [
            {"source": "email_analysis", "signal": "credential_phishing_keywords", "severity": 30, "effective_severity": 30},
            {"source": "page_analyzer", "signal": "password_input_form", "severity": 35, "effective_severity": 35}
        ]
        contradicting = []
        stage_results = {
            "email": {"risk_score": 30},
            "payload": {"risk_score": 0},
            "url_intelligence": {"url_risk": 65}
        }

        risk, conf, qual = calculate_independent_metrics(supporting, contradicting, stage_results)

        # Ensure metrics are calculated independently
        self.assertIsInstance(risk, int)
        self.assertIsInstance(conf, int)
        self.assertIsInstance(qual, int)
        self.assertGreaterEqual(risk, 65)
        self.assertNotEqual(risk, qual)

    def test_06_cross_stage_attack_hypotheses_generation(self):
        """Task 6: Attack chain tracer synthesizes hypothesis nodes from multi-stage signals."""
        email_bundle = {
            "sender": "alert@fake-bank.xyz",
            "subject": "Urgent Security Alert",
            "signals": {"credential_phishing_keywords": True}
        }
        page_analysis = {
            "target_brand": "BankOfAmerica",
            "clone_verdict": {"is_clone": True, "clone_classification": "STRONG_BRAND_CLONE"},
            "form_analysis": {"has_credential_submission": True, "evaluated_forms": []}
        }

        res = trace_attack_chain(
            investigation_id="INV-HYPO-06",
            target_url="https://fake-bank.xyz/login.html",
            email_bundle=email_bundle,
            page_analysis=page_analysis
        )

        hypo_ids = [h["hypothesis_id"] for h in res["hypotheses"]]
        self.assertIn("EXTERNAL_IMPERSONATION", hypo_ids)
        self.assertIn("CREDENTIAL_HARVESTING", hypo_ids)
        self.assertGreater(len(res["evidence_items"]), 0)

    def test_07_non_attributable_infrastructure_terminology(self):
        """Task 7: Infrastructure correlation uses 'potentially related infrastructure' terminology."""
        with patch("services.chain_tracer.get_domain_entity_profile") as mock_rdap:
            mock_rdap.return_value = {
                "registrar": "NameCheap",
                "nameservers": ["dns1.registrar-servers.com"],
                "domain_age": {"classification": "ESTABLISHED"},
                "infrastructure_entities": [
                    {"target_asset": "other-phish.xyz", "relationship": "POTENTIALLY_RELATED_TO", "evidence": "Shared IP 192.0.2.45"}
                ],
                "entity_risk": {"entity_risk_score": 35}
            }

            res = trace_attack_chain(investigation_id="INV-INFRA-07", target_url="https://target-domain.com")

            # Check that cluster nodes and risk descriptions do not claim definitive hacker attribution
            risk_desc = " ".join([s["description"] for s in res["risk_signals"]])
            self.assertIn("potentially related infrastructure", risk_desc.lower())

    def test_08_investigation_orchestration_api_compatibility(self):
        """Task 8: End-to-end investigation orchestration returns unified attack graph and metrics."""
        res = analyze_investigation(investigation_id="INV-ORCH-08")

        self.assertIn("verdict", res)
        self.assertIn("risk_score", res)
        self.assertIn("confidence", res)
        self.assertIn("evidence_quality", res)
        self.assertIn("nodes", res)
        self.assertIn("edges", res)
        self.assertIn("hypotheses", res)
        self.assertIn("evidence_groups", res)
        self.assertIn("evidence_items", res)
        self.assertIn("metrics", res)


if __name__ == "__main__":
    unittest.main()
