"""
tests/test_entity_background_attack_chain.py

KEIKAI — Phase 8 WHOIS/RDAP Entity Background & Attack Chain Tracer Test Suite
==================================================================================
Tests RDAP primary lookups, socket WHOIS fallback, domain age classification,
privacy protection disclosures, infrastructure entity correlation, attack chain tracer
graph nodes and directed edges, redirect chain preservation, form action edges, and API contracts.
"""

import os
import sys
import unittest
from unittest.mock import patch, MagicMock

# Ensure workspace root is on Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from services.entity_intelligence import (
    get_domain_entity_profile,
    calculate_domain_age,
    evaluate_privacy_protection,
    correlate_entity_infrastructure,
    calculate_entity_risk_score,
    parse_raw_whois_text
)
from services.chain_tracer import trace_attack_chain, AttackGraph


class TestEntityBackgroundAttackChain(unittest.TestCase):

    def test_01_rdap_primary_success(self):
        """Task 1 & 2: RDAP primary lookup extracts registrar, creation date, domain age, and nameservers."""
        with patch("services.entity_intelligence.fetch_rdap_data") as mock_rdap:
            mock_rdap.return_value = {
                "status": "RDAP_SUCCESS",
                "registrar": "NameCheap Inc.",
                "creation_date": "2026-09-01T00:00:00Z",
                "expiration_date": "2027-09-01T00:00:00Z",
                "nameservers": ["dns1.namecheap.com", "dns2.namecheap.com"],
                "abuse_email": "abuse@namecheap.com"
            }

            res = get_domain_entity_profile("amaz0n-security-login.xyz", use_cache=False)

            self.assertEqual(res["provenance"]["source_used"], "RDAP")
            self.assertEqual(res["provenance"]["status"], "SUCCESS")
            self.assertEqual(res["registrar"]["name"], "NameCheap Inc.")
            self.assertEqual(res["domain_age"]["classification"], "VERY_NEW")
            self.assertEqual(len(res["nameservers"]), 2)

    def test_02_whois_fallback_when_rdap_unavailable(self):
        """Task 3: Falls back to WHOIS when RDAP returns unavailable."""
        with patch("services.entity_intelligence.fetch_rdap_data") as mock_rdap:
            with patch("services.entity_intelligence.query_whois_socket") as mock_whois:
                mock_rdap.return_value = {"status": "RDAP_UNAVAILABLE"}
                mock_whois.return_value = """
                Domain Name: amaz0n-security-login.xyz
                Registrar: MarkMonitor Inc.
                Creation Date: 2020-01-15T00:00:00Z
                Name Server: ns1.markmonitor.com
                Name Server: ns2.markmonitor.com
                Registrar Abuse Contact Email: abuse@markmonitor.com
                """

                res = get_domain_entity_profile("amaz0n-security-login.xyz", use_cache=False)

                self.assertEqual(res["provenance"]["primary_source"], "RDAP")
                self.assertEqual(res["provenance"]["fallback_source"], "WHOIS")
                self.assertEqual(res["provenance"]["source_used"], "WHOIS")
                self.assertEqual(res["provenance"]["status"], "SUCCESS")
                self.assertEqual(res["registrar"]["name"], "MarkMonitor Inc.")
                self.assertEqual(res["domain_age"]["classification"], "ESTABLISHED")

    def test_03_both_sources_unavailable_returns_unavailable_status(self):
        """Task 3: Returns status = UNAVAILABLE when both RDAP and WHOIS fail."""
        with patch("services.entity_intelligence.fetch_rdap_data") as mock_rdap:
            with patch("services.entity_intelligence.query_whois_socket") as mock_whois:
                mock_rdap.return_value = {"status": "RDAP_UNAVAILABLE"}
                mock_whois.return_value = None

                res = get_domain_entity_profile("unreachable-phish-domain.xyz", use_cache=False)

                self.assertEqual(res["provenance"]["source_used"], "NONE")
                self.assertEqual(res["provenance"]["status"], "UNAVAILABLE")
                self.assertFalse(res["provenance"]["live"])
                self.assertEqual(res["domain_age"]["classification"], "UNKNOWN")

    def test_04_privacy_protection_disclosure(self):
        """Task 4: Detects privacy protection proxy and redacts PII without deanonymizing."""
        privacy_res = evaluate_privacy_protection("Domains By Proxy, LLC", raw_text="Redacted for Privacy")
        self.assertEqual(privacy_res["privacy_status"], "PRIVACY_PROTECTED")
        self.assertTrue(privacy_res["is_privacy_protected"])
        self.assertIn("protected by a WHOIS privacy proxy", privacy_res["disclosure"])

    def test_05_infrastructure_entity_correlation(self):
        """Task 6: Correlates shared registrar, nameservers, and IP across investigated campaign assets."""
        entity_profile = {
            "domain": "phish-domain-a.xyz",
            "registrar": {"name": "NameCheap Inc."},
            "nameservers": ["ns1.hoster.com", "ns2.hoster.com"],
            "resolved_ips": ["93.184.216.34"]
        }
        existing_assets = [
            {
                "asset_id": "phish-domain-b.xyz",
                "ip_address": "93.184.216.34",
                "metadata": {"registrar": "NameCheap Inc.", "nameservers": ["ns1.hoster.com"]}
            }
        ]

        rel_list = correlate_entity_infrastructure("phish-domain-a.xyz", entity_profile, existing_assets)

        self.assertGreaterEqual(len(rel_list), 2)
        relationships = [r["relationship"] for r in rel_list]
        self.assertIn("SHARED_REGISTRAR", relationships)
        self.assertIn("SHARED_NAMESERVER", relationships)
        self.assertIn("SHARED_IP", relationships)

    def test_06_attack_chain_graph_node_and_edge_generation(self):
        """Task 8, 9 & 10: Generates directed attack chain nodes and evidence-backed edges."""
        email_bundle = {
            "sender": "attacker@fake-finance.example",
            "message_id": "MSG-9988",
            "subject": "Urgent Security Verification",
            "urls": ["http://short.link/xyz123"]
        }

        with patch("services.chain_tracer.trace_safe_redirect_chain") as mock_red:
            with patch("services.chain_tracer.get_domain_entity_profile") as mock_ent:
                mock_red.return_value = {
                    "has_redirects": True,
                    "chain_length": 2,
                    "final_url": "https://amaz0n-security-login.xyz/auth/login.html",
                    "redirect_chain": [
                        {"url": "http://short.link/xyz123", "location": "https://amaz0n-security-login.xyz/auth/login.html", "status_code": 302}
                    ]
                }
                mock_ent.return_value = {
                    "domain": "amaz0n-security-login.xyz",
                    "nameservers": ["dns1.phishdns.com"],
                    "domain_age": {"classification": "VERY_NEW", "message": "Domain is 3 days old"},
                    "infrastructure_entities": []
                }

                page_analysis = {
                    "target_brand": "Amazon",
                    "clone_verdict": {"is_clone": True, "clone_classification": "STRONG_BRAND_CLONE"},
                    "form_analysis": {
                        "has_credential_submission": True,
                        "evaluated_forms": [
                            {"action_url": "https://collector.evil.xyz/submit", "action_hostname": "collector.evil.xyz", "is_cross_domain": True}
                        ]
                    }
                }

                chain = trace_attack_chain(
                    investigation_id="INV-TEST-01",
                    target_url="http://short.link/xyz123",
                    email_bundle=email_bundle,
                    page_analysis=page_analysis
                )

                self.assertEqual(chain["investigation_id"], "INV-TEST-01")
                self.assertGreaterEqual(len(chain["nodes"]), 7)
                self.assertGreaterEqual(len(chain["edges"]), 6)

                node_types = [n["type"] for n in chain["nodes"]]
                self.assertIn("SENDER", node_types)
                self.assertIn("EMAIL", node_types)
                self.assertIn("URL", node_types)
                self.assertIn("REDIRECT", node_types)
                self.assertIn("DOMAIN", node_types)
                self.assertIn("LANDING_PAGE", node_types)
                self.assertIn("FORM_ACTION", node_types)
                self.assertIn("BRAND", node_types)

                edge_relationships = [e["relationship"] for e in chain["edges"]]
                self.assertIn("EMAIL_CONTAINS_URL", edge_relationships)
                self.assertIn("URL_REDIRECTS_TO", edge_relationships)
                self.assertIn("URL_RESOLVES_TO", edge_relationships)
                self.assertIn("PAGE_SUBMITS_TO", edge_relationships)
                self.assertIn("PAGE_IMPERSONATES", edge_relationships)

    def test_07_preserved_redirect_chain_hops(self):
        """Task 11: Preserves every redirect chain hop without collapsing nodes."""
        with patch("services.chain_tracer.trace_safe_redirect_chain") as mock_red:
            with patch("services.chain_tracer.get_domain_entity_profile") as mock_ent:
                mock_red.return_value = {
                    "has_redirects": True,
                    "chain_length": 3,
                    "final_url": "https://amaz0n-security-login.xyz/login",
                    "redirect_chain": [
                        {"url": "http://short.link/step1", "location": "http://cdn-gate.xyz/step2", "status_code": 301},
                        {"url": "http://cdn-gate.xyz/step2", "location": "https://amaz0n-security-login.xyz/login", "status_code": 302}
                    ]
                }
                mock_ent.return_value = {"domain": "amaz0n-security-login.xyz", "nameservers": [], "domain_age": {"classification": "VERY_NEW"}}

                chain = trace_attack_chain(target_url="http://short.link/step1")

                redirect_nodes = [n for n in chain["nodes"] if n["type"] == "REDIRECT"]
                self.assertGreaterEqual(len(redirect_nodes), 2)

    def test_08_separate_entity_risk_score(self):
        """Task 14: Calculates separate entity_risk_score based on domain age and infrastructure linkages."""
        domain_age_info = {"classification": "VERY_NEW"}
        privacy_info = {"is_privacy_protected": True}
        infra_rel = [{"relationship": "SHARED_REGISTRAR"}]
        status_flags = []

        res = calculate_entity_risk_score(domain_age_info, privacy_info, infra_rel, status_flags)

        self.assertGreaterEqual(res["entity_risk_score"], 50)
        self.assertEqual(res["severity"], "HIGH")
        self.assertIn("Very new domain registration (< 14 days old)", res["evidence_reasons"])


if __name__ == "__main__":
    unittest.main()
