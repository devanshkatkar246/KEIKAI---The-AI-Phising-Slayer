"""
Tests & SSRF Security Audit for Advanced URL, Domain, and Redirect Intelligence (Phase 7)
========================================================================================
Verifies URL canonicalization, obfuscation detection, static credential page indicators,
RDAP domain age classification, deterministic redirect chain inspection, and rigorous SSRF guards
(localhost, 127.0.0.1, private IPs, cloud metadata, public-to-private redirect hops, bounded depth loops).
"""

import os
import sys
import unittest
from unittest.mock import patch, MagicMock

# Ensure workspace root is on Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from services.url_intelligence import (
    normalize_and_analyze_url,
    inspect_redirect_chain,
    detect_credential_page,
    get_domain_age_intelligence,
    analyze_url_intelligence
)
from services.multi_http_verifier import is_safe_external_target


class TestUrlIntelligence(unittest.TestCase):

    def test_01_url_normalization_canonicalization(self):
        """Task 2: Canonicalizes URL, strips tracking params, lowercases host."""
        raw_url = "HTTPS://AMAZON-SECURITY-LOGIN.EXAMPLE/auth/login.html?utm_source=email&fbclid=12345&user_id=88"
        res = normalize_and_analyze_url(raw_url)

        self.assertTrue(res["is_valid"])
        self.assertEqual(res["hostname"], "amazon-security-login.example")
        self.assertEqual(res["canonical_url"], "https://amazon-security-login.example/auth/login.html?user_id=88")
        self.assertNotIn("utm_source", res["canonical_url"])
        self.assertNotIn("fbclid", res["canonical_url"])

    def test_02_obfuscation_signals_detection(self):
        """Task 2: Detects URL encoding tricks, userinfo abuse, excessive subdomains, non-standard ports, IP host, punycode."""
        # Test A: Userinfo abuse & excessive subdomains
        res1 = normalize_and_analyze_url("http://admin:secret@login.verify.account.m365.update.phish.xyz/auth")
        self.assertIn("userinfo_auth_abuse", res1["obfuscation_signals"])
        self.assertIn("excessive_subdomain_depth", res1["obfuscation_signals"])

        # Test B: IP-based hostname & non-standard port
        res2 = normalize_and_analyze_url("http://192.168.1.1:8080/login")
        self.assertIn("ip_based_hostname", res2["obfuscation_signals"])
        self.assertIn("suspicious_non_standard_port", res2["obfuscation_signals"])

        # Test C: Punycode / Homoglyph
        res3 = normalize_and_analyze_url("https://xn--amazn-0qa.com/login")
        self.assertIn("punycode_homoglyph_indicator", res3["obfuscation_signals"])

    def test_03_ssrf_audit_localhost_and_loopback(self):
        """Task 11 SSRF AUDIT: Blocks localhost, 127.0.0.1, ::1, 0.0.0.0."""
        targets = ["localhost", "127.0.0.1", "0.0.0.0", "http://[::1]/admin", "http://localhost:8000/api"]
        for target in targets:
            is_safe, reason = is_safe_external_target(target)
            self.assertFalse(is_safe, f"Target '{target}' should have been blocked by SSRF Guard")
            self.assertIn("Blocked", reason)

    def test_04_ssrf_audit_private_ips(self):
        """Task 11 SSRF AUDIT: Blocks 10.0.0.1, 172.16.0.1, 192.168.1.1 private ranges."""
        private_targets = ["10.0.0.1", "172.16.0.1", "192.168.1.100", "http://192.168.0.1/router"]
        for target in private_targets:
            is_safe, reason = is_safe_external_target(target)
            self.assertFalse(is_safe, f"Private IP '{target}' must be blocked by SSRF Guard")

    def test_05_ssrf_audit_cloud_metadata(self):
        """Task 11 SSRF AUDIT: Blocks 169.254.169.254 and metadata.google.internal."""
        metadata_targets = [
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/computeMetadata/v1/"
        ]
        for target in metadata_targets:
            is_safe, reason = is_safe_external_target(target)
            self.assertFalse(is_safe, f"Cloud metadata target '{target}' must be blocked")

    def test_06_ssrf_audit_public_to_private_redirect_hop(self):
        """Task 11 SSRF AUDIT: Redirect from public domain to private internal IP is intercepted and blocked."""
        # Mock public URL redirecting to private IP 192.168.1.1
        with patch("urllib.request.build_opener") as mock_opener_builder:
            mock_opener = MagicMock()
            mock_opener_builder.return_value = mock_opener

            mock_resp = MagicMock()
            mock_resp.status = 302
            mock_resp.headers = {"Location": "http://192.168.1.1/internal-admin"}
            mock_resp.__enter__.return_value = mock_resp
            mock_opener.open.return_value = mock_resp

            res = inspect_redirect_chain("https://public-shortener.example/link")
            self.assertTrue(res["ssrf_blocked"])
            self.assertEqual(res["redirect_chain"][-1]["status_code"], 403)
            self.assertIn("SSRF Guard Blocked", res["redirect_chain"][-1]["reason"])

    def test_07_bounded_redirect_depth_loop(self):
        """Task 3 & 11: Bounded redirect depth (max 5 hops) prevents infinite redirect loops."""
        with patch("urllib.request.build_opener") as mock_opener_builder:
            mock_opener = MagicMock()
            mock_opener_builder.return_value = mock_opener

            step_count = [0]

            def mock_open_side_effect(req, timeout=None):
                step_count[0] += 1
                mock_resp = MagicMock()
                mock_resp.status = 302
                mock_resp.headers = {"Location": f"https://redirect-loop.example/step{step_count[0]}"}
                mock_resp.__enter__.return_value = mock_resp
                return mock_resp

            mock_opener.open.side_effect = mock_open_side_effect

            res = inspect_redirect_chain("https://redirect-loop.example/start", max_depth=5)
            self.assertLessEqual(res["chain_length"], 5)
            self.assertTrue(res["has_redirects"])

    def test_08_static_credential_page_detection(self):
        """Task 4: Static indicators identify credential harvesting landing pages without code execution."""
        html_payload = """
        <html>
          <head><title>Account Login</title></head>
          <body>
            <h2>Sign in to your Corporate Account</h2>
            <form action="https://amaz0n-security-login.xyz/collect" method="POST">
              <input type="email" name="user" />
              <input type="password" name="pass" />
              <button type="submit">Verify Credentials</button>
            </form>
          </body>
        </html>
        """
        res = detect_credential_page("https://amaz0n-security-login.xyz/auth/login.html", html_content=html_payload)
        self.assertTrue(res["is_credential_page"])
        self.assertIn("password_input_field", res["indicators"])
        self.assertIn("html_form_present", res["indicators"])
        self.assertIn("sensitive_authentication_language", res["indicators"])

    def test_09_domain_age_rdap_signals(self):
        """Task 5: Domain age RDAP signal classification."""
        # Test A: Very new domain (< 14 days)
        with patch("services.url_intelligence.fetch_rdap_data") as mock_rdap:
            mock_rdap.return_value = {
                "status": "RDAP_SUCCESS",
                "creation_date": "2026-09-01T00:00:00Z",
                "registrar": "NameCheap"
            }
            res_new = get_domain_age_intelligence("brand-new-phish.xyz")
            self.assertEqual(res_new["signal"], "VERY_NEW_DOMAIN")
            self.assertEqual(res_new["risk_points"], 30)

        # Test B: Established domain (>= 365 days)
        with patch("services.url_intelligence.fetch_rdap_data") as mock_rdap:
            mock_rdap.return_value = {
                "status": "RDAP_SUCCESS",
                "creation_date": "2020-01-01T00:00:00Z",
                "registrar": "MarkMonitor"
            }
            res_old = get_domain_age_intelligence("amazon.com")
            self.assertEqual(res_old["signal"], "ESTABLISHED_DOMAIN")
            self.assertEqual(res_old["risk_points"], 0)

    def test_10_unified_url_intelligence_aggregator(self):
        """Task 8: Unified analyze_url_intelligence consolidates signals and computes url_risk."""
        with patch("services.url_intelligence.inspect_redirect_chain") as mock_red:
            with patch("services.url_intelligence.get_domain_age_intelligence") as mock_age:
                mock_red.return_value = {
                    "original_url": "http://short.link/123",
                    "final_url": "https://amaz0n-login.xyz/auth",
                    "has_redirects": True,
                    "chain_length": 2,
                    "redirect_chain": []
                }
                mock_age.return_value = {
                    "signal": "VERY_NEW_DOMAIN",
                    "age_days": 5,
                    "risk_points": 30
                }

                res = analyze_url_intelligence("http://short.link/123")
                self.assertGreaterEqual(res["url_risk"], 40)
                self.assertEqual(res["domain_age_signal"]["signal"], "VERY_NEW_DOMAIN")
                self.assertTrue(res["redirect_signal"]["has_redirects"])


if __name__ == "__main__":
    unittest.main()
