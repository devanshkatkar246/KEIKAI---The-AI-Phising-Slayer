"""
tests/test_dynamic_browser_analysis.py

Unit test suite for Phase 2 Safe Dynamic Browser Analysis Engine:
1. Pre-navigation destination validation with SSRF Guard.
2. Blocking private IPs, loopback, and cloud metadata targets.
3. Unsupported scheme handling.
4. Level 1 (Static) vs Level 2 (Dynamic) DOM comparison.
5. Injected JS form input detection.
6. Safe fallback on timeout or navigation error.
"""

import unittest
from unittest.mock import patch, MagicMock
from services.dynamic_browser import analyze_dynamic_url
from services.page_analyzer import analyze_landing_page


class TestDynamicBrowserAnalysis(unittest.TestCase):

    def test_01_ssrf_guard_blocks_private_ip_dynamic_navigation(self):
        """Task 12 & 28: Dynamic browser blocks loopback and private IP ranges."""
        res_loopback = analyze_dynamic_url("http://127.0.0.1/admin")
        self.assertEqual(res_loopback["status"], "BLOCKED_BY_SSRF_GUARD")
        self.assertEqual(res_loopback["provenance"], "SSRF_GUARD_SAFETY")

        res_private = analyze_dynamic_url("http://192.168.1.100/config")
        self.assertEqual(res_private["status"], "BLOCKED_BY_SSRF_GUARD")

        res_metadata = analyze_dynamic_url("http://169.254.169.254/latest/meta-data")
        self.assertEqual(res_metadata["status"], "BLOCKED_BY_SSRF_GUARD")

    def test_02_unsupported_scheme_rejection(self):
        """Task 28: Rejects non-HTTP(S) schemes prior to browser launch."""
        res_file = analyze_dynamic_url("file:///etc/passwd")
        self.assertEqual(res_file["status"], "UNSUPPORTED_SCHEME")

        res_ftp = analyze_dynamic_url("ftp://malicious.example/payload.exe")
        self.assertEqual(res_ftp["status"], "UNSUPPORTED_SCHEME")

    @patch("services.dynamic_browser.validate_target_ssrf_safety")
    def test_03_mocked_playwright_js_credential_form_detection(self, mock_ssrf):
        """Task 15: Detects credential forms rendered dynamically by JavaScript."""
        mock_ssrf.return_value = (True, "Public IP", "93.184.216.34")

        # Simulate dynamic browser finding post-JS password input
        with patch("playwright.sync_api.sync_playwright") as mock_pw:
            mock_browser = MagicMock()
            mock_context = MagicMock()
            mock_page = MagicMock()

            mock_pw.return_value.__enter__.return_value.chromium.launch.return_value = mock_browser
            mock_browser.new_context.return_value = mock_context
            mock_context.new_page.return_value = mock_page

            mock_page.url = "https://amaz0n-security-login.xyz/auth/login.html"
            mock_page.title.return_value = "Amazon Sign-In (Dynamic)"
            mock_page.evaluate.return_value = {
                "forms": [
                    {
                        "action": "https://collector.evil.xyz/submit",
                        "method": "POST",
                        "input_count": 2,
                        "has_password_field": True,
                        "has_email_field": True,
                        "password_field_names": ["password"]
                    }
                ],
                "has_standalone_password": True,
                "standalone_password_count": 1
            }

            res = analyze_dynamic_url("https://amaz0n-security-login.xyz/auth/login.html")
            self.assertEqual(res["status"], "SUCCESS")
            self.assertTrue(res["has_credential_submission"])
            self.assertEqual(len(res["forms_found"]), 1)
            self.assertTrue(res["forms_found"][0]["is_cross_domain"])
            self.assertEqual(res["provenance"], "PLAYWRIGHT_DYNAMIC_DOM")

    def test_04_static_vs_dynamic_dom_comparison_in_page_analyzer(self):
        """Task 15 & 21: Page analyzer emits DYNAMIC_CREDENTIAL_FORM when password is post-JS rendered."""
        static_html_no_password = """
        <html>
            <head><title>Portal Login</title><script src="/app.js"></script></head>
            <body>
                <div id="root">Loading portal...</div>
            </body>
        </html>
        """

        mock_dynamic_res = {
            "status": "SUCCESS",
            "initial_url": "https://amaz0n-security-login.xyz/login.html",
            "final_url": "https://amaz0n-security-login.xyz/login.html",
            "rendered_title": "Amazon Corporate Login",
            "has_credential_submission": True,
            "forms_found": [
                {
                    "action_url": "https://collector.evil.xyz/submit",
                    "action_hostname": "collector.evil.xyz",
                    "is_cross_domain": True,
                    "has_password_field": True
                }
            ],
            "js_redirects_detected": False,
            "provenance": "PLAYWRIGHT_DYNAMIC_DOM"
        }

        with patch("services.page_analyzer.fetch_page_safely") as mock_fetch:
            with patch("services.dynamic_browser.analyze_dynamic_url") as mock_dyn:
                mock_fetch.return_value = (True, "https://amaz0n-security-login.xyz/login.html", static_html_no_password, {})
                mock_dyn.return_value = mock_dynamic_res

                res = analyze_landing_page(
                    url="https://amaz0n-security-login.xyz/login.html",
                    target_brand="Amazon",
                    official_domain="amazon.com"
                )

                self.assertIn("dynamic_browser_analysis", res)
                self.assertEqual(res["dynamic_browser_analysis"]["status"], "SUCCESS")
                signals = [e["signal"] for e in res["evidence"]]
                self.assertIn("DYNAMIC_CREDENTIAL_FORM", signals)
                self.assertTrue(res["form_analysis"]["has_credential_submission"])

    def test_05_graceful_fallback_on_browser_timeout(self):
        """Task 19: Browser timeout or failure returns structured status without raising exception."""
        with patch("services.dynamic_browser.validate_target_ssrf_safety") as mock_ssrf:
            mock_ssrf.return_value = (True, "Public IP", "93.184.216.34")
            with patch("playwright.sync_api.sync_playwright") as mock_pw:
                mock_pw.side_effect = Exception("Simulated browser crash")

                res = analyze_dynamic_url("https://slow-phish.xyz/login.html")
                self.assertEqual(res["status"], "BROWSER_UNAVAILABLE_FALLBACK")
                self.assertFalse(res["has_credential_submission"])
                self.assertEqual(res["provenance"], "DYNAMIC_BROWSER_FALLBACK")


if __name__ == "__main__":
    unittest.main()
