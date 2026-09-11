"""
tests/test_ssrf_guard.py

Unit test for SSRF Guard Protection in services/multi_http_verifier.py:
- Loopback (localhost, 127.0.0.1, ::1)
- Internal IP ranges (10.0.0.1, 192.168.1.1, 172.16.0.1)
- AWS/GCP Metadata endpoint (169.254.169.254)
- Restricted internal service ports (22, 6379, 8000, 27017)
- External legitimate domains (example.com, amazon.com)
"""

import pytest
from services.multi_http_verifier import is_safe_external_target, MultiAttemptHTTPVerifier


def test_ssrf_blocks_loopback_and_internal_ips():
    bad_targets = [
        "http://localhost",
        "http://127.0.0.1:8000",
        "http://127.0.0.1/admin",
        "http://[::1]",
        "http://169.254.169.254/latest/meta-data/",
        "http://internal-service.local",
        "http://10.0.0.1",
        "http://192.168.1.100",
        "http://172.16.0.5:6379"
    ]

    for target in bad_targets:
        is_safe, reason = is_safe_external_target(target)
        assert is_safe is False, f"Expected '{target}' to be blocked by SSRF guard"
        assert "Blocked SSRF" in reason


def test_ssrf_allows_legitimate_external_domains():
    good_targets = [
        "example.com",
        "https://amazon.com",
        "https://google.com/search"
    ]

    for target in good_targets:
        is_safe, reason = is_safe_external_target(target)
        assert is_safe is True, f"Expected '{target}' to be allowed"
        assert reason == "Allowed"


def test_multi_http_verifier_ssrf_blocking():
    res = MultiAttemptHTTPVerifier.verify_http("localhost")
    assert res["status"] == "BLOCKED"
    assert "SSRF Guard blocked" in res["detail"]
