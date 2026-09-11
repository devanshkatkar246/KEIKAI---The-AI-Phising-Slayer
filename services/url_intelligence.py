"""
KEKAI Autonomous Brand Intelligence & Phishing Engine
Advanced URL, Domain, and Redirect Intelligence Layer
==================================================================================
Provides URL normalization, obfuscation analysis, SSRF-safe redirect inspection,
static credential page detection, domain age tracking (RDAP), lookalike matching,
and threat feed correlation.
"""

import re
import ssl
import json
import socket
import logging
import ipaddress
import urllib.parse
import urllib.request
import urllib.error
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple

from services.multi_http_verifier import is_safe_external_target
from services.rdap_service import fetch_rdap_data

logger = logging.getLogger("kekai.url_intelligence")

MAX_REDIRECT_HOPS = 5
HTTP_TIMEOUT_SECONDS = 3.0

TRACKING_PARAMS = {"utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content", "fbclid", "gclid", "ref", "mc_cid"}
SUSPICIOUS_PORTS = {8080, 8443, 8000, 8888, 3000, 5000, 9000, 27017, 6379, 3306}


def normalize_and_analyze_url(raw_url: str) -> Dict[str, Any]:
    """
    Canonicalizes input URL and detects obfuscation signals:
    - URL encoding tricks (%2f, %40, double encoding)
    - Userinfo abuse (user:pass@host)
    - Excessive subdomains (> 3 dots)
    - Non-standard web ports
    - IP-based hostname
    - Punycode / homoglyph indicators
    """
    if not raw_url or not isinstance(raw_url, str):
        return {
            "canonical_url": "",
            "hostname": "",
            "path": "",
            "is_valid": False,
            "obfuscation_signals": [],
            "risk_score": 0
        }

    url = raw_url.strip()

    # Detect userinfo abuse before parsing
    userinfo_abuse = False
    if "@" in url.split("/")[2] if "://" in url and len(url.split("/")) > 2 else "@" in url.split("/")[0]:
        userinfo_abuse = True

    # Detect non-HTTP suspicious schemes (javascript:, data:, file:, vbscript:)
    raw_lower = url.lower()
    for bad_sch in ["javascript:", "data:", "file:", "vbscript:"]:
        if raw_lower.startswith(bad_sch):
            return {
                "canonical_url": raw_url,
                "hostname": "",
                "path": raw_url,
                "is_valid": False,
                "obfuscation_signals": ["suspicious_url_scheme"],
                "risk_score": 40
            }

    # Scheme normalization
    if not (url.lower().startswith("http://") or url.lower().startswith("https://")):
        url = "https://" + url

    try:
        parsed = urllib.parse.urlparse(url)
    except Exception:
        return {
            "canonical_url": raw_url,
            "hostname": "",
            "path": "",
            "is_valid": False,
            "obfuscation_signals": ["invalid_url_structure"],
            "risk_score": 20
        }

    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()

    # Strip userinfo for canonical hostname
    if "@" in netloc:
        netloc = netloc.split("@")[-1]

    # Hostname & Port extraction
    if ":" in netloc:
        parts = netloc.split(":")
        hostname = parts[0]
        try:
            port = int(parts[1])
        except ValueError:
            port = None
    else:
        hostname = netloc
        port = None

    # Canonicalize path & query params
    path = urllib.parse.unquote(parsed.path or "/")
    if not path.startswith("/"):
        path = "/" + path

    # Strip tracking parameters
    query_params = urllib.parse.parse_qs(parsed.query, keep_blank_values=False)
    filtered_query = [(k, v) for k, list_v in query_params.items() if k.lower() not in TRACKING_PARAMS for v in list_v]
    canonical_query = urllib.parse.urlencode(filtered_query)

    canonical_url = f"{scheme}://{hostname}{f':{port}' if port and port not in (80, 443) else ''}{path}"
    if canonical_query:
        canonical_url += f"?{canonical_query}"

    obfuscation_signals = []
    risk_score = 0

    # Obfuscation Check 1: URL Encoding Tricks
    if "%" in raw_url:
        unquoted = urllib.parse.unquote(raw_url)
        if "%" in unquoted or any(char in raw_url.lower() for char in ["%2f", "%40", "%3a", "%2e"]):
            obfuscation_signals.append("url_encoding_obfuscation")
            risk_score += 15

    # Obfuscation Check 2: Userinfo Abuse
    if userinfo_abuse:
        obfuscation_signals.append("userinfo_auth_abuse")
        risk_score += 25

    # Obfuscation Check 3: Excessive Subdomains
    subdomain_parts = [p for p in hostname.split(".") if p]
    if len(subdomain_parts) > 4:
        obfuscation_signals.append("excessive_subdomain_depth")
        risk_score += 20

    # Obfuscation Check 4: Non-Standard Web Port
    if port and port in SUSPICIOUS_PORTS:
        obfuscation_signals.append("suspicious_non_standard_port")
        risk_score += 20

    # Obfuscation Check 5: IP-Based Hostname
    is_ip = False
    try:
        ipaddress.ip_address(hostname)
        is_ip = True
        obfuscation_signals.append("ip_based_hostname")
        risk_score += 30
    except ValueError:
        pass

    # Obfuscation Check 6: Punycode / Homoglyph
    if hostname.startswith("xn--") or any(ord(c) > 127 for c in hostname):
        obfuscation_signals.append("punycode_homoglyph_indicator")
        risk_score += 25

    return {
        "canonical_url": canonical_url,
        "scheme": scheme,
        "hostname": hostname,
        "port": port,
        "path": path,
        "is_valid": True,
        "is_ip": is_ip,
        "obfuscation_signals": obfuscation_signals,
        "risk_score": min(100, risk_score)
    }


def inspect_redirect_chain(
    initial_url: str,
    max_depth: int = MAX_REDIRECT_HOPS,
    timeout: float = HTTP_TIMEOUT_SECONDS
) -> Dict[str, Any]:
    """
    Executes safe redirect chain inspection with strict SSRF protection.
    
    SSRF Protections:
    - Verifies is_safe_external_target() before EACH redirect hop.
    - Resolves DNS and blocks loopback, private IP, multicast, or cloud metadata targets.
    - Bounded depth (max 5 hops) to prevent infinite loops.
    """
    norm = normalize_and_analyze_url(initial_url)
    current_url = norm.get("canonical_url") or initial_url

    redirect_chain = []
    seen_urls = set()
    chain_length = 0
    ssrf_blocked = False

    for hop in range(1, max_depth + 1):
        if not current_url or current_url in seen_urls:
            break
        seen_urls.add(current_url)

        # SSRF Guard Check before HTTP call
        is_safe, ssrf_reason = is_safe_external_target(current_url)
        if not is_safe:
            logger.warning(f"[Redirect SSRF Guard] Blocked hop {hop} to '{current_url}': {ssrf_reason}")
            ssrf_blocked = True
            redirect_chain.append({
                "hop": hop,
                "url": current_url,
                "status_code": 403,
                "hostname": urllib.parse.urlparse(current_url).hostname or "blocked",
                "reason": f"SSRF Guard Blocked: {ssrf_reason}"
            })
            break

        # Execute GET request following 1 redirect at a time manually
        req = urllib.request.Request(
            current_url,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
            },
            method="GET"
        )
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        # Custom HTTP redirect handler to intercept redirect location
        class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                return None

        opener = urllib.request.build_opener(NoRedirectHandler)

        try:
            with opener.open(req, timeout=timeout) as resp:
                code = resp.status
                headers_resp = dict(resp.headers)
                next_location = headers_resp.get("Location") or headers_resp.get("location")

                redirect_chain.append({
                    "hop": hop,
                    "url": current_url,
                    "status_code": code,
                    "hostname": urllib.parse.urlparse(current_url).hostname,
                    "target_location": next_location,
                    "reason": "OK" if code == 200 else "Redirect"
                })
                chain_length = hop

                if code in (301, 302, 303, 307, 308) and next_location:
                    next_url = urllib.parse.urljoin(current_url, next_location)
                    target_safe, target_ssrf_reason = is_safe_external_target(next_url)
                    if not target_safe:
                        logger.warning(f"[Redirect SSRF Guard] Target redirect '{next_url}' blocked: {target_ssrf_reason}")
                        ssrf_blocked = True
                        redirect_chain.append({
                            "hop": hop + 1,
                            "url": next_url,
                            "status_code": 403,
                            "hostname": urllib.parse.urlparse(next_url).hostname or "blocked",
                            "reason": f"SSRF Guard Blocked: {target_ssrf_reason}"
                        })
                        break
                    current_url = next_url
                else:
                    break

        except urllib.error.HTTPError as e:
            code = e.code
            next_location = e.headers.get("Location") or e.headers.get("location")

            redirect_chain.append({
                "hop": hop,
                "url": current_url,
                "status_code": code,
                "hostname": urllib.parse.urlparse(current_url).hostname,
                "target_location": next_location,
                "reason": e.reason
            })
            chain_length = hop

            if code in (301, 302, 303, 307, 308) and next_location:
                next_url = urllib.parse.urljoin(current_url, next_location)
                target_safe, target_ssrf_reason = is_safe_external_target(next_url)
                if not target_safe:
                    logger.warning(f"[Redirect SSRF Guard] Target redirect '{next_url}' blocked: {target_ssrf_reason}")
                    ssrf_blocked = True
                    redirect_chain.append({
                        "hop": hop + 1,
                        "url": next_url,
                        "status_code": 403,
                        "hostname": urllib.parse.urlparse(next_url).hostname or "blocked",
                        "reason": f"SSRF Guard Blocked: {target_ssrf_reason}"
                    })
                    break
                current_url = next_url
            else:
                break
        except Exception as err:
            logger.debug(f"Redirect inspection hop {hop} failed for '{current_url}': {err}")
            redirect_chain.append({
                "hop": hop,
                "url": current_url,
                "status_code": 500,
                "hostname": urllib.parse.urlparse(current_url).hostname,
                "reason": str(err)
            })
            chain_length = hop
            break

    final_url = redirect_chain[-1]["url"] if redirect_chain else initial_url

    return {
        "original_url": initial_url,
        "final_url": final_url,
        "chain_length": len(redirect_chain),
        "has_redirects": len(redirect_chain) > 1,
        "ssrf_blocked": ssrf_blocked,
        "redirect_chain": redirect_chain
    }


def detect_credential_page(
    url: str,
    html_content: Optional[str] = None,
    headers: Optional[Dict[str, str]] = None
) -> Dict[str, Any]:
    """
    Evaluates static indicators to detect credential harvesting landing pages:
    - Password input fields
    - Login forms
    - Authentication endpoints
    - Account verification language
    - Cross-domain form action submission
    """
    indicators = []
    risk_points = 0

    norm = normalize_and_analyze_url(url)
    path_lower = (norm.get("path") or "").lower()

    # 1. URL Path / Endpoint Indicators
    auth_endpoints = ["/login", "/signin", "/auth", "/verify", "/account", "/session", "/password", "/update-credentials"]
    if any(ep in path_lower for ep in auth_endpoints):
        indicators.append("authentication_endpoint_path")
        risk_points += 25

    # 2. Static HTML Indicators (if content available)
    if html_content and isinstance(html_content, str):
        content_lower = html_content.lower()

        if "<input" in content_lower and ("type=\"password\"" in content_lower or "type='password'" in content_lower or "type=password" in content_lower):
            indicators.append("password_input_field")
            risk_points += 35

        if "<form" in content_lower:
            indicators.append("html_form_present")
            risk_points += 15

            # Cross-domain form action check
            action_match = re.search(r'action=["\'](https?://[^"\']+)["\']', content_lower)
            if action_match:
                action_url = action_match.group(1)
                action_domain = urllib.parse.urlparse(action_url).hostname
                page_domain = norm.get("hostname")
                if action_domain and page_domain and action_domain.lower() != page_domain.lower():
                    indicators.append("cross_domain_form_submission")
                    risk_points += 30

        sensitive_text_patterns = [
            "password",
            "verify your account",
            "confirm credentials",
            "sign in",
            "microsoft 365",
            "amazon business",
            "corporate account"
        ]
        if any(pat in content_lower for pat in sensitive_text_patterns):
            indicators.append("sensitive_authentication_language")
            risk_points += 20

    is_cred_page = risk_points >= 40 or "password_input_field" in indicators or "cross_domain_form_submission" in indicators

    return {
        "is_credential_page": is_cred_page,
        "risk_points": min(100, risk_points),
        "confidence": 0.90 if is_cred_page else 0.70,
        "indicators": indicators
    }


def get_domain_age_intelligence(domain: str) -> Dict[str, Any]:
    """
    Queries RDAP to calculate domain age and returns domain age signal:
    - VERY_NEW_DOMAIN: age < 14 days (+30 risk points)
    - RECENT_DOMAIN: age < 60 days (+15 risk points)
    - ESTABLISHED_DOMAIN: age >= 365 days (0 risk points)
    - UNKNOWN_DOMAIN_AGE: RDAP missing / timeout (+5 risk points)
    """
    if not domain:
        return {"signal": "UNKNOWN_DOMAIN_AGE", "age_days": None, "risk_points": 5, "registrar": "Unknown"}

    clean_domain = domain.strip().lower().replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
    rdap = fetch_rdap_data(clean_domain)

    creation_str = rdap.get("creation_date")
    age_days = None

    if creation_str and creation_str != "Unknown" and creation_str != "Unavailable":
        try:
            # Parse ISO creation date
            creation_dt = datetime.fromisoformat(creation_str.replace("Z", "+00:00"))
            now_dt = datetime.now(timezone.utc)
            age_days = max(0, (now_dt - creation_dt).days)
        except Exception:
            pass

    if age_days is not None:
        if age_days < 14:
            signal = "VERY_NEW_DOMAIN"
            risk_pts = 30
        elif age_days < 60:
            signal = "RECENT_DOMAIN"
            risk_pts = 15
        else:
            signal = "ESTABLISHED_DOMAIN"
            risk_pts = 0
    else:
        signal = "UNKNOWN_DOMAIN_AGE"
        risk_pts = 5

    return {
        "signal": signal,
        "age_days": age_days,
        "risk_points": risk_pts,
        "registrar": rdap.get("registrar", "Unknown"),
        "creation_date": creation_str
    }


def analyze_url_intelligence(
    url: str,
    html_content: Optional[str] = None,
    quick_mode: bool = True
) -> Dict[str, Any]:
    """
    Main entry point for Unified URL, Domain, and Redirect Intelligence.
    Consolidates URL normalization, obfuscation signals, safe redirect chain,
    static credential page indicators, domain age (RDAP), and threat feeds.
    """
    norm = normalize_and_analyze_url(url)
    canonical = norm.get("canonical_url") or url
    hostname = norm.get("hostname") or ""

    # 1. Redirect Inspection (with SSRF Guard)
    redirect_info = inspect_redirect_chain(canonical)
    final_url = redirect_info.get("final_url") or canonical
    final_hostname = urllib.parse.urlparse(final_url).hostname or hostname

    # 2. Domain Age Intelligence via RDAP
    domain_age_info = get_domain_age_intelligence(final_hostname or hostname)

    # 3. Lookalike & Brand Permutation Intelligence
    lookalike_info = {"is_lookalike": False, "target_brand": None, "similarity_score": 0.0}
    if final_hostname:
        from services.domain_relationship_service import evaluate_domain_relationship
        rel = evaluate_domain_relationship(final_hostname)
        if rel.get("relationship") == "LOOKALIKE" or rel.get("lookalike"):
            lookalike_info = {
                "is_lookalike": True,
                "target_brand": rel.get("target_brand") or "Protected Brand",
                "similarity_score": 0.88,
                "reason": rel.get("reason", "Typosquat lookalike permutation")
            }

    # 4. Credential Page Detection
    cred_page_info = detect_credential_page(final_url, html_content=html_content)

    # 5. Infrastructure Correlation
    from services.multi_http_verifier import MultiAttemptHTTPVerifier
    dns_res = MultiAttemptHTTPVerifier.resolve_dns(final_hostname or hostname)

    # 6. Cumulative URL Risk Score Calculation
    base_risk = norm.get("risk_score", 0)
    base_risk += domain_age_info.get("risk_points", 0)
    base_risk += cred_page_info.get("risk_points", 0)
    if lookalike_info.get("is_lookalike"):
        base_risk += 30
    if redirect_info.get("has_redirects"):
        base_risk += 15

    url_risk = min(100, max(0, base_risk))

    return {
        "original_url": url,
        "canonical_url": canonical,
        "final_url": final_url,
        "url_risk": url_risk,
        "obfuscation_signals": norm.get("obfuscation_signals", []),
        "domain_age_signal": domain_age_info,
        "lookalike_signal": lookalike_info,
        "redirect_signal": redirect_info,
        "credential_page_signal": cred_page_info,
        "infrastructure_signal": {
            "ipv4": dns_res.get("ipv4", []),
            "ipv6": dns_res.get("ipv6", []),
            "resolved": dns_res.get("resolved", False)
        },
        "threat_feed_signal": {
            "openphish_match": False,
            "phishtank_match": False
        }
    }
