"""
services/url_intelligence.py

KEKAI Autonomous Brand Intelligence & Phishing Engine
Complete URL & Domain Threat Analysis Pipeline (PS #2)
==================================================================================
Consolidates:
1. URL Normalization & Obfuscation Signals
2. Lookalike Domain & Permutation Analysis
3. Domain Registration Intelligence (RDAP) & Age Classification
4. DNS Intelligence (A, AAAA, MX, NS, TXT)
5. Safe Redirect Chain Tracer (with per-hop SSRF Protection)
6. Final Landing Page Credential-Page Inspection
7. Transparent Domain Risk Model & Provenance Metadata
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
from typing import Dict, Any, List, Optional, Tuple, Set

from services.redirect_tracer import trace_safe_redirect_chain, validate_target_ssrf_safety, KNOWN_URL_SHORTENERS
inspect_redirect_chain = trace_safe_redirect_chain
from services.rdap_service import fetch_rdap_data
from services.dns_intelligence_service import resolve_dns_records

logger = logging.getLogger("keikai.url_intelligence")

SUSPICIOUS_PORTS = {8080, 8443, 8000, 8888, 3000, 5000, 9000, 27017, 6379, 3306}
REJECTED_SCHEMES = {"javascript:", "data:", "file:", "ftp:", "about:", "blob:", "vbscript:"}
TRACKING_PARAMS = {"utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content", "fbclid", "gclid", "ref", "mc_cid"}


def normalize_and_analyze_url(raw_url: str) -> Dict[str, Any]:
    """
    Normalizes input URL and detects obfuscation signals:
    - Scheme, hostname, port, path, query, fragment normalization
    - Userinfo / auth abuse (user:pass@host)
    - IP-based hostname
    - Excessive subdomains (> 3 dots)
    - Non-standard web ports
    - Encoded hostname / URL encoding tricks
    - Punycode / IDN homoglyphs
    - Suspicious path / query parameters
    - Shortened or nested URLs
    """
    now_iso = datetime.now(timezone.utc).isoformat()

    if not raw_url or not isinstance(raw_url, str):
        return {
            "canonical_url": "",
            "scheme": "",
            "hostname": "",
            "port": None,
            "path": "",
            "is_valid": False,
            "is_ip": False,
            "obfuscation_signals": ["invalid_url_input"],
            "risk_score": 0,
            "provenance": {"source": "url_normalization", "status": "ERROR", "live": False, "retrieved_at": now_iso}
        }

    url = raw_url.strip()
    raw_lower = url.lower()

    # Reject unsupported/dangerous schemes
    for bad_scheme in REJECTED_SCHEMES:
        if raw_lower.startswith(bad_scheme):
            return {
                "canonical_url": raw_url,
                "scheme": bad_scheme.rstrip(":"),
                "hostname": "",
                "path": raw_url,
                "is_valid": False,
                "is_ip": False,
                "obfuscation_signals": ["suspicious_url_scheme", "rejected_unsupported_scheme"],
                "risk_score": 50,
                "provenance": {"source": "url_normalization", "status": "REJECTED_SCHEME", "live": False, "retrieved_at": now_iso}
            }

    # Detect userinfo abuse before scheme addition
    userinfo_abuse = False
    if "@" in url.split("/")[2] if "://" in url and len(url.split("/")) > 2 else "@" in url.split("/")[0]:
        userinfo_abuse = True

    # Scheme normalization
    if not (raw_lower.startswith("http://") or raw_lower.startswith("https://")):
        url = "https://" + url

    try:
        parsed = urllib.parse.urlparse(url)
    except Exception as err:
        return {
            "canonical_url": raw_url,
            "scheme": "",
            "hostname": "",
            "path": "",
            "is_valid": False,
            "is_ip": False,
            "obfuscation_signals": ["malformed_url_format"],
            "risk_score": 30,
            "provenance": {"source": "url_normalization", "status": "ERROR", "live": False, "retrieved_at": now_iso, "error": str(err)}
        }

    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()

    # Strip userinfo from netloc for hostname extraction
    if "@" in netloc:
        netloc = netloc.split("@")[-1]

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

    # Strip trailing dot from hostname
    hostname = hostname.rstrip(".")

    # Filter out tracking parameters
    query_params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    filtered_query = []
    for k, v_list in query_params.items():
        if k.lower() not in TRACKING_PARAMS:
            for val in v_list:
                filtered_query.append((k, val))

    canonical_query = urllib.parse.urlencode(filtered_query)

    canonical_url = f"{scheme}://{hostname}{f':{port}' if port and port not in (80, 443) else ''}{path}"
    if canonical_query:
        canonical_url += f"?{canonical_query}"

    obfuscation_signals: List[str] = []
    risk_score = 0

    # Signal 1: Encoding tricks
    if "%" in raw_url:
        unquoted = urllib.parse.unquote(raw_url)
        if "%" in unquoted or any(c in raw_lower for c in ["%2f", "%40", "%3a", "%2e"]):
            obfuscation_signals.append("url_encoding_obfuscation")
            risk_score += 15

    # Signal 2: Userinfo auth abuse
    if userinfo_abuse:
        obfuscation_signals.append("userinfo_auth_abuse")
        risk_score += 25

    # Signal 3: Excessive subdomains (> 3 dots)
    subdomain_parts = [p for p in hostname.split(".") if p]
    if len(subdomain_parts) > 3:
        obfuscation_signals.append("excessive_subdomain_depth")
        risk_score += 20

    # Signal 4: Non-standard port
    if port and port in SUSPICIOUS_PORTS:
        obfuscation_signals.append("suspicious_non_standard_port")
        risk_score += 20

    # Signal 5: IP-based hostname
    is_ip = False
    try:
        ipaddress.ip_address(hostname)
        is_ip = True
        obfuscation_signals.append("ip_based_hostname")
        risk_score += 30
    except ValueError:
        pass

    # Signal 6: Punycode / IDN homoglyph
    if hostname.startswith("xn--") or any(ord(c) > 127 for c in hostname):
        obfuscation_signals.append("punycode_homoglyph_indicator")
        risk_score += 25

    # Signal 7: Shortened URL
    if hostname.lower() in KNOWN_URL_SHORTENERS:
        obfuscation_signals.append("url_shortener_detected")
        risk_score += 15

    # Signal 8: Nested URL in query string
    if "http://" in parsed.query.lower() or "https://" in parsed.query.lower():
        obfuscation_signals.append("nested_url_detected")
        risk_score += 20

    return {
        "canonical_url": canonical_url,
        "scheme": scheme,
        "hostname": hostname,
        "port": port,
        "path": path,
        "is_valid": True,
        "is_ip": is_ip,
        "obfuscation_signals": obfuscation_signals,
        "risk_score": min(100, risk_score),
        "provenance": {
            "source": "url_normalization",
            "status": "SUCCESS",
            "live": True,
            "retrieved_at": now_iso
        }
    }


def get_lookalike_analysis(candidate_domain: str, official_domain: Optional[str] = None) -> Dict[str, Any]:
    """
    Evaluates lookalike domain indicators:
    - Typo insertion/deletion/substitution/transposition
    - Bitsquatting / hyphenation
    - Subdomain abuse & IDN/punycode
    """
    now_iso = datetime.now(timezone.utc).isoformat()
    clean_cand = candidate_domain.strip().lower().replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]

    from services.domain_relationship_service import evaluate_domain_relationship
    rel_res = evaluate_domain_relationship(clean_cand, official_domain=official_domain)

    is_lookalike = rel_res.get("relationship") == "LOOKALIKE" or rel_res.get("lookalike", False)
    fuzzer_type = rel_res.get("fuzzer_type") or ("homoglyph" if clean_cand.startswith("xn--") else "typosquat")
    similarity_pct = rel_res.get("similarity_percentage", 85.0 if is_lookalike else 0.0)

    # Check DNS resolution
    dns_info = resolve_dns_records(clean_cand, use_cache=True)
    resolves = len(dns_info.get("resolved_ips", [])) > 0

    risk = 80 if (is_lookalike and resolves) else (50 if is_lookalike else 0)

    candidate_meta = {
        "domain": clean_cand,
        "official_domain": official_domain or rel_res.get("target_brand_domain", "amazon.com"),
        "similarity": similarity_pct,
        "fuzzer_type": fuzzer_type,
        "punycode": clean_cand.startswith("xn--") or any(ord(c) > 127 for c in clean_cand),
        "resolves": resolves,
        "risk": risk
    }

    return {
        "is_lookalike": is_lookalike,
        "target_brand": rel_res.get("target_brand") or "Protected Brand",
        "candidate": candidate_meta,
        "reason": rel_res.get("reason", "Domain similarity evaluation"),
        "provenance": {
            "source": "lookalike_engine",
            "status": "SUCCESS",
            "live": True,
            "retrieved_at": now_iso
        }
    }


def get_domain_registration_intelligence(domain: str) -> Dict[str, Any]:
    """
    Queries RDAP for registration metadata and domain age classification:
    - VERY_NEW: < 30 days
    - RECENT: 30 - 180 days
    - ESTABLISHED: > 180 days
    - UNKNOWN: RDAP missing/unavailable
    """
    now_iso = datetime.now(timezone.utc).isoformat()
    if not domain:
        return _build_registration_error(domain, "INVALID_INPUT", now_iso)

    clean_domain = domain.strip().lower().replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
    rdap = fetch_rdap_data(clean_domain, use_cache=True)

    status_msg = rdap.get("status", "RDAP_UNAVAILABLE")
    creation_str = rdap.get("creation_date")
    expiration_str = rdap.get("expiration_date")
    registrar = rdap.get("registrar", "Unknown")

    age_days = None
    classification = "UNKNOWN"
    risk_points = 5

    if creation_str and creation_str not in ["Unknown", "Unavailable"]:
        try:
            creation_dt = datetime.fromisoformat(creation_str.replace("Z", "+00:00"))
            now_dt = datetime.now(timezone.utc)
            age_days = max(0, (now_dt - creation_dt).days)

            if age_days < 30:
                classification = "VERY_NEW"
                risk_points = 30
            elif age_days < 180:
                classification = "RECENT"
                risk_points = 15
            else:
                classification = "ESTABLISHED"
                risk_points = 0
        except Exception:
            pass

    sig_label = f"{classification}_DOMAIN" if classification != "UNKNOWN" else "UNKNOWN_DOMAIN_AGE"
    if classification == "VERY_NEW" and age_days is not None and age_days < 14:
        sig_label = "VERY_NEW_DOMAIN"

    return {
        "status": status_msg,
        "domain": clean_domain,
        "domain_age_days": age_days,
        "classification": classification,
        "signal": sig_label,
        "creation_date": creation_str,
        "expiration_date": expiration_str,
        "registrar": registrar,
        "nameservers": rdap.get("nameservers", []),
        "abuse_contact": rdap.get("abuse_email", "Not Disclosed"),
        "risk_points": risk_points,
        "provenance": {
            "source": "rdap",
            "status": status_msg,
            "live": status_msg == "RDAP_SUCCESS",
            "retrieved_at": now_iso
        }
    }


get_domain_age_intelligence = get_domain_registration_intelligence


def _build_registration_error(domain: str, status_msg: str, timestamp: str) -> Dict[str, Any]:
    return {
        "status": status_msg,
        "domain": domain,
        "domain_age_days": None,
        "classification": "UNKNOWN",
        "signal": "UNKNOWN_DOMAIN_AGE",
        "creation_date": "Unavailable",
        "expiration_date": "Unavailable",
        "registrar": "Unavailable",
        "nameservers": [],
        "abuse_contact": "Unavailable",
        "risk_points": 5,
        "provenance": {
            "source": "rdap",
            "status": status_msg,
            "live": False,
            "retrieved_at": timestamp
        }
    }


def detect_credential_page(
    url: str,
    html_content: Optional[str] = None,
    headers: Optional[Dict[str, str]] = None
) -> Dict[str, Any]:
    """
    Analyzes final URL & static HTML DOM for credential harvesting landing page indicators.
    Does NOT submit credentials or execute binaries.
    """
    now_iso = datetime.now(timezone.utc).isoformat()
    norm = normalize_and_analyze_url(url)
    path_lower = (norm.get("path") or "").lower()

    credential_indicators: List[str] = []
    form_action_domains: List[str] = []
    login_form = False
    password_input = False
    email_username_input = False
    risk_points = 0

    # 1. URL Path auth endpoint check
    auth_paths = ["/login", "/signin", "/auth", "/verify", "/account", "/session", "/password", "/update-credentials"]
    if any(ap in path_lower for ap in auth_paths):
        credential_indicators.append("authentication_endpoint_path")
        risk_points += 20

    # 2. Static HTML DOM Inspection
    if html_content and isinstance(html_content, str):
        content_lower = html_content.lower()

        if "<input" in content_lower and ("type=\"password\"" in content_lower or "type='password'" in content_lower or "type=password" in content_lower):
            password_input = True
            credential_indicators.append("password_input_detected")
            credential_indicators.append("password_input_field")
            risk_points += 35

        if "<input" in content_lower and ("type=\"email\"" in content_lower or "name=\"username\"" in content_lower or "name=\"email\"" in content_lower):
            email_username_input = True
            credential_indicators.append("email_username_input_detected")
            risk_points += 15

        if "<form" in content_lower:
            login_form = True
            credential_indicators.append("login_form_detected")
            credential_indicators.append("html_form_present")
            risk_points += 15

            # Extract form action submission domains
            actions = re.findall(r'action=["\'](https?://[^"\']+)["\']', content_lower)
            for act in actions:
                act_host = urllib.parse.urlparse(act).hostname
                if act_host:
                    form_action_domains.append(act_host.lower())
                    if norm.get("hostname") and act_host.lower() != norm.get("hostname").lower():
                        credential_indicators.append("cross_domain_form_action")
                        risk_points += 30

        auth_text_terms = ["verify your account", "confirm credentials", "sign in", "sign in to continue", "corporate account", "microsoft 365 login", "amazon corporate access"]
        if any(term in content_lower for term in auth_text_terms):
            credential_indicators.append("sensitive_authentication_language")
            risk_points += 20

    is_cred_page = risk_points >= 35 or password_input or "cross_domain_form_action" in credential_indicators

    return {
        "credential_page": is_cred_page,
        "is_credential_page": is_cred_page,
        "login_form": login_form,
        "password_input": password_input,
        "email_username_input": email_username_input,
        "credential_indicators": credential_indicators,
        "indicators": credential_indicators,
        "form_action_domains": list(set(form_action_domains)),
        "risk_points": min(100, risk_points),
        "provenance": {
            "source": "credential_page_detector",
            "status": "SUCCESS",
            "live": True,
            "retrieved_at": now_iso
        }
    }


def calculate_domain_risk_model(
    url_norm: Dict[str, Any],
    lookalike_info: Dict[str, Any],
    registration_info: Dict[str, Any],
    redirect_info: Dict[str, Any],
    cred_page_info: Dict[str, Any],
    dns_info: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Transparent, non-double-counted domain risk calculation:
    - domain_similarity: 0 - 30 pts (Lookalike / typosquat candidate)
    - registration: 0 - 30 pts (Very new / recent domain age)
    - redirect: 0 - 25 pts (Multi-hop / shortener / cross-domain redirects)
    - credential_page: 0 - 35 pts (Static HTML DOM password / auth form indicators)
    - infrastructure: 0 - 15 pts (Obfuscation signals / suspicious ports)
    Max cap: 100 pts.
    """
    # 1. Domain Similarity
    sim_pts = 0
    if lookalike_info.get("is_lookalike"):
        sim_pts = 30
    elif lookalike_info.get("signal") in ["HIGH_SIMILARITY", "EXACT_TYPOSQUAT"]:
        sim_pts = 25

    # 2. Registration / Domain Age
    reg_pts = registration_info.get("risk_points", 0)
    sig = registration_info.get("signal")
    if sig == "VERY_NEW_DOMAIN":
        reg_pts = max(reg_pts, 30)
    elif sig == "RECENT_DOMAIN":
        reg_pts = max(reg_pts, 20)

    # 3. Redirect
    red_pts = 0
    signals = redirect_info.get("signals", [])
    if "MULTI_HOP_REDIRECT" in signals or redirect_info.get("has_redirects") or redirect_info.get("chain_length", 0) > 1:
        red_pts += 15
    if "SHORTENER_REDIRECT" in signals:
        red_pts += 10
    if "CROSS_DOMAIN_REDIRECT" in signals:
        red_pts += 10
    red_pts = min(25, max(red_pts, 15 if redirect_info.get("has_redirects") else 0))

    # 4. Credential Page
    cred_pts = cred_page_info.get("risk_points", 0)
    if cred_page_info.get("is_credential_page") and cred_pts == 0:
        cred_pts = 35
    cred_pts = min(35, cred_pts)

    # 5. Infrastructure / Obfuscation
    infra_pts = min(15, url_norm.get("risk_score", 0))

    total_risk = min(100, sim_pts + reg_pts + red_pts + cred_pts + infra_pts)

    return {
        "domain_similarity": sim_pts,
        "registration": reg_pts,
        "redirect": red_pts,
        "credential_page": cred_pts,
        "infrastructure": infra_pts,
        "total": total_risk
    }


def analyze_url_intelligence(
    url: str,
    html_content: Optional[str] = None,
    official_domain: Optional[str] = None,
    brand: Optional[str] = None,
    quick_mode: bool = True
) -> Dict[str, Any]:
    """
    Main entry point for Complete URL, Domain, and Redirect Intelligence (PS #2).
    Consolidates URL normalization, lookalike domain matching, RDAP age tracking,
    DNS resolution, SSRF-safe redirect tracer, static credential landing page analysis,
    and transparent risk modeling.
    """
    now_iso = datetime.now(timezone.utc).isoformat()

    # 1. Normalization
    norm = normalize_and_analyze_url(url)
    canonical = norm.get("canonical_url") or url
    hostname = norm.get("hostname") or ""

    # 2. Safe Redirect Chain Tracer (SSRF Guard Enabled)
    redirect_info = inspect_redirect_chain(canonical)
    final_url = redirect_info.get("final_url") or canonical
    final_hostname = urllib.parse.urlparse(final_url).hostname or hostname

    # 3. Lookalike Engine
    lookalike_info = get_lookalike_analysis(final_hostname or hostname, official_domain=official_domain)

    # 4. Domain Registration Intelligence (RDAP)
    registration_info = get_domain_age_intelligence(final_hostname or hostname)

    # 5. DNS Intelligence
    dns_info = resolve_dns_records(final_hostname or hostname, use_cache=True)

    # 6. Credential Landing Page Analysis
    cred_page_info = detect_credential_page(final_url, html_content=html_content)

    # 7. Transparent Domain Risk Model
    risk_breakdown = calculate_domain_risk_model(norm, lookalike_info, registration_info, redirect_info, cred_page_info, dns_info)

    return {
        "original_url": url,
        "canonical_url": canonical,
        "final_url": final_url,
        "domain": final_hostname or hostname,
        "url_risk": risk_breakdown["total"],
        "risk_breakdown": risk_breakdown,
        "normalization": norm,
        "lookalike_analysis": lookalike_info,
        "registration": registration_info,
        "domain_age_signal": registration_info,
        "dns": dns_info,
        "redirect_chain": redirect_info,
        "redirect_signal": redirect_info,
        "credential_page": cred_page_info,
        "provenance": {
            "source": "url_intelligence_engine",
            "status": "SUCCESS",
            "live": True,
            "retrieved_at": now_iso
        }
    }
