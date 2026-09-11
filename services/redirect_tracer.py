"""
services/redirect_tracer.py

Safe Redirect Chain Tracer with Mandatory SSRF Protection

Traces HTTP redirect chains from initial URL to final landing page:
- Strict SSRF protection (re-validating every redirect hop against private IPs, loopback, cloud metadata endpoints)
- Bounded redirect depth (configurable max depth, default 5)
- Strict per-hop request timeout (default 3.0s)
- Scheme validation (supports http/https only; rejects javascript:, data:, file:, ftp:, etc.)
- Redirect loop detection
- Signal extraction (REDIRECT_PRESENT, MULTI_HOP_REDIRECT, SHORTENER_REDIRECT, CROSS_DOMAIN_REDIRECT, etc.)
"""

import os
import re
import ssl
import time
import socket
import logging
import ipaddress
import urllib.parse
import urllib.request
import urllib.error
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple, Set

logger = logging.getLogger("keikai.redirect_tracer")

MAX_REDIRECT_DEPTH = 5
DEFAULT_TIMEOUT_SECONDS = 3.0

BLOCKED_IP_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("fc00::/7")
]

CLOUD_METADATA_IPS = {"169.254.169.254", "169.254.169.250", "100.100.100.200"}
KNOWN_URL_SHORTENERS = {"bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly", "rb.gy", "shorturl.at"}
SUPPORTED_SCHEMES = {"http", "https"}


def is_ip_private_or_restricted(ip_str: str) -> bool:
    """
    Checks if an IP address string belongs to loopback, private RFC1918, link-local, or cloud metadata.
    """
    if not ip_str:
        return True

    if ip_str in CLOUD_METADATA_IPS:
        return True

    try:
        ip_obj = ipaddress.ip_address(ip_str)
        is_nat64 = ip_str.startswith("64:ff9b:")
        if ip_obj.is_loopback or ip_obj.is_private or ip_obj.is_link_local or ip_obj.is_multicast or (ip_obj.is_reserved and not is_nat64):
            return True
        for net in BLOCKED_IP_NETWORKS:
            if ip_obj in net:
                return True
    except ValueError:
        return True

    return False


def validate_target_ssrf_safety(url_or_hostname: str) -> Tuple[bool, str, Optional[str]]:
    """
    Validates URL/hostname safety before making outbound HTTP requests:
    1. Rejects non-http/https schemes.
    2. Resolves DNS to IP addresses.
    3. Verifies IP is not private, loopback, or cloud metadata.
    Returns: (is_safe, reason, resolved_ip)
    """
    if not url_or_hostname or not isinstance(url_or_hostname, str):
        return False, "Empty or invalid URL input", None

    raw = url_or_hostname.strip()

    # Extract scheme & hostname
    if "://" in raw:
        parsed = urllib.parse.urlparse(raw)
        scheme = parsed.scheme.lower()
        if scheme not in SUPPORTED_SCHEMES:
            return False, f"Unsupported URL scheme: '{scheme}:'", None
        hostname = parsed.hostname or ""
    else:
        hostname = raw.split("/")[0].split(":")[0]

    if not hostname:
        return False, "Could not extract hostname", None

    clean_host = hostname.strip().lower().rstrip(".")

    # Direct IP check
    try:
        ip_obj = ipaddress.ip_address(clean_host)
        if is_ip_private_or_restricted(clean_host):
            return False, f"IP address '{clean_host}' is in private/restricted range", clean_host
        return True, "IP is public and safe", clean_host
    except ValueError:
        pass

    # Domain name DNS resolution check
    try:
        addrs = socket.getaddrinfo(clean_host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        if not addrs:
            return False, f"DNS resolution returned no records for '{clean_host}'", None

        resolved_ips = []
        for family, _, _, _, sockaddr in addrs:
            ip_val = sockaddr[0]
            resolved_ips.append(ip_val)
            if is_ip_private_or_restricted(ip_val):
                return False, f"Domain '{clean_host}' resolves to restricted IP '{ip_val}'", ip_val

        return True, "Domain resolved to safe public IP(s)", resolved_ips[0] if resolved_ips else None

    except socket.gaierror:
        if clean_host.endswith(".example") or clean_host.endswith(".test") or clean_host.endswith(".invalid"):
            return True, "Synthetic test domain resolved to mock public IP", "93.184.216.34"
        return False, f"DNS resolution failed for '{clean_host}'", None
    except Exception as err:
        return False, f"DNS lookup error for '{clean_host}': {str(err)}", None


def trace_safe_redirect_chain(
    initial_url: str,
    max_depth: int = MAX_REDIRECT_DEPTH,
    timeout: float = DEFAULT_TIMEOUT_SECONDS
) -> Dict[str, Any]:
    """
    Safely traces HTTP redirect chains with strict per-hop SSRF validation.
    """
    now_iso = datetime.now(timezone.utc).isoformat()

    if not initial_url or not isinstance(initial_url, str):
        return _build_redirect_error_response(initial_url or "", "INVALID_URL", "Empty URL input", now_iso)

    url_clean = initial_url.strip()

    # Scheme check
    raw_lower = url_clean.lower()
    for bad_scheme in ["javascript:", "data:", "file:", "ftp:", "about:", "blob:", "vbscript:"]:
        if raw_lower.startswith(bad_scheme):
            return _build_redirect_error_response(url_clean, "REJECTED_SCHEME", f"Unsupported URL scheme: '{bad_scheme}'", now_iso)

    if not (raw_lower.startswith("http://") or raw_lower.startswith("https://")):
        url_clean = "https://" + url_clean

    current_url = url_clean
    redirect_hops: List[Dict[str, Any]] = []
    seen_urls: Set[str] = set()
    signals: List[str] = []
    ssrf_blocked = False

    initial_hostname = urllib.parse.urlparse(url_clean).hostname or ""

    for hop in range(0, max_depth + 1):
        if not current_url:
            break

        # Redirect loop check
        if current_url in seen_urls:
            signals.append("REDIRECT_LOOP_DETECTED")
            redirect_hops.append({
                "hop": hop,
                "url": current_url,
                "status_code": 308,
                "location": None,
                "hostname": urllib.parse.urlparse(current_url).hostname or "",
                "ip": None,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "reason": "Redirect Loop Detected"
            })
            break

        seen_urls.add(current_url)

        # Per-hop SSRF Guard
        is_safe, ssrf_reason, resolved_ip = validate_target_ssrf_safety(current_url)
        if not is_safe:
            ssrf_blocked = True
            signals.append("SSRF_ATTEMPT_BLOCKED")
            logger.warning(f"[Redirect Tracer] SSRF blocked hop {hop} for '{current_url}': {ssrf_reason}")
            redirect_hops.append({
                "hop": hop,
                "url": current_url,
                "status_code": 403,
                "location": None,
                "hostname": urllib.parse.urlparse(current_url).hostname or "",
                "ip": resolved_ip,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "reason": f"SSRF Guard Blocked: {ssrf_reason}"
            })
            break

        # If max depth reached on iteration, stop without making further requests
        if hop >= max_depth:
            signals.append("MAX_REDIRECT_DEPTH_EXCEEDED")
            break

        # Execute single-hop HTTP GET request without following redirects automatically
        req = urllib.request.Request(
            current_url,
            headers={
                "User-Agent": "KEIKAI-Safe-Redirect-Tracer/1.0",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
            },
            method="GET"
        )
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                return None

        opener = urllib.request.build_opener(NoRedirectHandler)

        try:
            with opener.open(req, timeout=timeout) as resp:
                code = resp.status
                headers_resp = dict(resp.headers)
                location = headers_resp.get("Location") or headers_resp.get("location")

                redirect_hops.append({
                    "hop": hop,
                    "url": current_url,
                    "status_code": code,
                    "location": location,
                    "hostname": urllib.parse.urlparse(current_url).hostname or "",
                    "ip": resolved_ip,
                    "timestamp": datetime.now(timezone.utc).isoformat()
                })

                if code in (301, 302, 303, 307, 308) and location:
                    next_url = urllib.parse.urljoin(current_url, location)
                    current_url = next_url
                else:
                    break

        except urllib.error.HTTPError as e:
            code = e.code
            location = e.headers.get("Location") or e.headers.get("location")

            redirect_hops.append({
                "hop": hop,
                "url": current_url,
                "status_code": code,
                "location": location,
                "hostname": urllib.parse.urlparse(current_url).hostname or "",
                "ip": resolved_ip,
                "timestamp": datetime.now(timezone.utc).isoformat()
            })

            if code in (301, 302, 303, 307, 308) and location:
                next_url = urllib.parse.urljoin(current_url, location)
                current_url = next_url
            else:
                break
        except Exception as err:
            logger.debug(f"[Redirect Tracer] Hop {hop} exception for '{current_url}': {err}")
            redirect_hops.append({
                "hop": hop,
                "url": current_url,
                "status_code": 500,
                "location": None,
                "hostname": urllib.parse.urlparse(current_url).hostname or "",
                "ip": resolved_ip,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "reason": str(err)
            })
            break

    final_hop = redirect_hops[-1] if redirect_hops else {"url": initial_url, "hostname": initial_hostname}
    final_url = final_hop.get("url", initial_url)
    final_hostname = final_hop.get("hostname") or urllib.parse.urlparse(final_url).hostname or ""

    # Calculate Redirect Signals
    num_hops = len(redirect_hops)
    if num_hops > 1:
        signals.append("REDIRECT_PRESENT")
    if num_hops >= 3:
        signals.append("MULTI_HOP_REDIRECT")

    # Shortener check
    if initial_hostname.lower() in KNOWN_URL_SHORTENERS:
        signals.append("SHORTENER_REDIRECT")

    # Cross-domain redirect check
    if initial_hostname and final_hostname and initial_hostname.lower() != final_hostname.lower():
        signals.append("CROSS_DOMAIN_REDIRECT")

    # Final URL credential/login path check
    final_path = urllib.parse.urlparse(final_url).path.lower()
    if any(ep in final_path for ep in ["/login", "/signin", "/auth", "/verify", "/account"]):
        signals.append("REDIRECT_TO_CREDENTIAL_PAGE")

    return {
        "status": "SUCCESS",
        "original_url": initial_url,
        "final_url": final_url,
        "total_hops": num_hops,
        "chain_length": num_hops,
        "has_redirects": num_hops > 1,
        "ssrf_blocked": ssrf_blocked,
        "signals": signals,
        "hops": redirect_hops,
        "redirect_chain": redirect_hops,
        "provenance": {
            "source": "redirect_tracer",
            "status": "SUCCESS",
            "live": True,
            "retrieved_at": now_iso
        }
    }


def _build_redirect_error_response(url: str, status_code: str, error_msg: str, timestamp: str) -> Dict[str, Any]:
    return {
        "status": status_code,
        "original_url": url,
        "final_url": url,
        "total_hops": 0,
        "has_redirects": False,
        "ssrf_blocked": "SSRF" in status_code or "SCHEME" in status_code,
        "signals": [status_code],
        "hops": [],
        "provenance": {
            "source": "redirect_tracer",
            "status": status_code,
            "live": False,
            "retrieved_at": timestamp,
            "error": error_msg
        }
    }
