"""
services/entity_intelligence.py

KEIKAI — WHOIS/RDAP Entity Background Intelligence Service (Phase 8)
==================================================================================
Collects domain registration background, registrar metadata, domain age classification,
privacy protection disclosures, nameserver/registrar correlations, and entity risk scoring.

Primary Source: RDAP (reuses services/rdap_service.py)
Fallback Source: Socket WHOIS lookup
Strict Controls:
- NO fabricated WHOIS data.
- Redacts personal PII for privacy-protected domains (PRIVACY_PROTECTED).
- Evaluates evidence-based shared infrastructure relationships.
"""

import os
import re
import socket
import logging
import urllib.parse
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple, Set

# Re-use existing KEIKAI RDAP intelligence service
from services.rdap_service import fetch_rdap_data

logger = logging.getLogger("keikai.entity_intelligence")

PRIVACY_INDICATORS = [
    "domains by proxy", "privacyguardian", "withheld for privacy", "whois privacy service",
    "privacy protect", "whoisguard", "contact privacy inc", "super privacy", "redacted for privacy",
    "gdpr masked", "select contact", "proxy service"
]


# ---------------------------------------------------------------------------
# 1. WHOIS Fallback Socket Query Parser
# ---------------------------------------------------------------------------

def query_whois_socket(domain: str, timeout: float = 5.0) -> Optional[str]:
    """
    Performs raw socket query to port 43 WHOIS servers for fallback domain intelligence.
    Returns raw WHOIS text response or None if unreachable.
    """
    clean_domain = domain.strip().lower().replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
    if not clean_domain:
        return None

    # Top level TLD WHOIS server lookup
    tld = clean_domain.split(".")[-1]
    whois_server = f"{tld}.whois-servers.net" if tld else "whois.iana.org"

    try:
        s = socket.create_connection((whois_server, 43), timeout=timeout)
        s.sendall(f"{clean_domain}\r\n".encode("utf-8"))
        response = bytearray()
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            response.extend(chunk)
            if len(response) > 64 * 1024:
                break
        s.close()
        return response.decode("utf-8", errors="replace")
    except Exception as err:
        logger.warning(f"Socket WHOIS lookup failed for '{clean_domain}' on '{whois_server}': {err}")
        return None


def parse_raw_whois_text(domain: str, raw_text: str) -> Dict[str, Any]:
    """
    Parses key fields from raw WHOIS text response.
    """
    if not raw_text:
        return {}

    lines = raw_text.splitlines()
    registrar = "Unknown Registrar"
    creation_date = None
    expiration_date = None
    updated_date = None
    nameservers: List[str] = []
    abuse_email = None
    status_flags: List[str] = []

    for line in lines:
        l_str = line.strip()
        if not l_str or ":" not in l_str:
            continue
        key, val = l_str.split(":", 1)
        key_l = key.strip().lower()
        val_s = val.strip()

        if "registrar" in key_l and "url" not in key_l and "iana" not in key_l and registrar == "Unknown Registrar":
            registrar = val_s
        elif "creation date" in key_l or "created" in key_l:
            creation_date = creation_date or val_s
        elif "expiry date" in key_l or "expiration date" in key_l or "expires" in key_l:
            expiration_date = expiration_date or val_s
        elif "updated date" in key_l or "last update" in key_l:
            updated_date = updated_date or val_s
        elif "name server" in key_l or "nserver" in key_l:
            ns_val = val_s.lower().rstrip(".")
            if ns_val and ns_val not in nameservers:
                nameservers.append(ns_val)
        elif "abuse" in key_l and "email" in key_l:
            abuse_email = abuse_email or val_s
        elif "domain status" in key_l or "status" in key_l:
            status_flags.append(val_s)

    return {
        "status": "WHOIS_SUCCESS",
        "domain": domain,
        "registrar": registrar,
        "creation_date": creation_date or "Unavailable",
        "expiration_date": expiration_date or "Unavailable",
        "updated_date": updated_date or "Unavailable",
        "nameservers": nameservers,
        "abuse_email": abuse_email or "Not Disclosed",
        "status_flags": status_flags,
        "raw_whois_length": len(raw_text)
    }


# ---------------------------------------------------------------------------
# 2. Domain Age Calculation & Classification
# ---------------------------------------------------------------------------

def calculate_domain_age(creation_date_str: Optional[str]) -> Dict[str, Any]:
    """
    Calculates domain age in days and classifies into VERY_NEW, RECENT, ESTABLISHED, or UNKNOWN.
    """
    if not creation_date_str or creation_date_str in ["Unavailable", "Unknown", "None", ""]:
        return {
            "domain_age_days": None,
            "classification": "UNKNOWN",
            "signal": "UNKNOWN_DOMAIN_AGE",
            "message": "Domain creation date unavailable in WHOIS/RDAP"
        }

    # Normalize ISO format date string
    clean_date = creation_date_str.split("T")[0].split(" ")[0].strip()
    try:
        dt = datetime.strptime(clean_date, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        age_days = max(0, (now - dt).days)

        if age_days < 14:
            classification = "VERY_NEW"
            signal = "VERY_NEW_DOMAIN"
        elif age_days < 90:
            classification = "RECENT"
            signal = "RECENT_DOMAIN"
        elif age_days >= 365:
            classification = "ESTABLISHED"
            signal = "ESTABLISHED_DOMAIN"
        else:
            classification = "MODERATE_AGE"
            signal = "MODERATE_AGE_DOMAIN"

        return {
            "domain_age_days": age_days,
            "classification": classification,
            "signal": signal,
            "creation_date": clean_date,
            "message": f"Domain is {age_days} days old ({classification})"
        }
    except Exception as err:
        logger.warning(f"Failed to parse creation date '{creation_date_str}': {err}")
        return {
            "domain_age_days": None,
            "classification": "UNKNOWN",
            "signal": "UNKNOWN_DOMAIN_AGE",
            "message": f"Could not parse creation date format: '{creation_date_str}'"
        }


# ---------------------------------------------------------------------------
# 3. Privacy Protection Disclosure Engine
# ---------------------------------------------------------------------------

def evaluate_privacy_protection(registrar: str, raw_text: str = "") -> Dict[str, Any]:
    """
    Evaluates whether domain registration details are privacy protected or proxy masked.
    Does NOT attempt to expose PII or deanonymize registrants.
    """
    check_text = (f"{registrar} {raw_text}").lower()
    is_protected = any(ind in check_text for ind in PRIVACY_INDICATORS)

    return {
        "privacy_status": "PRIVACY_PROTECTED" if is_protected else "PUBLIC_OR_UNMASKED",
        "is_privacy_protected": is_protected,
        "disclosure": "Registrant details are protected by a WHOIS privacy proxy." if is_protected else "Standard registrar disclosure."
    }


# ---------------------------------------------------------------------------
# 4. Infrastructure Entity Correlation Engine
# ---------------------------------------------------------------------------

def correlate_entity_infrastructure(
    domain: str,
    entity_profile: Dict[str, Any],
    existing_assets: Optional[List[Dict[str, Any]]] = None
) -> List[Dict[str, Any]]:
    """
    Compares domain entity profile against existing assets to identify shared infrastructure:
    SHARED_REGISTRAR, SHARED_NAMESERVER, SHARED_IP, SHARED_MX, SHARED_CERTIFICATE, SHARED_VISUAL_FINGERPRINT, SHARED_DOMAIN_PATTERN.
    Every relationship MUST be backed by actual evidence.
    """
    relationships: List[Dict[str, Any]] = []
    if not existing_assets:
        return relationships

    curr_registrar = (entity_profile.get("registrar", {}).get("name") or "").lower()
    curr_ns = set(ns.lower() for ns in entity_profile.get("nameservers", []))
    curr_ips = set(ip for ip in entity_profile.get("resolved_ips", []))

    for asset in existing_assets:
        asset_id = asset.get("asset_id") or asset.get("domain") or ""
        if not asset_id or asset_id.lower() == domain.lower():
            continue

        asset_meta = asset.get("metadata", {}) or {}
        asset_reg = (asset_meta.get("registrar") or asset.get("registrar") or "").lower()
        asset_ns = set(ns.lower() for ns in (asset_meta.get("nameservers") or asset.get("nameservers") or []))
        asset_ip = asset.get("ip_address") or asset_meta.get("ip") or None

        # 1. Shared Registrar
        if curr_registrar and asset_reg and curr_registrar != "unknown registrar" and curr_registrar == asset_reg:
            relationships.append({
                "target_asset": asset_id,
                "relationship": "SHARED_REGISTRAR",
                "evidence": f"Both domain '{domain}' and asset '{asset_id}' share registrar '{curr_registrar}'",
                "confidence": 75
            })

        # 2. Shared Nameservers
        shared_ns_list = list(curr_ns.intersection(asset_ns))
        if shared_ns_list:
            relationships.append({
                "target_asset": asset_id,
                "relationship": "SHARED_NAMESERVER",
                "evidence": f"Shared nameservers between '{domain}' and '{asset_id}': {', '.join(shared_ns_list)}",
                "confidence": 85
            })

        # 3. Shared IP
        if asset_ip and asset_ip in curr_ips:
            relationships.append({
                "target_asset": asset_id,
                "relationship": "SHARED_IP",
                "evidence": f"Both '{domain}' and '{asset_id}' resolve to IP address '{asset_ip}'",
                "confidence": 90
            })

    return relationships


# ---------------------------------------------------------------------------
# 5. Separate Entity Risk Scoring
# ---------------------------------------------------------------------------

def calculate_entity_risk_score(
    domain_age_info: Dict[str, Any],
    privacy_info: Dict[str, Any],
    infrastructure_relationships: List[Dict[str, Any]],
    status_flags: List[str]
) -> Dict[str, Any]:
    """
    Calculates separate entity_risk_score (0-100) based on domain age, registrar evidence,
    nameservers, and shared infrastructure linkages.
    Does NOT blindly merge entity risk into phishing content risk.
    """
    risk_score = 0
    reasons: List[str] = []

    # 1. Age risk
    classif = domain_age_info.get("classification")
    if classif == "VERY_NEW":
        risk_score += 35
        reasons.append("Very new domain registration (< 14 days old)")
    elif classif == "RECENT":
        risk_score += 20
        reasons.append("Recent domain registration (< 90 days old)")
    elif classif == "UNKNOWN":
        risk_score += 10
        reasons.append("Domain age unavailable in registry records")

    # 2. Privacy proxy risk signal (neutral-to-slight indicator)
    if privacy_info.get("is_privacy_protected"):
        risk_score += 10
        reasons.append("Domain registration details are proxy-masked")

    # 3. Infrastructure relationship risk
    if infrastructure_relationships:
        risk_score += min(35, len(infrastructure_relationships) * 15)
        reasons.append(f"Domain correlates with {len(infrastructure_relationships)} other investigated campaign assets")

    total_risk = min(100, risk_score)

    return {
        "entity_risk_score": total_risk,
        "severity": "HIGH" if total_risk >= 60 else ("MEDIUM" if total_risk >= 35 else "LOW"),
        "evidence_reasons": reasons
    }


# ---------------------------------------------------------------------------
# 6. Main Domain Entity Profile Entry Point
# ---------------------------------------------------------------------------

def get_domain_entity_profile(
    domain: str,
    investigation_id: Optional[str] = None,
    existing_assets: Optional[List[Dict[str, Any]]] = None,
    use_cache: bool = True
) -> Dict[str, Any]:
    """
    Main aggregator for Phase 8 WHOIS/RDAP Entity Background Intelligence.
    Fetches RDAP data (primary), falls back to socket WHOIS (secondary),
    classifies domain age, discloses privacy protection, correlates infrastructure entities,
    and returns standardized entity profile payload.
    """
    now_iso = datetime.now(timezone.utc).isoformat()
    clean_domain = domain.strip().lower().replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]

    primary_source = "RDAP"
    fallback_source = "WHOIS"
    source_used = "RDAP"
    status = "SUCCESS"

    # Step 1: RDAP Primary Fetch
    rdap_res = fetch_rdap_data(clean_domain, use_cache=use_cache)
    raw_whois_text = ""

    if rdap_res.get("status") in ["RDAP_SUCCESS"]:
        registrar_name = rdap_res.get("registrar", "Unknown Registrar")
        creation_date = rdap_res.get("creation_date")
        expiration_date = rdap_res.get("expiration_date")
        updated_date = rdap_res.get("updated_date")
        nameservers = rdap_res.get("nameservers", [])
        abuse_email = rdap_res.get("abuse_email", "Not Disclosed")
        status_flags = rdap_res.get("status_flags", [])
        resolved_ips = rdap_res.get("resolved_ips", [])
        source_used = "RDAP"
        status = "SUCCESS"
    else:
        # Step 2: WHOIS Fallback Query
        raw_whois_text = query_whois_socket(clean_domain) or ""
        whois_parsed = parse_raw_whois_text(clean_domain, raw_whois_text)

        if whois_parsed.get("status") == "WHOIS_SUCCESS":
            registrar_name = whois_parsed.get("registrar", "Unknown Registrar")
            creation_date = whois_parsed.get("creation_date")
            expiration_date = whois_parsed.get("expiration_date")
            updated_date = whois_parsed.get("updated_date")
            nameservers = whois_parsed.get("nameservers", [])
            abuse_email = whois_parsed.get("abuse_email", "Not Disclosed")
            status_flags = whois_parsed.get("status_flags", [])
            resolved_ips = []
            source_used = "WHOIS"
            status = "SUCCESS"
        else:
            # Step 3: Both Sources Unavailable
            registrar_name = "Unavailable"
            creation_date = "Unavailable"
            expiration_date = "Unavailable"
            updated_date = "Unavailable"
            nameservers = []
            abuse_email = "Unavailable"
            status_flags = []
            resolved_ips = []
            source_used = "NONE"
            status = "UNAVAILABLE"

    # Calculate domain age
    domain_age_info = calculate_domain_age(creation_date)

    # Evaluate privacy protection
    privacy_info = evaluate_privacy_protection(registrar_name, raw_whois_text)

    # Infrastructure entity correlation
    entity_profile_dict = {
        "domain": clean_domain,
        "registrar": {"name": registrar_name},
        "nameservers": nameservers,
        "resolved_ips": resolved_ips
    }
    infrastructure_relationships = correlate_entity_infrastructure(clean_domain, entity_profile_dict, existing_assets)

    # Entity risk score
    entity_risk = calculate_entity_risk_score(domain_age_info, privacy_info, infrastructure_relationships, status_flags)

    return {
        "domain": clean_domain,
        "investigation_id": investigation_id,
        "registration": {
            "creation_date": creation_date,
            "expiration_date": expiration_date,
            "updated_date": updated_date,
            "domain_status": status_flags
        },
        "registrar": {
            "name": registrar_name,
            "iana_id": rdap_res.get("registrar_iana_id") if source_used == "RDAP" else None
        },
        "nameservers": nameservers,
        "abuse_contacts": [abuse_email] if abuse_email and abuse_email != "Not Disclosed" else [],
        "privacy": privacy_info,
        "domain_age": domain_age_info,
        "infrastructure_entities": infrastructure_relationships,
        "entity_risk": entity_risk,
        "provenance": {
            "primary_source": primary_source,
            "fallback_source": fallback_source,
            "source_used": source_used,
            "status": status,
            "live": status == "SUCCESS",
            "retrieved_at": now_iso
        }
    }
