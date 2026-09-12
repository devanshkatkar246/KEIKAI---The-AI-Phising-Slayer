"""
services/email_analysis.py

KEIKAI ORGANISATIONAL PHISHING DEFENCE — EMAIL THREAT ANALYSIS ENGINE

Provides end-to-end processing:
1. Email parsing & IOC extraction (URLs, domains, email addresses, IP addresses, brand mentions)
2. Deterministic security signal detection (urgency, credential harvesting, suspicious URLs, sender mismatch, brand impersonation, financial request)
3. Structured signal evidence compilation
4. Transparent weighted risk scoring
5. AI-assisted reasoning (Gemini API when credentials available, with seamless deterministic fallback)
6. Clean handoff package for existing KEKAI Threat Intelligence investigation engine
"""

import os
import re
import uuid
import json
import logging
import urllib.request
import urllib.parse
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple
from services.sender_behavior import evaluate_sender_behavior

logger = logging.getLogger("keikai.services.email_analysis")

# Configurable list of recognized corporate brand domains for impersonation detection
KNOWN_BRAND_MAP = {
    "amazon": ["amazon.com", "amazon.co.uk", "amazon.de", "aws.amazon.com"],
    "microsoft": ["microsoft.com", "office.com", "office365.com", "outlook.com", "live.com", "azure.com"],
    "apple": ["apple.com", "icloud.com"],
    "google": ["google.com", "gmail.com", "accounts.google.com"],
    "rolex": ["rolex.com"],
    "facebook": ["facebook.com", "meta.com"],
    "netflix": ["netflix.com"],
    "paypal": ["paypal.com"],
    "chase": ["chase.com"],
    "bank of america": ["bankofamerica.com"],
    "wells fargo": ["wellsfargo.com"],
    "docusign": ["docusign.com", "docusign.net"],
    "dhl": ["dhl.com"],
    "fedex": ["fedex.com"]
}

# Suspicious top-level domains commonly used in phishing campaigns
SUSPICIOUS_TLDS = {".xyz", ".online", ".top", ".click", ".site", ".support", ".vip", ".work", ".live", ".info", ".shop", ".app"}

# RegEx patterns for IOC extraction
URL_REGEX = re.compile(r'https?://[^\s<>"\':\)\(]+|www\.[^\s<>"\':\)\(]+|[a-zA-Z0-9-]+\.[a-zA-Z0-9-]+\.[a-zA-Z]{2,}(?:/[^\s<>"\':\)\(]*)?', re.IGNORECASE)
EMAIL_REGEX = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', re.IGNORECASE)
IPV4_REGEX = re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b')

# Signal detection keyword rules
URGENCY_KEYWORDS = [
    "urgent", "immediately", "within 24 hours", "within 48 hours", "account suspended",
    "action required", "verify now", "final warning", "expires today", "restricted",
    "unusual activity", "temporarily restricted", "terminate", "critical alert", "immediate attention"
]

CREDENTIAL_KEYWORDS = [
    "password", "login", "verify account", "confirm credentials", "sign in",
    "security verification", "reset password", "update account", "authenticate",
    "enter your credentials", "sign-in", "verification link"
]

SUSPICIOUS_PATH_KEYWORDS = [
    "/login", "/auth", "/verify", "/account", "/signin", "/credential", "/update",
    "/secure", "/wallet", "/confirm", "/admin", "/checkpoint"
]

FINANCIAL_KEYWORDS = [
    "invoice", "overdue", "payment", "wire transfer", "bank details", "settle invoice",
    "billing department", "remittance", "swift code", "bitcoin", "gift card", "unpaid bill"
]


def normalize_url(raw_url: str) -> str:
    """
    Robustly normalizes raw URL strings:
    - Extracts target URL from markdown link patterns like [text](http://url)
    - Strips angle brackets <...>, quotes "... ", square brackets [...]
    - Trims trailing punctuation (., ;, ), ], ", ') while preserving query string parameters and paths
    - Prepends https:// if starting with www.
    """
    if not raw_url:
        return ""
    
    url = raw_url.strip()

    # Handle Markdown link format: [anchor text](https://target-url)
    md_match = re.search(r'\[.*?\]\((https?://[^\s\)]+)\)', url, re.IGNORECASE)
    if md_match:
        url = md_match.group(1)
    else:
        md_match2 = re.search(r'(?:https?://[^\s\)]+)?\]\((https?://[^\s\)]+)\)', url, re.IGNORECASE)
        if md_match2:
            url = md_match2.group(1)
        else:
            md_match3 = re.search(r'\[.*?\]\(([^\s\)]+)\)', url)
            if md_match3:
                url = md_match3.group(1)

    # If url still contains "](", extract the embedded clean URL
    if ']' in url or '[' in url or '(' in url or ')' in url:
        sub_urls = re.findall(r'https?://[^\s<>"\':\)\(\]\[]+', url)
        if sub_urls:
            url = sub_urls[-1]  # Prefer the target link inside parentheses

    # Strip surrounding angle brackets, quotes, brackets, parens
    url = url.strip('<>"\'[]()')

    # Trim trailing punctuation (dot, comma, semicolon, closing paren/bracket) that are not part of query string
    url = re.sub(r'[\.,;\)\]]+$', '', url)

    url = url.strip()

    # Ensure URL starts with http:// or https:// if starting with www.
    if url.lower().startswith('www.'):
        url = 'https://' + url

    return url


def clean_domain(domain_or_url: str) -> str:
    """Cleans and extracts bare domain hostname from string or URL."""
    if not domain_or_url:
        return ""
    norm = normalize_url(domain_or_url)
    d = norm.lower()
    d = re.sub(r'^https?://', '', d)
    d = d.split('/')[0].split('?')[0].split('#')[0].split(':')[0]
    return d.strip()


def extract_iocs(subject: str, sender: str, body: str) -> Dict[str, List[str]]:
    """
    Extracts normalized URLs, domains, email addresses, and IPv4 addresses from email fields.
    """
    full_text = f"{subject or ''}\n{sender or ''}\n{body or ''}"

    # Extract URLs
    raw_urls = URL_REGEX.findall(full_text)
    clean_urls = []
    for u in raw_urls:
        u_norm = normalize_url(u)
        if not u_norm.startswith('http://') and not u_norm.startswith('https://'):
            u_norm = 'https://' + u_norm
        if u_norm not in clean_urls and len(u_norm) > 8:
            clean_urls.append(u_norm)

    # Extract Domains
    domains = []
    for url in clean_urls:
        d = clean_domain(url)
        if d and d not in domains and '.' in d:
            domains.append(d)

    # Also search for standalone domain-like tokens in text
    words = full_text.split()
    for w in words:
        w_clean = clean_domain(w)
        if w_clean and '.' in w_clean and len(w_clean.split('.')) >= 2:
            tld = '.' + w_clean.split('.')[-1]
            if len(tld) >= 3 and w_clean not in domains:
                domains.append(w_clean)

    # Extract Email Addresses
    raw_emails = EMAIL_REGEX.findall(full_text)
    clean_emails = []
    for e in raw_emails:
        e_clean = e.lower().strip()
        if e_clean not in clean_emails:
            clean_emails.append(e_clean)

    # Extract IP Addresses (exclude local loopbacks)
    raw_ips = IPV4_REGEX.findall(full_text)
    clean_ips = []
    for ip in raw_ips:
        if not ip.startswith('127.') and not ip.startswith('0.') and ip not in clean_ips:
            clean_ips.append(ip)

    return {
        "domains": domains,
        "urls": clean_urls,
        "ip_addresses": clean_ips,
        "email_addresses": clean_emails
    }


def detect_brand_mentions(text: str) -> List[str]:
    """Identifies major corporate brand names mentioned in text."""
    text_lower = text.lower()
    detected = []
    for brand in KNOWN_BRAND_MAP.keys():
        if re.search(r'\b' + re.escape(brand) + r'\b', text_lower):
            detected.append(brand.capitalize())
    return detected


def analyze_security_signals(
    subject: str,
    sender: str,
    body: str,
    iocs: Dict[str, List[str]]
) -> Tuple[Dict[str, bool], List[Dict[str, Any]]]:
    """
    Evaluates deterministic security rules and returns boolean signal map + structured evidence list.
    """
    full_text = f"{subject or ''} {sender or ''} {body or ''}".lower()
    body_lower = (body or "").lower()
    subject_lower = (subject or "").lower()
    sender_lower = (sender or "").lower()

    signals = {
        "urgency_language": False,
        "credential_request": False,
        "suspicious_link": False,
        "sender_domain_mismatch": False,
        "brand_impersonation": False,
        "financial_request": False,
        "attachment_present": False
    }

    evidence_list = []

    # 1. Urgency / Pressure Language Signal
    urgency_matches = [k for k in URGENCY_KEYWORDS if k in full_text]
    if urgency_matches:
        signals["urgency_language"] = True
        evidence_list.append({
            "type": "urgency",
            "severity": "HIGH",
            "evidence": f"Pressure language detected: '{urgency_matches[0]}'",
            "source": "subject" if urgency_matches[0] in subject_lower else "email_body"
        })

    # 2. Credential Harvesting Intent Signal
    cred_matches = [k for k in CREDENTIAL_KEYWORDS if k in full_text]
    if cred_matches:
        signals["credential_request"] = True
        evidence_list.append({
            "type": "credential_request",
            "severity": "HIGH",
            "evidence": f"Credential request phrasing found: '{cred_matches[0]}'",
            "source": "email_body"
        })

    # 3. Suspicious URL / Link Signal
    suspicious_urls = []
    for url in iocs.get("urls", []):
        url_lower = url.lower()
        has_path = any(p in url_lower for p in SUSPICIOUS_PATH_KEYWORDS)
        has_tld = any(url_lower.endswith(tld) or (tld + '/') in url_lower for tld in SUSPICIOUS_TLDS)
        has_hyphen = url_lower.count('-') >= 2
        if has_path or has_tld or has_hyphen:
            suspicious_urls.append(url)

    if suspicious_urls:
        signals["suspicious_link"] = True
        evidence_list.append({
            "type": "suspicious_link",
            "severity": "HIGH",
            "evidence": f"Suspicious target URL identified: {suspicious_urls[0]}",
            "source": "url"
        })

    # 4. Sender / Brand & Domain Mismatch Signals
    sender_domain = ""
    if "@" in sender_lower:
        sender_domain = sender_lower.split("@")[-1].replace(">", "").strip()

    detected_brands = detect_brand_mentions(f"{subject or ''} {body or ''}")
    
    if detected_brands and sender_domain:
        primary_brand = detected_brands[0].lower()
        official_domains = KNOWN_BRAND_MAP.get(primary_brand, [f"{primary_brand}.com"])

        # Check if sender domain matches official brand domain
        is_official_sender = any(sender_domain == od or sender_domain.endswith("." + od) for od in official_domains)
        
        if not is_official_sender:
            signals["sender_domain_mismatch"] = True
            signals["brand_impersonation"] = True
            evidence_list.append({
                "type": "brand_impersonation",
                "severity": "CRITICAL",
                "evidence": f"Sender domain '{sender_domain}' imitates brand '{detected_brands[0]}' but is not an official domain ({', '.join(official_domains)}).",
                "source": "sender"
            })
    elif sender_domain and iocs.get("domains"):
        # Check if sender domain matches extracted target domain
        target_d = iocs["domains"][0]
        if sender_domain != target_d and not target_d.endswith("." + sender_domain) and not sender_domain.endswith("." + target_d):
            signals["sender_domain_mismatch"] = True
            evidence_list.append({
                "type": "sender_mismatch",
                "severity": "MEDIUM",
                "evidence": f"Sender domain '{sender_domain}' differs from target URL domain '{target_d}'.",
                "source": "sender"
            })

    # 5. Financial / Invoice Request Signal
    fin_matches = [k for k in FINANCIAL_KEYWORDS if k in full_text]
    if fin_matches:
        signals["financial_request"] = True
        evidence_list.append({
            "type": "financial_request",
            "severity": "MEDIUM",
            "evidence": f"Financial / payment phrasing detected: '{fin_matches[0]}'",
            "source": "email_body"
        })

    # 6. Attachment Signal
    if re.search(r'\b(attachment|attached|invoice\.pdf|file\.zip|scan\.pdf)\b', full_text):
        signals["attachment_present"] = True
        evidence_list.append({
            "type": "attachment_present",
            "severity": "LOW",
            "evidence": "Email references attached file or document payload.",
            "source": "email_body"
        })

    return signals, evidence_list


def calculate_risk_and_threat_type(
    signals: Dict[str, bool],
    evidence_list: List[Dict[str, Any]],
    iocs: Dict[str, List[str]]
) -> Tuple[int, str, str, float]:
    """
    Computes explainable risk score (0-100), severity, threat_type, and confidence score.
    """
    pts = 0
    if signals.get("brand_impersonation"):
        pts += 35
    if signals.get("credential_request"):
        pts += 25
    if signals.get("suspicious_link"):
        pts += 20
    if signals.get("urgency_language"):
        pts += 15
    if signals.get("sender_domain_mismatch"):
        pts += 15
    if signals.get("financial_request"):
        pts += 10

    risk_score = min(100, pts)

    # Classify Severity & Threat Type
    if risk_score >= 85:
        severity = "CRITICAL"
        threat_type = "brand_impersonation_credential_phish" if signals.get("brand_impersonation") else "credential_phishing"
        confidence = 0.95
    elif risk_score >= 65:
        severity = "HIGH"
        threat_type = "credential_phishing" if signals.get("credential_request") else "suspicious_email"
        confidence = 0.88
    elif risk_score >= 40:
        severity = "MEDIUM"
        threat_type = "financial_phishing" if signals.get("financial_request") else "suspicious_communication"
        confidence = 0.75
    elif risk_score >= 15:
        severity = "LOW"
        threat_type = "potential_spam"
        confidence = 0.60
    else:
        severity = "BENIGN"
        threat_type = "benign_email"
        confidence = 0.90

    return risk_score, severity, threat_type, confidence


def load_env_vars():
    """Loads environment variables from .env file into os.environ if present."""
    env_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env")
    if os.path.exists(env_path):
        try:
            with open(env_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        k, v = line.split("=", 1)
                        k = k.strip()
                        v = v.strip().strip("'\"")
                        if k:
                            os.environ[k] = v
        except Exception as e:
            logger.debug(f"Failed to read .env file: {e}")


def run_gemini_ai_reasoning(
    subject: str,
    sender: str,
    body: str,
    signals: Dict[str, bool],
    risk_score: int,
    severity: str,
    threat_type: str,
    iocs: Dict[str, List[str]]
) -> Optional[Dict[str, Any]]:
    """
    Attempts Google AI Gemini REST call for structured AI reasoning & correlation.
    Returns None on failure/missing credentials to trigger fallback engine.
    """
    load_env_vars()

    api_key = (os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY") or "").strip()
    
    # Filter out empty strings and common placeholder values
    is_placeholder = (
        not api_key or
        api_key.lower().startswith("your_") or
        "placeholder" in api_key.lower() or
        api_key == "your_gemini_api_key_here" or
        api_key.startswith("YOUR_")
    )

    if is_placeholder:
        logger.info("Gemini API key not configured or using placeholder. Running deterministic reasoning fallback.")
        return None

    models_to_try = [
        "gemini-2.5-flash-lite",
        "gemini-1.5-flash",
        "gemini-2.0-flash-exp",
        "gemini-1.5-pro"
    ]

    prompt_text = f"""
You are an expert cybersecurity SOC analyst evaluating a suspicious email.
Email Subject: {subject}
Sender: {sender}
Body Snippet: {body[:800]}
Extracted Domains: {iocs.get('domains', [])}
Security Signals: {json.dumps(signals)}
Risk Score: {risk_score}/100, Severity: {severity}

Return a valid JSON object ONLY with the following structure:
{{
  "reasoning": [
    "Bullet point 1 explaining the attack mechanism",
    "Bullet point 2 explaining why the sender or URL is malicious",
    "Bullet point 3 providing security recommendation"
  ],
  "threat_summary": "Concise 1-sentence threat verdict summary",
  "confidence": 0.92
}}
"""

    payload = {
        "contents": [{"parts": [{"text": prompt_text}]}],
        "generationConfig": {
            "temperature": 0.2,
            "responseMimeType": "application/json"
        }
    }

    for model_name in models_to_try:
        try:
            url = f"https://generativelanguage.googleapis.com/v1beta/models/{model_name}:generateContent?key={api_key}"
            req = urllib.request.Request(
                url,
                data=json.dumps(payload).encode('utf-8'),
                headers={'Content-Type': 'application/json'}
            )
            
            with urllib.request.urlopen(req, timeout=8) as resp:
                res_data = json.loads(resp.read().decode('utf-8'))
                text_content = res_data['candidates'][0]['content']['parts'][0]['text']
                parsed_ai = json.loads(text_content)
                logger.info(f"Successfully executed Gemini AI reasoning using model '{model_name}'.")
                return parsed_ai

        except urllib.error.HTTPError as http_err:
            if http_err.code == 404:
                logger.debug(f"Gemini model '{model_name}' returned 404, trying next model fallback.")
                continue
            err_body = http_err.read().decode('utf-8', errors='ignore')
            logger.warning(f"Gemini API call to model '{model_name}' failed HTTP {http_err.code}: {err_body}")
            break
        except Exception as err:
            logger.warning(f"Gemini AI reasoning call for model '{model_name}' failed: {err}")
            break

    logger.info("Gemini API call failed or timed out. Falling back to deterministic reasoning engine.")
    return None


def generate_deterministic_reasoning(
    signals: Dict[str, bool],
    evidence_list: List[Dict[str, Any]],
    iocs: Dict[str, List[str]],
    risk_score: int
) -> List[str]:
    """Generates structured explainable reasoning bullet points when AI is unavailable."""
    reasons = []
    
    if signals.get("brand_impersonation"):
        reasons.append("Brand Impersonation: Sender identity or email body imitates a recognized corporate brand, but links to an unauthorized third-party domain.")

    if signals.get("credential_request"):
        reasons.append("Credential Harvesting Risk: Message requests user authentication, login verification, or password updates.")

    if signals.get("urgency_language"):
        reasons.append("Social Engineering Pressure: Contains urgent time-sensitive pressure language threatening account suspension or service disruption.")

    if signals.get("suspicious_link"):
        reasons.append(f"Suspicious Target URL: Extracted URL destination ({iocs.get('urls', ['N/A'])[0] if iocs.get('urls') else 'N/A'}) leads to an authentication or login path.")

    if signals.get("sender_domain_mismatch"):
        reasons.append("Sender Domain Anomaly: Displayed sender identity does not match the actual sending email server domain.")

    if not reasons:
        if risk_score < 20:
            reasons.append("No significant phishing indicators or social engineering pressure tactics detected in email payload.")
            reasons.append("Sender domain and link destinations appear consistent with normal communication.")
        else:
            reasons.append("General security notice: Exercise caution when clicking embedded links from external senders.")

    return reasons


def analyze_email_threat(
    subject: Optional[str] = None,
    sender: Optional[str] = None,
    body: Optional[str] = None,
    received_at: Optional[str] = None,
    headers: Optional[Any] = None
) -> Dict[str, Any]:
    """
    Main entry point for Email Threat Analysis Pipeline.
    """
    analysis_id = f"EMA-{uuid.uuid4().hex[:8].upper()}"
    now_iso = datetime.now(timezone.utc).isoformat()

    if isinstance(subject, dict):
        d = subject
        subject = d.get("subject")
        sender = sender or d.get("sender")
        body = body or d.get("body")
        received_at = received_at or d.get("received_at")
        headers = headers or d.get("headers")

    sub = (subject or "").strip() if isinstance(subject, str) else ""
    snd = (sender or "").strip() if isinstance(sender, str) else ""
    bdy = (body or "").strip() if isinstance(body, str) else ""

    # Step 1: Ingestion & IOC Extraction
    iocs = extract_iocs(subject=sub, sender=snd, body=bdy)

    # Step 2: Deterministic Security Signals & Evidence
    signals, evidence_list = analyze_security_signals(subject=sub, sender=snd, body=bdy, iocs=iocs)

    # Step 3: Organisational Sender Behavior Telemetry
    sender_behavior = evaluate_sender_behavior(
        sender=snd,
        subject=sub,
        body=bdy,
        received_at=received_at or now_iso,
        extracted_urls=iocs.get("urls", []),
        extracted_domains=iocs.get("domains", []),
        content_signals=signals
    )

    # If sender behavior indicates possible account compromise, enrich evidence list
    if sender_behavior.get("hypothesis") == "POSSIBLE_ACCOUNT_COMPROMISE":
        evidence_list.append({
            "type": "account_compromise_hypothesis",
            "severity": "HIGH",
            "evidence": f"Sender Behavioral Anomaly ({sender_behavior.get('anomaly_score')}/100): {sender_behavior.get('hypothesis_label')}",
            "source": "sender_behavior_engine"
        })

    # Step 4: Transparent Risk Scoring
    risk_score, severity, threat_type, base_confidence = calculate_risk_and_threat_type(
        signals=signals,
        evidence_list=evidence_list,
        iocs=iocs
    )

    # If sender behavior hypothesis is account compromise, elevate threat_type label
    if sender_behavior.get("hypothesis") == "POSSIBLE_ACCOUNT_COMPROMISE":
        threat_type = "possible_account_compromise"
        risk_score = max(risk_score, 75)
        if severity not in ["CRITICAL", "HIGH"]:
            severity = "HIGH"

    # Step 5: Provider-Agnostic AI Reasoning Engine (OpenRouter primary, cached, deterministic fallback)
    from services.ai_reasoning import generate_deterministic_reasoning
    evidence_payload = {
        "subject": sub,
        "sender": snd,
        "body_snippet": bdy[:500],
        "signals": signals,
        "signal_evidence": evidence_list,
        "risk_score": risk_score,
        "severity": severity,
        "threat_type": threat_type,
        "extracted_domains": iocs.get("domains", []),
        "extracted_urls": iocs.get("urls", []),
        "iocs": iocs,
        "sender_behavior": sender_behavior
    }
    ai_eval = generate_deterministic_reasoning(evidence_payload)

    reasoning = ai_eval.get("reasoning") or ai_eval.get("key_evidence") or []
    confidence = float(ai_eval.get("confidence", base_confidence))
    ai_used = bool(ai_eval.get("ai_used", False))
    reasoning_source = ai_eval.get("reasoning_source", "deterministic_engine")

    # Recommended Security Action
    if risk_score >= 65 or sender_behavior.get("hypothesis") == "POSSIBLE_ACCOUNT_COMPROMISE":
        recommended_action = "investigate"
    elif risk_score >= 40:
        recommended_action = "monitor"
    else:
        recommended_action = "allow"

    # Step 6: Handoff Target Resolution for KEKAI Threat Intelligence
    extracted_domain = iocs["domains"][0] if iocs.get("domains") else ""
    extracted_url = iocs["urls"][0] if iocs.get("urls") else ""
    investigation_ready = bool(extracted_domain)

    investigation_target = {
        "domain": extracted_domain,
        "url": extracted_url
    } if investigation_ready else None

    # Step 7: Build Complete Response Package
    return {
        "analysis_id": analysis_id,
        "status": "completed",
        "email": {
            "subject": sub or "Untitled Message",
            "sender": snd or "Unknown Sender",
            "recipient": "security-inbox@corporate.internal",
            "received_at": received_at or now_iso
        },
        "indicators": iocs,
        "signals": signals,
        "signal_evidence": evidence_list,
        "sender_behavior": sender_behavior,
        "organisation": sender_behavior.get("organisation", {"id": "org_acme_01", "name": "Acme Corporation"}),
        "threat_type": threat_type,
        "risk_score": risk_score,
        "severity": severity,
        "confidence": round(confidence, 2),
        "evidence_quality": "HIGH" if confidence >= 0.8 else ("MEDIUM" if confidence >= 0.5 else "LOW"),
        "attack_hypothesis": (
            "POSSIBLE_ACCOUNT_COMPROMISE" if sender_behavior.get("hypothesis") == "POSSIBLE_ACCOUNT_COMPROMISE"
            else ("CREDENTIAL_PHISHING" if risk_score >= 65 and signals.get("credential_request")
            else ("BRAND_IMPERSONATION" if risk_score >= 60 and signals.get("brand_impersonation")
            else ("SUSPICIOUS_BEHAVIOUR" if risk_score >= 40
            else "BENIGN_INTERNAL")))
        ),
        "reasoning": reasoning,
        "recommended_action": recommended_action,
        "extracted_domain": extracted_domain,
        "extracted_url": extracted_url,
        "investigation_ready": investigation_ready,
        "investigation_target": investigation_target,
        "ai_used": ai_used,
        "reasoning_source": reasoning_source,
        "analyzed_at": now_iso
    }
