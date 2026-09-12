"""
services/page_analyzer.py

KEIKAI — Complete Page Similarity & Brand Clone Detection Engine (Phase 6)
==================================================================================
Provides static HTML DOM inspection, structural fingerprinting, brand text & asset analysis,
form action security evaluation, domain alignment, brand template repository matching,
actual visual similarity computation, multi-signal clone classification, and safe page fetching.

Strict Security Controls:
- Static HTML analysis via BeautifulSoup only.
- NO JavaScript execution, NO form submission, NO binary code execution.
- Mandatory SSRF validation for network page fetching.
- NO hardcoded or fabricated similarity scores (returns status: "UNAVAILABLE" when inputs missing).
"""

import os
import re
import math
import hashlib
import logging
import urllib.parse
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple, Set

try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except ImportError:
    BeautifulSoup = None
    HAS_BS4 = False

try:
    from PIL import Image
    import io
    HAS_PIL = True
except ImportError:
    Image = None
    io = None
    HAS_PIL = False

# Import existing KEIKAI security services
from services.redirect_tracer import validate_target_ssrf_safety, trace_safe_redirect_chain
from services.imagehash_service import normalize_image_for_hashing
try:
    import imagehash
    HAS_IMAGEHASH = True
except ImportError:
    imagehash = None
    HAS_IMAGEHASH = False

logger = logging.getLogger("keikai.page_analyzer")

# Max HTML body fetch size (5 MB limit)
MAX_HTML_FETCH_SIZE = 5 * 1024 * 1024
DEFAULT_HTTP_TIMEOUT = 10.0


# ---------------------------------------------------------------------------
# 1. Brand Template Abstraction & Database
# ---------------------------------------------------------------------------

class BrandTemplate:
    """
    Authoritative reference template profile for a target brand.
    """
    def __init__(
        self,
        brand: str,
        official_domain: str,
        reference_urls: List[str],
        reference_text: List[str],
        structural_fingerprint: Dict[str, Any],
        asset_fingerprints: List[str],
        aliases: Optional[List[str]] = None,
        reference_image_hash: Optional[str] = None
    ):
        self.brand = brand
        self.official_domain = official_domain.lower().strip()
        self.reference_urls = reference_urls
        self.reference_text = [t.lower() for t in reference_text]
        self.structural_fingerprint = structural_fingerprint
        self.asset_fingerprints = [a.lower() for a in asset_fingerprints]
        self.aliases = [a.lower() for a in (aliases or [])]
        self.reference_image_hash = reference_image_hash

    def to_dict(self) -> Dict[str, Any]:
        return {
            "brand": self.brand,
            "official_domain": self.official_domain,
            "reference_urls": self.reference_urls,
            "aliases": self.aliases,
            "structural_fingerprint": self.structural_fingerprint,
            "has_reference_image": bool(self.reference_image_hash)
        }


# Known Brand Reference Template Repository
BRAND_TEMPLATE_REPOSITORY: Dict[str, BrandTemplate] = {
    "amazon": BrandTemplate(
        brand="Amazon",
        official_domain="amazon.com",
        reference_urls=["https://www.amazon.com/ap/signin", "https://www.amazon.com"],
        reference_text=["amazon", "sign in", "keep me signed in", "email or mobile phone number", "continue", "need help", "conditions of use", "privacy notice"],
        structural_fingerprint={"forms": 1, "password_inputs": 1, "inputs": 3, "buttons": 1, "dom_depth": 6},
        asset_fingerprints=["amazon_logo", "nav-sprite", "favicon.ico", "ap_navbar_logo"],
        aliases=["aws", "amazonpay", "prime", "amaz0n"]
    ),
    "microsoft": BrandTemplate(
        brand="Microsoft",
        official_domain="microsoft.com",
        reference_urls=["https://login.microsoftonline.com", "https://login.live.com"],
        reference_text=["microsoft", "sign in", "email, phone, or skype", "no account? create one!", "can't access your account?", "terms of use", "privacy & cookies"],
        structural_fingerprint={"forms": 1, "password_inputs": 1, "inputs": 2, "buttons": 2, "dom_depth": 7},
        asset_fingerprints=["microsoft_logo", "logo_ms", "favicon.ico", "svg_ms_logo"],
        aliases=["azure", "office365", "outlook", "m365", "onedrive"]
    ),
    "apple": BrandTemplate(
        brand="Apple",
        official_domain="apple.com",
        reference_urls=["https://appleid.apple.com", "https://www.icloud.com"],
        reference_text=["apple id", "sign in to apple id", "manage your apple account", "forgot apple id or password?", "privacy policy", "copyright"],
        structural_fingerprint={"forms": 1, "password_inputs": 1, "inputs": 2, "buttons": 1, "dom_depth": 5},
        asset_fingerprints=["apple_logo", "apple-touch-icon", "apple_id_icon"],
        aliases=["icloud", "appstore", "iphone", "macbook"]
    ),
    "google": BrandTemplate(
        brand="Google",
        official_domain="google.com",
        reference_urls=["https://accounts.google.com/signin"],
        reference_text=["google", "sign in", "use your google account", "email or phone", "forgot email?", "not your computer?", "next", "create account"],
        structural_fingerprint={"forms": 1, "password_inputs": 1, "inputs": 2, "buttons": 2, "dom_depth": 8},
        asset_fingerprints=["google_logo", "google_favicon", "g_logo", "google_g"],
        aliases=["gmail", "googlecloud", "workspace", "youtube"]
    ),
    "paypal": BrandTemplate(
        brand="PayPal",
        official_domain="paypal.com",
        reference_urls=["https://www.paypal.com/signin"],
        reference_text=["paypal", "log in to your paypal account", "email address or mobile number", "forgot password?", "sign up", "privacy"],
        structural_fingerprint={"forms": 1, "password_inputs": 1, "inputs": 2, "buttons": 2, "dom_depth": 6},
        asset_fingerprints=["paypal_logo", "pp_favicon", "paypal_monogram"],
        aliases=["venmo", "pypl"]
    ),
    "rolex": BrandTemplate(
        brand="Rolex",
        official_domain="rolex.com",
        reference_urls=["https://www.rolex.com"],
        reference_text=["rolex", "official rolex website", "swiss luxury watches", "oyster perpetual", "datejust", "submariner", "gmt-master"],
        structural_fingerprint={"forms": 0, "password_inputs": 0, "inputs": 1, "buttons": 2, "dom_depth": 9},
        asset_fingerprints=["rolex_crown", "rolex_logo", "crown_symbol"],
        aliases=["oyster", "daytona", "submariner"]
    ),
    "facebook": BrandTemplate(
        brand="Facebook",
        official_domain="facebook.com",
        reference_urls=["https://www.facebook.com/login"],
        reference_text=["facebook", "log in to facebook", "email address or phone number", "password", "forgot account?", "create new account"],
        structural_fingerprint={"forms": 1, "password_inputs": 1, "inputs": 2, "buttons": 1, "dom_depth": 6},
        asset_fingerprints=["fb_logo", "facebook_icon", "fb_favicon"],
        aliases=["meta", "instagram", "whatsapp"]
    ),
    "netflix": BrandTemplate(
        brand="Netflix",
        official_domain="netflix.com",
        reference_urls=["https://www.netflix.com/login"],
        reference_text=["netflix", "sign in", "email or phone number", "password", "remember me", "need help?", "new to netflix? sign up now."],
        structural_fingerprint={"forms": 1, "password_inputs": 1, "inputs": 2, "buttons": 1, "dom_depth": 5},
        asset_fingerprints=["netflix_logo", "nf_icon", "netflix_red_n"],
        aliases=["nflx"]
    )
}


def get_brand_template(brand_name_or_domain: str) -> Optional[BrandTemplate]:
    """
    Retrieves reference BrandTemplate by brand name, domain, or alias.
    """
    if not brand_name_or_domain:
        return None

    query = brand_name_or_domain.lower().strip()
    if query.startswith("http://") or query.startswith("https://"):
        query = urllib.parse.urlparse(query).hostname or query

    # Direct match by key
    if query in BRAND_TEMPLATE_REPOSITORY:
        return BRAND_TEMPLATE_REPOSITORY[query]

    # Match by official domain or alias
    for key, tmpl in BRAND_TEMPLATE_REPOSITORY.items():
        if query == tmpl.official_domain or query == tmpl.brand.lower():
            return tmpl
        if query in tmpl.aliases:
            return tmpl
        if tmpl.official_domain in query or query in tmpl.official_domain:
            return tmpl

    return None


# ---------------------------------------------------------------------------
# 2. BeautifulSoup Static HTML Parsing & Structural DOM Fingerprinting
# ---------------------------------------------------------------------------

def analyze_page_static_html(html_content: str, url: str) -> Dict[str, Any]:
    """
    Performs static HTML analysis using BeautifulSoup without executing JavaScript or forms.
    Returns structured features and deterministic DOM fingerprint.
    """
    now_iso = datetime.now(timezone.utc).isoformat()

    if not html_content or not isinstance(html_content, str):
        return {
            "status": "MALFORMED_OR_EMPTY_HTML",
            "title": "",
            "meta_description": "",
            "headings": [],
            "visible_text": "",
            "forms": [],
            "inputs": [],
            "password_inputs": [],
            "buttons": [],
            "links": [],
            "external_link_count": 0,
            "images": [],
            "favicon": None,
            "script_count": 0,
            "stylesheet_count": 0,
            "dom_depth": 0,
            "dom_fingerprint": "",
            "structural_features": {
                "forms": 0,
                "password_inputs": 0,
                "inputs": 0,
                "buttons": 0,
                "external_links": 0,
                "images": 0,
                "dom_depth": 0,
                "dom_fingerprint": ""
            }
        }

    parsed_url = urllib.parse.urlparse(url)
    base_host = (parsed_url.hostname or "").lower()

    if HAS_BS4 and BeautifulSoup:
        try:
            soup = BeautifulSoup(html_content, "html.parser")
        except Exception as err:
            logger.warning(f"BeautifulSoup parsing error: {err}")
            soup = None
    else:
        soup = None

    if not soup:
        # Fallback regex extraction if BS4 unavailable
        title_match = re.search(r'<title[^>]*>(.*?)</title>', html_content, re.IGNORECASE | re.DOTALL)
        title = title_match.group(1).strip() if title_match else ""
        forms_count = len(re.findall(r'<form', html_content, re.IGNORECASE))
        password_count = len(re.findall(r'type=["\']password["\']', html_content, re.IGNORECASE))
        input_count = len(re.findall(r'<input', html_content, re.IGNORECASE))
        button_count = len(re.findall(r'<button', html_content, re.IGNORECASE))
        img_count = len(re.findall(r'<img', html_content, re.IGNORECASE))

        return {
            "status": "REGEX_PARSED",
            "title": title,
            "meta_description": "",
            "headings": [],
            "visible_text": re.sub(r'<[^>]+>', ' ', html_content)[:2000],
            "forms": [],
            "inputs": [],
            "password_inputs": [],
            "buttons": [],
            "links": [],
            "external_link_count": 0,
            "images": [],
            "favicon": None,
            "script_count": len(re.findall(r'<script', html_content, re.IGNORECASE)),
            "stylesheet_count": len(re.findall(r'rel=["\']stylesheet["\']', html_content, re.IGNORECASE)),
            "dom_depth": 3,
            "dom_fingerprint": f"forms:{forms_count}|pass:{password_count}|inputs:{input_count}",
            "structural_features": {
                "forms": forms_count,
                "password_inputs": password_count,
                "inputs": input_count,
                "buttons": button_count,
                "external_links": 0,
                "images": img_count,
                "dom_depth": 3,
                "dom_fingerprint": f"forms:{forms_count}|pass:{password_count}|inputs:{input_count}"
            }
        }

    # 1. Title & Meta
    title = soup.title.string.strip() if soup.title and soup.title.string else ""
    meta_desc = ""
    meta_tag = soup.find("meta", attrs={"name": re.compile(r"description", re.I)})
    if meta_tag and meta_tag.get("content"):
        meta_desc = meta_tag["content"].strip()

    # 2. Headings
    headings = []
    for h_tag in soup.find_all(re.compile(r"^h[1-6]$", re.I)):
        text = h_tag.get_text(strip=True)
        if text:
            headings.append(text)

    # 3. Visible Text (excluding script/style)
    for script_or_style in soup(["script", "style", "noscript", "svg", "iframe"]):
        script_or_style.extract()
    visible_text = soup.get_text(separator=" ", strip=True)

    # 4. Forms & Inputs Analysis
    forms = []
    inputs = []
    password_inputs = []
    buttons = []

    for form in soup.find_all("form"):
        action = form.get("action") or ""
        method = (form.get("method") or "GET").upper()
        form_inputs = []

        for inp in form.find_all("input"):
            inp_type = (inp.get("type") or "text").lower()
            inp_name = inp.get("name") or inp.get("id") or ""
            inp_placeholder = inp.get("placeholder") or ""
            inp_info = {"type": inp_type, "name": inp_name, "placeholder": inp_placeholder}
            inputs.append(inp_info)
            form_inputs.append(inp_info)
            if inp_type == "password":
                password_inputs.append(inp_info)

        # Action hostname analysis
        action_url = urllib.parse.urljoin(url, action) if action else url
        action_host = urllib.parse.urlparse(action_url).hostname or base_host
        is_cross_domain = bool(base_host and action_host and action_host.lower() != base_host.lower())

        forms.append({
            "action": action,
            "action_url": action_url,
            "action_hostname": action_host,
            "method": method,
            "inputs": form_inputs,
            "input_count": len(form_inputs),
            "has_password": any(i["type"] == "password" for i in form_inputs),
            "is_cross_domain": is_cross_domain
        })

    # Non-form standalone inputs & buttons
    for inp in soup.find_all("input"):
        if not inp.find_parent("form"):
            inp_type = (inp.get("type") or "text").lower()
            inp_info = {"type": inp_type, "name": inp.get("name") or "", "placeholder": inp.get("placeholder") or ""}
            inputs.append(inp_info)
            if inp_type == "password" and inp_info not in password_inputs:
                password_inputs.append(inp_info)

    for btn in soup.find_all(["button", "a"]):
        is_button = btn.name == "button" or "btn" in (btn.get("class") or []) or btn.get("role") == "button"
        if is_button:
            btn_text = btn.get_text(strip=True)
            if btn_text:
                buttons.append(btn_text)

    # 5. Links & External Link Count
    links = []
    external_link_count = 0
    for a_tag in soup.find_all("a", href=True):
        href = a_tag["href"]
        links.append(href)
        if href.startswith("http://") or href.startswith("https://"):
            link_host = urllib.parse.urlparse(href).hostname
            if link_host and base_host and link_host.lower() != base_host.lower():
                external_link_count += 1

    # 6. Images & Favicon
    images = []
    for img in soup.find_all("img"):
        src = img.get("src") or ""
        alt = img.get("alt") or ""
        if src:
            images.append({
                "src": src,
                "full_url": urllib.parse.urljoin(url, src),
                "alt": alt,
                "filename": os.path.basename(urllib.parse.urlparse(src).path)
            })

    favicon = None
    fav_link = soup.find("link", rel=re.compile(r"icon|shortcut icon", re.I))
    if fav_link and fav_link.get("href"):
        favicon = urllib.parse.urljoin(url, fav_link["href"])

    # 7. DOM Depth & Structural Tag Sequence Fingerprint
    def compute_depth(element, depth=1):
        children = [c for c in element.children if getattr(c, 'name', None)]
        if not children:
            return depth
        return max(compute_depth(c, depth + 1) for c in children)

    dom_depth = compute_depth(soup.html) if soup.html else 1

    # Generate tag sequence digest
    important_tags = [tag.name for tag in soup.find_all(["form", "input", "button", "h1", "h2", "table", "a", "img"])]
    tag_seq_str = ">".join(important_tags[:30])
    fingerprint_raw = f"forms:{len(forms)}|pass:{len(password_inputs)}|inputs:{len(inputs)}|btn:{len(buttons)}|img:{len(images)}|seq:{tag_seq_str}"
    dom_fingerprint = hashlib.sha256(fingerprint_raw.encode("utf-8")).hexdigest()[:16]

    structural_features = {
        "forms": len(forms),
        "password_inputs": len(password_inputs),
        "inputs": len(inputs),
        "buttons": len(buttons),
        "external_links": external_link_count,
        "images": len(images),
        "dom_depth": dom_depth,
        "dom_fingerprint": dom_fingerprint,
        "tag_sequence": tag_seq_str
    }

    return {
        "status": "SUCCESS",
        "title": title,
        "meta_description": meta_desc,
        "headings": headings,
        "visible_text": visible_text,
        "forms": forms,
        "inputs": inputs,
        "password_inputs": password_inputs,
        "buttons": buttons,
        "links": links,
        "external_link_count": external_link_count,
        "images": images,
        "favicon": favicon,
        "script_count": len(soup.find_all("script")),
        "stylesheet_count": len(soup.find_all("link", rel=re.compile(r"stylesheet", re.I))),
        "dom_depth": dom_depth,
        "dom_fingerprint": dom_fingerprint,
        "structural_features": structural_features
    }


# ---------------------------------------------------------------------------
# 3. Brand Text & Asset Analysis
# ---------------------------------------------------------------------------

def analyze_brand_text(
    visible_text: str,
    target_brand: str,
    official_domain: Optional[str] = None
) -> Dict[str, Any]:
    """
    Analyzes visible page text for target brand occurrences, login/account/security terms,
    and calculates text match metrics without marking pages malicious solely due to brand mentions.
    """
    text_lower = (visible_text or "").lower()
    tmpl = get_brand_template(target_brand or official_domain or "")

    brand_name = tmpl.brand if tmpl else (target_brand or "Unknown")
    brand_keywords = tmpl.reference_text if tmpl else [brand_name.lower()]

    detected_brand_mentions: List[str] = []
    if brand_name.lower() in text_lower:
        detected_brand_mentions.append(brand_name.lower())

    if tmpl:
        for alias in tmpl.aliases:
            if alias in text_lower:
                detected_brand_mentions.append(alias)

    # Terminology categories
    login_terms = ["sign in", "login", "log in", "log on", "enter password", "keep me signed in"]
    account_terms = ["account", "profile", "user id", "email address", "phone number", "mobile number"]
    security_terms = ["security update", "verify your account", "action required", "unauthorized access", "confirm identity"]
    copyright_terms = ["copyright", "rights reserved", "terms of use", "privacy policy", "inc.", "llc", "corp"]

    found_login_terms = [t for t in login_terms if t in text_lower]
    found_account_terms = [t for t in account_terms if t in text_lower]
    found_security_terms = [t for t in security_terms if t in text_lower]
    found_copyright_terms = [t for t in copyright_terms if t in text_lower]

    matched_kw_count = sum(1 for kw in brand_keywords if kw in text_lower)
    text_similarity_score = round(matched_kw_count / max(1, len(brand_keywords)), 2)

    return {
        "target_brand": brand_name,
        "brand_mentioned": len(detected_brand_mentions) > 0,
        "detected_brand_mentions": list(set(detected_brand_mentions)),
        "text_similarity_score": text_similarity_score,
        "matched_keyword_count": matched_kw_count,
        "reference_keyword_count": len(brand_keywords),
        "terminology": {
            "login_terms": found_login_terms,
            "account_terms": found_account_terms,
            "security_terms": found_security_terms,
            "copyright_terms": found_copyright_terms
        }
    }


def analyze_brand_assets(
    images: List[Dict[str, Any]],
    favicon: Optional[str],
    target_brand: str,
    official_domain: Optional[str] = None
) -> Dict[str, Any]:
    """
    Inspects image alt text, filenames, favicon, and CSS references for target brand assets.
    Records source URL for every detected asset.
    """
    tmpl = get_brand_template(target_brand or official_domain or "")
    brand_key = (tmpl.brand.lower() if tmpl else (target_brand or "")).lower()
    asset_keys = tmpl.asset_fingerprints if tmpl else [brand_key]

    detected_assets: List[Dict[str, Any]] = []

    for img in images:
        src = img.get("src", "").lower()
        alt = img.get("alt", "").lower()
        filename = img.get("filename", "").lower()

        match_found = False
        match_reason = ""

        if brand_key and (brand_key in alt or brand_key in filename or brand_key in src):
            match_found = True
            match_reason = f"Brand key '{brand_key}' matched in image filename/alt/src"
        else:
            for ak in asset_keys:
                if ak in alt or ak in filename or ak in src:
                    match_found = True
                    match_reason = f"Asset fingerprint '{ak}' matched"
                    break

        if match_found:
            detected_assets.append({
                "type": "image_logo",
                "source_url": img.get("full_url") or img.get("src"),
                "filename": img.get("filename"),
                "alt": img.get("alt"),
                "reason": match_reason
            })

    if favicon:
        fav_lower = favicon.lower()
        if brand_key and brand_key in fav_lower:
            detected_assets.append({
                "type": "favicon",
                "source_url": favicon,
                "reason": f"Favicon URL matches brand key '{brand_key}'"
            })

    has_brand_assets = len(detected_assets) > 0
    asset_similarity_score = min(1.0, round(len(detected_assets) / max(1, len(asset_keys)), 2)) if tmpl else (0.85 if has_brand_assets else 0.0)

    return {
        "target_brand": tmpl.brand if tmpl else target_brand,
        "has_brand_assets": has_brand_assets,
        "detected_asset_count": len(detected_assets),
        "detected_assets": detected_assets,
        "asset_similarity_score": asset_similarity_score
    }


# ---------------------------------------------------------------------------
# 4. Form Action & Security Analysis
# ---------------------------------------------------------------------------

def analyze_form_actions(
    forms: List[Dict[str, Any]],
    landing_url: str,
    official_domain: Optional[str] = None
) -> Dict[str, Any]:
    """
    Evaluates form action security: credential harvesting, cross-domain submission,
    external endpoints, and suspicious non-SSL or IP submission targets.
    """
    landing_host = (urllib.parse.urlparse(landing_url).hostname or "").lower()
    off_domain = official_domain.lower().strip() if official_domain else ""

    evaluated_forms = []
    has_cross_domain = False
    has_external_action = False
    has_credential_submission = False
    has_suspicious_endpoint = False
    risk_points = 0

    for form in forms:
        action_url = form.get("action_url") or landing_url
        action_host = (form.get("action_hostname") or landing_host).lower()
        has_password = form.get("has_password", False)

        is_cross_domain = bool(landing_host and action_host and action_host != landing_host)
        is_external = bool(off_domain and action_host and not action_host.endswith(off_domain))

        # Check suspicious action endpoints (e.g. raw IP, HTTP submission on HTTPS page, PHP collectors)
        is_suspicious = False
        reasons = []

        if is_cross_domain:
            has_cross_domain = True
            reasons.append("Form submits to different domain than landing page host")
            risk_points += 30

        if is_external and off_domain:
            has_external_action = True
            reasons.append(f"Form submits to external domain outside official domain '{off_domain}'")

        if has_password:
            has_credential_submission = True
            reasons.append("Form contains password input field (credential harvesting endpoint)")
            risk_points += 35

        # IP host check on action URL
        if action_host and re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', action_host):
            is_suspicious = True
            has_suspicious_endpoint = True
            reasons.append("Form action target is an un-domain-indexed IP address")
            risk_points += 25

        if landing_url.startswith("https://") and action_url.startswith("http://"):
            is_suspicious = True
            has_suspicious_endpoint = True
            reasons.append("Insecure HTTP form submission target from HTTPS landing page")
            risk_points += 20

        evaluated_forms.append({
            "action_url": action_url,
            "action_hostname": action_host,
            "method": form.get("method", "POST"),
            "has_password": has_password,
            "is_cross_domain": is_cross_domain,
            "is_external": is_external,
            "is_suspicious": is_suspicious,
            "security_reasons": reasons
        })

    return {
        "form_count": len(forms),
        "has_cross_domain": has_cross_domain,
        "has_external_action": has_external_action,
        "has_credential_submission": has_credential_submission,
        "has_suspicious_endpoint": has_suspicious_endpoint,
        "risk_points": min(100, risk_points),
        "evaluated_forms": evaluated_forms
    }


# ---------------------------------------------------------------------------
# 5. Domain Alignment Calculation
# ---------------------------------------------------------------------------

def calculate_domain_alignment(landing_domain: str, official_domain: str) -> Dict[str, Any]:
    """
    Compares official brand domain vs final landing domain.
    Returns domain alignment score [0.0, 1.0] and alignment classification.
    """
    if not landing_domain or not official_domain:
        return {
            "alignment_classification": "UNKNOWN",
            "alignment_score": 0.50,
            "is_aligned": False,
            "message": "Missing landing domain or official domain input"
        }

    land = landing_domain.lower().strip()
    off = official_domain.lower().strip()

    if land == off or land == f"www.{off}":
        return {
            "alignment_classification": "EXACT_MATCH",
            "alignment_score": 1.0,
            "is_aligned": True,
            "message": f"Landing domain '{land}' exactly matches official domain '{off}'"
        }

    if land.endswith(f".{off}"):
        return {
            "alignment_classification": "ALIGNED_SUBDOMAIN",
            "alignment_score": 0.90,
            "is_aligned": True,
            "message": f"Landing domain '{land}' is an authorized subdomain of official domain '{off}'"
        }

    # Common legitimate CDN / SSO domain patterns
    if any(cdn in land for cdn in ["cloudfront.net", "akamai.net", "azureedge.net", "okta.com"]):
        return {
            "alignment_classification": "POTENTIALLY_ALIGNED_CDN",
            "alignment_score": 0.50,
            "is_aligned": False,
            "message": f"Landing domain '{land}' is a third-party CDN / Identity portal"
        }

    return {
        "alignment_classification": "UNRELATED_DOMAIN",
        "alignment_score": 0.0,
        "is_aligned": False,
        "message": f"Landing domain '{land}' is unrelated to official brand domain '{off}'"
    }


# ---------------------------------------------------------------------------
# 6. Actual Visual Similarity Engine
# ---------------------------------------------------------------------------

def compute_visual_similarity(
    candidate_image_bytes: Optional[bytes],
    reference_image_bytes: Optional[bytes] = None,
    candidate_image_path: Optional[str] = None,
    target_url: str = ""
) -> Dict[str, Any]:
    """
    Computes actual visual perceptual hash similarity using imagehash (pHash).
    Compares against the reference template corpus in reference_templates/.
    Returns status: "UNAVAILABLE" if image bytes/path are missing (DOES NOT fabricate scores).
    """
    from services.imagehash_service import compare_target_against_reference_templates

    temp_path = None
    if candidate_image_path and os.path.exists(candidate_image_path):
        target_path = candidate_image_path
    elif candidate_image_bytes:
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tf:
            tf.write(candidate_image_bytes)
            temp_path = tf.name
        target_path = temp_path
    else:
        return {
            "method": "perceptual_hash",
            "computed": False,
            "status": "UNAVAILABLE",
            "similarity": None,
            "distance": None,
            "best_match": None,
            "matches": [],
            "message": "Reference or candidate screenshot image missing. Visual page similarity unavailable."
        }

    try:
        res = compare_target_against_reference_templates(target_path, threshold=16)
        if temp_path and os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except Exception:
                pass

        if res.get("status") == "complete" and res.get("best_match"):
            best = res["best_match"]
            return {
                "method": "perceptual_hash",
                "computed": True,
                "status": "SUCCESS",
                "target_url": target_url,
                "distance": best["distance"],
                "similarity": best["similarity"],
                "best_match": best,
                "matches": res.get("matches", []),
                "threshold_distance": res.get("threshold_distance", 16),
                "threshold_similarity": res.get("threshold_similarity", 0.75),
                "page_similarity": {
                    "target_url": target_url,
                    "matches": res.get("matches", []),
                    "best_match": best,
                    "method": "perceptual_hash",
                    "status": "complete"
                },
                "message": f"Actual perceptual hash visual similarity computed against reference templates: {best['similarity']*100:.1f}% (Best match: {best['brand']}, distance: {best['distance']})"
            }
        else:
            return {
                "method": "perceptual_hash",
                "computed": False,
                "status": res.get("status", "UNAVAILABLE"),
                "similarity": None,
                "distance": None,
                "best_match": None,
                "matches": [],
                "message": res.get("reason", "Reference templates unavailable or comparison failed.")
            }
    except Exception as err:
        if temp_path and os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except Exception:
                pass
        logger.error(f"Error computing visual similarity: {err}")
        return {
            "method": "perceptual_hash",
            "computed": False,
            "status": "ERROR",
            "similarity": None,
            "distance": None,
            "best_match": None,
            "matches": [],
            "message": f"Failed to compute visual hash: {str(err)}"
        }


# ---------------------------------------------------------------------------
# 7. Multi-Signal Page Similarity & Clone Classification
# ---------------------------------------------------------------------------

def calculate_multi_signal_similarity(
    html_analysis: Dict[str, Any],
    brand_text_info: Dict[str, Any],
    brand_asset_info: Dict[str, Any],
    form_info: Dict[str, Any],
    domain_align_info: Dict[str, Any],
    visual_info: Dict[str, Any],
    target_brand: Optional[str] = None
) -> Dict[str, Any]:
    """
    Calculates independent similarity scores across all 6 dimensions:
    - visual_similarity (float [0-1] or None if UNAVAILABLE)
    - structural_similarity (float [0-1])
    - text_similarity (float [0-1])
    - asset_similarity (float [0-1])
    - credential_similarity (float [0-1])
    - domain_alignment (float [0-1])

    Returns each dimension independently without collapsing into one unexplained number.
    """
    tmpl = get_brand_template(target_brand or "")

    # 1. Structural Similarity against brand reference
    struct_sim = 0.50
    if tmpl and tmpl.structural_fingerprint:
        ref_struct = tmpl.structural_fingerprint
        cand_struct = html_analysis.get("structural_features", {})

        f_diff = abs(ref_struct.get("forms", 1) - cand_struct.get("forms", 0))
        p_diff = abs(ref_struct.get("password_inputs", 1) - cand_struct.get("password_inputs", 0))
        i_diff = abs(ref_struct.get("inputs", 2) - cand_struct.get("inputs", 0))

        diff_total = f_diff + p_diff + min(3, i_diff)
        struct_sim = max(0.20, round(1.0 - (diff_total * 0.15), 2))
    elif html_analysis.get("status") == "SUCCESS":
        struct_sim = 0.70 if html_analysis.get("password_inputs") else 0.40

    # 2. Text Similarity
    text_sim = brand_text_info.get("text_similarity_score", 0.0)
    if brand_text_info.get("brand_mentioned") and text_sim == 0.0:
        text_sim = 0.65

    # 3. Asset Similarity
    asset_sim = brand_asset_info.get("asset_similarity_score", 0.0)

    # 4. Credential Similarity
    cred_sim = 0.0
    if form_info.get("has_credential_submission"):
        cred_sim = 0.90
    elif html_analysis.get("password_inputs"):
        cred_sim = 0.75

    # 5. Domain Alignment
    domain_align = domain_align_info.get("alignment_score", 0.0)

    # 6. Visual Similarity
    vis_sim = visual_info.get("similarity")  # float or None

    return {
        "visual_similarity": vis_sim,
        "structural_similarity": struct_sim,
        "text_similarity": text_sim,
        "asset_similarity": asset_sim,
        "credential_similarity": cred_sim,
        "domain_alignment": domain_align,
        "provenance": {
            "source": "multi_signal_similarity_engine",
            "live": True,
            "computed_at": datetime.now(timezone.utc).isoformat()
        }
    }


def classify_brand_clone(
    multi_similarity: Dict[str, Any],
    form_info: Dict[str, Any],
    domain_align_info: Dict[str, Any],
    brand_text_info: Dict[str, Any],
    brand_asset_info: Dict[str, Any],
    target_brand: Optional[str] = None
) -> Dict[str, Any]:
    """
    Multi-signal clone detection classifier:
    - STRONG_BRAND_CLONE: Requires multiple independent signals (e.g. High asset/text/cred similarity + Unrelated domain + Cross-domain/credential form).
    - POSSIBLE_BRAND_CLONE: Medium similarity across signals or 1-2 strong signals with ambiguous domain.
    - LOW_SIMILARITY: Page does not mimic target brand structure or assets.
    - INCONCLUSIVE: Missing page content or insufficient signals.
    """
    struct_sim = multi_similarity.get("structural_similarity", 0.0)
    text_sim = multi_similarity.get("text_similarity", 0.0)
    asset_sim = multi_similarity.get("asset_similarity", 0.0)
    cred_sim = multi_similarity.get("credential_similarity", 0.0)
    vis_sim = multi_similarity.get("visual_similarity")  # float or None
    dom_align = multi_similarity.get("domain_alignment", 1.0)

    is_unrelated_domain = dom_align == 0.0
    has_brand_assets = brand_asset_info.get("has_brand_assets", False)
    has_brand_mentions = brand_text_info.get("brand_mentioned", False)
    has_cred_form = form_info.get("has_credential_submission", False) or cred_sim >= 0.75
    has_cross_domain_form = form_info.get("has_cross_domain", False) or form_info.get("has_external_action", False)

    reasons: List[str] = []
    signals_count = 0

    if has_brand_assets or asset_sim >= 0.60:
        signals_count += 1
        reasons.append(f"Target brand '{target_brand or 'brand'}' logo/asset fingerprints detected on page")

    if text_sim >= 0.50 or has_brand_mentions:
        signals_count += 1
        reasons.append("Target brand terminology and copyright references present")

    if has_cred_form:
        signals_count += 1
        reasons.append("Credential harvesting form (password input) present on landing page")

    if is_unrelated_domain:
        signals_count += 1
        reasons.append(f"Landing page domain is completely unrelated to official domain ({domain_align_info.get('message')})")

    if has_cross_domain_form:
        signals_count += 1
        reasons.append("Form submits credentials to cross-domain / external action target endpoint")

    if vis_sim is not None and vis_sim >= 0.80:
        signals_count += 1
        reasons.append(f"High visual perceptual hash similarity ({vis_sim * 100:.1f}%) with reference template")

    # Classification logic
    if is_unrelated_domain and (has_brand_assets or asset_sim >= 0.60) and has_cred_form:
        classification = "STRONG_BRAND_CLONE"
        confidence = "HIGH"
    elif is_unrelated_domain and signals_count >= 3:
        classification = "STRONG_BRAND_CLONE"
        confidence = "HIGH"
    elif signals_count >= 2 and is_unrelated_domain:
        classification = "POSSIBLE_BRAND_CLONE"
        confidence = "MEDIUM"
    elif (has_brand_assets or text_sim >= 0.60) and not is_unrelated_domain:
        classification = "LOW_SIMILARITY"
        confidence = "HIGH"
        reasons.append("Page belongs to legitimate official domain or authorized portal")
    elif signals_count == 1:
        classification = "POSSIBLE_BRAND_CLONE"
        confidence = "LOW"
    else:
        classification = "LOW_SIMILARITY"
        confidence = "MEDIUM"
        reasons.append("Insufficient brand similarity signals detected")

    return {
        "clone_classification": classification,
        "confidence": confidence,
        "is_clone": classification in ["STRONG_BRAND_CLONE", "POSSIBLE_BRAND_CLONE"],
        "signal_matches": signals_count,
        "evidence_reasons": reasons,
        "target_brand": target_brand or "Unknown"
    }


# ---------------------------------------------------------------------------
# 8. Safe Page Fetcher with SSRF Protection
# ---------------------------------------------------------------------------

def fetch_page_safely(
    url: str,
    timeout: float = DEFAULT_HTTP_TIMEOUT,
    max_size: int = MAX_HTML_FETCH_SIZE
) -> Tuple[bool, str, str, Dict[str, str]]:
    """
    Safely fetches HTML content over network:
    1. Validates SSRF safety.
    2. Bounds redirect depth.
    3. Enforces response timeout & byte size limit.
    Returns: (success, final_url, html_content_or_error_msg, headers)
    """
    is_safe, reason, resolved_ip = validate_target_ssrf_safety(url)
    if not is_safe:
        logger.warning(f"[Page Analyzer SSRF Guard Blocked] URL '{url}': {reason}")
        return False, url, f"SSRF Guard Blocked: {reason}", {}

    import urllib.request

    try:
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "KEIKAI-Security-Inspection-Bot/1.0 (+https://keikai-security.org)"
            }
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            final_url = resp.geturl()
            # Double check SSRF on final redirected URL
            is_final_safe, final_reason, _ = validate_target_ssrf_safety(final_url)
            if not is_final_safe:
                return False, final_url, f"SSRF Guard Blocked on Redirect: {final_reason}", {}

            resp_headers = dict(resp.headers)
            content_bytes = resp.read(max_size + 1)
            if len(content_bytes) > max_size:
                content_bytes = content_bytes[:max_size]

            html_text = content_bytes.decode("utf-8", errors="replace")
            return True, final_url, html_text, resp_headers
    except Exception as err:
        logger.warning(f"Error fetching page safely for '{url}': {err}")
        return False, url, f"HTTP Fetch Error: {str(err)}", {}


# ---------------------------------------------------------------------------
# 9. Main Landing Page Analyzer Pipeline Entry Point
# ---------------------------------------------------------------------------

def analyze_landing_page(
    url: str,
    html_content: Optional[str] = None,
    candidate_image_bytes: Optional[bytes] = None,
    target_brand: Optional[str] = None,
    official_domain: Optional[str] = None
) -> Dict[str, Any]:
    """
    Main aggregator for Phase 6 Complete Page Similarity & Brand Clone Detection.
    Executes end-to-end pipeline:
    Safe Page Fetch -> Static HTML BeautifulSoup Parsing -> Brand Text Analysis ->
    Brand Asset Analysis -> Form Action Analysis -> Domain Alignment ->
    Visual Perceptual Hash Similarity -> Multi-Signal Clone Classification.
    """
    now_iso = datetime.now(timezone.utc).isoformat()

    # 1. Page Fetch / Content Acquisition
    final_url = url
    fetch_success = True
    page_status = "PROVIDED_HTML"

    if not html_content:
        fetch_success, final_url, fetched_html, _ = fetch_page_safely(url)
        if fetch_success:
            html_content = fetched_html
            page_status = "LIVE_FETCHED_SUCCESS"
        else:
            html_content = ""
            page_status = "FETCH_FAILED"

    landing_hostname = urllib.parse.urlparse(final_url).hostname or urllib.parse.urlparse(url).hostname or ""

    # Resolve target brand & official domain from template if unspecified
    tmpl = get_brand_template(target_brand or official_domain or landing_hostname)
    resolved_brand = target_brand or (tmpl.brand if tmpl else "Unknown")
    resolved_official_domain = official_domain or (tmpl.official_domain if tmpl else "")

    # 2. BeautifulSoup Static HTML Analysis & Structural Fingerprinting
    html_analysis = analyze_page_static_html(html_content, final_url)

    # 3. Brand Text Analysis
    brand_text_info = analyze_brand_text(
        html_analysis.get("visible_text", ""),
        target_brand=resolved_brand,
        official_domain=resolved_official_domain
    )

    # 4. Brand Asset Analysis
    brand_asset_info = analyze_brand_assets(
        html_analysis.get("images", []),
        html_analysis.get("favicon"),
        target_brand=resolved_brand,
        official_domain=resolved_official_domain
    )

    # 5. Form Action Security Analysis
    form_info = analyze_form_actions(
        html_analysis.get("forms", []),
        landing_url=final_url,
        official_domain=resolved_official_domain
    )

    # 6. Domain Alignment
    domain_align_info = calculate_domain_alignment(
        landing_domain=landing_hostname,
        official_domain=resolved_official_domain
    )

    # 7. Actual Visual Perceptual Hash Similarity
    ref_image_bytes = None
    visual_info = compute_visual_similarity(candidate_image_bytes, ref_image_bytes)

    # 8. Multi-Signal Similarity Breakdown
    multi_similarity = calculate_multi_signal_similarity(
        html_analysis,
        brand_text_info,
        brand_asset_info,
        form_info,
        domain_align_info,
        visual_info,
        target_brand=resolved_brand
    )

    # 9. Clone Classification Verdict
    clone_verdict = classify_brand_clone(
        multi_similarity,
        form_info,
        domain_align_info,
        brand_text_info,
        brand_asset_info,
        target_brand=resolved_brand
    )

    # Assemble structured evidence items
    evidence = []

    # 8. Level 2 Dynamic Browser Analysis Escalation
    from services.dynamic_browser import analyze_dynamic_url

    static_has_pass = len(html_analysis.get("password_inputs", [])) > 0
    script_count = html_analysis.get("script_count", 0)

    # Escalation condition: Scripts present, no static password field, or live fetch URL
    should_escalate_dynamic = (script_count > 0 and not static_has_pass) or not html_content or (clone_verdict.get("is_clone", False))

    dynamic_res = {}
    if should_escalate_dynamic:
        dynamic_res = analyze_dynamic_url(final_url)

        # Static vs Dynamic DOM Comparison
        if dynamic_res.get("status") == "SUCCESS":
            dyn_has_cred = dynamic_res.get("has_credential_submission", False)
            if not static_has_pass and dyn_has_cred:
                evidence.append({
                    "signal": "DYNAMIC_CREDENTIAL_FORM",
                    "description": "Password input form field detected after client-side JavaScript execution (Playwright Dynamic DOM)",
                    "severity": 40,
                    "provenance": "PLAYWRIGHT_DYNAMIC_DOM"
                })
                # Upgrade credential similarity & form info
                form_info["has_credential_submission"] = True
                multi_similarity["credential_similarity"] = max(multi_similarity.get("credential_similarity", 0.0), 0.90)
                clone_verdict["has_cred_form"] = True

            # If dynamic browser captured screenshot, calculate dynamic visual similarity
            dyn_ss_b64 = dynamic_res.get("screenshot_base64")
            if dyn_ss_b64 and not candidate_image_bytes:
                try:
                    dyn_img_bytes = base64.b64decode(dyn_ss_b64)
                    dyn_vis_info = compute_visual_similarity(dyn_img_bytes, ref_image_bytes)
                    if dyn_vis_info.get("similarity") is not None:
                        visual_info["dynamic_rendered_similarity"] = dyn_vis_info.get("similarity")
                        multi_similarity["visual_similarity"] = max(multi_similarity.get("visual_similarity") or 0.0, dyn_vis_info.get("similarity"))
                except Exception as ss_err:
                    logger.warning(f"Failed decoding dynamic screenshot for visual comparison: {ss_err}")

    # Re-classify clone verdict if dynamic analysis provided additional evidence
    if dynamic_res and dynamic_res.get("status") == "SUCCESS":
        clone_verdict = classify_brand_clone(
            multi_similarity,
            form_info,
            domain_align_info,
            brand_text_info,
            brand_asset_info,
            target_brand=resolved_brand
        )

    for reason in clone_verdict.get("evidence_reasons", []):
        evidence.append({
            "signal": "brand_clone_evidence",
            "description": reason,
            "severity": 30 if clone_verdict.get("is_clone") else 0
        })

    return {
        "original_url": url,
        "final_url": dynamic_res.get("final_url") if dynamic_res and dynamic_res.get("final_url") else final_url,
        "page_status": page_status,
        "target_brand": resolved_brand,
        "official_domain": resolved_official_domain,
        "html_analysis": {
            "title": dynamic_res.get("rendered_title") or html_analysis.get("title"),
            "meta_description": html_analysis.get("meta_description"),
            "dom_depth": html_analysis.get("dom_depth"),
            "dom_fingerprint": html_analysis.get("dom_fingerprint"),
            "structural_features": html_analysis.get("structural_features"),
            "form_count": len(html_analysis.get("forms", [])),
            "password_input_count": len(html_analysis.get("password_inputs", []))
        },
        "brand_text_analysis": brand_text_info,
        "brand_asset_analysis": brand_asset_info,
        "form_analysis": form_info,
        "domain_alignment": domain_align_info,
        "visual_analysis": visual_info,
        "similarity": multi_similarity,
        "clone_verdict": clone_verdict,
        "dynamic_browser_analysis": dynamic_res,
        "evidence": evidence,
        "provenance": {
            "source": "page_analyzer_engine",
            "status": "SUCCESS" if fetch_success else "FETCH_FAILED",
            "live": page_status == "LIVE_FETCHED_SUCCESS",
            "dynamic_escalation": should_escalate_dynamic,
            "retrieved_at": now_iso
        }
    }

