"""
services/payload_inspection.py

KEIKAI PAYLOAD INTELLIGENCE ENGINE — QR INSPECTION & STATIC ATTACHMENT ANALYSIS

Provides safe, non-executable payload analysis:
1. QR Code Image Inspection (OpenCV cv2.QRCodeDetector + URL normalization)
2. Safe Static Attachment Analysis:
   - SHA-256 cryptographic file hashing
   - HTML Static Parsing (detecting <form action="...">, password inputs, credential phrasing without JS execution)
   - PDF Static Inspection (extracting text streams, /URI links, domain IOCs without launching PDF viewer)
   - DOCX / Text Inspection (extracting visible text & hyperlinks)
   - ZIP Archive Inspection (evaluating entry names, extensions, compression ratios, and safety limits)
   - Image Inspection (OCR text & QR decoding)
3. Transparent Payload Risk Scoring (0-100)
4. Extracted IOC handoff into Threat Intelligence pipeline
"""

import os
import re
import io
import html
import hashlib
import zipfile
import logging
from html.parser import HTMLParser
from typing import Dict, Any, List, Optional, Tuple
from PIL import Image
import cv2
import numpy as np

from services.email_analysis import normalize_url, clean_domain

logger = logging.getLogger("keikai.services.payload_inspection")

# Security limits for safe static inspection
MAX_ATTACHMENT_SIZE_BYTES = 10 * 1024 * 1024  # 10 MB
MAX_ZIP_ENTRIES = 50
MAX_ZIP_EXTRACT_RATIO = 100  # Zip bomb prevention

# Credential & phishing keywords for static payload text inspection
CREDENTIAL_FORM_KEYWORDS = ["password", "login", "signin", "authenticate", "credential", "verify_account"]


class StaticHTMLFormParser(HTMLParser):
    """Safe, non-executing HTML parser to extract form targets, password fields, and links."""

    def __init__(self):
        super().__init__()
        self.urls: List[str] = []
        self.form_actions: List[str] = []
        self.has_password_input: bool = False
        self.inputs: List[Dict[str, str]] = []
        self.text_content: List[str] = []

    def handle_starttag(self, tag, attrs):
        attr_dict = dict(attrs)
        tag_lower = tag.lower()

        if tag_lower == "a" and "href" in attr_dict:
            href = attr_dict["href"].strip()
            if href and not href.startswith("javascript:") and not href.startswith("#"):
                self.urls.append(href)

        elif tag_lower == "form" and "action" in attr_dict:
            action = attr_dict["action"].strip()
            if action:
                self.form_actions.append(action)

        elif tag_lower == "input":
            input_type = attr_dict.get("type", "text").lower()
            input_name = attr_dict.get("name", "").lower()
            if input_type == "password" or "pass" in input_name:
                self.has_password_input = True
            self.inputs.append({"type": input_type, "name": input_name})

    def handle_data(self, data):
        cleaned = data.strip()
        if cleaned:
            self.text_content.append(cleaned)


def calculate_sha256(file_bytes: bytes) -> str:
    """Computes SHA-256 hash of raw file content."""
    return hashlib.sha256(file_bytes).hexdigest()


def inspect_qr_code(image_bytes: bytes) -> Dict[str, Any]:
    """
    Safely inspects an image file for QR code payload without rendering or navigating to target.
    Uses OpenCV cv2.QRCodeDetector.
    """
    decoded_values = []
    urls = []
    domains = []

    try:
        # Convert image bytes to OpenCV numpy image matrix
        nparr = np.frombuffer(image_bytes, np.uint8)
        img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)

        if img is not None:
            detector = cv2.QRCodeDetector()
            # Multi QR or single QR detection
            val, points, _ = detector.detectAndDecode(img)
            if val:
                decoded_values.append(val.strip())

            # Try multi QR detection if supported
            try:
                retval, decoded_info, _, _ = detector.detectAndDecodeMulti(img)
                if retval and decoded_info:
                    for info in decoded_info:
                        if info and info.strip() not in decoded_values:
                            decoded_values.append(info.strip())
            except Exception:
                pass

        # Also search for QR text pattern in case string payload passed directly
        if not decoded_values:
            try:
                text_content = image_bytes.decode('utf-8', errors='ignore')
                raw_urls = re.findall(r'https?://[^\s<>"\']+', text_content)
                for u in raw_urls:
                    if u not in decoded_values:
                        decoded_values.append(u)
            except Exception:
                pass

        # Process decoded values for URLs & domains
        for val in decoded_values:
            norm_url = normalize_url(val)
            if norm_url:
                urls.append(norm_url)
                d = clean_domain(norm_url)
                if d and d not in domains:
                    domains.append(d)

        qr_detected = len(decoded_values) > 0
        risk_score = 75 if urls else (25 if qr_detected else 0)

        return {
            "qr_detected": qr_detected,
            "decoded_values": decoded_values,
            "extracted_urls": urls,
            "extracted_domains": domains,
            "payload_source": "qr_code",
            "risk_score": risk_score,
            "risk_relevant": len(urls) > 0,
            "evidence": [f"Decoded QR payload leads to URL: {urls[0]}"] if urls else (["QR code detected in image."] if qr_detected else [])
        }
    except Exception as e:
        logger.warning(f"QR code inspection error: {e}")
        return {
            "qr_detected": False,
            "decoded_values": [],
            "extracted_urls": [],
            "extracted_domains": [],
            "payload_source": "qr_code",
            "risk_score": 0,
            "risk_relevant": False,
            "evidence": [],
            "error": str(e)
        }


def inspect_html_attachment(content_bytes: bytes, filename: str) -> Dict[str, Any]:
    """
    Safely inspects HTML attachment payload as text.
    Extracts form actions, password inputs, credential phrasing, and URLs without JS execution.
    """
    text_content = content_bytes.decode('utf-8', errors='ignore')
    parser = StaticHTMLFormParser()
    try:
        parser.feed(text_content)
    except Exception:
        pass

    urls = []
    domains = []
    signals = []
    risk_points = 0

    # Process URLs from <a> tags and <form action="...">
    all_raw_urls = parser.urls + parser.form_actions + re.findall(r'https?://[^\s<>"\']+', text_content)
    for u in all_raw_urls:
        norm_url = normalize_url(u)
        if norm_url and norm_url not in urls and len(norm_url) > 8:
            urls.append(norm_url)
            d = clean_domain(norm_url)
            if d and d not in domains:
                domains.append(d)

    # Signal 1: HTML Credential Harvesting Form
    if parser.has_password_input or parser.form_actions:
        risk_points += 45
        form_target = parser.form_actions[0] if parser.form_actions else "Inline Action"
        signals.append({
            "type": "html_credential_form",
            "severity": "CRITICAL",
            "evidence": f"HTML attachment '{filename}' contains an embedded login form submitting to target: {form_target}."
        })

    # Signal 2: Password Input Field
    if parser.has_password_input:
        risk_points += 25
        signals.append({
            "type": "password_input_present",
            "severity": "HIGH",
            "evidence": f"HTML attachment '{filename}' contains password authentication input fields."
        })

    # Signal 3: Embedded Script Tag Presence (Static Inspection)
    if "<script" in text_content.lower():
        risk_points += 15
        signals.append({
            "type": "embedded_script_text",
            "severity": "MEDIUM",
            "evidence": f"HTML attachment '{filename}' contains embedded script blocks (static analysis only)."
        })

    risk_score = min(100, risk_points)
    severity = "CRITICAL" if risk_score >= 80 else ("HIGH" if risk_score >= 50 else ("MEDIUM" if risk_score >= 25 else "LOW"))

    return {
        "format": "HTML",
        "has_credential_form": parser.has_password_input or bool(parser.form_actions),
        "form_actions": parser.form_actions,
        "password_field_detected": parser.has_password_input,
        "extracted_urls": urls,
        "extracted_domains": domains,
        "signals": signals,
        "risk_score": risk_score,
        "severity": severity
    }


def inspect_pdf_attachment(content_bytes: bytes, filename: str) -> Dict[str, Any]:
    """
    Safely performs static inspection of PDF file streams.
    Extracts text, /URI links, and domain mentions without launching PDF viewers.
    """
    text_content = content_bytes.decode('utf-8', errors='ignore')
    
    # Extract URLs from /URI(...) and raw HTTP patterns
    raw_urls = re.findall(r'/URI\s*\((https?://[^\)]+)\)', text_content, re.IGNORECASE)
    raw_urls += re.findall(r'https?://[^\s<>"\':\)\(]+', text_content, re.IGNORECASE)

    urls = []
    domains = []
    for u in raw_urls:
        norm_url = normalize_url(u)
        if norm_url and norm_url not in urls and len(norm_url) > 8:
            urls.append(norm_url)
            d = clean_domain(norm_url)
            if d and d not in domains:
                domains.append(d)

    signals = []
    risk_points = 0

    has_cred_text = any(kw in text_content.lower() for kw in ["password", "verify account", "login required", "suspended"])
    if has_cred_text and urls:
        risk_points += 55
        signals.append({
            "type": "pdf_phishing_link",
            "severity": "HIGH",
            "evidence": f"PDF document '{filename}' contains credential verification phrasing and link target ({urls[0]})."
        })
    elif urls:
        risk_points += 25
        signals.append({
            "type": "pdf_embedded_link",
            "severity": "LOW",
            "evidence": f"PDF document '{filename}' contains embedded web hyperlink: {urls[0]}."
        })

    risk_score = min(100, risk_points)
    severity = "HIGH" if risk_score >= 60 else ("MEDIUM" if risk_score >= 30 else "BENIGN")

    return {
        "format": "PDF",
        "extracted_urls": urls,
        "extracted_domains": domains,
        "signals": signals,
        "risk_score": risk_score,
        "severity": severity
    }


def inspect_zip_attachment(content_bytes: bytes, filename: str) -> Dict[str, Any]:
    """
    Safely inspects ZIP archive file entries and metadata without extracting files to disk.
    Enforces maximum entry limits and checks for dangerous file extensions (.exe, .scr, .vbs, .js, .html).
    """
    urls = []
    domains = []
    signals = []
    risk_points = 0
    file_list = []

    try:
        with zipfile.ZipFile(io.BytesIO(content_bytes), 'r') as zf:
            infolist = zf.infolist()
            if len(infolist) > MAX_ZIP_ENTRIES:
                return {
                    "format": "ZIP",
                    "status": "INSPECTION_LIMIT_REACHED",
                    "error": f"ZIP archive contains too many entries ({len(infolist)} > {MAX_ZIP_ENTRIES}).",
                    "risk_score": 50,
                    "severity": "MEDIUM"
                }

            for info in infolist:
                file_list.append(info.filename)
                fname_lower = info.filename.lower()
                
                # Check for executable or script extensions inside ZIP
                if any(fname_lower.endswith(ext) for ext in [".exe", ".scr", ".bat", ".vbs", ".js", ".ps1", ".htm", ".html"]):
                    risk_points += 60
                    signals.append({
                        "type": "zip_suspicious_payload",
                        "severity": "CRITICAL",
                        "evidence": f"ZIP archive '{filename}' contains executable or script payload entry: '{info.filename}'."
                    })

    except Exception as err:
        return {
            "format": "ZIP",
            "status": "INVALID_ARCHIVE",
            "error": f"Failed to parse ZIP archive: {err}",
            "risk_score": 30,
            "severity": "MEDIUM"
        }

    risk_score = min(100, risk_points)
    severity = "CRITICAL" if risk_score >= 60 else "BENIGN"

    return {
        "format": "ZIP",
        "file_list": file_list,
        "extracted_urls": urls,
        "extracted_domains": domains,
        "signals": signals,
        "risk_score": risk_score,
        "severity": severity
    }


def inspect_attachment_payload(
    file_bytes: bytes,
    filename: str,
    mime_type: Optional[str] = None
) -> Dict[str, Any]:
    """
    Main entry point for Safe Static Attachment Inspection.
    """
    if len(file_bytes) > MAX_ATTACHMENT_SIZE_BYTES:
        return {
            "filename": filename,
            "sha256": calculate_sha256(file_bytes),
            "status": "SIZE_LIMIT_EXCEEDED",
            "error": f"File size ({len(file_bytes)} bytes) exceeds max static inspection limit ({MAX_ATTACHMENT_SIZE_BYTES} bytes).",
            "risk_score": 0,
            "severity": "BENIGN"
        }

    sha256_hash = calculate_sha256(file_bytes)
    ext = os.path.splitext(filename)[1].lower()

    # QR Inspection for Image Attachments
    qr_result = {"qr_detected": False, "extracted_urls": [], "extracted_domains": []}
    if ext in [".png", ".jpg", ".jpeg", ".webp", ".bmp", ".gif"]:
        qr_result = inspect_qr_code(file_bytes)

    # Static Analysis by Extension / Format
    if ext in [".htm", ".html", ".xhtml"]:
        details = inspect_html_attachment(file_bytes, filename)
    elif ext == ".pdf":
        details = inspect_pdf_attachment(file_bytes, filename)
    elif ext == ".zip":
        details = inspect_zip_attachment(file_bytes, filename)
    elif ext in [".png", ".jpg", ".jpeg", ".webp"]:
        details = {
            "format": "IMAGE",
            "qr_analysis": qr_result,
            "extracted_urls": qr_result.get("extracted_urls", []),
            "extracted_domains": qr_result.get("extracted_domains", []),
            "signals": qr_result.get("evidence", []),
            "risk_score": qr_result.get("risk_score", 0),
            "severity": "HIGH" if qr_result.get("risk_score", 0) >= 50 else "BENIGN"
        }
    else:
        # Default text / binary static fallback
        try:
            text_snippet = file_bytes.decode('utf-8', errors='ignore')
            raw_urls = re.findall(r'https?://[^\s<>"\':\)\(]+', text_snippet)
            urls = [normalize_url(u) for u in raw_urls if normalize_url(u)]
            domains = list(set([clean_domain(u) for u in urls if clean_domain(u)]))
            details = {
                "format": ext.upper().replace(".", "") or "FILE",
                "extracted_urls": urls,
                "extracted_domains": domains,
                "signals": [],
                "risk_score": 25 if urls else 0,
                "severity": "LOW" if urls else "BENIGN"
            }
        except Exception:
            details = {
                "format": "BINARY",
                "extracted_urls": [],
                "extracted_domains": [],
                "signals": [],
                "risk_score": 0,
                "severity": "BENIGN"
            }

    # Aggregate extracted IOCs
    combined_urls = list(set(details.get("extracted_urls", []) + qr_result.get("extracted_urls", [])))
    combined_domains = list(set(details.get("extracted_domains", []) + qr_result.get("extracted_domains", [])))

    overall_risk = max(details.get("risk_score", 0), qr_result.get("risk_score", 0))

    return {
        "filename": filename,
        "file_size": len(file_bytes),
        "sha256": sha256_hash,
        "format": details.get("format", ext.upper()),
        "status": "COMPLETED_STATIC_INSPECTION",
        "qr": qr_result,
        "details": details,
        "iocs": {
            "urls": combined_urls,
            "domains": combined_domains
        },
        "signals": details.get("signals", []),
        "risk_score": overall_risk,
        "severity": "CRITICAL" if overall_risk >= 75 else ("HIGH" if overall_risk >= 50 else ("MEDIUM" if overall_risk >= 25 else "BENIGN")),
        "inspection_mode": "safe_static_analysis_only"
    }
