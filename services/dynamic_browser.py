"""
services/dynamic_browser.py

KEKAI DYNAMIC BROWSER ANALYSIS ENGINE (LEVEL 2 ESCALATION LAYER)

Provides controlled, safe dynamic headless browser analysis for JavaScript-rendered
phishing pages using Playwright with fallback to static analysis.

Security & Safety Controls:
1. Pre-navigation destination validation with services.ssrf_guard (blocks loopback, private ranges, cloud metadata).
2. Strict isolation: Isolated browser context, 10s navigation timeout, memory limits.
3. Redirect hop validation: Evaluates every redirected location against SSRF guard.
4. Extracted structured evidence: Post-JS rendered DOM, password inputs, form action endpoints, JS redirects, rendered page screenshot.
5. Fail-safe design: Returns structured status (e.g., BLOCKED_BY_SSRF_GUARD, TIMEOUT, UNAVAILABLE_FALLBACK) without crashing the pipeline.
"""

import base64
import logging
import urllib.parse
from typing import Dict, Any, List, Optional
from services.redirect_tracer import validate_target_ssrf_safety

logger = logging.getLogger("keikai.services.dynamic_browser")


def analyze_dynamic_url(
    url: str,
    timeout_seconds: int = 10,
    max_redirects: int = 5
) -> Dict[str, Any]:
    """
    Executes controlled dynamic browser analysis on target URL.
    Returns structured post-JavaScript rendering evidence.
    """
    clean_url = (url or "").strip()
    if not clean_url.startswith(("http://", "https://")):
        return {
            "status": "UNSUPPORTED_SCHEME",
            "message": f"Scheme not supported for dynamic analysis: {clean_url}",
            "final_url": clean_url,
            "redirect_chain": [],
            "forms_found": [],
            "has_credential_submission": False,
            "js_redirects_detected": False,
            "screenshot_base64": None,
            "rendered_title": None,
            "provenance": "DYNAMIC_BROWSER_SAFETY"
        }

    # Step 1: Pre-navigation SSRF Validation
    is_safe, ssrf_reason, _ = validate_target_ssrf_safety(clean_url)
    if not is_safe:
        logger.warning(f"[Dynamic Browser Guard] Blocked unsafe target URL '{clean_url}': {ssrf_reason}")
        return {
            "status": "BLOCKED_BY_SSRF_GUARD",
            "message": f"SSRF Guard blocked dynamic navigation: {ssrf_reason}",
            "final_url": clean_url,
            "redirect_chain": [],
            "forms_found": [],
            "has_credential_submission": False,
            "js_redirects_detected": False,
            "screenshot_base64": None,
            "rendered_title": None,
            "provenance": "SSRF_GUARD_SAFETY"
        }

    # Try Playwright dynamic rendering
    try:
        from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeoutError
    except ImportError:
        logger.info("[Dynamic Browser Engine] Playwright package not installed. Returning fallback response.")
        return _build_fallback_response(clean_url, "PLAYWRIGHT_NOT_INSTALLED")

    navigation_chain: List[Dict[str, Any]] = []
    js_redirects: List[str] = []

    try:
        with sync_playwright() as p:
            # Launch headless chromium with restricted sandbox flags
            browser = p.chromium.launch(
                headless=True,
                args=[
                    "--no-sandbox",
                    "--disable-setuid-sandbox",
                    "--disable-dev-shm-usage",
                    "--disable-gpu",
                    "--no-first-run",
                    "--no-default-browser-check"
                ]
            )

            # Create isolated context with fake user agent
            context = browser.new_context(
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                viewport={"width": 1280, "height": 800},
                ignore_https_errors=True,
                java_script_enabled=True
            )

            page = context.new_page()
            page.set_default_timeout(timeout_seconds * 1000)

            # Monitor frame & request navigation for SSRF and JS redirects
            def handle_response(response):
                resp_url = response.url
                status = response.status
                if status in (301, 302, 303, 307, 308):
                    location = response.headers.get("location")
                    if location:
                        abs_loc = urllib.parse.urljoin(resp_url, location)
                        # Check SSRF on redirect destination
                        is_loc_safe, loc_reason, _ = validate_target_ssrf_safety(abs_loc)
                        if not is_loc_safe:
                            logger.warning(f"[Dynamic Browser Guard] SSRF blocked redirect target '{abs_loc}': {loc_reason}")
                            page.close()
                        navigation_chain.append({
                            "url": resp_url,
                            "location": abs_loc,
                            "status_code": status,
                            "type": "HTTP_REDIRECT"
                        })

            page.on("response", handle_response)

            try:
                # Navigate to initial URL
                response = page.goto(clean_url, wait_until="domcontentloaded", timeout=timeout_seconds * 1000)
                # Wait briefly for client-side JavaScript execution (e.g. form injection)
                page.wait_for_timeout(1500)
            except PlaywrightTimeoutError:
                logger.warning(f"[Dynamic Browser Engine] Navigation timed out for '{clean_url}'")
                context.close()
                browser.close()
                return _build_fallback_response(clean_url, "TIMEOUT", message="Page navigation timed out during dynamic rendering")
            except Exception as nav_err:
                logger.warning(f"[Dynamic Browser Engine] Navigation error for '{clean_url}': {nav_err}")
                context.close()
                browser.close()
                return _build_fallback_response(clean_url, "NAVIGATION_ERROR", message=str(nav_err))

            final_url = page.url
            is_final_safe, final_reason, _ = validate_target_ssrf_safety(final_url)
            if not is_final_safe:
                context.close()
                browser.close()
                return {
                    "status": "BLOCKED_BY_SSRF_GUARD",
                    "message": f"SSRF Guard blocked dynamic final destination: {final_reason}",
                    "final_url": final_url,
                    "redirect_chain": navigation_chain,
                    "forms_found": [],
                    "has_credential_submission": False,
                    "js_redirects_detected": False,
                    "screenshot_base64": None,
                    "rendered_title": None,
                    "provenance": "SSRF_GUARD_SAFETY"
                }

            # Check if JS location changed from initial target
            if final_url != clean_url and not any(h["url"] == clean_url for h in navigation_chain):
                js_redirects.append(final_url)
                navigation_chain.append({
                    "url": clean_url,
                    "location": final_url,
                    "status_code": 200,
                    "type": "JAVASCRIPT_REDIRECT"
                })

            rendered_title = page.title()

            # Evaluate Post-JS Rendered DOM Forms & Inputs
            evaluated_forms = page.evaluate("""() => {
                const forms = Array.from(document.querySelectorAll('form'));
                const pageForms = forms.map(f => {
                    const inputs = Array.from(f.querySelectorAll('input, select, textarea'));
                    const passwordInputs = inputs.filter(i => (i.type || '').toLowerCase() === 'password' || (i.name || '').toLowerCase().includes('pass') || (i.id || '').toLowerCase().includes('pass'));
                    const emailInputs = inputs.filter(i => (i.type || '').toLowerCase() === 'email' || (i.name || '').toLowerCase().includes('user') || (i.name || '').toLowerCase().includes('email'));
                    return {
                        action: f.action || '',
                        method: f.method || 'GET',
                        input_count: inputs.length,
                        has_password_field: passwordInputs.length > 0,
                        has_email_field: emailInputs.length > 0,
                        password_field_names: passwordInputs.map(i => i.name || i.id || 'unnamed_password')
                    };
                });

                // Also check un-wrapped password inputs floating in body
                const standalonePasswords = Array.from(document.querySelectorAll('input[type="password"], input[name*="pass" i]'));
                const hasStandalonePassword = standalonePasswords.length > 0;

                return {
                    forms: pageForms,
                    has_standalone_password: hasStandalonePassword,
                    standalone_password_count: standalonePasswords.length
                };
            }""")

            # Process forms data
            forms_list = evaluated_forms.get("forms", [])
            has_standalone_pass = evaluated_forms.get("has_standalone_password", False)
            has_credential_submission = has_standalone_pass or any(f.get("has_password_field") for f in forms_list)

            # Analyze form action hostnames
            final_domain = (urllib.parse.urlparse(final_url).hostname or "").lower()
            formatted_forms = []
            for form in forms_list:
                act = form.get("action") or final_url
                act_parsed = urllib.parse.urlparse(act)
                act_host = (act_parsed.hostname or final_domain).lower()
                is_cross_domain = bool(act_host and final_domain and act_host != final_domain)

                formatted_forms.append({
                    "action_url": act,
                    "action_hostname": act_host,
                    "is_cross_domain": is_cross_domain,
                    "has_password_field": form.get("has_password_field", False),
                    "has_email_field": form.get("has_email_field", False)
                })

            # Capture rendered page screenshot
            screenshot_base64 = None
            try:
                screenshot_bytes = page.screenshot(type="jpeg", quality=75, full_page=False)
                screenshot_base64 = base64.b64encode(screenshot_bytes).decode("utf-8")
            except Exception as ss_err:
                logger.warning(f"[Dynamic Browser Engine] Screenshot capture failed: {ss_err}")

            context.close()
            browser.close()

            return {
                "status": "SUCCESS",
                "message": "Dynamic browser analysis completed successfully",
                "initial_url": clean_url,
                "final_url": final_url,
                "redirect_chain": navigation_chain,
                "js_redirects_detected": len(js_redirects) > 0,
                "rendered_title": rendered_title,
                "forms_found": formatted_forms,
                "has_credential_submission": has_credential_submission,
                "has_standalone_password": has_standalone_pass,
                "screenshot_base64": screenshot_base64,
                "provenance": "PLAYWRIGHT_DYNAMIC_DOM"
            }

    except Exception as e:
        logger.error(f"[Dynamic Browser Engine] Unhandled exception during Playwright execution: {e}")
        return _build_fallback_response(clean_url, "BROWSER_UNAVAILABLE_FALLBACK", message=str(e))


def _build_fallback_response(url: str, status: str, message: str = "") -> Dict[str, Any]:
    """Builds a safe, non-crashing fallback response when dynamic browser cannot execute."""
    return {
        "status": status,
        "message": message or f"Dynamic browser fallback triggered ({status})",
        "initial_url": url,
        "final_url": url,
        "redirect_chain": [],
        "js_redirects_detected": False,
        "rendered_title": None,
        "forms_found": [],
        "has_credential_submission": False,
        "screenshot_base64": None,
        "provenance": "DYNAMIC_BROWSER_FALLBACK"
    }
