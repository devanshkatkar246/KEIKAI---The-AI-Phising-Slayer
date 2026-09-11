"""
evaluation/fixtures/evaluation_cases.py

Deterministic evaluation dataset containing 12 representative test cases for KEKAI PS #2 evaluation:
1. BENIGN_INTERNAL
2. BENIGN_EXTERNAL
3. EXTERNAL_BRAND_IMPERSONATION
4. LOOKALIKE_DOMAIN
5. NEW_DOMAIN_CREDENTIAL_PHISHING
6. COMPROMISED_INTERNAL_ACCOUNT
7. QR_PHISHING
8. MALICIOUS_ATTACHMENT_HTML
9. VISUAL_BRAND_CLONE
10. REDIRECT_TO_CREDENTIAL_PAGE
11. HIGH_RISK_FALSE_POSITIVE
12. INCONCLUSIVE_CASE
"""

EVALUATION_CASES = [
    {
        "id": "CASE-01",
        "name": "BENIGN_INTERNAL",
        "description": "Legitimate internal team email matching organizational sender baseline",
        "expected_verdict": "BENIGN",
        "expected_action": "ALLOW",
        "bundle": {
            "subject": "Q3 Engineering Sync Notes",
            "sender": "alice@acme-corp.com",
            "email_analysis": {
                "email": {
                    "subject": "Q3 Engineering Sync Notes",
                    "sender": "alice@acme-corp.com",
                    "body": "Hi team, here are the meeting notes from today's architecture sync. Thanks!"
                },
                "extracted_domain": "acme-corp.com",
                "threat_signals": [],
                "email_signals": {"urgency_language": False, "credential_request": False, "brand_impersonation": False}
            },
            "sender_behavior": {
                "anomaly_score": 0,
                "hypothesis": "ALIGNS_WITH_BASELINE",
                "profile_available": True,
                "domain_match": True,
                "historical_count": 45
            },
            "domain_intelligence": {
                "domain": "acme-corp.com",
                "domain_risk": 0,
                "registration_age_days": 1825,
                "is_official": True
            },
            "url_intelligence": {
                "url_risk": 0,
                "final_url": "https://acme-corp.com/docs/notes",
                "redirect_signal": {"has_redirects": False, "chain_length": 0},
                "credential_page_signal": {"is_credential_page": False}
            },
            "visual_phishing": {"verdict": "BENIGN", "confidence": 0, "max_similarity": 0},
            "payload_inspection": {"qr_detected": False, "attachment_present": False, "suspicious_file_type": False}
        }
    },
    {
        "id": "CASE-02",
        "name": "BENIGN_EXTERNAL",
        "description": "Standard external newsletter from verified industry domain",
        "expected_verdict": "BENIGN",
        "expected_action": "ALLOW",
        "bundle": {
            "subject": "Weekly Tech Digest #142",
            "sender": "newsletter@techdigest.io",
            "email_analysis": {
                "email": {
                    "subject": "Weekly Tech Digest #142",
                    "sender": "newsletter@techdigest.io",
                    "body": "Check out this week's top stories in AI and cloud architecture."
                },
                "extracted_domain": "techdigest.io",
                "threat_signals": [],
                "email_signals": {"urgency_language": False, "credential_request": False, "brand_impersonation": False}
            },
            "sender_behavior": {
                "anomaly_score": 15,
                "hypothesis": "STANDARD_EXTERNAL_SENDER",
                "profile_available": True,
                "domain_match": True,
                "historical_count": 12
            },
            "domain_intelligence": {
                "domain": "techdigest.io",
                "domain_risk": 10,
                "registration_age_days": 730
            },
            "url_intelligence": {
                "url_risk": 5,
                "final_url": "https://techdigest.io/issue-142",
                "redirect_signal": {"has_redirects": False, "chain_length": 0},
                "credential_page_signal": {"is_credential_page": False}
            },
            "visual_phishing": {"verdict": "BENIGN", "confidence": 0},
            "payload_inspection": {"qr_detected": False, "attachment_present": False}
        }
    },
    {
        "id": "CASE-03",
        "name": "EXTERNAL_BRAND_IMPERSONATION",
        "description": "External spoofed email claiming urgent PayPal account suspension",
        "expected_verdict": "MALICIOUS",
        "expected_action": "BLOCK_AND_QUARANTINE",
        "bundle": {
            "subject": "URGENT: Your PayPal Account Has Been Suspended!",
            "sender": "support@paypal-security-alert.net",
            "email_analysis": {
                "email": {
                    "subject": "URGENT: Your PayPal Account Has Been Suspended!",
                    "sender": "support@paypal-security-alert.net",
                    "body": "Immediate action required! Your account will be locked in 24 hours unless you verify your password at the link below."
                },
                "extracted_domain": "paypal-security-alert.net",
                "threat_signals": ["urgency_language", "credential_request", "brand_impersonation"],
                "email_signals": {"urgency_language": True, "credential_request": True, "brand_impersonation": True}
            },
            "sender_behavior": {
                "anomaly_score": 90,
                "hypothesis": "ANOMALOUS_EXTERNAL_SENDER",
                "profile_available": False,
                "domain_match": False
            },
            "domain_intelligence": {
                "domain": "paypal-security-alert.net",
                "domain_risk": 85,
                "registration_age_days": 12
            },
            "url_intelligence": {
                "url_risk": 85,
                "final_url": "https://paypal-security-alert.net/login.php",
                "redirect_signal": {"has_redirects": False, "chain_length": 0},
                "credential_page_signal": {"is_credential_page": True}
            },
            "visual_phishing": {"verdict": "Phishing", "target_brand": "PayPal", "confidence": 92, "max_similarity": 94},
            "payload_inspection": {"qr_detected": False, "attachment_present": False}
        }
    },
    {
        "id": "CASE-04",
        "name": "LOOKALIKE_DOMAIN",
        "description": "Typosquatted domain impersonating Microsoft corporate login",
        "expected_verdict": "MALICIOUS",
        "expected_action": "BLOCK_AND_QUARANTINE",
        "bundle": {
            "subject": "Microsoft 365 Password Expiration Notice",
            "sender": "admin@micros0ft-verify.org",
            "email_analysis": {
                "email": {
                    "subject": "Microsoft 365 Password Expiration Notice",
                    "sender": "admin@micros0ft-verify.org",
                    "body": "Your Microsoft 365 password expires today. Click here to update your credentials immediately."
                },
                "extracted_domain": "micros0ft-verify.org",
                "threat_signals": ["brand_impersonation", "credential_request"],
                "email_signals": {"urgency_language": True, "credential_request": True, "brand_impersonation": True}
            },
            "sender_behavior": {
                "anomaly_score": 85,
                "hypothesis": "LOOKALIKE_DOMAIN_SENDER",
                "profile_available": False
            },
            "domain_intelligence": {
                "domain": "micros0ft-verify.org",
                "domain_risk": 90,
                "typosquat_detected": True,
                "target_brand": "Microsoft"
            },
            "url_intelligence": {
                "url_risk": 88,
                "final_url": "https://micros0ft-verify.org/auth/login",
                "redirect_signal": {"has_redirects": False, "chain_length": 0},
                "credential_page_signal": {"is_credential_page": True}
            },
            "visual_phishing": {"verdict": "Phishing", "target_brand": "Microsoft", "confidence": 95},
            "payload_inspection": {"qr_detected": False, "attachment_present": False}
        }
    },
    {
        "id": "CASE-05",
        "name": "NEW_DOMAIN_CREDENTIAL_PHISHING",
        "description": "Newly registered domain (<3 days old) hosting credential form",
        "expected_verdict": "MALICIOUS",
        "expected_action": "BLOCK_AND_QUARANTINE",
        "bundle": {
            "subject": "Important Account Update Required",
            "sender": "no-reply@auth-update-center-2026.info",
            "email_analysis": {
                "email": {
                    "subject": "Important Account Update Required",
                    "sender": "no-reply@auth-update-center-2026.info",
                    "body": "Please authenticate your credentials to maintain active account status."
                },
                "extracted_domain": "auth-update-center-2026.info",
                "threat_signals": ["credential_request"],
                "email_signals": {"urgency_language": True, "credential_request": True}
            },
            "sender_behavior": {"anomaly_score": 80, "hypothesis": "NEW_DOMAIN_SENDER"},
            "domain_intelligence": {
                "domain": "auth-update-center-2026.info",
                "domain_risk": 92,
                "registration_age_days": 2
            },
            "url_intelligence": {
                "url_risk": 90,
                "final_url": "https://auth-update-center-2026.info/login",
                "domain_age_signal": {"signal": "VERY_NEW_DOMAIN", "age_days": 2},
                "redirect_signal": {"has_redirects": False, "chain_length": 0},
                "credential_page_signal": {"is_credential_page": True}
            },
            "visual_phishing": {"verdict": "BENIGN", "confidence": 0},
            "payload_inspection": {"qr_detected": False, "attachment_present": False}
        }
    },
    {
        "id": "CASE-06",
        "name": "COMPROMISED_INTERNAL_ACCOUNT",
        "description": "Legitimate internal account sending anomalous external credential link",
        "expected_verdict": "SUSPICIOUS",
        "expected_action": "ISOLATE_AND_INVESTIGATE",
        "bundle": {
            "subject": "Revised Invoice Document",
            "sender": "bob@acme-corp.com",
            "email_analysis": {
                "email": {
                    "subject": "Revised Invoice Document",
                    "sender": "bob@acme-corp.com",
                    "body": "Please review the updated invoice at https://external-storage-share.temp/invoice."
                },
                "extracted_domain": "external-storage-share.temp",
                "threat_signals": ["anomalous_external_link"],
                "email_signals": {"urgency_language": False, "credential_request": True}
            },
            "sender_behavior": {
                "anomaly_score": 65,
                "hypothesis": "POSSIBLE_COMPROMISED_ACCOUNT",
                "profile_available": True,
                "domain_match": True,
                "anomalous_recipient": True,
                "anomalous_time": True
            },
            "domain_intelligence": {
                "domain": "external-storage-share.temp",
                "domain_risk": 60,
                "registration_age_days": 15
            },
            "url_intelligence": {
                "url_risk": 65,
                "final_url": "https://external-storage-share.temp/invoice",
                "redirect_signal": {"has_redirects": False, "chain_length": 0},
                "credential_page_signal": {"is_credential_page": False}
            },
            "visual_phishing": {"verdict": "BENIGN", "confidence": 0},
            "payload_inspection": {"qr_detected": False, "attachment_present": False}
        }
    },
    {
        "id": "CASE-07",
        "name": "QR_PHISHING",
        "description": "Email containing embedded QR code pointing to credential login URL",
        "expected_verdict": "MALICIOUS",
        "expected_action": "BLOCK_AND_QUARANTINE",
        "bundle": {
            "subject": "2FA Authentication Device Reset Required",
            "sender": "security@mfa-update-online.com",
            "email_analysis": {
                "email": {
                    "subject": "2FA Authentication Device Reset Required",
                    "sender": "security@mfa-update-online.com",
                    "body": "Scan the attached QR code with your authenticator app to restore access."
                },
                "extracted_domain": "mfa-update-online.com",
                "threat_signals": ["qr_phishing", "credential_request"],
                "email_signals": {"urgency_language": True, "credential_request": True}
            },
            "sender_behavior": {"anomaly_score": 85, "hypothesis": "ANOMALOUS_EXTERNAL_SENDER"},
            "domain_intelligence": {"domain": "mfa-update-online.com", "domain_risk": 80},
            "url_intelligence": {
                "url_risk": 85,
                "final_url": "https://mfa-update-online.com/qr-verify",
                "credential_page_signal": {"is_credential_page": True}
            },
            "visual_phishing": {"verdict": "BENIGN", "confidence": 0},
            "payload_inspection": {
                "qr_detected": True,
                "qr_decoded_url": "https://mfa-update-online.com/qr-verify",
                "attachment_present": True,
                "suspicious_file_type": False
            }
        }
    },
    {
        "id": "CASE-08",
        "name": "MALICIOUS_ATTACHMENT_HTML",
        "description": "Email with attached HTML file containing password input fields",
        "expected_verdict": "MALICIOUS",
        "expected_action": "BLOCK_AND_QUARANTINE",
        "bundle": {
            "subject": "Secure Document Portal Access",
            "sender": "docs@secure-cloud-share.org",
            "email_analysis": {
                "email": {
                    "subject": "Secure Document Portal Access",
                    "sender": "docs@secure-cloud-share.org",
                    "body": "Open the attached HTML file to view your encrypted confidential document."
                },
                "extracted_domain": "secure-cloud-share.org",
                "threat_signals": ["malicious_attachment"],
                "email_signals": {"urgency_language": True, "credential_request": True}
            },
            "sender_behavior": {"anomaly_score": 80, "hypothesis": "EXTERNAL_ATTACHMENT_SENDER"},
            "domain_intelligence": {"domain": "secure-cloud-share.org", "domain_risk": 75},
            "url_intelligence": {"url_risk": 50},
            "visual_phishing": {"verdict": "BENIGN", "confidence": 0},
            "payload_inspection": {
                "qr_detected": False,
                "attachment_present": True,
                "filename": "secure_doc.html",
                "suspicious_file_type": True,
                "html_form_detected": True,
                "password_input_detected": True
            }
        }
    },
    {
        "id": "CASE-09",
        "name": "VISUAL_BRAND_CLONE",
        "description": "Target website with 96% pHash visual layout similarity to Google Workspace",
        "expected_verdict": "MALICIOUS",
        "expected_action": "BLOCK_AND_QUARANTINE",
        "bundle": {
            "subject": "Google Workspace Storage Full",
            "sender": "admin@google-storage-alert.com",
            "email_analysis": {
                "email": {
                    "subject": "Google Workspace Storage Full",
                    "sender": "admin@google-storage-alert.com",
                    "body": "Your Google Drive storage is 99% full. Click to manage storage."
                },
                "extracted_domain": "google-storage-alert.com",
                "threat_signals": ["visual_brand_clone"],
                "email_signals": {"urgency_language": True, "credential_request": True}
            },
            "sender_behavior": {"anomaly_score": 85, "hypothesis": "BRAND_IMPERSONATION"},
            "domain_intelligence": {"domain": "google-storage-alert.com", "domain_risk": 85},
            "url_intelligence": {"url_risk": 80},
            "visual_phishing": {
                "verdict": "Phishing",
                "overall_status": "CONFIRMED",
                "target_brand": "Google",
                "confidence": 96,
                "max_similarity": 96
            },
            "payload_inspection": {"qr_detected": False, "attachment_present": False}
        }
    },
    {
        "id": "CASE-10",
        "name": "REDIRECT_TO_CREDENTIAL_PAGE",
        "description": "Multi-hop redirect chain terminating at a credential harvesting landing page",
        "expected_verdict": "MALICIOUS",
        "expected_action": "BLOCK_AND_QUARANTINE",
        "bundle": {
            "subject": "DocuSign: Please Sign Annual Policy",
            "sender": "docusign@express-redirect-service.net",
            "email_analysis": {
                "email": {
                    "subject": "DocuSign: Please Sign Annual Policy",
                    "sender": "docusign@express-redirect-service.net",
                    "body": "Click here to review and sign your policy document."
                },
                "extracted_domain": "express-redirect-service.net",
                "threat_signals": ["redirect_chain", "credential_harvesting"],
                "email_signals": {"urgency_language": True, "credential_request": True}
            },
            "sender_behavior": {"anomaly_score": 75, "hypothesis": "REDIRECT_CHAIN_PHISHING"},
            "domain_intelligence": {"domain": "express-redirect-service.net", "domain_risk": 70},
            "url_intelligence": {
                "url_risk": 90,
                "final_url": "https://credential-harvest-landing.com/auth",
                "redirect_signal": {
                    "has_redirects": True,
                    "chain_length": 3,
                    "chain": ["https://express-redirect-service.net/r1", "https://track-click.io/r2", "https://credential-harvest-landing.com/auth"]
                },
                "credential_page_signal": {"is_credential_page": True}
            },
            "visual_phishing": {"verdict": "Phishing", "target_brand": "DocuSign", "confidence": 90},
            "payload_inspection": {"qr_detected": False, "attachment_present": False}
        }
    },
    {
        "id": "CASE-11",
        "name": "HIGH_RISK_FALSE_POSITIVE",
        "description": "External vendor with newly registered sub-domain but clean sender history",
        "expected_verdict": "BENIGN",
        "expected_action": "ALLOW",
        "bundle": {
            "subject": "Monthly Service Invoice #8841",
            "sender": "billing@vendor-billing-portal.com",
            "email_analysis": {
                "email": {
                    "subject": "Monthly Service Invoice #8841",
                    "sender": "billing@vendor-billing-portal.com",
                    "body": "Your monthly statement is available in the billing portal."
                },
                "extracted_domain": "vendor-billing-portal.com",
                "threat_signals": [],
                "email_signals": {"urgency_language": False, "credential_request": False}
            },
            "sender_behavior": {
                "anomaly_score": 10,
                "hypothesis": "KNOWN_VENDOR_COMMUNICATION",
                "profile_available": True,
                "historical_count": 30
            },
            "domain_intelligence": {
                "domain": "vendor-billing-portal.com",
                "domain_risk": 30,
                "registration_age_days": 60
            },
            "url_intelligence": {
                "url_risk": 15,
                "final_url": "https://vendor-billing-portal.com/invoices/8841",
                "redirect_signal": {"has_redirects": False, "chain_length": 0},
                "credential_page_signal": {"is_credential_page": False}
            },
            "visual_phishing": {"verdict": "BENIGN", "confidence": 0},
            "payload_inspection": {"qr_detected": False, "attachment_present": False},
            "analyst_feedback": {"analyst_label": "ANALYST_FALSE_POSITIVE"}
        }
    },
    {
        "id": "CASE-12",
        "name": "INCONCLUSIVE_CASE",
        "description": "Sparse evidence payload with minimal content and unverified domain",
        "expected_verdict": "INCONCLUSIVE",
        "expected_action": "MONITOR_SENDER",
        "bundle": {
            "subject": "Hello",
            "sender": "unknown@unverified-domain-99.org",
            "email_analysis": {
                "email": {
                    "subject": "Hello",
                    "sender": "unknown@unverified-domain-99.org",
                    "body": "Hi"
                },
                "extracted_domain": "unverified-domain-99.org",
                "threat_signals": [],
                "email_signals": {"urgency_language": False, "credential_request": False}
            },
            "sender_behavior": {
                "anomaly_score": 30,
                "hypothesis": "UNVERIFIED_SENDER",
                "profile_available": False
            },
            "domain_intelligence": {
                "domain": "unverified-domain-99.org",
                "domain_risk": 35
            },
            "url_intelligence": {"url_risk": 20},
            "visual_phishing": {"verdict": "NOT_RUN", "confidence": 0},
            "payload_inspection": {"qr_detected": False, "attachment_present": False}
        }
    }
]
