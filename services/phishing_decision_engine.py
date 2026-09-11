"""
KEKAI Autonomous Brand Intelligence & Phishing Engine
Unified Organisational Phishing Decision Engine
==================================================================================
Consolidates evidence from Email Analysis, Sender Behavior Telemetry, Payload / QR
Inspection, Domain Intelligence, Visual Phishing / Logo Recognition, and Threat Feeds
into ONE authoritative organisational verdict.

Calculates independent metrics:
- risk_score (0-100): Threat severity & likelihood
- confidence (0-100): Certainty based on signal agreement & high-fidelity confirmations
- evidence_quality (0-100): Completeness of multi-stage evidence gathering
"""

import os
import json
import logging
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple

logger = logging.getLogger("kekai.phishing_decision_engine")

DECISION_VERSION = "v1.0-organisational-unified"


def extract_evidence_provenance(bundle: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], Dict[str, Any]]:
    """
    Extracts structured supporting and contradicting evidence items with provenance metadata.
    Returns: (supporting_evidence, contradicting_evidence, stage_results)
    """
    now_iso = datetime.now(timezone.utc).isoformat()

    supporting: List[Dict[str, Any]] = []
    contradicting: List[Dict[str, Any]] = []
    stage_results: Dict[str, Any] = {}

    # Stage 1: Email Threat Analysis
    email_data = bundle.get("email_analysis") or bundle.get("email") or {}
    if email_data:
        stage_results["email"] = {
            "risk_score": email_data.get("risk_score", 0),
            "severity": email_data.get("severity", "LOW"),
            "threat_type": email_data.get("threat_type", "benign")
        }

        signals = email_data.get("signals") or {}
        if signals.get("credential_request") or signals.get("credential_phishing_keywords"):
            supporting.append({
                "source": "email_content",
                "signal": "credential_phishing_keywords",
                "value": "Urgent authentication or credential harvesting keywords detected in text",
                "severity": 30,
                "confidence": 0.85,
                "timestamp": now_iso
            })
        if signals.get("urgency_language"):
            supporting.append({
                "source": "email_content",
                "signal": "urgency_language",
                "value": "Social engineering pressure language forcing immediate action",
                "severity": 20,
                "confidence": 0.80,
                "timestamp": now_iso
            })
        if signals.get("suspicious_link") or signals.get("suspicious_domain_mismatch"):
            supporting.append({
                "source": "email_content",
                "signal": "suspicious_domain_mismatch",
                "value": "Mismatch between displayed sender domain and body link destination",
                "severity": 25,
                "confidence": 0.90,
                "timestamp": now_iso
            })
        if signals.get("lookalike_domain_detected"):
            supporting.append({
                "source": "email_content",
                "signal": "lookalike_domain_detected",
                "value": "Extracted link leads to a registered typo-squatted brand domain",
                "severity": 30,
                "confidence": 0.90,
                "timestamp": now_iso
            })
        if signals.get("untrusted_tld"):
            supporting.append({
                "source": "email_content",
                "signal": "untrusted_tld",
                "value": "Link hosted on high-risk generic TLD",
                "severity": 15,
                "confidence": 0.75,
                "timestamp": now_iso
            })

    # Stage 2: Sender Behavior Telemetry
    sender_data = bundle.get("sender_behavior") or {}
    if sender_data:
        stage_results["sender_behavior"] = {
            "hypothesis": sender_data.get("hypothesis", "NO_BASELINE"),
            "anomaly_score": sender_data.get("anomaly_score", 0),
            "profile_available": sender_data.get("profile_available", False)
        }

        hypo = sender_data.get("hypothesis") or ""
        if "COMPROMISE" in hypo or hypo == "POSSIBLE_ACCOUNT_COMPROMISE":
            supporting.append({
                "source": "sender_behavior",
                "signal": "possible_account_compromise",
                "value": f"Internal account anomaly (score {sender_data.get('anomaly_score', 75)}/100): off-hours transmission to external recipient",
                "severity": 40,
                "confidence": 0.85,
                "timestamp": now_iso
            })
        elif hypo == "SUSPICIOUS_BEHAVIOR" or "ANOMALOUS" in hypo or "LOOKALIKE" in hypo or "NEW_DOMAIN" in hypo or "UNRECOGNIZED" in hypo or "REDIRECT" in hypo or "BRAND" in hypo or "ATTACHMENT" in hypo:
            supporting.append({
                "source": "sender_behavior",
                "signal": "suspicious_behavior",
                "value": f"Sender behavioral anomaly detected (score {sender_data.get('anomaly_score', 40)}/100)",
                "severity": 25,
                "confidence": 0.75,
                "timestamp": now_iso
            })
        elif hypo == "BENIGN_INTERNAL":
            contradicting.append({
                "source": "sender_behavior",
                "signal": "benign_internal_sender",
                "value": "Sender matches verified internal baseline profile with normal communication patterns",
                "severity": 0,
                "confidence": 0.90,
                "timestamp": now_iso
            })

    # Stage 3: Payload / Attachment / QR Inspection
    payload_data = bundle.get("payload_inspection") or bundle.get("payload") or {}
    if payload_data:
        stage_results["payload"] = {
            "risk_score": payload_data.get("risk_score", 0),
            "is_html_form": payload_data.get("is_html_form", False) or payload_data.get("html_form_detected", False),
            "qr_detected": bool(payload_data.get("qr_decoded_url") or payload_data.get("qr_detected"))
        }

        if payload_data.get("qr_decoded_url") or payload_data.get("qr_detected"):
            supporting.append({
                "source": "payload_inspection",
                "signal": "qr_code_credential_url",
                "value": f"Decoded QR code URL leading to external target: {payload_data.get('qr_decoded_url', 'QR payload')}",
                "severity": 45,
                "confidence": 0.95,
                "timestamp": now_iso
            })
        if payload_data.get("is_html_form") or payload_data.get("has_login_form") or payload_data.get("html_form_detected") or payload_data.get("password_input_detected"):
            supporting.append({
                "source": "payload_inspection",
                "signal": "attachment_credential_form",
                "value": "Attachment contains embedded HTML credential harvesting form",
                "severity": 45,
                "confidence": 0.95,
                "timestamp": now_iso
            })
        if payload_data.get("has_double_extension") or payload_data.get("suspicious_executable") or payload_data.get("suspicious_file_type"):
            supporting.append({
                "source": "payload_inspection",
                "signal": "malicious_attachment_format",
                "value": "Attachment exhibits suspicious double extension, executable signature, or malicious HTML script",
                "severity": 40,
                "confidence": 0.90,
                "timestamp": now_iso
            })

    # Stage 4: Domain Intelligence
    domain_data = bundle.get("domain_intelligence") or bundle.get("domain") or {}
    if domain_data:
        stage_results["domain"] = {
            "domain": domain_data.get("domain") or domain_data.get("candidate_domain", ""),
            "relationship": domain_data.get("relationship") or domain_data.get("domain_relationship", {}).get("relationship"),
            "lookalike": domain_data.get("lookalike", False) or domain_data.get("is_lookalike", False) or domain_data.get("typosquat_detected", False)
        }

        rel = domain_data.get("relationship") or domain_data.get("domain_relationship", {}).get("relationship")
        if rel in ["OFFICIAL_EXACT", "OFFICIAL_SUBDOMAIN"] or domain_data.get("is_official"):
            contradicting.append({
                "source": "domain_intelligence",
                "signal": "official_brand_domain",
                "value": f"Target domain ({domain_data.get('domain', 'official')}) matches verified official brand infrastructure",
                "severity": 0,
                "confidence": 1.0,
                "timestamp": now_iso
            })
        elif rel == "LOOKALIKE" or domain_data.get("lookalike") or domain_data.get("is_lookalike") or domain_data.get("typosquat_detected"):
            supporting.append({
                "source": "domain_intelligence",
                "signal": "lookalike_domain_permutation",
                "value": f"Domain {domain_data.get('domain')} is a registered typosquat lookalike permutation",
                "severity": 40,
                "confidence": 0.95,
                "timestamp": now_iso
            })

        rdap_age = domain_data.get("rdap_age_days") if domain_data.get("rdap_age_days") is not None else (domain_data.get("age_days") if domain_data.get("age_days") is not None else domain_data.get("registration_age_days"))
        if rdap_age is not None and rdap_age < 30:
            supporting.append({
                "source": "domain_intelligence",
                "signal": "newly_registered_domain",
                "value": f"Domain registered within last 30 days ({rdap_age} days old)",
                "severity": 20,
                "confidence": 0.85,
                "timestamp": now_iso
            })

    # Stage 5: Visual Phishing / Logo Recognition
    visual_data = bundle.get("visual_phishing") or bundle.get("visual") or {}
    if visual_data:
        stage_results["visual"] = {
            "verdict": visual_data.get("verdict", "BENIGN"),
            "target_brand": visual_data.get("target_brand", ""),
            "confidence": visual_data.get("confidence", 0)
        }

        if visual_data.get("verdict") == "Phishing" or visual_data.get("overall_status") == "CONFIRMED":
            target = visual_data.get("target_brand") or "Protected Corporate Brand"
            supporting.append({
                "source": "visual_phishing",
                "signal": "visual_brand_impersonation",
                "value": f"Confirmed visual logo and page layout clone matching protected brand '{target}'",
                "severity": 45,
                "confidence": float(visual_data.get("confidence") or 90) / 100.0,
                "timestamp": now_iso
            })

    # Stage 6: Threat Intelligence Feeds
    intel_data = bundle.get("threat_intelligence") or bundle.get("threat_intel") or {}
    if intel_data:
        openphish = intel_data.get("openphish") or {}
        phishtank = intel_data.get("phishtank") or {}
        stage_results["threat_intel"] = {
            "openphish_status": openphish.get("status", "NOT_CHECKED"),
            "phishtank_status": phishtank.get("status", "NOT_CHECKED")
        }

        if openphish.get("status") == "MATCH":
            supporting.append({
                "source": "threat_intelligence",
                "signal": "openphish_active_feed_match",
                "value": "Confirmed active malicious URL in global OpenPhish intelligence feed",
                "severity": 50,
                "confidence": 1.0,
                "timestamp": now_iso
            })
        if phishtank.get("status") == "MATCH":
            supporting.append({
                "source": "threat_intelligence",
                "signal": "phishtank_verified_database_match",
                "value": "Verified threat match in PhishTank community database",
                "severity": 50,
                "confidence": 1.0,
                "timestamp": now_iso
            })

    # Stage 7: Analyst & Organisational Feedback Signals
    feedback_data = bundle.get("analyst_feedback") or bundle.get("feedback") or {}
    if feedback_data:
        label = (feedback_data.get("analyst_label") or "").upper()
        if label in {"ANALYST_CONFIRMED_PHISHING", "CONFIRMED_PHISHING", "USER_REPORTED_PHISHING"}:
            supporting.append({
                "source": "analyst_feedback",
                "signal": "analyst_confirmed_phishing",
                "value": f"Verified decision '{label}' recorded for this investigation payload",
                "severity": 80,
                "confidence": 1.0,
                "timestamp": now_iso
            })
        elif label in {"ANALYST_FALSE_POSITIVE", "FALSE_POSITIVE", "USER_MARKED_SAFE", "ANALYST_CONFIRMED_BENIGN"}:
            contradicting.append({
                "source": "analyst_feedback",
                "signal": "analyst_false_positive_override",
                "value": f"Verified decision '{label}' marked investigation as legitimate false positive",
                "severity": 0,
                "confidence": 1.0,
                "timestamp": now_iso
            })

    # Stage 7b: Historical Organisational Feedback Adaptation (Evidence Sample Threshold >= 5)
    try:
        from database import fetch_all_analyst_feedback
        historical = fetch_all_analyst_feedback()
        if len(historical) >= 5:
            # Check if domain or sender hypothesis has strong historical consensus
            domain = bundle.get("domain_intelligence", {}).get("domain") or bundle.get("email_analysis", {}).get("extracted_domain") or ""
            domain_fp_count = 0
            domain_phish_count = 0
            for h in historical:
                h_feats = h.get("features", {}).get("features") if isinstance(h.get("features"), dict) and "features" in h["features"] else h.get("features", {})
                h_dom = h_feats.get("target_domain") if isinstance(h_feats, dict) else ""
                h_lbl = h.get("analyst_label")
                if domain and h_dom and domain.lower() == h_dom.lower():
                    if h_lbl in {"ANALYST_FALSE_POSITIVE", "FALSE_POSITIVE", "USER_MARKED_SAFE"}:
                        domain_fp_count += 1
                    elif h_lbl in {"ANALYST_CONFIRMED_PHISHING", "CONFIRMED_PHISHING", "USER_REPORTED_PHISHING"}:
                        domain_phish_count += 1

            if domain_fp_count >= 3 and domain_fp_count > domain_phish_count * 2:
                contradicting.append({
                    "source": "organisational_learning",
                    "signal": "organisational_false_positive_history",
                    "value": f"Domain '{domain}' has {domain_fp_count} historical false positive records across organization",
                    "severity": 0,
                    "confidence": 0.80,
                    "timestamp": now_iso
                })
            elif domain_phish_count >= 3 and domain_phish_count > domain_fp_count * 2:
                supporting.append({
                    "source": "organisational_learning",
                    "signal": "organisational_phishing_history",
                    "value": f"Domain '{domain}' has {domain_phish_count} historical confirmed phishing records across organization",
                    "severity": 25,
                    "confidence": 0.85,
                    "timestamp": now_iso
                })
    except Exception as ex:
        logger.debug(f"Historical feedback signal aggregation skipped: {ex}")

    # Stage 8: URL Intelligence & Redirect Chains
    url_intel_data = bundle.get("url_intelligence") or bundle.get("url_intel") or {}
    if url_intel_data:
        stage_results["url_intelligence"] = {
            "url_risk": url_intel_data.get("url_risk", 0),
            "final_url": url_intel_data.get("final_url", ""),
            "has_redirects": url_intel_data.get("redirect_signal", {}).get("has_redirects", False)
        }

        domain_age_sig = url_intel_data.get("domain_age_signal", {}).get("signal")
        if domain_age_sig == "VERY_NEW_DOMAIN":
            supporting.append({
                "source": "url_intelligence",
                "signal": "very_new_domain_registration",
                "value": f"Newly registered domain ({url_intel_data.get('domain_age_signal', {}).get('age_days', 0)} days old)",
                "severity": 30,
                "confidence": 0.90,
                "timestamp": now_iso
            })

        redirect_sig = url_intel_data.get("redirect_signal", {})
        if redirect_sig.get("has_redirects"):
            supporting.append({
                "source": "url_intelligence",
                "signal": "redirect_chain_detected",
                "value": f"Redirect chain of length {redirect_sig.get('chain_length', 1)} detected ending at {url_intel_data.get('final_url')}",
                "severity": 20,
                "confidence": 0.85,
                "timestamp": now_iso
            })

        cred_sig = url_intel_data.get("credential_page_signal", {})
        if cred_sig.get("is_credential_page"):
            supporting.append({
                "source": "url_intelligence",
                "signal": "redirect_chain_credential_landing",
                "value": "URL destination landing page exhibits static credential harvesting form indicators",
                "severity": 35,
                "confidence": 0.90,
                "timestamp": now_iso
            })

    return supporting, contradicting, stage_results


def determine_attack_hypothesis(
    bundle: Dict[str, Any],
    supporting: List[Dict[str, Any]],
    contradicting: List[Dict[str, Any]],
    risk_score: int
) -> str:
    """
    Determines the primary attack hypothesis based on deterministic signal correlation rules.
    """
    has_official_domain = any(item["signal"] == "official_brand_domain" for item in contradicting)
    has_analyst_fp = any(item["signal"] == "analyst_false_positive_override" for item in contradicting)
    has_benign_sender = any(item["signal"] == "benign_internal_sender" for item in contradicting)

    if has_official_domain or has_analyst_fp:
        return "BENIGN_INTERNAL" if has_benign_sender else "INCONCLUSIVE"

    signals_set = {item["signal"] for item in supporting}

    # 1. QR Phishing
    if "qr_code_credential_url" in signals_set:
        return "QR_PHISHING"

    # 2. Malicious Attachment
    if "attachment_credential_form" in signals_set or "malicious_attachment_format" in signals_set:
        return "MALICIOUS_ATTACHMENT"

    # 3. Account Compromise
    if "possible_account_compromise" in signals_set:
        return "POSSIBLE_ACCOUNT_COMPROMISE"

    # 4. Visual Brand Clone
    if "visual_brand_impersonation" in signals_set:
        return "VISUAL_BRAND_CLONE"

    # 5. External Impersonation / Lookalike Domain
    if "lookalike_domain_detected" in signals_set or "lookalike_domain_permutation" in signals_set:
        if "credential_phishing_keywords" in signals_set or "suspicious_domain_mismatch" in signals_set:
            return "EXTERNAL_IMPERSONATION"
        return "LOOKALIKE_DOMAIN"

    # 6. Credential Harvesting
    if "credential_phishing_keywords" in signals_set or "openphish_active_feed_match" in signals_set or "phishtank_verified_database_match" in signals_set:
        return "CREDENTIAL_HARVESTING"

    # 7. Suspicious Internal Behavior
    if "suspicious_behavior" in signals_set:
        return "SUSPICIOUS_INTERNAL_BEHAVIOR"

    if has_benign_sender and risk_score < 25:
        return "BENIGN_INTERNAL"

    if risk_score < 20 and len(supporting) == 0:
        return "INCONCLUSIVE"

    return "CREDENTIAL_HARVESTING" if risk_score >= 50 else "INCONCLUSIVE"


def calculate_independent_metrics(
    supporting: List[Dict[str, Any]],
    contradicting: List[Dict[str, Any]],
    stage_results: Dict[str, Any]
) -> Tuple[int, int, int]:
    """
    Calculates independent Risk Score, Confidence, and Evidence Quality.
    CRITICAL RULE: risk_score != confidence != evidence_quality
    """
    # 1. Calculate Risk Score (0 - 100)
    sum_severities = sum(item.get("severity", 0) for item in supporting)

    stage_max_risk = max(
        stage_results.get("email", {}).get("risk_score", 0),
        stage_results.get("payload", {}).get("risk_score", 0),
        stage_results.get("visual", {}).get("confidence", 0) if stage_results.get("visual", {}).get("verdict") == "Phishing" else 0,
        0
    )

    raw_risk_points = max(sum_severities, stage_max_risk)

    # Contradicting mitigations
    if any(item["signal"] == "official_brand_domain" for item in contradicting):
        raw_risk_points = 0
    elif any(item["signal"] == "analyst_false_positive_override" for item in contradicting):
        raw_risk_points = 0
    elif any(item["signal"] == "benign_internal_sender" for item in contradicting):
        raw_risk_points = max(0, raw_risk_points - 40)

    risk_score = min(100, max(0, int(raw_risk_points)))

    # 2. Calculate Evidence Quality Score (0 - 100)
    quality_points = 0
    if "email" in stage_results:
        quality_points += 15
    if "sender_behavior" in stage_results and stage_results["sender_behavior"].get("profile_available"):
        quality_points += 15
    if "payload" in stage_results:
        quality_points += 15
    if "domain" in stage_results and stage_results["domain"].get("domain"):
        quality_points += 20
    if "visual" in stage_results and stage_results["visual"].get("verdict") != "NOT_RUN":
        quality_points += 20
    if "threat_intel" in stage_results and stage_results["threat_intel"].get("openphish_status") != "NOT_CHECKED":
        quality_points += 15

    evidence_quality = min(100, quality_points)

    # 3. Calculate Confidence Score (0 - 100)
    base_confidence = 60.0

    # Source Agreement Bonus
    unique_sources = {item["source"] for item in supporting}
    if len(unique_sources) >= 3:
        base_confidence += 25
    elif len(unique_sources) >= 2:
        base_confidence += 15

    # High-Fidelity Confirmation Bonus
    high_fidelity_signals = {
        "openphish_active_feed_match",
        "phishtank_verified_database_match",
        "visual_brand_impersonation",
        "qr_code_credential_url",
        "attachment_credential_form",
        "analyst_confirmed_phishing",
        "official_brand_domain"
    }

    if any(item["signal"] in high_fidelity_signals for item in supporting + contradicting):
        base_confidence += 15

    # Conflict Penalty (Supporting AND Contradicting present)
    if supporting and contradicting:
        base_confidence -= 25

    # Sparse Evidence Penalty
    if evidence_quality < 40:
        base_confidence -= 20

    confidence = min(100, max(10, int(base_confidence)))

    return risk_score, confidence, evidence_quality


def evaluate_phishing_decision(evidence_bundle: Dict[str, Any]) -> Dict[str, Any]:
    """
    Main entry point for Unified Organisational Phishing Decision Engine.
    
    1. Extracts structured supporting/contradicting evidence with provenance.
    2. Calculates independent Risk Score, Confidence, and Evidence Quality.
    3. Determines primary attack hypothesis via deterministic correlation.
    4. Formulates final organizational verdict & recommended action.
    5. Calls AI Reasoning service for 1-pass explainable correlation.
    """
    supporting, contradicting, stage_results = extract_evidence_provenance(evidence_bundle)
    risk_score, confidence, evidence_quality = calculate_independent_metrics(supporting, contradicting, stage_results)

    # Verdict Classification
    if any(item["signal"] == "analyst_confirmed_phishing" for item in supporting):
        verdict = "MALICIOUS"
    elif any(item["signal"] == "analyst_false_positive_override" for item in contradicting):
        verdict = "BENIGN"
    elif any(item["signal"] == "official_brand_domain" for item in contradicting) and not any(item["severity"] >= 35 for item in supporting):
        verdict = "BENIGN"
    elif risk_score >= 70:
        verdict = "MALICIOUS"
    elif risk_score >= 35 or any(item["severity"] >= 35 for item in supporting):
        verdict = "SUSPICIOUS" if risk_score < 70 else "MALICIOUS"
    elif evidence_quality <= 55 and risk_score < 35 and not any(item["signal"] in ("official_brand_domain", "benign_internal_sender") for item in contradicting):
        verdict = "INCONCLUSIVE"
    else:
        verdict = "BENIGN"

    attack_hypothesis = determine_attack_hypothesis(evidence_bundle, supporting, contradicting, risk_score)

    # Primary Reasons Synthesis
    primary_reasons = [item["value"] for item in supporting[:4]]
    if not primary_reasons:
        if verdict == "BENIGN":
            primary_reasons.append("Email payload and domain infrastructure match baseline legitimate parameters.")
        else:
            primary_reasons.append("Sparse evidence gathered; no high-risk threat signals detected.")

    # Recommended Action
    if verdict == "MALICIOUS":
        recommended_action = "BLOCK_AND_QUARANTINE"
    elif verdict == "SUSPICIOUS":
        recommended_action = "ISOLATE_AND_INVESTIGATE" if risk_score >= 60 else "MONITOR_SENDER"
    elif verdict == "INCONCLUSIVE":
        recommended_action = "MONITOR_SENDER"
    else:
        recommended_action = "ALLOW"

    ai_input_payload = {
        "subject": evidence_bundle.get("email_analysis", {}).get("email", {}).get("subject") or evidence_bundle.get("subject", ""),
        "sender": evidence_bundle.get("email_analysis", {}).get("email", {}).get("sender") or evidence_bundle.get("sender", ""),
        "risk_score": risk_score,
        "severity": "CRITICAL" if risk_score >= 85 else "HIGH" if risk_score >= 65 else "MEDIUM" if risk_score >= 40 else "LOW",
        "threat_type": attack_hypothesis.lower(),
        "signals": {item["signal"]: True for item in supporting},
        "extracted_domains": [stage_results.get("domain", {}).get("domain")] if stage_results.get("domain", {}).get("domain") else [],
        "sender_behavior_hypothesis": attack_hypothesis
    }

    try:
        from services.ai_reasoning import analyze_evidence
        ai_eval = analyze_evidence(ai_input_payload)
    except Exception as ex:
        logger.warning(f"AI reasoning execution error caught: {ex}")
        ai_eval = {
            "ai_used": False,
            "reasoning_source": "deterministic_engine",
            "model": "deterministic",
            "summary": "Deterministic security decision applied.",
            "key_evidence": primary_reasons
        }

    return {
        "verdict": verdict,
        "risk_score": risk_score,
        "confidence": confidence,
        "evidence_quality": evidence_quality,
        "attack_hypothesis": attack_hypothesis,
        "primary_reasons": primary_reasons,
        "supporting_evidence": supporting,
        "contradicting_evidence": contradicting,
        "recommended_action": recommended_action,
        "stage_results": stage_results,
        "ai_reasoning": {
            "ai_used": ai_eval.get("ai_used", False),
            "reasoning_source": ai_eval.get("reasoning_source", "deterministic_engine"),
            "model": ai_eval.get("model", "deterministic"),
            "summary": ai_eval.get("summary", ""),
            "key_evidence": ai_eval.get("key_evidence", [])
        },
        "decision_version": DECISION_VERSION,
        "evaluated_at": datetime.now(timezone.utc).isoformat()
    }
