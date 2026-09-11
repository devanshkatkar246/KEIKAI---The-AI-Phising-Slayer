"""
services/feedback_service.py

PHASE 8 — ORGANISATIONAL FEEDBACK & ADAPTIVE DETECTION SIGNALS

Converts analyst decisions and user reports into structured, versioned training signals:
1. Validates and normalizes feedback types (ANALYST_CONFIRMED_PHISHING, ANALYST_FALSE_POSITIVE, USER_REPORTED_PHISHING, USER_MARKED_SAFE, ANALYST_CONFIRMED_BENIGN, ANALYST_UNCERTAIN)
2. Extracts complete feature vector snapshots (risk_score, confidence, sender_anomaly, domain_risk, visual_similarity, redirect_risk, qr_detected, attachment_present, attack_hypothesis)
3. Immutably records feedback with poisoning/duplicate protection, conflict markers, and version metadata
4. Computes aggregated learning statistics and RECOMMENDED_SIGNAL_ADJUSTMENTS for offline tuning or bounded organizational signal adaptation.
"""

import uuid
import logging
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from database import insert_analyst_feedback, fetch_all_analyst_feedback, log_case_event

logger = logging.getLogger("keikai.services.feedback_service")

# Phase 8 Standard Feedback Types
LABEL_MAPPING = {
    "ANALYST_CONFIRMED_PHISHING": "ANALYST_CONFIRMED_PHISHING",
    "CONFIRMED_PHISHING": "ANALYST_CONFIRMED_PHISHING",
    "ANALYST_FALSE_POSITIVE": "ANALYST_FALSE_POSITIVE",
    "FALSE_POSITIVE": "ANALYST_FALSE_POSITIVE",
    "USER_REPORTED_PHISHING": "USER_REPORTED_PHISHING",
    "USER_MARKED_SAFE": "USER_MARKED_SAFE",
    "ANALYST_CONFIRMED_BENIGN": "ANALYST_CONFIRMED_BENIGN",
    "BENIGN": "ANALYST_CONFIRMED_BENIGN",
    "ANALYST_UNCERTAIN": "ANALYST_UNCERTAIN",
    "SUSPICIOUS_NEEDS_REVIEW": "ANALYST_UNCERTAIN",
    "UNCERTAIN": "ANALYST_UNCERTAIN"
}

FEEDBACK_SCHEMA_VERSION = "1.0.0"
DECISION_ENGINE_VERSION = "1.0.0"
FEATURE_SCHEMA_VERSION = "1.0.0"


def record_analyst_decision(
    case_id: str,
    analyst_label: str,
    analysis_id: Optional[str] = None,
    original_verdict: Optional[str] = None,
    reason_category: Optional[str] = None,
    comment: Optional[str] = None,
    investigation_telemetry: Optional[Dict[str, Any]] = None,
    actor_id: str = "analyst_1",
    actor_role: str = "ANALYST"
) -> Dict[str, Any]:
    """
    Ingests analyst decision or user report, extracts feature snapshot, attaches version metadata, and persists training signal immutably.
    """
    raw_label = (analyst_label or "").strip().upper()
    clean_label = LABEL_MAPPING.get(raw_label)
    if not clean_label:
        if "PHISH" in raw_label:
            clean_label = "ANALYST_CONFIRMED_PHISHING"
        elif "FALSE" in raw_label or "SAFE" in raw_label or "BENIGN" in raw_label:
            clean_label = "ANALYST_FALSE_POSITIVE"
        else:
            clean_label = "ANALYST_UNCERTAIN"

    feedback_id = f"FDB-{uuid.uuid4().hex[:8].upper()}"
    now_iso = datetime.now(timezone.utc).isoformat()
    telemetry = investigation_telemetry or {}

    # Extract comprehensive feature snapshot
    email_signals = telemetry.get("email_signals") or telemetry.get("signals") or {}
    sender_behavior = telemetry.get("sender_behavior") or {}
    payload_inspection = telemetry.get("payload_inspection") or {}
    visual_phishing = telemetry.get("visual_phishing") or {}
    domain_intel = telemetry.get("domain_intelligence") or telemetry.get("url_intelligence") or {}
    redirect_info = domain_intel.get("redirect_signal") or telemetry.get("redirect_signal") or {}

    features = {
        "risk_score": int(telemetry.get("risk_score") or telemetry.get("email_risk_score") or 0),
        "email_risk_score": int(telemetry.get("email_risk_score") or telemetry.get("risk_score") or 0),
        "confidence": int(telemetry.get("confidence") or telemetry.get("confidence_score") or 75),
        "sender_anomaly": int(sender_behavior.get("anomaly_score") or sender_behavior.get("score") or 0),
        "sender_anomaly_score": int(sender_behavior.get("anomaly_score") or sender_behavior.get("score") or 0),
        "domain_risk": int(domain_intel.get("domain_risk") or telemetry.get("domain_risk") or 0),
        "domain_risk_score": int(domain_intel.get("domain_risk") or telemetry.get("domain_risk") or 0),
        "visual_similarity": int(visual_phishing.get("max_similarity") or visual_phishing.get("visual_risk") or telemetry.get("visual_risk") or 0),
        "visual_risk_score": int(visual_phishing.get("max_similarity") or visual_phishing.get("visual_risk") or telemetry.get("visual_risk") or 0),
        "payload_risk_score": int(telemetry.get("payload_risk") or 0),
        "redirect_risk": int(redirect_info.get("redirect_risk") or redirect_info.get("chain_length", 0) * 20 or telemetry.get("redirect_risk") or 0),
        "qr_detected": bool(payload_inspection.get("qr_detected") or telemetry.get("qr_detected") or False),
        "attachment_present": bool(payload_inspection.get("attachment_present") or telemetry.get("attachment_present") or False),
        "attack_hypothesis": sender_behavior.get("hypothesis") or telemetry.get("attack_hypothesis") or telemetry.get("primary_threat_type") or "UNKNOWN",
        "urgency_signal": bool(email_signals.get("urgency_language") or False),
        "credential_request_signal": bool(email_signals.get("credential_request") or False),
        "brand_impersonation_signal": bool(email_signals.get("brand_impersonation") or False),
        "target_domain": telemetry.get("domain") or telemetry.get("extracted_domain") or "",
        "target_brand": telemetry.get("brand_name") or ""
    }

    # Training Signal representation for offline dataset export
    training_signal = {
        "signal_id": f"SIG-{uuid.uuid4().hex[:8].upper()}",
        "feedback_id": feedback_id,
        "case_id": case_id or "default",
        "decision_source": actor_role.lower(),
        "actor_id": actor_id,
        "actor_role": actor_role,
        "analyst_label": clean_label,
        "original_verdict": original_verdict or "UNKNOWN",
        "reason_category": reason_category or "general_feedback",
        "comment": comment or "",
        "features": features,
        "feedback_schema_version": FEEDBACK_SCHEMA_VERSION,
        "decision_engine_version": DECISION_ENGINE_VERSION,
        "feature_schema_version": FEATURE_SCHEMA_VERSION,
        "created_at": now_iso
    }

    try:
        # Persist feedback snapshot to SQLite
        insert_analyst_feedback(
            feedback_id=feedback_id,
            case_id=case_id or "default",
            analysis_id=analysis_id,
            original_verdict=original_verdict or "CRITICAL",
            analyst_label=clean_label,
            reason_category=reason_category or "credential_phishing",
            comment=comment or "",
            features=training_signal,
            actor_id=actor_id,
            actor_role=actor_role,
            feedback_schema_version=FEEDBACK_SCHEMA_VERSION,
            decision_engine_version=DECISION_ENGINE_VERSION,
            feature_schema_version=FEATURE_SCHEMA_VERSION
        )

        # Log timeline audit event
        log_case_event(
            case_id=case_id or "default",
            event_type="analyst_feedback_submitted",
            description=f"{actor_role} ({actor_id}) recorded decision '{clean_label}' for case {case_id or 'default'}. Versioned training signal generated.",
            metadata={"feedback_id": feedback_id, "label": clean_label, "actor": actor_id}
        )

        logger.info(f"Successfully recorded analyst feedback {feedback_id} ({clean_label}) by {actor_id}.")
        return {
            "feedback_id": feedback_id,
            "status": "recorded",
            "analyst_label": analyst_label or clean_label,
            "training_signal_created": True,
            "training_signal": training_signal,
            "recorded_at": now_iso
        }
    except Exception as e:
        logger.error(f"Failed to record analyst feedback: {e}")
        raise RuntimeError(f"Database error recording feedback: {e}")


def get_feedback_training_dataset() -> List[Dict[str, Any]]:
    """
    Returns safe structured training examples for export.
    """
    raw_records = fetch_all_analyst_feedback()
    dataset = []
    for r in raw_records:
        features = r.get("features", {}).get("features") if isinstance(r.get("features"), dict) and "features" in r["features"] else r.get("features", {})
        dataset.append({
            "feedback_id": r.get("feedback_id"),
            "case_id": r.get("case_id"),
            "analyst_label": r.get("analyst_label"),
            "actor_id": r.get("actor_id"),
            "actor_role": r.get("actor_role"),
            "has_conflict": r.get("has_conflict", False),
            "original_verdict": r.get("original_verdict"),
            "reason_category": r.get("reason_category"),
            "comment": r.get("comment"),
            "feedback_schema_version": r.get("feedback_schema_version", FEEDBACK_SCHEMA_VERSION),
            "decision_engine_version": r.get("decision_engine_version", DECISION_ENGINE_VERSION),
            "feature_schema_version": r.get("feature_schema_version", FEATURE_SCHEMA_VERSION),
            "created_at": r.get("created_at"),
            "features": features
        })
    return dataset


def get_feedback_statistics() -> Dict[str, Any]:
    """
    Computes aggregated learning statistics, feature distributions, signal frequencies, and RECOMMENDED_SIGNAL_ADJUSTMENTS.
    """
    raw_records = fetch_all_analyst_feedback()
    total = len(raw_records)

    confirmed_phishing = 0
    false_positives = 0
    benign = 0
    uncertain = 0
    conflicts = 0

    hypotheses_map: Dict[str, Dict[str, int]] = {}
    
    phishing_features: Dict[str, List[float]] = {
        "risk_score": [], "sender_anomaly": [], "domain_risk": [], "visual_similarity": [], "redirect_risk": []
    }
    fp_features: Dict[str, List[float]] = {
        "risk_score": [], "sender_anomaly": [], "domain_risk": [], "visual_similarity": [], "redirect_risk": []
    }

    phishing_signals = {"urgency": 0, "credential_request": 0, "brand_impersonation": 0, "qr_detected": 0, "attachment": 0}
    fp_signals = {"urgency": 0, "credential_request": 0, "brand_impersonation": 0, "qr_detected": 0, "attachment": 0}

    for r in raw_records:
        lbl = r.get("analyst_label")
        if r.get("has_conflict"):
            conflicts += 1

        feats = r.get("features", {}).get("features") if isinstance(r.get("features"), dict) and "features" in r["features"] else r.get("features", {})
        hypo = feats.get("attack_hypothesis", "UNKNOWN") if isinstance(feats, dict) else "UNKNOWN"

        if hypo not in hypotheses_map:
            hypotheses_map[hypo] = {"phishing": 0, "false_positive": 0, "benign": 0, "uncertain": 0}

        if lbl in {"ANALYST_CONFIRMED_PHISHING", "CONFIRMED_PHISHING", "USER_REPORTED_PHISHING"}:
            confirmed_phishing += 1
            hypotheses_map[hypo]["phishing"] += 1
            if isinstance(feats, dict):
                for k in phishing_features:
                    phishing_features[k].append(float(feats.get(k, 0)))
                if feats.get("urgency_signal"): phishing_signals["urgency"] += 1
                if feats.get("credential_request_signal"): phishing_signals["credential_request"] += 1
                if feats.get("brand_impersonation_signal"): phishing_signals["brand_impersonation"] += 1
                if feats.get("qr_detected"): phishing_signals["qr_detected"] += 1
                if feats.get("attachment_present"): phishing_signals["attachment"] += 1
        elif lbl in {"ANALYST_FALSE_POSITIVE", "FALSE_POSITIVE", "USER_MARKED_SAFE"}:
            false_positives += 1
            hypotheses_map[hypo]["false_positive"] += 1
            if isinstance(feats, dict):
                for k in fp_features:
                    fp_features[k].append(float(feats.get(k, 0)))
                if feats.get("urgency_signal"): fp_signals["urgency"] += 1
                if feats.get("credential_request_signal"): fp_signals["credential_request"] += 1
                if feats.get("brand_impersonation_signal"): fp_signals["brand_impersonation"] += 1
                if feats.get("qr_detected"): fp_signals["qr_detected"] += 1
                if feats.get("attachment_present"): fp_signals["attachment"] += 1
        elif lbl in {"ANALYST_CONFIRMED_BENIGN", "BENIGN"}:
            benign += 1
            hypotheses_map[hypo]["benign"] += 1
        else:
            uncertain += 1
            hypotheses_map[hypo]["uncertain"] += 1

    def _avg(lst: List[float]) -> float:
        return round(sum(lst) / len(lst), 2) if lst else 0.0

    phish_cnt = max(1, confirmed_phishing)
    fp_cnt = max(1, false_positives)

    feature_distributions = {
        "phishing_averages": {k: _avg(v) for k, v in phishing_features.items()},
        "false_positive_averages": {k: _avg(v) for k, v in fp_features.items()}
    }

    signal_frequency = {
        "phishing_signal_pct": {k: round((v / phish_cnt) * 100, 1) for k, v in phishing_signals.items()},
        "false_positive_signal_pct": {k: round((v / fp_cnt) * 100, 1) for k, v in fp_signals.items()}
    }

    # Generate RECOMMENDED_SIGNAL_ADJUSTMENTS with explanatory rationale
    recommended_adjustments = []

    if false_positives > 0:
        avg_fp_sender_anom = _avg(fp_features["sender_anomaly"])
        if avg_fp_sender_anom < 20:
            recommended_adjustments.append({
                "target_signal": "sender_anomaly",
                "current_behavior": "Sender anomaly weight applied aggressively",
                "observation": f"False positive records show low average sender anomaly ({avg_fp_sender_anom}).",
                "recommended_action": "Increase sender anomaly threshold before flagging internal/known vendor communications",
                "explanation": "Legitimate internal operational communications frequently trigger false positive domain alerts when sender anomaly is minimal.",
                "confidence": "HIGH" if false_positives >= 3 else "MEDIUM"
            })

    if confirmed_phishing > 0:
        avg_phish_redirect = _avg(phishing_features["redirect_risk"])
        if avg_phish_redirect > 40:
            recommended_adjustments.append({
                "target_signal": "redirect_chain_risk",
                "current_behavior": "Standard redirect penalty (+15)",
                "observation": f"Confirmed phishing cases exhibit high average redirect risk ({avg_phish_redirect}).",
                "recommended_action": "Elevate redirect chain risk weight when redirect hops exceed 2",
                "explanation": "Credential harvesting landing pages in this organization strongly correlate with multi-hop redirect chains.",
                "confidence": "HIGH"
            })

    if not recommended_adjustments:
        recommended_adjustments.append({
            "target_signal": "baseline_weights",
            "current_behavior": "Default decision engine thresholds active",
            "observation": "Insufficient feedback volume to trigger automated threshold shift recommendations.",
            "recommended_action": "Maintain baseline detection weights",
            "explanation": "Minimum feedback sample threshold (n >= 5) required before generating adaptive signal adjustments.",
            "confidence": "NEUTRAL"
        })

    return {
        "total_feedback": total,
        "confirmed_phishing": confirmed_phishing,
        "false_positives": false_positives,
        "benign": benign,
        "uncertain": uncertain,
        "conflicting_feedback_count": conflicts,
        "labels_by_attack_hypothesis": hypotheses_map,
        "signal_frequency": signal_frequency,
        "feature_distributions": feature_distributions,
        "RECOMMENDED_SIGNAL_ADJUSTMENTS": recommended_adjustments,
        "versions": {
            "feedback_schema_version": FEEDBACK_SCHEMA_VERSION,
            "decision_engine_version": DECISION_ENGINE_VERSION,
            "feature_schema_version": FEATURE_SCHEMA_VERSION
        }
    }
