"""
KEKAI Autonomous Brand Intelligence & Phishing Engine
Pre-Interaction Organisation Policy & Enforcement Engine
==================================================================================
Evaluates unified decision engine verdicts against configurable organisation policies
BEFORE a user interacts with a message. Determines policy enforcement actions:
ALLOW, WARN, QUARANTINE, BLOCK, or ANALYST_REVIEW.

Generates immutable audit event logs for compliance and SOC tracking.
Supports auditable analyst manual overrides.
"""

import uuid
import logging
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field

logger = logging.getLogger("kekai.policy_engine")

# In-Memory Audit Event Log Store
_AUDIT_LOG_STORE: Dict[str, Dict[str, Any]] = {}

# Default Organisation Policy Configurations
DEFAULT_ORGANISATION_POLICIES: Dict[str, Dict[str, Any]] = {
    "default": {
        "organisation_id": "default",
        "high_risk_threshold": 75,
        "medium_risk_threshold": 40,
        "require_high_confidence_for_block": True,
        "auto_block_enabled": True,
        "quarantine_enabled": True,
        "analyst_review_on_low_quality": True,
        "min_quality_threshold": 35
    },
    "org_acme_01": {
        "organisation_id": "org_acme_01",
        "high_risk_threshold": 75,
        "medium_risk_threshold": 40,
        "require_high_confidence_for_block": True,
        "auto_block_enabled": True,
        "quarantine_enabled": True,
        "analyst_review_on_low_quality": True,
        "min_quality_threshold": 35
    }
}


def get_organisation_policy(org_id: str) -> Dict[str, Any]:
    """Retrieves policy configuration for an organisation, falling back to default."""
    return DEFAULT_ORGANISATION_POLICIES.get(org_id, DEFAULT_ORGANISATION_POLICIES["default"]).copy()


def set_organisation_policy(org_id: str, policy_config: Dict[str, Any]) -> Dict[str, Any]:
    """Sets or updates policy configuration for a specific organisation."""
    existing = get_organisation_policy(org_id)
    existing.update(policy_config)
    existing["organisation_id"] = org_id
    DEFAULT_ORGANISATION_POLICIES[org_id] = existing
    return existing


def evaluate_message_policy(
    message: Any,
    decision_verdict: Dict[str, Any],
    policy_override: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Evaluates unified decision engine verdict against organisation policy configuration.
    
    Returns structured pre-interaction policy decision & action:
    - action: BLOCK | QUARANTINE | ANALYST_REVIEW | WARN | ALLOW
    - audit_id: unique audit event identifier
    """
    if isinstance(message, dict):
        msg_id = message.get("message_id") or f"MSG-{uuid.uuid4().hex[:10].upper()}"
        org_id = message.get("organisation_id", "org_acme_01")
    elif hasattr(message, "message_id"):
        msg_id = getattr(message, "message_id")
        org_id = getattr(message, "organisation_id", "org_acme_01")
    else:
        msg_id = str(message)
        org_id = "org_acme_01"
    now_iso = datetime.now(timezone.utc).isoformat()

    policy = get_organisation_policy(org_id)

    # 1. Check for Analyst Manual Override
    if policy_override and policy_override.get("override_action"):
        action = policy_override["override_action"].upper()
        audit_id = f"AUD-{uuid.uuid4().hex[:10].upper()}"
        reasons = [f"SOC Analyst Manual Override: {policy_override.get('rationale', 'No rationale provided')} (Analyst: {policy_override.get('analyst_id', 'unknown')})"]

        audit_record = {
            "audit_id": audit_id,
            "message_id": msg_id,
            "organisation_id": org_id,
            "decision": action,
            "action": action,
            "risk_score": decision_verdict.get("risk_score", 0),
            "confidence": decision_verdict.get("confidence", 0),
            "evidence_quality": decision_verdict.get("evidence_quality", 0),
            "attack_hypothesis": decision_verdict.get("attack_hypothesis", "MANUAL_OVERRIDE"),
            "policy_used": policy,
            "evidence_summary": decision_verdict.get("primary_reasons", []),
            "reasons": reasons,
            "ai_used": decision_verdict.get("ai_reasoning", {}).get("ai_used", False),
            "ai_provider": decision_verdict.get("ai_reasoning", {}).get("reasoning_source", "deterministic_engine"),
            "override": {
                "is_override": True,
                "analyst_id": policy_override.get("analyst_id", "unknown"),
                "override_action": action,
                "rationale": policy_override.get("rationale", "")
            },
            "timestamp": now_iso,
            "enforcement_mode": "SIMULATED_POLICY_DECISION"
        }

        _AUDIT_LOG_STORE[audit_id] = audit_record
        _AUDIT_LOG_STORE[msg_id] = audit_record
        return audit_record

    # 2. Automated Policy Evaluation
    risk_score = decision_verdict.get("risk_score", 0)
    confidence = decision_verdict.get("confidence", 0)
    evidence_quality = decision_verdict.get("evidence_quality", 0)
    verdict = decision_verdict.get("verdict", "BENIGN")
    hypothesis = decision_verdict.get("attack_hypothesis", "INCONCLUSIVE")

    high_thresh = policy.get("high_risk_threshold", 75)
    med_thresh = policy.get("medium_risk_threshold", 40)
    require_high_conf = policy.get("require_high_confidence_for_block", True)
    min_quality = policy.get("min_quality_threshold", 35)

    reasons = []

    # Rule A: High Risk + Low Quality -> Analyst Review (Uncertainty rule)
    if risk_score >= high_thresh and evidence_quality < min_quality and policy.get("analyst_review_on_low_quality", True):
        action = "ANALYST_REVIEW"
        reasons.append(f"High risk score ({risk_score}/100) detected with insufficient evidence quality ({evidence_quality}/100 < {min_quality}). Escalated to SOC Analyst Review.")

    # Rule B: High Risk (Block vs Quarantine)
    elif risk_score >= high_thresh or verdict == "MALICIOUS":
        if require_high_conf and confidence < 70:
            action = "QUARANTINE"
            reasons.append(f"High risk threat ({risk_score}/100) with moderate confidence ({confidence}%). Quarantined for analyst verification.")
        elif hypothesis == "CREDENTIAL_HARVESTING" and policy.get("auto_block_enabled", True):
            action = "BLOCK"
            reasons.append("High risk credential harvesting threat auto-blocked prior to user inbox delivery.")
        elif policy.get("quarantine_enabled", True):
            action = "QUARANTINE"
            reasons.append(f"High risk threat ({risk_score}/100) quarantined per organisation policy.")
        else:
            action = "BLOCK"
            reasons.append("High risk threat blocked per policy.")

    # Rule C: Medium Risk (Warn vs Analyst Review)
    elif risk_score >= med_thresh or verdict == "SUSPICIOUS":
        if confidence < 50:
            action = "ANALYST_REVIEW"
            reasons.append(f"Medium risk score ({risk_score}/100) with low confidence ({confidence}%). Routed for analyst review.")
        else:
            action = "WARN"
            reasons.append(f"Medium risk score ({risk_score}/100) detected. Message delivered with prominent security warning banner.")

    # Rule D: Low Risk / Benign -> Allow
    else:
        action = "ALLOW"
        reasons.append("Message content and sender baseline match legitimate parameters. Permitted into recipient inbox.")

    audit_id = f"AUD-{uuid.uuid4().hex[:10].upper()}"
    audit_record = {
        "audit_id": audit_id,
        "message_id": msg_id,
        "organisation_id": org_id,
        "decision": action,
        "action": action,
        "risk_score": risk_score,
        "confidence": confidence,
        "evidence_quality": evidence_quality,
        "attack_hypothesis": hypothesis,
        "policy_used": policy,
        "evidence_summary": decision_verdict.get("primary_reasons", []),
        "reasons": reasons,
        "ai_used": decision_verdict.get("ai_reasoning", {}).get("ai_used", False),
        "ai_provider": decision_verdict.get("ai_reasoning", {}).get("reasoning_source", "deterministic_engine"),
        "override": {"is_override": False},
        "timestamp": now_iso,
        "enforcement_mode": "SIMULATED_POLICY_DECISION"
    }

    _AUDIT_LOG_STORE[audit_id] = audit_record
    _AUDIT_LOG_STORE[msg_id] = audit_record
    return audit_record


def get_audit_record(audit_or_message_id: str) -> Optional[Dict[str, Any]]:
    """Retrieves an audit event record by audit_id or message_id."""
    return _AUDIT_LOG_STORE.get(audit_or_message_id)


def list_audit_records(organisation_id: Optional[str] = None, limit: int = 50) -> List[Dict[str, Any]]:
    """Lists audit event records, optionally filtered by organisation_id."""
    records = list(_AUDIT_LOG_STORE.values())
    if organisation_id:
        records = [r for r in records if r.get("organisation_id") == organisation_id]
    # Filter unique audit_ids
    seen = set()
    unique_records = []
    for r in reversed(records):
        aid = r.get("audit_id")
        if aid and aid not in seen:
            seen.add(aid)
            unique_records.append(r)
    return unique_records[:limit]
