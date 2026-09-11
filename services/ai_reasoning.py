"""
KEKAI Autonomous Brand Intelligence & Phishing Engine
Provider-Agnostic AI Reasoning Service (OpenRouter Primary + Deterministic Fallback)
==================================================================================
Provides explainable AI reasoning for security evidence correlation without altering
authoritative deterministic risk scores or threat verdicts.
"""

import os
import json
import logging
import hashlib
import urllib.request
import urllib.error
from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional

logger = logging.getLogger("kekai.ai_reasoning")

# Global Telemetry Counters
AI_TELEMETRY = {
    "requests_total": 0,
    "cache_hits": 0,
    "fallbacks": 0,
    "rate_limits": 0
}

# In-Memory Evidence Reasoning Cache
_REASONING_CACHE: Dict[str, Dict[str, Any]] = {}


def get_ai_telemetry() -> Dict[str, int]:
    """Returns current AI request and cache telemetry metrics."""
    return dict(AI_TELEMETRY)


def reset_ai_telemetry() -> None:
    """Resets AI telemetry counters and clears reasoning cache (used in tests)."""
    global AI_TELEMETRY, _REASONING_CACHE
    AI_TELEMETRY = {
        "requests_total": 0,
        "cache_hits": 0,
        "fallbacks": 0,
        "rate_limits": 0
    }
    _REASONING_CACHE.clear()


def calculate_evidence_fingerprint(evidence: Dict[str, Any]) -> str:
    """
    Computes a deterministic SHA-256 fingerprint for a given evidence payload.
    Ensures identical evidence across renders/investigations reuses cached reasoning.
    """
    try:
        # Create a normalized version filtering transient runtime keys
        normalized = {
            "subject": evidence.get("subject", ""),
            "sender": evidence.get("sender", ""),
            "body_snippet": (evidence.get("body_snippet") or evidence.get("body") or "")[:500],
            "signals": evidence.get("signals", {}),
            "risk_score": evidence.get("risk_score", 0),
            "severity": evidence.get("severity", ""),
            "threat_type": evidence.get("threat_type", ""),
            "extracted_domains": sorted(evidence.get("extracted_domains") or evidence.get("iocs", {}).get("domains", [])),
            "extracted_urls": sorted(evidence.get("extracted_urls") or evidence.get("iocs", {}).get("urls", [])),
            "sender_behavior_hypothesis": evidence.get("sender_behavior_hypothesis") or (evidence.get("sender_behavior", {}).get("hypothesis") if isinstance(evidence.get("sender_behavior"), dict) else None)
        }
        raw_bytes = json.dumps(normalized, sort_keys=True, default=str).encode('utf-8')
        return hashlib.sha256(raw_bytes).hexdigest()
    except Exception as e:
        logger.warning(f"Error computing evidence fingerprint: {e}")
        return hashlib.sha256(str(evidence).encode('utf-8')).hexdigest()


class AIProvider(ABC):
    @abstractmethod
    def analyze(self, evidence: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        pass


class OpenRouterProvider(AIProvider):
    """
    Primary AI Provider using OpenRouter API (OpenAI chat completions compatible).
    Defaults to 'openrouter/free' router for zero cost, configurable via OPENROUTER_MODEL.
    """

    def __init__(self):
        self.api_key = (os.getenv("OPENROUTER_API_KEY") or "").strip()
        self.model = (os.getenv("OPENROUTER_MODEL") or "openrouter/free").strip()
        try:
            self.timeout = int(os.getenv("OPENROUTER_TIMEOUT_SECONDS", "15"))
        except ValueError:
            self.timeout = 15

    def is_configured(self) -> bool:
        if not self.api_key:
            return False
        placeholder_keywords = ["your_", "placeholder", "xxx", "api_key_here"]
        if any(p in self.api_key.lower() for p in placeholder_keywords):
            return False
        return True

    def analyze(self, evidence: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if not self.is_configured():
            logger.info("OpenRouter API key not configured or using placeholder. Using deterministic reasoning.")
            return None

        url = "https://openrouter.ai/api/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://kekai.security",
            "X-Title": "KEKAI Autonomous Brand Intelligence"
        }

        # Build clean structured evidence prompt (omitting raw attachments or heavy bodies)
        prompt_data = {
            "subject": evidence.get("subject", ""),
            "sender": evidence.get("sender", ""),
            "body_snippet": (evidence.get("body_snippet") or evidence.get("body") or "")[:500],
            "signals": evidence.get("signals", {}),
            "risk_score": evidence.get("risk_score", 0),
            "severity": evidence.get("severity", ""),
            "threat_type": evidence.get("threat_type", ""),
            "domains": evidence.get("extracted_domains") or evidence.get("iocs", {}).get("domains", []),
            "urls": evidence.get("extracted_urls") or evidence.get("iocs", {}).get("urls", []),
            "sender_behavior_hypothesis": evidence.get("sender_behavior_hypothesis") or (evidence.get("sender_behavior", {}).get("hypothesis") if isinstance(evidence.get("sender_behavior"), dict) else None)
        }

        user_prompt = (
            "Analyze the following structured email security evidence:\n"
            f"{json.dumps(prompt_data, indent=2)}\n\n"
            "Return a strictly valid JSON object ONLY with no surrounding commentary or markdown headers, matching this structure:\n"
            "{\n"
            '  "attack_hypothesis": "1-sentence description of the attack vector",\n'
            '  "summary": "1-2 sentence executive summary of security findings",\n'
            '  "key_evidence": [\n'
            '    "Bullet point 1 detailing specific signal or anomaly",\n'
            '    "Bullet point 2 detailing domain, sender, or payload risk",\n'
            '    "Bullet point 3 providing security analyst recommendation"\n'
            '  ],\n'
            '  "reasoning_confidence": 0.85\n'
            "}"
        )

        payload = {
            "model": self.model,
            "temperature": 0.1,
            "messages": [
                {
                    "role": "system",
                    "content": "You are KEKAI's security reasoning engine. Analyze structured security evidence and explain why this email is or is not suspicious. You MUST respond with ONLY a valid JSON object matching the requested schema. Do NOT invent new factual evidence like domains or threat feeds not present in the input."
                },
                {
                    "role": "user",
                    "content": user_prompt
                }
            ]
        }

        req_body = json.dumps(payload).encode('utf-8')

        # Retry once max if safe
        max_attempts = 2
        for attempt in range(1, max_attempts + 1):
            try:
                req = urllib.request.Request(url, data=req_body, headers=headers, method="POST")
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    resp_bytes = resp.read()
                    data = json.loads(resp_bytes.decode('utf-8'))

                    # Extract content text
                    choices = data.get("choices", [])
                    if not choices:
                        logger.warning("OpenRouter API returned empty choices array.")
                        return None

                    content_text = choices[0].get("message", {}).get("content", "").strip()

                    # Sanitize JSON if wrapped in markdown codeblocks
                    if content_text.startswith("```"):
                        lines = content_text.splitlines()
                        if lines[0].startswith("```"):
                            lines = lines[1:]
                        if lines and lines[-1].startswith("```"):
                            lines = lines[:-1]
                        content_text = "\n".join(lines).strip()

                    parsed = json.loads(content_text)

                    # Validate required fields
                    reasoning_list = parsed.get("key_evidence") or parsed.get("reasoning") or []
                    if not isinstance(reasoning_list, list) or len(reasoning_list) == 0:
                        logger.warning("OpenRouter response missing valid key_evidence array.")
                        return None

                    attack_hypo = str(parsed.get("attack_hypothesis") or parsed.get("summary") or "Security signal correlation")
                    summary_text = str(parsed.get("summary") or attack_hypo)
                    conf_val = float(parsed.get("reasoning_confidence") or parsed.get("confidence") or 0.85)

                    returned_model = data.get("model") or self.model

                    return {
                        "ai_used": True,
                        "reasoning_source": "openrouter",
                        "model": returned_model,
                        "attack_hypothesis": attack_hypo,
                        "summary": summary_text,
                        "key_evidence": reasoning_list,
                        "reasoning": reasoning_list,
                        "confidence": conf_val
                    }

            except urllib.error.HTTPError as http_err:
                code = http_err.code
                if code == 429:
                    AI_TELEMETRY["rate_limits"] += 1
                    logger.warning("OpenRouter returned HTTP 429 (Rate Limit Exceeded). Falling back to deterministic engine immediately.")
                    return None
                elif code in (401, 403):
                    logger.warning(f"OpenRouter authentication error HTTP {code}. Check OPENROUTER_API_KEY.")
                    return None
                else:
                    logger.warning(f"OpenRouter HTTP error {code} on attempt {attempt}: {http_err.reason}")
                    if attempt == max_attempts:
                        return None
            except Exception as err:
                logger.warning(f"OpenRouter call error on attempt {attempt}: {err}")
                if attempt == max_attempts:
                    return None

        return None


class GeminiProvider(AIProvider):
    """
    Optional Legacy Gemini Provider. Used ONLY if explicitly configured via AI_PROVIDER=gemini.
    """

    def __init__(self):
        self.api_key = (os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY") or "").strip()

    def is_configured(self) -> bool:
        if not self.api_key or "your_" in self.api_key.lower() or "placeholder" in self.api_key.lower():
            return False
        return True

    def analyze(self, evidence: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if not self.is_configured():
            return None
        # Lightweight wrapper around legacy Gemini REST endpoint
        models = ["gemini-2.5-flash-lite", "gemini-1.5-flash"]
        prompt_text = f"Analyze email evidence: {json.dumps(evidence)}. Return JSON with key_evidence array, summary, attack_hypothesis."
        payload = {
            "contents": [{"parts": [{"text": prompt_text}]}],
            "generationConfig": {"temperature": 0.2, "responseMimeType": "application/json"}
        }
        for m in models:
            try:
                url = f"https://generativelanguage.googleapis.com/v1beta/models/{m}:generateContent?key={self.api_key}"
                req = urllib.request.Request(url, data=json.dumps(payload).encode('utf-8'), headers={'Content-Type': 'application/json'})
                with urllib.request.urlopen(req, timeout=10) as resp:
                    res_data = json.loads(resp.read().decode('utf-8'))
                    text_content = res_data['candidates'][0]['content']['parts'][0]['text']
                    parsed = json.loads(text_content)
                    return {
                        "ai_used": True,
                        "reasoning_source": "gemini",
                        "model": m,
                        "attack_hypothesis": parsed.get("attack_hypothesis", "Gemini Reasoning"),
                        "summary": parsed.get("summary", ""),
                        "key_evidence": parsed.get("key_evidence", parsed.get("reasoning", [])),
                        "reasoning": parsed.get("key_evidence", parsed.get("reasoning", [])),
                        "confidence": float(parsed.get("confidence", 0.85))
                    }
            except Exception as e:
                logger.debug(f"Gemini legacy call failed: {e}")
        return None


def generate_deterministic_reasoning(evidence: Dict[str, Any]) -> Dict[str, Any]:
    """
    Authoritative deterministic reasoning fallback.
    Generates explainable bullet points based strictly on verified security signals.
    """
    signals = evidence.get("signals") or {}
    evidence_list = evidence.get("signal_evidence") or evidence.get("evidence") or []
    iocs = evidence.get("iocs") or {}
    risk_score = evidence.get("risk_score", 0)
    severity = evidence.get("severity", "LOW")
    threat_type = evidence.get("threat_type", "benign")

    reasoning_bullets = []

    # Process explicit evidence items if provided
    if isinstance(evidence_list, list):
        for item in evidence_list:
            if isinstance(item, dict) and "description" in item:
                desc = item["description"]
                if desc not in reasoning_bullets:
                    reasoning_bullets.append(desc)

    # Signal-based reasoning synthesis
    if signals.get("credential_phishing_keywords"):
        reasoning_bullets.append("Email text contains urgent credential harvesting language and sensitive action triggers.")
    if signals.get("suspicious_domain_mismatch"):
        reasoning_bullets.append("Mismatch detected between sender envelope domain and destination body link domains.")
    if signals.get("lookalike_domain_detected"):
        reasoning_bullets.append("Extracted domain matches registered typo-squatted / lookalike brand pattern.")
    if signals.get("off_hours_transmission"):
        reasoning_bullets.append("Email dispatched outside baseline organizational operating hours.")
    if signals.get("urgent_call_to_action"):
        reasoning_bullets.append("High urgency language urging immediate account verification to avoid suspension.")
    if signals.get("untrusted_tld"):
        reasoning_bullets.append("Destination link hosted on high-risk generic TLD associated with phishing campaigns.")

    sender_behavior = evidence.get("sender_behavior") or {}
    if isinstance(sender_behavior, dict) and sender_behavior.get("profile_available"):
        hypo = sender_behavior.get("hypothesis")
        if hypo == "POSSIBLE_ACCOUNT_COMPROMISE":
            reasoning_bullets.insert(0, "Sender Behaviour: Internal account exhibiting severe off-hours and external recipient anomalies (Possible Account Compromise).")
        elif hypo == "SUSPICIOUS_BEHAVIOR":
            reasoning_bullets.insert(0, f"Sender Behaviour: {sender_behavior.get('explanation', ['Anomaly detected'])[0]}")

    if not reasoning_bullets:
        if risk_score < 30:
            reasoning_bullets.append("Email content and sender metadata match standard internal/trusted communication baselines.")
        else:
            reasoning_bullets.append(f"Heuristic risk score elevated ({risk_score}/100) based on cumulative signal analysis.")

    return {
        "ai_used": False,
        "reasoning_source": "DETERMINISTIC_FALLBACK",
        "model": "deterministic",
        "attack_hypothesis": threat_type.replace("_", " ").title(),
        "summary": f"Deterministic security analysis calculated risk score {risk_score}/100 ({severity}).",
        "key_evidence": reasoning_bullets,
        "reasoning": reasoning_bullets,
        "confidence": 0.85 if risk_score > 50 else 0.95
    }


def analyze_evidence(evidence: Dict[str, Any]) -> Dict[str, Any]:
    """
    Main entry point for AI reasoning correlation.
    
    1. Computes evidence fingerprint.
    2. Checks in-memory reasoning cache.
    3. If miss, attempts OpenRouter provider.
    4. On failure or 429, falls back seamlessly to deterministic engine.
    """
    fingerprint = calculate_evidence_fingerprint(evidence)

    # 1. Check reasoning cache
    if fingerprint in _REASONING_CACHE:
        AI_TELEMETRY["cache_hits"] += 1
        logger.info(f"Cache HIT for evidence fingerprint {fingerprint[:12]}. Reusing stored reasoning.")
        cached = dict(_REASONING_CACHE[fingerprint])
        cached["cached"] = True
        return cached

    # 2. Cache MISS -> Prepare inference
    AI_TELEMETRY["requests_total"] += 1
    logger.info(f"Cache MISS for evidence fingerprint {fingerprint[:12]}. Performing reasoning evaluation.")

    provider_name = (os.getenv("AI_PROVIDER") or "openrouter").lower().strip()
    ai_result = None

    try:
        if provider_name == "gemini":
            provider = GeminiProvider()
            ai_result = provider.analyze(evidence)
        else:
            provider = OpenRouterProvider()
            ai_result = provider.analyze(evidence)
    except Exception as exc:
        logger.warning(f"AI Provider execution failed ({exc}). Falling back to deterministic reasoning.")
        ai_result = None

    if ai_result and isinstance(ai_result, dict) and ai_result.get("key_evidence"):
        ai_result["cached"] = False
        ai_result["evidence_fingerprint"] = fingerprint
        _REASONING_CACHE[fingerprint] = ai_result
        return ai_result

    # 3. Fallback to Deterministic Engine
    AI_TELEMETRY["fallbacks"] += 1
    logger.info("AI provider unavailable or failed validation. Executing deterministic reasoning fallback.")
    fallback_result = generate_deterministic_reasoning(evidence)
    fallback_result["cached"] = False
    fallback_result["evidence_fingerprint"] = fingerprint
    _REASONING_CACHE[fingerprint] = fallback_result
    return fallback_result
