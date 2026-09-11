# KEKAI — Autonomous Brand Intelligence & Organisational Phishing Prevention Engine

## Architectural Design & Data Flow

```
                           Message Ingestion
                                   │
              ┌────────────────────┴────────────────────┐
              ▼                                         ▼
       Content Analysis                     Sender Behaviour Model
       (NLP / Urgency / Creds)             (Baseline / Anomaly / Hypo)
              │                                         │
              └────────────────────┬────────────────────┘
                                   │
                                   ▼
                    Payload & Attachment Inspection
                    (QR / Form / PDF / ZIP Static Scan)
                                   │
                                   ▼
                    URL & Domain Intelligence Layer
                  (Normalization / Obfuscation / RDAP)
                                   │
                                   ▼
                    Infrastructure Correlation Engine
                     (IP / ASN / NS / MX / Fingerprints)
                                   │
                                   ▼
                   Visual Phishing Recognition Engine
                   (pHash / dHash / Logo Detection)
                                   │
                                   ▼
                    Unified Phishing Decision Engine
                 (Stage 1-8 Evidence Correlation & Risk)
                                   │
                                   ▼
                    Pre-Interaction Policy Engine
                  (ALLOW / WARN / QUARANTINE / BLOCK)
                                   │
                                   ▼
                   Immutable Audit & Event Logging
                  (SHA-256 Snapshots & Case Timeline)
                                   │
                                   ▼
                    Organisational Feedback Loop
                  (Analyst Overrides & User Reports)
                                   │
                                   ▼
                    Adaptive Detection Signal Engine
                  (Versioned Signals & Recommendation)
```

---

## Stage Breakdown

1. **Ingestion Layer**:
   - Ingests inbound messages (email headers, body text, attachments, URLs) via standardized JSON schema (`MessageIngestionRequest`).
   - Assigns unique `message_id` and `ingestion_timestamp`.

2. **Pre-Interaction Analysis**:
   - Executes multi-stage threat detection before message delivery or user interaction.
   - Evaluates content intent, sender anomalies, static payload artifacts, domain registration age, redirect chains, and visual brand impersonation.

3. **Unified Phishing Decision Engine (`services/phishing_decision_engine.py`)**:
   - Aggregates supporting and contradicting evidence across 8 independent detection stages.
   - Calculates independent metrics:
     - `risk_score` (0-100)
     - `confidence` (0-100)
     - `evidence_quality` (0-100)
   - Resolves attack hypothesis (`EXTERNAL_IMPERSONATION`, `LOOKALIKE_DOMAIN_SENDER`, `POSSIBLE_ACCOUNT_COMPROMISE`, `NEW_DOMAIN_SENDER`, `REDIRECT_CHAIN_PHISHING`, `BRAND_IMPERSONATION`, `BENIGN_INTERNAL`, `UNKNOWN`).

4. **Pre-Interaction Organisational Policy Engine (`services/policy_engine.py`)**:
   - Applies organizational risk thresholds and rule policies (`RULE_EXPLICIT_BLOCKED_DOMAIN`, `RULE_VERIFIED_OFFICIAL_BRAND`, `POLICY_CRITICAL_MALICIOUS`, etc.).
   - Emits enforcement action: `BLOCK`, `QUARANTINE`, `WARN`, `REVIEW`, `ALLOW`.

5. **AI Provider Reasoning Abstraction (`services/ai_reasoning.py`)**:
   - 1-Pass explainable reasoning correlation via OpenRouter / Gemini provider abstraction.
   - Evidence fingerprint caching (`lru_cache`) ensures identical evidence payloads reuse cached reasoning without redundant API calls.
   - Strict 100% deterministic fallback ensures security verdicts execute uninterrupted even under API timeouts, HTTP 429 rate limits, or network failures.

6. **Organisational Feedback & Signal Engine (`services/feedback_service.py`)**:
   - Captures analyst decisions and user reports immutably.
   - Computes feature vector snapshots, schema versioning metadata (`1.0.0`), conflict flags, and `RECOMMENDED_SIGNAL_ADJUSTMENTS`.
