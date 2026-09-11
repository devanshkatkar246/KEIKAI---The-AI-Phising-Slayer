# KEIKAI Data Lineage & Provenance Inventory

This document provides a complete, traceable inventory of all security-relevant fields displayed across the KEIKAI Anti-Impersonation and Phishing Detection Engine.

---

## Data Source Classifications

All security intelligence within KEIKAI is classified into one of the following authoritative categories:

1. **`LIVE_EXTERNAL`**: Data fetched from an external live service at query time (e.g. RDAP bootstrap servers, DNS resolvers, live OpenPhish/PhishTank feeds).
2. **`DETERMINISTIC_LOCAL`**: Computed algorithmically from real input data using local logic (e.g. pHash/dHash, URL canonicalization, Levenshtein distance, SHA-256).
3. **`AI_GENERATED`**: Produced by an AI model (e.g. OpenRouter/Gemini reasoning layer) using real security signals.
4. **`SIMULATED_BASELINE`**: Synthetic organizational behavioral telemetry used to demonstrate baseline anomaly detection during demonstrations.
5. **`FIXTURE`**: Controlled test or demo scenario data, strictly isolated to test suites and explicit demo modes.
6. **`FALLBACK`**: Returned only when a live external service is unreachable or missing prerequisites.
7. **`UNKNOWN`**: Data whose origin cannot be established. *(Strict Policy: UNKNOWN data is NEVER presented as live intelligence in KEIKAI)*.

---

## Security Intelligence Inventory

| Component / Surface | Displayed Field | Data Classification | API Endpoint | Source Service / Provider | Cache & Refresh Behavior |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Email Analysis** | IOC Extraction (URLs, Domains, IPs) | `DETERMINISTIC_LOCAL` | `/api/email-analyze` | `services/email_analysis.py` | Computed on message submit; no cache |
| **Email Analysis** | NLP Security Signals (Urgency, Credential Theft) | `DETERMINISTIC_LOCAL` | `/api/email-analyze` | `services/email_analysis.py` | Computed on message submit; no cache |
| **Email Analysis** | AI Attack Reasoning & Explanation | `AI_GENERATED` | `/api/email-analyze` | `services/ai_reasoning.py` (OpenRouter API) | Generated per request; fallback to deterministic summary on quota limit |
| **Sender Behaviour** | Sender Anomaly Score & Signals | `DETERMINISTIC_LOCAL` | `/api/sender-behavior/analyze` | `services/sender_behavior.py` | Computed against organizational baseline |
| **Sender Behaviour** | Organizational Sender Profile | `SIMULATED_BASELINE` | `/api/organisation/baselines` | `services/sender_behavior.py` | Synthetic organizational rules (`org_acme_01`) |
| **URL Intelligence** | Canonical URL & Hostname Normalization | `DETERMINISTIC_LOCAL` | `/api/url-intelligence` | `services/url_intelligence.py` | Computed on URL submission |
| **URL Intelligence** | Obfuscation & Homograph Detection | `DETERMINISTIC_LOCAL` | `/api/url-intelligence` | `services/url_intelligence.py` | Computed algorithmically (punycode, tracking stripped) |
| **URL Intelligence** | Redirect Chain Inspection | `LIVE_EXTERNAL` | `/api/url-intelligence` | `services/url_intelligence.py` (HTTP Client) | Executed with SSRF safety guards; short TTL |
| **Domain Intelligence** | DNS Records (A, AAAA, CNAME, MX, NS) | `LIVE_EXTERNAL` | `/api/domain-intelligence` | `services/dns_intelligence_service.py` (dnspython) | 5-minute in-memory cache; refresh per investigation |
| **Domain Intelligence** | RDAP Registration & Domain Age | `LIVE_EXTERNAL` | `/api/domain-intelligence` | `services/rdap_service.py` (ICANN RDAP Bootstrap) | 10-minute in-memory cache; returns `RDAP_UNAVAILABLE` on network error |
| **Domain Intelligence** | ASN & Hosting Provider Info | `LIVE_EXTERNAL` | `/api/asn-intelligence` | `services/asn_intelligence_service.py` (bgp.tools / ip-api) | 60-minute in-memory cache |
| **Threat Intelligence** | Lookalike Permutations | `DETERMINISTIC_LOCAL` | `/api/domain-scan` | `services/threat_intelligence/dnstwist_adapter.py` | Computed per domain scan |
| **Threat Intelligence** | OpenPhish Feed Matches | `LIVE_EXTERNAL` | `/api/domain-scan` | `services/threat_intelligence/openphish_adapter.py` | Live HTTP fetch; returns `status: UNAVAILABLE` when offline |
| **Threat Intelligence** | PhishTank Feed Matches | `LIVE_EXTERNAL` | `/api/domain-scan` | `services/threat_intelligence/phishtank_adapter.py` | Live HTTP fetch; returns `status: UNAVAILABLE` when offline |
| **Visual Analysis** | Phishpedia Logo Detection Bounding Box | `DETERMINISTIC_LOCAL` | `/api/visual-brand-analysis` | `services/phishpedia_service.py` (PyTorch R-CNN) | Computed on screenshot image; fallback to hash if weights absent |
| **Visual Analysis** | Perceptual Image Similarity (pHash / dHash) | `DETERMINISTIC_LOCAL` | `/api/logo-compare` | `services/imagehash_service.py` (ImageHash) | Computed algorithmically on image bytes |
| **Payload Inspection** | Static QR Code Payload Extraction | `DETERMINISTIC_LOCAL` | `/api/payload/inspect` | `services/payload_inspection.py` (pyzbar / OpenCV) | Computed on file upload; no code execution |
| **Payload Inspection** | HTML Form & Password Input Detection | `DETERMINISTIC_LOCAL` | `/api/payload/inspect` | `services/payload_inspection.py` (BeautifulSoup4) | Static DOM parse; no JS execution |
| **Infrastructure** | Linked Assets & IP Fingerprints | `DETERMINISTIC_LOCAL` | `/api/link-infrastructure` | `services/infrastructure_service.py` | Scoped strictly to active `investigation_id` |
| **Infrastructure** | Offender Clusters & Graph Edges | `DETERMINISTIC_LOCAL` | `/api/offender-clusters` | `services/infrastructure_service.py` | Computed dynamically from overlapping IP/hash/brand signals in SQLite |
| **Decision Engine** | Unified Verdict & Composite Risk Score | `DETERMINISTIC_LOCAL` | `/api/phishing-decision` | `services/phishing_decision_engine.py` | Computed using weighted multi-signal evidence fusion |
| **Policy Engine** | Pre-Interaction Action (ALLOW / BLOCK / WARN) | `DETERMINISTIC_LOCAL` | `/api/messages/inspect` | `services/policy_engine.py` | Evaluated against organizational policy rules |
| **Analyst Feedback** | Decision Snapshots & Signal Adjustments | `DETERMINISTIC_LOCAL` | `/api/feedback` | `services/feedback_service.py` | Immutable SQLite records with conflict detection |

---

## Provenance Metadata Specifications

Every response returned by KEIKAI intelligence APIs contains explicit provenance metadata:

```json
{
  "provenance": {
    "source": "rdap | dns | openphish | phishtank | phishpedia | phash | sender_telemetry",
    "status": "SUCCESS | UNAVAILABLE | ERROR | NOT_RUN | NO_MATCH",
    "live": true,
    "retrieved_at": "2026-09-11T23:30:00Z",
    "investigation_id": "inv_amazon_01"
  }
}
```

### Unreachable / Offline Service Contracts

When an external provider (such as RDAP or OpenPhish) is unreachable or times out:
- `status` is set to `"UNAVAILABLE"`
- `live` is set to `false`
- `reason` describes the network/HTTP state
- **The engine NEVER converts unavailable external state into synthetic match results or invented success scores.**
