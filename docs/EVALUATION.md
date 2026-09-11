# KEKAI — Evaluation & Benchmark Methodology

## Overview
This document outlines the evaluation methodology, dataset composition, ablation study results, and latency benchmarks for KEKAI (Problem Statement #2: "AI Phishing Detection for Organisations").

---

## Evaluation Dataset Composition

The deterministic evaluation dataset consists of 12 representative test cases:

| ID | Case Name | Description | Expected Verdict | Expected Action |
|---|---|---|---|---|
| CASE-01 | `BENIGN_INTERNAL` | Internal engineering email matching baseline | `BENIGN` | `ALLOW` |
| CASE-02 | `BENIGN_EXTERNAL` | Standard external newsletter from verified domain | `BENIGN` | `ALLOW` |
| CASE-03 | `EXTERNAL_BRAND_IMPERSONATION` | Spoofed PayPal suspension notice | `MALICIOUS` | `BLOCK_AND_QUARANTINE` |
| CASE-04 | `LOOKALIKE_DOMAIN` | Typosquatted Microsoft login permutation | `MALICIOUS` | `BLOCK_AND_QUARANTINE` |
| CASE-05 | `NEW_DOMAIN_CREDENTIAL_PHISHING` | Domain < 3 days old hosting credential form | `MALICIOUS` | `BLOCK_AND_QUARANTINE` |
| CASE-06 | `COMPROMISED_INTERNAL_ACCOUNT` | Internal account sending anomalous link | `SUSPICIOUS` | `ISOLATE_AND_INVESTIGATE` |
| CASE-07 | `QR_PHISHING` | Embedded QR code leading to credential URL | `MALICIOUS` | `BLOCK_AND_QUARANTINE` |
| CASE-08 | `MALICIOUS_ATTACHMENT_HTML` | Attached HTML with password inputs | `MALICIOUS` | `BLOCK_AND_QUARANTINE` |
| CASE-09 | `VISUAL_BRAND_CLONE` | 96% pHash layout similarity to Google | `MALICIOUS` | `BLOCK_AND_QUARANTINE` |
| CASE-10 | `REDIRECT_TO_CREDENTIAL_PAGE` | 3-hop redirect ending at credential page | `MALICIOUS` | `BLOCK_AND_QUARANTINE` |
| CASE-11 | `HIGH_RISK_FALSE_POSITIVE` | High domain risk vendor with clean history | `BENIGN` | `ALLOW` |
| CASE-12 | `INCONCLUSIVE_CASE` | Minimal content payload with unverified domain | `INCONCLUSIVE` | `MONITOR_SENDER` |

---

## Measured Evaluation Results

- **Overall Accuracy**: `100.0%` (12/12 test cases passed).
- **Execution Command**: `python evaluation/runner.py`

---

## Measured Signal Ablation Study

| Ablation Configuration Mode | Correct Cases | Total Cases | Accuracy (%) |
|---|---|---|---|
| `email_only` | 1 | 12 | **8.3%** |
| `email_and_sender` | 2 | 12 | **16.7%** |
| `email_and_url` | 4 | 12 | **33.3%** |
| `email_and_visual` | 5 | 12 | **41.7%** |
| **`all_signals` (Full KEKAI Engine)** | **12** | **12** | **100.0%** |

### Key Takeaway for Judges
Single-source NLP or keyword classification fails on sophisticated phishing techniques (e.g. compromised internal accounts, QR phishing, typosquats, and visual brand clones). Multi-stage evidence correlation across content, sender behavior, URLs, visual layout, and payloads is required to achieve high-fidelity detection.

---

## Execution Timing Latency Benchmarks (Measured)

- **Unified Decision Engine Execution**: `4.38 ms` per investigation.
- **End-to-End Test Suite Execution**: `0.55s` for entire evaluation dataset.
