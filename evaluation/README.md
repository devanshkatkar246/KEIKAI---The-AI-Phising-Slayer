# KEKAI PS #2 Evaluation Suite

## Quick Start

To execute the full deterministic evaluation suite, ablation study, and latency benchmarks, run:

```bash
python evaluation/runner.py
```

## Overview

The evaluation harness evaluates KEKAI's Unified Phishing Decision Engine against 12 deterministic test fixtures covering:
1. Internal Legitimate Communications
2. External Legitimate Communications
3. External Brand Impersonation
4. Lookalike / Typosquatted Domains
5. Newly Registered Domain Credential Phishing
6. Compromised Internal Account Transmission
7. QR Code Phishing (Quishing)
8. Malicious HTML Attachment Inspection
9. Visual Brand Logo & Page Cloning
10. Multi-Hop Redirect Chains to Credential Pages
11. Vendor False Positive Calibration
12. Inconclusive Low-Evidence Payloads

## File Structure

- `evaluation/fixtures/evaluation_cases.py`: Contains the 12 deterministic test fixtures.
- `evaluation/runner.py`: Execution script that runs evaluation, computes signal ablation mode metrics, and prints formatted output.
- `evaluation/README.md`: Instructions and documentation.
