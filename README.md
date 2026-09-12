# KEKAI
### Evidence-Driven Phishing Detection & Threat Investigation

KEKAI ingests suspicious messages and URLs, correlates deterministic evidence across content, sender behaviour, domains, landing pages, payloads, infrastructure, and threat feeds, then returns an analyst-facing, explainable verdict.

## 1. Why KEKAI?

Modern phishing is an evidence-correlation problem. A message may pair social engineering and brand impersonation with a lookalike domain; its credential form may appear only after JavaScript runs; attackers may reuse DNS or hosting infrastructure; and attachments or QR codes can hide the destination. Any one signal is fallible. A suspicious message becomes meaningful when independent signals converge.

## 2. Problem Statement

| PS requirement | KEKAI capability | Status |
|---|---|---|
| Content analysis | IOC extraction and deterministic urgency, credential, financial, link, brand, and sender-mismatch rules | Implemented |
| URL & domain analysis | Normalization, lookalike checks, DNS, RDAP, provider/ASN data, and safe redirect tracing | Implemented; network sources are conditional |
| Page similarity detection | DOM/brand/form analysis and perceptual-hash comparison; optional Phishpedia path | Implemented with fallbacks |
| Sender behaviour modelling | Explainable comparison against supplied organisational baselines | Implemented for demo/supplied baselines |
| Explainable verdicts | Evidence groups, hypotheses, metrics, graph data, and recommended action | Implemented |
| Feedback loop | Versioned feedback and exportable SQLite training signals | Implemented; no live retraining |
| Attachment / QR bonus | Non-executing file inspection, QR decoding, IOC extraction | Implemented |

## 3. The Core Idea

KEKAI does not blindly trust one phishing score:

```text
Message -> content + IOC extraction -> sender baseline
       -> URL/domain + redirect analysis -> page inspection
       -> payload/QR inspection -> infrastructure + threat intelligence
       -> attack-chain graph -> evidence fusion -> explainable verdict
```

`POST /api/investigations/{investigation_id}/analyze` orchestrates the end-to-end path; individual services remain available for evidence inspection.

## 4. Key Features

### 4.1 Email Threat Analysis

`POST /api/email-analyze` accepts sender, subject, body, headers, and received time. It extracts URLs, domains, emails, and IPs, then produces structured evidence and a classification.

### 4.2 Content / NLP Analysis

This is deterministic rule-based content analysis, not a trained NLP model. It detects urgency, credential-harvesting language, suspicious URLs, brand/sender mismatch, financial requests, and attachment mentions. Its evidence identifies the matched signal and source.

### 4.3 URL & Domain Intelligence

`POST /api/url-intelligence` normalizes URLs, evaluates lookalike patterns, resolves DNS, queries RDAP registration intelligence, and traces redirects with bounded depth. URL handling blocks loopback, private-address, and cloud-metadata SSRF targets. DNS/RDAP/ASN results may be unavailable or partial when their external sources fail.

### 4.4 Domain Watch

The domain discovery path uses the bundled `dnstwist` integration and a Python permutation fallback. OpenPhish and PhishTank adapters retrieve/caches feeds when network access allows. Cached or unavailable source status is preserved rather than converted into a threat hit.

### 4.5 Static Webpage Analysis

`POST /api/page-analysis` uses BeautifulSoup, when installed, to inspect HTML without executing scripts or submitting forms. It extracts the title, visible text, DOM features/fingerprint, images/favicon references, forms, password inputs, form actions, and cross-domain credential-submission indicators.

### 4.6 Dynamic Browser Analysis

The optional Playwright layer renders JavaScript pages in an isolated headless context, inspects the post-render DOM and credential fields, tracks redirects, and captures a screenshot. It returns a structured fallback if Playwright, Chromium, or navigation is unavailable; it never claims a successful dynamic render in that case.

### 4.7 Page Similarity & Brand Clone Detection

Page similarity, logo detection, and DOM similarity are separate inputs. The working deterministic visual path normalizes images and compares `pHash`/`dHash`; the fallback engine also uses related image, OCR, brand-text, layout, favicon, and lexical-domain signals. The clone classifier additionally considers forms and official-domain alignment.

Phishpedia is optional. Its deep-learning logo path runs only when the expected local weights exist in `Phishpedia/models/`; otherwise KEKAI uses the fallback chain. A visual match is supporting evidence, never proof by itself.

### 4.8 Sender Behaviour Modelling

The sender engine compares sending time, recipients, target links, language, and attachment types against `ORGANISATION_BASELINES`. It can identify unknown external senders and possible account-compromise patterns. The included baselines are synthetic/demo profiles, not production mail telemetry.

### 4.9 Threat Intelligence

OpenPhish and PhishTank adapters contribute URL/candidate observations. RDAP contributes registration and registrar metadata; DNS and ASN/provider services contribute technical context. Each returns provenance and status, allowing unavailable data to remain unavailable rather than fabricated.

### 4.10 Infrastructure Correlation

Investigation-scoped assets can be linked using DNS, IP/ASN, nameservers, MX records, registration data, SSL/provider observations, and visual fingerprints where provided. These relationships are correlation signals, not attribution or proof of common ownership.

### 4.11 Attack Chain Reconstruction

`POST /api/attack-chain` returns provenance-bearing nodes, directed edges, evidence items, and hypotheses. Available evidence can connect message, sender, URL, redirects, domain, IP/nameserver, landing page, form action, brand, and threat-feed observations.

### 4.12 Explainable Verdicts

The decision engine deduplicates related observations into evidence groups and returns verdict, risk score, confidence, evidence quality, attack hypotheses, supporting/contradicting evidence, missing context where available, and a recommended action. It is intended to answer what happened, why it was flagged, and what an analyst should do.

### 4.13 AI Investigation Insight

Google Gemini, using `gemini-2.5-flash-lite`, is an optional evidence-synthesis layer. It receives normalized structured evidence and does not perform authoritative DNS, RDAP, or deterministic scoring. If no valid `GEMINI_API_KEY` is configured, KEKAI emits deterministic reasoning instead. The legacy `OPENROUTER_*` variables in `.env.example` are not an active provider path.

### 4.14 Analyst Feedback Loop

`POST /api/feedback` records analyst/user labels including confirmed phishing, false positive, user-reported phishing, and user-marked safe. It persists a versioned feature snapshot in SQLite and exposes dataset/statistics endpoints for offline improvement. Automatic real-time retraining is not implemented.

### 4.15 Attachment & QR Inspection

`POST /api/payload/inspect` safely hashes and statically examines HTML, PDF, DOCX/text, ZIP, and images. It extracts links/form targets, decodes QR URLs from images, and enforces size, entry-count, and compression-ratio limits. It does not detonate or open attachments in office/PDF applications.

## 5. Architecture

```text
 Email / Message / File
          |
          v
 Content & IOC extraction ---- Sender baseline
          |                         |
          +---- URL/domain intelligence ---- Threat feeds
          |              |
          |              +---- Static DOM (BeautifulSoup)
          |              +---- Dynamic DOM (Playwright, optional)
          |              +---- Visual comparison / optional Phishpedia
          |
 Payload + QR inspection ---- Infrastructure/entity correlation
                                      |
                                      v
                         Attack-chain graph + evidence fusion
                                      |
                         Gemini insight (optional) / deterministic fallback
                                      |
                         Explainable verdict + analyst feedback
```

The React/Vite frontend consumes FastAPI. SQLite persists assets, timelines, feedback, evidence snapshots, and abuse-control state. Abuse-control routes require human approval; `DRY_RUN` is the default mode.

## 6. Run locally

Prerequisites: Python 3.10+ and Node.js/npm.

```bash
python -m venv venv
# Windows
venv\Scripts\activate
# macOS/Linux: source venv/bin/activate
pip install -r requirements.txt
pip install beautifulsoup4

cd frontend
npm install
cd ..

Copy-Item .env.example .env   # PowerShell
python steps.py
```

Open `http://localhost:5173`; Swagger API docs are at `http://localhost:8000/docs`.

For dynamic page inspection, install Playwright in the same environment and provision Chromium:

```bash
pip install playwright
playwright install chromium
```

This is optional. Without it, dynamic analysis returns a fallback status. To enable Gemini, set `GEMINI_API_KEY` (optionally `GEMINI_MODEL`) in `.env`. Phishpedia weights can be fetched with `scripts/download_phishpedia_weights.py`; visual fallback remains usable without them.

## 7. Configuration and limits

Safe defaults include `ABUSE_SUBMISSION_MODE=DRY_RUN`, feed toggles, RDAP, and the Phishpedia integration toggle. Live feeds/RDAP require outbound connectivity and can rate-limit; protected sites can prevent browser capture. `ABUSE_SUBMISSION_MODE=LIVE` requires configured Cloudflare credentials and human approval—do not enable it merely for a demo.

## 8. Verify

Run representative backend tests from the repository root:

```bash
python -m unittest test_email_analysis.py test_sender_behavior.py tests/test_payload_inspection.py tests/test_page_similarity_clone_detection.py tests/test_unified_evidence_phishing_verdict.py
```

Build the frontend:

```bash
cd frontend
npm run build
```

## 9. Repository map

```text
main.py                         FastAPI routes and orchestration
services/email_analysis.py      Email IOC extraction and rules
services/url_intelligence.py    URL/domain, DNS, RDAP, redirects
services/page_analyzer.py       Static page and clone analysis
services/dynamic_browser.py     Optional Playwright rendering
services/payload_inspection.py  Safe attachment and QR inspection
services/chain_tracer.py        Evidence graph construction
services/phishing_decision_engine.py  Evidence fusion and verdicts
services/ai_reasoning.py        Gemini with deterministic fallback
services/feedback_service.py    Feedback and offline signals
frontend/                       React/Vite analyst dashboard
```

## 10. Security note

KEKAI is a defensive investigation tool. Scores, visual matches, and infrastructure relationships are analyst aids, not proof of maliciousness or authorization to take down a domain. Review evidence and obtain authority before external response actions.
