# KEKAI — Security & Defensive Hardening Model

## Defensive Security Posture & Hardening Controls

### 1. Server-Side Request Forgery (SSRF) Protection
- **Hostname & IP Validation**: `services/multi_http_verifier.py` validates all external target hostnames and DNS-resolved IP addresses using Python `ipaddress`.
- **Blocked Ranges**:
  - IPv4 Loopback (`127.0.0.0/8`) & `localhost`
  - Private RFC1918 Ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`)
  - Cloud Provider IMDS Metadata IP (`169.254.169.254`)
  - Link-Local & Carrier-Grade NAT (`169.254.0.0/16`, `100.64.0.0/10`)
  - IPv6 Loopback & Link-Local (`::1`, `fe80::/10`)
- **Redirect Hop Inspection**: Redirect chains in `services/url_intelligence.py` inspect each hop and immediately abort with `ssrf_blocked: True` if any intermediate hop attempts to pivot to a private or internal IP address.

### 2. Static Safe Payload & File Inspection
- **Zero Binary / Code Execution**: Attachments, HTML documents, PDFs, and ZIP archives are inspected purely via static parsing without rendering DOM, running JavaScript, executing macros, or executing binaries.
- **Resource Limits**:
  - Maximum attachment inspection size limit: 10 MB (`SIZE_LIMIT_EXCEEDED` fallback).
  - Maximum ZIP entries limit: 100 entries (`INSPECTION_LIMIT_REACHED` fallback).
  - Maximum decompression expansion ratio guard against ZIP bomb attacks.
- **Executable & Script Detection**: Flags dangerous attachment formats (`.exe`, `.scr`, `.bat`, `.vbs`, `.js`, `.ps1`) and static HTML credential harvesting form inputs (`<input type="password">`).

### 3. Safe Redirect & URL Intelligence
- **Bounded Depth**: Redirect inspection is capped at maximum 5 hops.
- **Strict Timeouts**: 3.0 second socket timeout per HTTP request.
- **Scheme Validation**: Non-HTTP schemes (`javascript:`, `data:`, `file:`, `vbscript:`) are flagged with `suspicious_url_scheme` and prevented from navigating.
- **Obfuscation Detection**: Identifies URL encoding tricks (`%2f`, `%40`), userinfo authentication abuse (`user:pass@host`), and excessive subdomain depth (>4 levels).

### 4. AI Provider Boundary & Prompt Injection Defense
- **Strict Schema Enforcement**: AI reasoning outputs are parsed and validated server-side. Unvalidated AI fields cannot alter security verdicts or action classifications.
- **Deterministic Action Precedence**: The deterministic decision engine remains the authoritative decision-maker for security verdicts and policy enforcement actions (`BLOCK`, `QUARANTINE`, `WARN`, `ALLOW`).
- **Quota & Timeout Resilience**: Provider timeouts, HTTP 429 quota exhaustion, or malformed provider responses trigger seamless fallback to the local deterministic engine without interrupting processing.

### 5. Secrets Management & Takedown Safety Controls
- **Zero Frontend Secret Exposure**: API keys (`OPENROUTER_API_KEY`, `GEMINI_API_KEY`) are accessed strictly on the backend.
- **Environment Isolation**: `.env` is listed in `.gitignore` to prevent secret commits.
- **Abuse Takedown Safety**: All takedown and abuse reporting actions default to `DRY_RUN = True`. Automated live takedowns are strictly prohibited without explicit human SOC analyst confirmation.
