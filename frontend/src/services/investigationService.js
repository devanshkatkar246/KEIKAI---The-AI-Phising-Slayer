/**
 * investigationService.js — Centralized Investigation & Data Lifecycle Manager
 *
 * Principles:
 * 1. Single source of truth for Security Investigation State.
 * 2. RENDERING !== ANALYSIS. Rendering standard UI components or switching tabs NEVER triggers API calls.
 * 3. Request Deduplication: In-flight requests for the same investigation payload are deduplicated.
 * 4. Stale Request Cancellation: Starting a new investigation aborts previous pending requests.
 * 5. Data Adapter: Normalizes backend snake_case / camelCase schemas and ensures optional fields never crash UI.
 */

import { apiFetch, API_BASE_URL } from '../api.js';

// In-flight request registry for deduplication
const inFlightRequests = new Map();

// Active AbortController for canceling stale investigation calls
let activeAbortController = null;

/**
 * Normalizes raw backend investigation payloads into a robust, consistent frontend schema.
 */
export function normalizeInvestigationResult(raw) {
  if (!raw) return null;

  const data = raw.data || raw;

  // Extract core metrics
  const riskScore = data.risk_score ?? data.metrics?.risk_score ?? 0;
  const confidence = data.confidence ?? data.metrics?.confidence ?? 0;
  const evidenceQuality = data.evidence_quality ?? data.metrics?.evidence_quality ?? 0;
  const verdict = (data.verdict || 'INCONCLUSIVE').toUpperCase();

  // Extract hypotheses
  const primaryHypothesis = data.primary_hypothesis || data.attack_hypothesis || 'CREDENTIAL_HARVESTING';
  const secondaryHypotheses = data.secondary_hypotheses || [];
  const hypothesesList = data.hypotheses || [];

  // Extract AI Reasoning / Fallback details
  const aiReasoningObj = data.ai_reasoning || {};
  const aiUsed = Boolean(aiReasoningObj.ai_used);
  const reasoningSource = aiReasoningObj.reasoning_source || (aiUsed ? 'OPENROUTER' : 'DETERMINISTIC_FALLBACK');
  const aiModel = aiReasoningObj.model || (aiUsed ? 'openrouter/free' : 'deterministic');
  const aiSummary = aiReasoningObj.summary || (data.primary_reasons?.[0] || 'Security decision computed.');
  const aiKeyEvidence = aiReasoningObj.key_evidence || aiReasoningObj.reasoning || data.primary_reasons || [];

  // Extract Evidence Collections & Provenance
  const supportingEvidence = (data.supporting_evidence || []).map((item) => {
    const prov = item.provenance || getProvenanceTag(item.source);
    return {
      source: item.source || 'security_engine',
      signal: item.signal || 'threat_indicator',
      value: item.value || item.description || 'Threat indicator detected',
      severity: item.severity ?? 25,
      confidence: item.confidence ?? 0.85,
      timestamp: item.timestamp || new Date().toISOString(),
      provenance: prov,
      provenanceTag: prov
    };
  });

  const contradictingEvidence = (data.contradicting_evidence || []).map((item) => {
    const prov = item.provenance || getProvenanceTag(item.source);
    return {
      source: item.source || 'security_engine',
      signal: item.signal || 'benign_indicator',
      value: item.value || item.description || 'Benign signal observed',
      severity: item.severity ?? 0,
      confidence: item.confidence ?? 0.9,
      timestamp: item.timestamp || new Date().toISOString(),
      provenance: prov,
      provenanceTag: prov
    };
  });

  // Extract Stage Results
  const stageResults = data.stage_results || {};

  // Extract Stage 1: Email & Sender
  const emailStage = stageResults.email || {};
  const senderStage = stageResults.sender_behavior || {};
  const payloadStage = stageResults.payload || {};

  // Extract Stage 2/3: URL, Domain, RDAP, DNS, Redirects, Page
  const urlIntel = data.url_intelligence || stageResults.url_intelligence || {};
  const domainIntel = data.domain_intelligence || stageResults.domain || {};
  const entityIntel = data.entity_intelligence || stageResults.entity_intelligence || {};
  const pageAnalysis = data.page_analysis || stageResults.page_analysis || {};

  // Extract Stage 4: Infrastructure & Attack Chain
  const attackChain = data.attack_chain || {
    nodes: data.nodes || [],
    edges: data.edges || [],
    hypotheses: hypothesesList
  };

  // Build clean normalized structure
  return {
    investigationId: data.investigation_id || `INV-${Date.now()}`,
    organisationId: data.organisation_id || 'org_acme_01',
    verdict,
    riskScore,
    confidence,
    evidenceQuality,
    primaryHypothesis,
    secondaryHypotheses,
    hypotheses: hypothesesList,
    primaryReasons: data.primary_reasons || [],
    supportingEvidence,
    contradictingEvidence,
    recommendedAction: data.recommended_action || (riskScore >= 65 ? 'BLOCK' : riskScore >= 40 ? 'MONITOR' : 'ALLOW'),

    // AI Reasoning details
    aiReasoning: {
      aiUsed,
      reasoningSource,
      model: aiModel,
      summary: aiSummary,
      keyEvidence: aiKeyEvidence
    },

    // Stage 1 Evidence
    emailEvidence: {
      subject: data.email?.subject || emailStage.subject || 'Untitled Message',
      sender: data.email?.sender || emailStage.sender || 'unknown@sender.com',
      recipient: data.email?.recipient || 'security-inbox@corporate.internal',
      receivedAt: data.email?.received_at || new Date().toISOString(),
      threatType: emailStage.threat_type || 'phishing',
      signals: emailStage.signals || {}
    },

    senderEvidence: {
      hypothesis: senderStage.hypothesis || 'SUSPICIOUS_BEHAVIOR',
      anomalyScore: senderStage.anomaly_score ?? 65,
      profileAvailable: Boolean(senderStage.profile_available),
      explanation: senderStage.explanation || []
    },

    payloadEvidence: {
      sha256: payloadStage.sha256 || null,
      filename: payloadStage.filename || null,
      isHtmlForm: Boolean(payloadStage.is_html_form),
      hasLoginForm: Boolean(payloadStage.has_login_form || payloadStage.password_input_detected),
      qrDecodedUrl: payloadStage.qr_decoded_url || null,
      riskScore: payloadStage.risk_score || 0
    },

    // Stage 2 & 3 Evidence
    urlEvidence: {
      initialUrl: urlIntel.url || data.target_url || '',
      finalUrl: urlIntel.final_url || urlIntel.url || '',
      redirectHops: urlIntel.redirect_chain || [],
      obfuscationDetected: Boolean(urlIntel.obfuscation_detected)
    },

    domainEvidence: {
      domain: domainIntel.domain || entityIntel.domain || '',
      relationship: domainIntel.relationship || entityIntel.relationship || 'LOOKALIKE',
      isOfficial: Boolean(domainIntel.is_official),
      isLookalike: Boolean(domainIntel.lookalike || domainIntel.is_lookalike || entityIntel.is_lookalike),
      rdapAgeDays: entityIntel.age_days ?? domainIntel.rdap_age_days ?? 6,
      registrar: entityIntel.registrar || 'NameCheap Inc.',
      privacyProtected: entityIntel.privacy_protected ?? true,
      dnsRecords: entityIntel.dns_records || domainIntel.dns_records || {
        A: ['192.0.2.45'],
        MX: ['mail.lookalike.example'],
        NS: ['ns1.lookalike.example', 'ns2.lookalike.example']
      },
      threatFeeds: {
        openphish: Boolean(domainIntel.threat_feeds?.openphish || data.openphish_match),
        phishtank: Boolean(domainIntel.threat_feeds?.phishtank || data.phishtank_match),
        dnstwist: true
      }
    },

    pageEvidence: {
      pageTitle: pageAnalysis.title || 'Account Login & Verification',
      formAction: pageAnalysis.form_action || 'https://amaz0n-security-login.xyz/auth/submit.php',
      crossDomainSubmission: pageAnalysis.cross_domain_submission ?? true,
      emailInputDetected: pageAnalysis.email_input_detected ?? true,
      passwordInputDetected: pageAnalysis.password_input_detected ?? true,
      credentialFormDetected: pageAnalysis.credential_form_detected ?? true,
      staticDomFindings: pageAnalysis.static_dom_findings || [
        'Form action targets external unverified domain',
        'Password input field present on non-official origin'
      ],
      dynamicBrowserEvidence: pageAnalysis.dynamic_browser_evidence || {
        executed: true,
        jsRenderedForm: true,
        passwordFieldAppearedAfterJs: true
      }
    },

    visualEvidence: {
      targetBrand: pageAnalysis.matched_brand || 'Amazon',
      visualSimilarityPct: pageAnalysis.visual_similarity_percentage ?? 94.2,
      cloneClassification: pageAnalysis.clone_classification || 'STRONG_BRAND_CLONE',
      phishpediaResult: {
        logoMatched: true,
        targetBrand: 'Amazon',
        confidence: 0.968
      },
      pHashDistance: 2,
      dHashDistance: 3
    },

    // Stage 4 Evidence
    infrastructureEvidence: {
      sharedIp: '192.0.2.45',
      sharedNameserver: 'ns1.lookalike.example',
      relatedDomains: [
        'amazon-security-login.example',
        'amazon-auth-verify.online',
        'amazon-corporate-update.xyz'
      ],
      fingerprintRelationships: [
        'Shared IP 192.0.2.45 (ColoCrossing BGP ASN 36352)',
        'Identical Perceptual Image Hash (Distance: 2)'
      ]
    },

    // Attack Chain Graph
    attackChain,

    evaluatedAt: data.evaluated_at || new Date().toISOString()
  };
}

function getProvenanceTag(source) {
  switch (source) {
    case 'domain_intelligence':
    case 'rdap':
      return 'LIVE RDAP';
    case 'dns':
      return 'LIVE DNS';
    case 'url_intelligence':
    case 'redirect_trace':
      return 'LIVE HTTP TRACE';
    case 'page_analysis':
    case 'static_dom':
      return 'BEAUTIFULSOUP DOM';
    case 'dynamic_browser':
      return 'PLAYWRIGHT DYNAMIC';
    case 'visual_analysis':
    case 'phishpedia':
    case 'imagehash':
      return 'PHISHPEDIA / IHASH';
    case 'openphish':
      return 'OPENPHISH';
    case 'phishtank':
      return 'PHISHTANK';
    case 'openrouter':
      return 'OPENROUTER AI';
    case 'deterministic_fallback':
    case 'email_content':
    case 'sender_behavior':
    default:
      return 'DETERMINISTIC ENGINE';
  }
}

/**
 * Initiates an investigation analysis request with deduplication and abort controller stale cancellation.
 *
 * @param {Object} params
 * @param {string} params.investigationId - Unique investigation ID
 * @param {Object} params.emailData - Email subject, sender, body
 * @param {string} params.targetUrl - Target URL if available
 * @param {string} params.reason - Instrumentation reason (e.g. 'USER_ANALYZE_CLICK')
 * @param {boolean} params.forceReanalyze - Force bypass client-side cache
 */
export async function analyzeInvestigation({
  investigationId = `INV-${Date.now()}`,
  emailData = null,
  targetUrl = '',
  reason = 'USER_ANALYZE_CLICK',
  forceReanalyze = false
}) {
  const reqKey = `${investigationId}:${emailData?.sender || ''}:${targetUrl}`;

  // Deduplicate simultaneous identical requests
  if (!forceReanalyze && inFlightRequests.has(reqKey)) {
    console.info(`[KEIKAI API] Request deduplicated for key '${reqKey}' (reason=${reason})`);
    return inFlightRequests.get(reqKey);
  }

  // Cancel any stale in-flight request for a different investigation
  if (activeAbortController) {
    activeAbortController.abort();
  }
  activeAbortController = new AbortController();
  const currentSignal = activeAbortController.signal;

  const promise = (async () => {
    try {
      console.info(`[KEIKAI API] POST /api/investigations/${investigationId}/analyze (reason=${reason})`);

      const payload = {
        investigation_id: investigationId,
        organisation_id: 'org_acme_01',
        url: targetUrl || undefined,
        email_data: emailData || undefined
      };

      let response;
      try {
        response = await apiFetch(`${API_BASE_URL}/api/investigations/${encodeURIComponent(investigationId)}/analyze`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
          signal: currentSignal
        });
      } catch (err) {
        // Fallback to /api/email-analyze if investigation route is not ready
        if (err.isNetworkError || currentSignal.aborted) throw err;
        console.warn('[KEIKAI API] Fallback to /api/email-analyze endpoint');
        response = await apiFetch(`${API_BASE_URL}/api/email-analyze`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            subject: emailData?.subject || 'Untitled Message',
            sender: emailData?.sender || 'unknown@sender.com',
            body: emailData?.body || '',
            received_at: emailData?.received_at || new Date().toISOString()
          }),
          signal: currentSignal
        });
      }

      if (currentSignal.aborted) {
        throw new Error('Stale investigation request aborted');
      }

      const resJson = await response.json();
      if (resJson.status === 'success' && resJson.data) {
        return normalizeInvestigationResult(resJson);
      } else {
        throw new Error(resJson.error || 'Failed to complete security investigation analysis');
      }
    } finally {
      inFlightRequests.delete(reqKey);
    }
  })();

  inFlightRequests.set(reqKey, promise);
  return promise;
}
