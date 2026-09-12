import React, { useState, useEffect, useRef } from 'react';
import { Mail, AlertTriangle, ArrowRight, FileText, Search, ShieldAlert, Sparkles, CheckCircle, ExternalLink, RefreshCw, ShieldCheck, Loader2, Info, UserCheck, ShieldX, UserX, Clock, Building2, Upload, QrCode, Paperclip, FileCode, CheckCircle2 } from 'lucide-react';
import { apiFetch, safeParseJson } from '../api';

const API_BASE_URL = 'http://localhost:8000';

const SAMPLE_EMAILS = [
  {
    id: 'sample-1',
    title: 'Internal Account Compromise (Finance Sender Off-Hours)',
    sender: 'finance@acme.example',
    subject: 'URGENT: Corporate Vendor Account Login Verification Required',
    date: 'Today, 02:43',
    body: `Dear Team,

We detected unusual login activity on our Acme Corporate Vendor portal.

Please verify your credentials immediately to prevent service interruption:
https://amazon-security-login.example/auth/login.html

Finance Department
Acme Corporation`
  },
  {
    id: 'sample-2',
    title: 'External Impersonation (No Org Baseline)',
    sender: 'security-alert@amazon-security-login.example',
    subject: 'URGENT: Your Amazon Business Account has been suspended',
    date: 'Today, 14:22',
    body: `Dear Customer,

We detected unusual sign-in activity on your Amazon Corporate Account from an unknown IP address.

Your account access has been temporarily restricted for security reasons. You must verify your account details within 24 hours to prevent permanent suspension.

Please click the secure link below to verify your credentials:
https://amazon-security-login.example/auth/login.html

Thank you for your prompt attention.
Amazon Security Team`
  },
  {
    id: 'sample-3',
    title: 'Password Expiration Warning (Corporate M365)',
    sender: 'no-reply@microsoft-update-portal.online',
    subject: 'Action Required: Corporate Password Expires Today',
    date: 'Today, 11:05',
    body: `SECURITY NOTIFICATION

Your Microsoft 365 domain password is scheduled to expire in 4 hours.

Failure to renew your credentials will cause service interruption to your Microsoft Outlook, Teams, and OneDrive access.

Renew Password Now:
https://microsoft-update-portal.online/login

IT Helpdesk Administration`
  },
  {
    id: 'sample-4',
    title: 'Legitimate Internal Team Update (Benign Baseline)',
    sender: 'alex.rivers@corporate.internal',
    subject: 'Q3 Product Roadmap Review Meeting Notes',
    date: 'Yesterday, 09:15',
    body: `Hi Team,

Thanks for joining the Q3 product roadmap review session this morning.

Please review the updated project timeline document on the team wiki when you have a moment. Let me know if you have any feedback before our Friday sync.

Best regards,
Alex Rivers`
  }
];

const EmailThreatInboxTab = ({
  onNavigateTab,
  setDomainScanState,
  addToast,
  setBrandName,
  investigationContext,
  setInvestigationContext,
  investigationResult,
  handleRunInvestigation,
  isAnalyzing
}) => {
  const [selectedSample, setSelectedSample] = useState(SAMPLE_EMAILS[0]);
  const [customSubject, setCustomSubject] = useState('');
  const [customSender, setCustomSender] = useState('');
  const [customBody, setCustomBody] = useState('');
  const [mode, setMode] = useState('sample'); // 'sample' or 'custom'
  const lastAnalyzedKeyRef = useRef(null);

  const [analyzing, setAnalyzing] = useState(false);
  const [analysisResult, setAnalysisResult] = useState(null);
  const [analysisError, setAnalysisError] = useState(null);

  const [payloadUploading, setPayloadUploading] = useState(false);
  const [payloadResult, setPayloadResult] = useState(null);
  const [payloadError, setPayloadError] = useState(null);

  // Dedicated User-Initiated Gemini AI Insight State (PS Emergency Switch)
  const [aiInsightState, setAiInsightState] = useState({
    status: 'NOT_RUN', // 'NOT_RUN' | 'RUNNING' | 'COMPLETE' | 'FAILED'
    data: null,
    error: null
  });

  const handleFetchAIInsight = async () => {
    if (aiInsightState.status === 'RUNNING') return; // Duplicate click protection

    setAiInsightState({ status: 'RUNNING', data: null, error: null });

    try {
      const activeRes = investigationResult || analysisResult || {};
      const payload = {
        investigation_id: activeRes.analysis_id || activeRes.investigation_id || 'INV-CURRENT',
        subject: activeRes.email?.subject || selectedSample?.subject || customSubject,
        sender: activeRes.email?.sender || selectedSample?.sender || customSender,
        body: activeRes.email?.body || selectedSample?.body || customBody,
        signals: activeRes.signals || {},
        risk_score: activeRes.risk_score || 85,
        severity: activeRes.severity || 'HIGH',
        threat_type: activeRes.threat_type || 'credential_phishing',
        extracted_domains: activeRes.indicators?.domains || [activeRes.extracted_domain].filter(Boolean),
        extracted_urls: activeRes.indicators?.urls || [activeRes.extracted_url].filter(Boolean),
        sender_behavior: activeRes.sender_behavior || {}
      };

      const res = await apiFetch(`${API_BASE_URL}/api/ai-insight`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });

      const respData = await safeParseJson(res);
      if (respData.status === 'success' && respData.data) {
        setAiInsightState({
          status: 'COMPLETE',
          data: respData.data,
          error: null
        });
        addToast('AI Insight Ready', 'Google Gemini 2.5 Flash-Lite reasoning completed.', 'success');
      } else {
        throw new Error(respData.error || 'Failed to fetch AI insight');
      }
    } catch (err) {
      console.error('AI Insight fetch error:', err);
      setAiInsightState({
        status: 'FAILED',
        data: null,
        error: err.message || 'AI Insight service unavailable'
      });
      addToast('AI Insight Error', err.message || 'Failed to complete Gemini AI reasoning', 'error');
    }
  };

  const handleFileUpload = async (e) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setPayloadUploading(true);
    setPayloadError(null);
    setPayloadResult(null);

    try {
      const formData = new FormData();
      formData.append('file', file);

      const res = await apiFetch(`${API_BASE_URL}/api/payload/inspect`, {
        method: 'POST',
        body: formData
      });

      const data = await safeParseJson(res);
      if (data.status === 'success' && data.data) {
        setPayloadResult(data.data);
        addToast('Payload Inspected', `Safely analyzed ${file.name} (SHA256: ${data.data.sha256.slice(0, 12)}...)`, 'success');

        if (data.data.qr_decoded_url && setInvestigationContext) {
          const cleanUrl = sanitizeCanonicalUrl(data.data.qr_decoded_url);
          let domain = '';
          try {
            domain = new URL(cleanUrl).hostname;
          } catch (_) {
            domain = cleanUrl.replace(/^https?:\/\//i, '').split('/')[0];
          }

          setInvestigationContext((prev) => ({
            ...prev,
            source: 'payload_qr',
            domain: domain,
            url: cleanUrl,
            payload_qr_url: cleanUrl,
            payload_risk: data.data.risk_score,
            payload_inspection: data.data
          }));
        }
      } else {
        throw new Error(data.error || 'Failed to inspect payload');
      }
    } catch (err) {
      console.error('Payload inspection failed:', err);
      setPayloadError(err.message || 'Payload inspection failed');
      addToast('Payload Error', err.message || 'Failed to inspect payload', 'error');
    } finally {
      setPayloadUploading(false);
    }
  };

  // Helper to ensure 100% clean canonical URL without markdown syntax
  const sanitizeCanonicalUrl = (rawUrl) => {
    if (!rawUrl) return '';
    let u = rawUrl.trim();
    const mdMatch = u.match(/\]\((https?:\/\/[^\s\)]+)\)/i);
    if (mdMatch) {
      u = mdMatch[1];
    }
    u = u.replace(/^[\s<>"'\[\(\]]+/, '').replace(/[\s<>"'\]\)\.,;]+$/, '');
    if (u.toLowerCase().startsWith('www.')) {
      u = 'https://' + u;
    }
    return u;
  };

  // Trigger real backend analysis via API
  const handleAnalyzeEmail = async (subject, sender, body) => {
    setAnalyzing(true);
    setAnalysisError(null);

    try {
      const res = await apiFetch(`${API_BASE_URL}/api/email-analyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          subject: subject || 'Untitled Message',
          sender: sender || 'unknown@sender.com',
          body: body || '',
          received_at: selectedSample?.date || '02:43'
        })
      });

      const data = await safeParseJson(res);
      if (data.status === 'success' && data.data) {
        const payload = data.data;
        const cleanUrl = sanitizeCanonicalUrl(payload.extracted_url || payload.investigation_target?.url);
        const cleanDomain = payload.extracted_domain || payload.investigation_target?.domain || '';

        setAnalysisResult({
          ...payload,
          extracted_url: cleanUrl,
          extracted_domain: cleanDomain
        });

        if (setInvestigationContext) {
          setInvestigationContext({
            source: 'email',
            analysis_id: payload.analysis_id,
            domain: cleanDomain,
            url: cleanUrl,
            subject: payload.email?.subject || subject || 'Untitled Message',
            sender: payload.email?.sender || sender || 'unknown@sender.com',
            threat_type: payload.threat_type,
            email_risk_score: payload.risk_score,
            severity: payload.severity,
            email_signals: payload.signals,
            email_evidence: payload.signal_evidence,
            email_reasoning: payload.reasoning,
            sender_behavior: payload.sender_behavior,
            organisation: payload.organisation,
            email_stage_complete: true
          });
        }
      } else {
        throw new Error(data.error || 'Failed to analyze email threat');
      }
    } catch (err) {
      console.error('Email threat analysis failed:', err);
      setAnalysisError(err.message || 'Could not complete email threat analysis');
      addToast('Analysis Error', err.message || 'Failed to complete email analysis', 'error');
    } finally {
      setAnalyzing(false);
    }
  };

  // Sync analysisResult with central investigationResult if present
  const activeResult = investigationResult || analysisResult;

  const handleExplicitAnalyzeClick = async () => {
    const sub = mode === 'sample' ? selectedSample.subject : customSubject;
    const snd = mode === 'sample' ? selectedSample.sender : customSender;
    const bdy = mode === 'sample' ? selectedSample.body : customBody;

    if (handleRunInvestigation) {
      const invRes = await handleRunInvestigation({
        emailData: { subject: sub, sender: snd, body: bdy },
        reason: 'USER_EXPLICIT_ANALYZE'
      });
      if (invRes) setAnalysisResult(invRes);
    } else {
      handleAnalyzeEmail(sub, snd, bdy);
    }
  };

  const handleCustomSubmit = (e) => {
    e.preventDefault();
    if (!customBody.trim() && !customSubject.trim()) {
      addToast('Validation Error', 'Please paste email body or subject to analyze.', 'error');
      return;
    }
    handleAnalyzeEmail(customSubject, customSender, customBody);
  };

  const handleLaunchInvestigation = () => {
    const targetDomain = analysisResult?.extracted_domain || analysisResult?.investigation_target?.domain;
    if (!targetDomain) {
      addToast('Validation Error', 'No extracted domain found to investigate.', 'error');
      return;
    }

    const cleanBrand = targetDomain.split('.')[0].replace(/[-_]/g, ' ');
    const formattedBrand = cleanBrand.charAt(0).toUpperCase() + cleanBrand.slice(1);

    if (setBrandName) {
      setBrandName(formattedBrand);
    }

    if (setDomainScanState) {
      setDomainScanState((prev) => ({
        ...prev,
        domainInput: targetDomain,
        results: null
      }));
    }

    addToast('Extracted Threat IOC', `Extracted target domain '${targetDomain}'. Handoff to Threat Intelligence investigation.`, 'success');
    onNavigateTab('domain');
  };

  const renderSeverityBadge = (severity) => {
    switch (severity) {
      case 'CRITICAL':
        return <span className="px-2.5 py-1 rounded bg-error/10 text-error text-xs font-bold font-technical-data flex items-center gap-1"><AlertTriangle size={14} /> CRITICAL THREAT</span>;
      case 'HIGH':
        return <span className="px-2.5 py-1 rounded bg-error/10 text-error text-xs font-bold font-technical-data flex items-center gap-1"><AlertTriangle size={14} /> HIGH RISK</span>;
      case 'MEDIUM':
        return <span className="px-2.5 py-1 rounded bg-[#f59e0b]/10 text-[#d97706] text-xs font-bold font-technical-data flex items-center gap-1"><AlertTriangle size={14} /> MEDIUM RISK</span>;
      case 'LOW':
        return <span className="px-2.5 py-1 rounded bg-info/10 text-info text-xs font-bold font-technical-data flex items-center gap-1"><Info size={14} /> LOW RISK</span>;
      default:
        return <span className="px-2.5 py-1 rounded bg-[#10b981]/10 text-[#059669] text-xs font-bold font-technical-data flex items-center gap-1"><ShieldCheck size={14} /> BENIGN EMAIL</span>;
    }
  };

  const renderHypothesisBadge = (hypothesis, label) => {
    switch (hypothesis) {
      case 'POSSIBLE_ACCOUNT_COMPROMISE':
        return <span className="px-2.5 py-1 rounded bg-error/10 text-error text-xs font-bold font-technical-data flex items-center gap-1"><UserX size={14} /> {label || 'Possible Account Compromise'}</span>;
      case 'SUSPICIOUS_BEHAVIOR':
        return <span className="px-2.5 py-1 rounded bg-[#f59e0b]/10 text-[#d97706] text-xs font-bold font-technical-data flex items-center gap-1"><AlertTriangle size={14} /> {label || 'Suspicious Sender Behavior'}</span>;
      case 'BENIGN_INTERNAL':
        return <span className="px-2.5 py-1 rounded bg-[#10b981]/10 text-[#059669] text-xs font-bold font-technical-data flex items-center gap-1"><UserCheck size={14} /> {label || 'Benign Internal Sender'}</span>;
      default:
        return <span className="px-2.5 py-1 rounded bg-surface-container text-on-surface-variant text-xs font-semibold font-technical-data flex items-center gap-1"><Info size={14} /> {label || 'No Organisational Baseline'}</span>;
    }
  };

  return (
    <div className="space-y-6 animate-arrive-1">
      {/* Top Banner & Header */}
      <div className="bg-surface-container-lowest border border-outline-variant rounded-xl p-6 shadow-sm flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <span className="p-2 bg-primary/10 text-primary rounded-lg">
              <Mail size={22} />
            </span>
            <div>
              <h1 className="font-headline-md text-2xl font-bold text-on-background tracking-tight">
                Threat Inbox &amp; Organisational Sender Intelligence
              </h1>
              <p className="font-body-md text-xs text-on-surface-variant">
                Analyze email payloads, compare sender activity against organizational baselines, detect account compromises, and extract target IOCs.
              </p>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2 self-start md:self-auto">
          <button
            type="button"
            onClick={() => {
              setAnalysisResult(null);
              setAnalysisError(null);
              setPayloadResult(null);
              setSelectedSample(SAMPLE_EMAILS[0]);
              setMode('sample');
              lastAnalyzedKeyRef.current = null;
              if (setInvestigationContext) setInvestigationContext(null);
              addToast('Session Reset', 'Investigation state and evidence cache reset cleanly for new analysis session.', 'info');
            }}
            className="px-3 py-1.5 bg-surface-container hover:bg-surface-bright rounded-lg text-xs font-technical-data font-semibold text-on-surface-variant border border-outline-variant flex items-center gap-1.5 transition-all cursor-pointer"
            title="Reset active investigation context"
          >
            <RefreshCw size={13} className="text-primary" />
            <span>Reset Session</span>
          </button>
          <span className="px-3 py-1.5 bg-surface-container rounded-full text-xs font-technical-data font-semibold text-primary border border-outline-variant flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-primary animate-pulse inline-block"></span>
            Sender Behaviour Engine Active
          </span>
        </div>
      </div>

      {/* Main Inbox Interface Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: Message Selector & Samples (4 cols) */}
        <div className="lg:col-span-4 space-y-4">
          <div className="bg-surface-container-lowest border border-outline-variant rounded-xl p-4 space-y-3">
            <div className="flex items-center justify-between pb-2 border-b border-outline-variant">
              <h3 className="font-headline-md text-sm font-bold text-on-background flex items-center gap-1.5">
                <FileText size={16} className="text-primary" />
                <span>Suspicious Message Queue</span>
              </h3>
              <span className="text-[11px] font-technical-data text-on-surface-variant font-medium">
                {SAMPLE_EMAILS.length} Items
              </span>
            </div>

            <div className="flex bg-surface-container-low rounded-lg p-1 text-xs">
              <button
                type="button"
                onClick={() => setMode('sample')}
                className={`flex-1 py-1.5 font-medium rounded-md transition-all ${
                  mode === 'sample' ? 'bg-surface text-primary shadow-xs font-semibold' : 'text-on-surface-variant'
                }`}
              >
                Sample Threats
              </button>
              <button
                type="button"
                onClick={() => { setMode('custom'); setAnalysisResult(null); }}
                className={`flex-1 py-1.5 font-medium rounded-md transition-all ${
                  mode === 'custom' ? 'bg-surface text-primary shadow-xs font-semibold' : 'text-on-surface-variant'
                }`}
              >
                Paste Custom Email
              </button>
            </div>

            {mode === 'sample' && (
              <div className="space-y-2 pt-1">
                {SAMPLE_EMAILS.map((sample) => (
                  <button
                    key={sample.id}
                    type="button"
                    onClick={() => setSelectedSample(sample)}
                    className={`w-full text-left p-3 rounded-lg border transition-all flex flex-col gap-1.5 ${
                      selectedSample.id === sample.id
                        ? 'bg-primary/5 border-primary shadow-xs'
                        : 'bg-surface border-outline-variant hover:bg-surface-bright'
                    }`}
                  >
                    <div className="flex items-center justify-between text-xs">
                      <span className="font-bold text-on-background line-clamp-1">{sample.title}</span>
                      <span className="text-[10px] text-on-surface-variant shrink-0 font-technical-data">{sample.date}</span>
                    </div>
                    <p className="text-[11px] text-on-surface-variant font-technical-data line-clamp-1">
                      From: {sample.sender}
                    </p>
                  </button>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Right Column: Message Detail & Real Analysis Results (8 cols) */}
        <div className="lg:col-span-8 space-y-4">
          <div className="bg-surface-container-lowest border border-outline-variant rounded-xl p-6 space-y-6">
            {mode === 'sample' ? (
              <>
                {/* Header Information */}
                <div className="space-y-3 pb-4 border-b border-outline-variant">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    {analyzing ? (
                      <span className="px-2.5 py-1 rounded bg-primary/10 text-primary text-xs font-bold font-technical-data flex items-center gap-1.5">
                        <Loader2 size={14} className="animate-spin" /> ANALYZING MESSAGE...
                      </span>
                    ) : analysisResult ? (
                      <div className="flex items-center gap-2">
                        {renderSeverityBadge(analysisResult.severity)}
                        {analysisResult.sender_behavior && renderHypothesisBadge(
                          analysisResult.sender_behavior.hypothesis,
                          analysisResult.sender_behavior.hypothesis_label
                        )}
                      </div>
                    ) : null}

                    <span className="text-xs font-technical-data text-on-surface-variant">
                      Received: {selectedSample.date}
                    </span>
                  </div>

                  <h2 className="font-headline-md text-lg font-bold text-on-background">
                    {selectedSample.subject}
                  </h2>

                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs font-technical-data bg-surface-container-low p-3 rounded-lg border border-outline-variant">
                    <div>
                      <span className="text-on-surface-variant">Sender: </span>
                      <span className="font-semibold text-on-background">{selectedSample.sender}</span>
                    </div>
                    <div>
                      <span className="text-on-surface-variant">Organisation: </span>
                      <span className="font-semibold text-primary font-technical-data">
                        {analysisResult?.organisation?.name || 'Acme Corporation (Demo)'}
                      </span>
                    </div>
                  </div>
                </div>

                {/* Email Body Content */}
                <div className="space-y-2">
                  <label className="block text-xs font-label-caps text-on-surface-variant">
                    Raw Email Payload Preview
                  </label>
                  <div className="p-4 bg-surface rounded-lg border border-outline-variant font-mono text-xs text-on-background whitespace-pre-wrap leading-relaxed max-h-[160px] overflow-y-auto">
                    {selectedSample.body}
                  </div>
                  <div className="flex justify-end pt-2">
                    <button
                      type="button"
                      onClick={handleExplicitAnalyzeClick}
                      disabled={analyzing || isAnalyzing}
                      className="btn-primary py-2 px-6 rounded-lg text-xs font-bold inline-flex items-center gap-2 shadow-xs cursor-pointer"
                    >
                      {analyzing || isAnalyzing ? (
                        <>
                          <Loader2 size={14} className="animate-spin" />
                          <span>Analyzing Security Threat...</span>
                        </>
                      ) : (
                        <>
                          <Sparkles size={14} />
                          <span>Analyze Threat &amp; Sender Telemetry</span>
                        </>
                      )}
                    </button>
                  </div>
                </div>
              </>
            ) : (
              /* Custom Email Input Mode */
              <form onSubmit={handleCustomSubmit} className="space-y-4 pb-4 border-b border-outline-variant">
                <div className="space-y-1">
                  <h3 className="font-headline-md text-base font-bold text-on-background">
                    Paste Custom Email / Headers
                  </h3>
                  <p className="text-xs text-on-surface-variant">
                    Paste any raw email subject, sender, and message body to run real-time threat parsing &amp; sender modeling.
                  </p>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                  <div className="space-y-1">
                    <label className="block text-xs font-label-caps text-on-surface-variant">Subject</label>
                    <input
                      type="text"
                      value={customSubject}
                      onChange={(e) => setCustomSubject(e.target.value)}
                      placeholder="e.g. URGENT: Password Verification Required"
                      className="w-full px-3 py-2 bg-surface rounded-lg border border-outline-variant font-body-md text-xs text-on-background outline-none focus:border-primary"
                    />
                  </div>
                  <div className="space-y-1">
                    <label className="block text-xs font-label-caps text-on-surface-variant">Sender</label>
                    <input
                      type="text"
                      value={customSender}
                      onChange={(e) => setCustomSender(e.target.value)}
                      placeholder="e.g. finance@acme.example"
                      className="w-full px-3 py-2 bg-surface rounded-lg border border-outline-variant font-body-md text-xs text-on-background outline-none focus:border-primary"
                    />
                  </div>
                </div>

                <div className="space-y-1">
                  <label className="block text-xs font-label-caps text-on-surface-variant">Message Body</label>
                  <textarea
                    rows={4}
                    value={customBody}
                    onChange={(e) => setCustomBody(e.target.value)}
                    placeholder="Paste raw email text here..."
                    className="w-full p-3 bg-surface rounded-lg border border-outline-variant font-mono text-xs text-on-background outline-none focus:border-primary"
                  />
                </div>

                <div className="flex justify-end">
                  <button
                    type="submit"
                    disabled={analyzing}
                    className="btn-primary py-2 px-6 rounded-lg text-xs font-bold inline-flex items-center gap-2"
                  >
                    {analyzing ? (
                      <>
                        <Loader2 size={14} className="animate-spin" />
                        <span>Analyzing Message...</span>
                      </>
                    ) : (
                      <>
                        <Sparkles size={14} />
                        <span>Analyze Email &amp; Sender Baseline</span>
                      </>
                    )}
                  </button>
                </div>
              </form>
            )}

            {/* Analysis Result Loading State */}
            {analyzing && (
              <div className="py-8 text-center space-y-3 bg-surface-container-low rounded-xl border border-outline-variant">
                <Loader2 size={28} className="animate-spin text-primary mx-auto" />
                <p className="text-xs font-technical-data text-on-surface-variant">
                  Evaluating sender behavioral telemetry &amp; extracted IOCs...
                </p>
              </div>
            )}

            {/* Structured Analysis Results Output Card */}
            {!analyzing && analysisResult && (
              <div className="space-y-5 animate-arrive-2">
                {/* Risk & Anomaly Scores Summary Banner */}
                <div className="bg-surface-container-low border border-outline-variant rounded-xl p-5 flex flex-col sm:flex-row items-center justify-between gap-4">
                  <div className="flex items-center gap-4">
                    {/* Dual Score Indicators */}
                    <div className="flex items-center gap-3">
                      <div className="text-center">
                        <div className="w-14 h-14 rounded-full bg-surface border-4 border-primary flex items-center justify-center font-technical-data font-bold text-lg text-primary mx-auto">
                          {analysisResult.risk_score}
                        </div>
                        <span className="text-[10px] font-technical-data text-on-surface-variant block mt-1">Payload Risk</span>
                      </div>

                      {analysisResult.sender_behavior && (
                        <div className="text-center">
                          <div className={`w-14 h-14 rounded-full bg-surface border-4 flex items-center justify-center font-technical-data font-bold text-lg mx-auto ${
                            analysisResult.sender_behavior.anomaly_score >= 50 ? 'border-error text-error' : 'border-[#10b981] text-[#059669]'
                          }`}>
                            {analysisResult.sender_behavior.anomaly_score}
                          </div>
                          <span className="text-[10px] font-technical-data text-on-surface-variant block mt-1">Behavior Anomaly</span>
                        </div>
                      )}
                    </div>

                    <div className="space-y-1">
                      <div className="flex flex-wrap items-center gap-2">
                        <h4 className="font-headline-md text-base font-bold text-on-background">
                          Threat Severity: {analysisResult.severity}
                        </h4>
                        <span className="text-[11px] font-technical-data bg-surface-container px-2 py-0.5 rounded border text-on-surface">
                          Confidence: {Math.round((analysisResult.confidence || 0.9) * 100)}%
                        </span>
                      </div>
                      <p className="text-xs text-on-surface-variant font-technical-data">
                        Classification: <strong className="text-primary">{analysisResult.threat_type}</strong>
                      </p>
                    </div>
                  </div>

                  {analysisResult.investigation_ready && (
                    <button
                      type="button"
                      onClick={handleLaunchInvestigation}
                      className="btn-primary py-2.5 px-5 rounded-lg text-xs font-bold inline-flex items-center gap-2 shadow-xs whitespace-nowrap"
                    >
                      <span>Analyze Threat Intelligence</span>
                      <ArrowRight size={15} />
                    </button>
                  )}
                </div>

                {/* ── CONTENT ANALYSIS & NATURAL LANGUAGE INTENT SIGNALS (PS REQ 1) ── */}
                <div id="content-analysis-section" className="bg-surface border border-outline-variant rounded-xl p-5 space-y-4 shadow-xs">
                  <div className="flex items-center justify-between border-b border-outline-variant pb-3">
                    <h4 className="font-headline-md text-xs font-bold text-on-background flex items-center gap-2">
                      <FileText size={16} className="text-primary" />
                      <span>CONTENT ANALYSIS &amp; NATURAL LANGUAGE INTENT SIGNALS</span>
                    </h4>
                    <span className="text-[10px] font-technical-data bg-primary/10 text-primary px-2 py-0.5 rounded font-bold uppercase">
                      NLP Engine Active
                    </span>
                  </div>

                  <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 text-xs font-technical-data">
                    <div className={`p-3 rounded-lg border ${analysisResult.signals?.urgency_language ? 'bg-error/10 border-error/30 text-error' : 'bg-surface-container-low border-outline-variant text-on-surface-variant'}`}>
                      <span className="text-[10px] uppercase font-bold block opacity-75">Urgent Language</span>
                      <strong className="text-xs font-semibold">{analysisResult.signals?.urgency_language ? '⚠️ DETECTED' : '✓ Normal'}</strong>
                    </div>

                    <div className={`p-3 rounded-lg border ${analysisResult.signals?.sender_domain_mismatch || analysisResult.signals?.brand_impersonation ? 'bg-error/10 border-error/30 text-error' : 'bg-surface-container-low border-outline-variant text-on-surface-variant'}`}>
                      <span className="text-[10px] uppercase font-bold block opacity-75">Authority Impersonation</span>
                      <strong className="text-xs font-semibold">{analysisResult.signals?.sender_domain_mismatch || analysisResult.signals?.brand_impersonation ? '⚠️ DETECTED' : '✓ Normal'}</strong>
                    </div>

                    <div className={`p-3 rounded-lg border ${analysisResult.signals?.credential_request ? 'bg-error/10 border-error/30 text-error' : 'bg-surface-container-low border-outline-variant text-on-surface-variant'}`}>
                      <span className="text-[10px] uppercase font-bold block opacity-75">Credential Request</span>
                      <strong className="text-xs font-semibold">{analysisResult.signals?.credential_request ? '⚠️ DETECTED' : '✓ Normal'}</strong>
                    </div>

                    <div className={`p-3 rounded-lg border ${analysisResult.signals?.brand_impersonation ? 'bg-error/10 border-error/30 text-error' : 'bg-surface-container-low border-outline-variant text-on-surface-variant'}`}>
                      <span className="text-[10px] uppercase font-bold block opacity-75">Brand Impersonation</span>
                      <strong className="text-xs font-semibold">{analysisResult.signals?.brand_impersonation ? '⚠️ DETECTED' : '✓ Normal'}</strong>
                    </div>

                    <div className={`p-3 rounded-lg border ${analysisResult.signals?.suspicious_link ? 'bg-error/10 border-error/30 text-error' : 'bg-surface-container-low border-outline-variant text-on-surface-variant'}`}>
                      <span className="text-[10px] uppercase font-bold block opacity-75">Suspicious Link Path</span>
                      <strong className="text-xs font-semibold">{analysisResult.signals?.suspicious_link ? '⚠️ DETECTED' : '✓ Normal'}</strong>
                    </div>

                    <div className={`p-3 rounded-lg border ${analysisResult.signals?.financial_request ? 'bg-error/10 border-error/30 text-error' : 'bg-surface-container-low border-outline-variant text-on-surface-variant'}`}>
                      <span className="text-[10px] uppercase font-bold block opacity-75">Financial Request</span>
                      <strong className="text-xs font-semibold">{analysisResult.signals?.financial_request ? '⚠️ DETECTED' : '✓ Normal'}</strong>
                    </div>
                  </div>

                  {/* WHY THIS MATTERS CALLOUT */}
                  <div className="p-3.5 rounded-lg bg-surface-container-low border border-outline-variant text-xs text-on-background space-y-1">
                    <span className="font-bold text-[11px] text-primary uppercase block">WHY THIS MATTERS</span>
                    <p className="leading-relaxed text-on-surface-variant">
                      {analysisResult.signals?.urgency_language && analysisResult.signals?.credential_request
                        ? 'Message employs psychological urgency tactics and authority pressure to force the recipient into immediate credential verification before suspicious infrastructure is flagged.'
                        : analysisResult.signals?.brand_impersonation
                        ? 'Message imitates a recognized corporate brand while transmitting from an unauthenticated external domain.'
                        : 'Content analysis evaluates natural language patterns against established phishing intent baselines.'}
                    </p>
                  </div>
                </div>

                {/* Sender Behavioral Telemetry Card (PHASE 2) */}
                {analysisResult.sender_behavior && (
                  <div className="bg-surface border border-outline-variant rounded-xl p-4 space-y-3">
                    <div className="flex items-center justify-between border-b border-outline-variant pb-2.5">
                      <h4 className="font-headline-md text-xs font-bold text-on-background flex items-center gap-1.5">
                        <Building2 size={15} className="text-primary" />
                        <span>Organisational Sender Intelligence</span>
                      </h4>

                      <div className="flex items-center gap-2">
                        <span className="text-[11px] font-technical-data text-on-surface-variant">
                          Baseline: <strong className={analysisResult.sender_behavior.profile_available ? 'text-primary' : 'text-on-surface-variant'}>
                            {analysisResult.sender_behavior.profile_available ? 'Available (Internal Profile)' : 'No Baseline (External)'}
                          </strong>
                        </span>
                      </div>
                    </div>

                    {analysisResult.sender_behavior.profile_available ? (
                      <div className="space-y-3">
                        {/* Behavioral Signals */}
                        {analysisResult.sender_behavior.signals && analysisResult.sender_behavior.signals.length > 0 ? (
                          <div className="space-y-1.5">
                            <span className="text-[11px] font-label-caps text-on-surface-variant block">Behavioral Anomaly Signals Detected</span>
                            <div className="space-y-1">
                              {analysisResult.sender_behavior.signals.map((sig, idx) => (
                                <div key={idx} className="p-2 rounded bg-error/5 border border-error/20 text-xs text-error font-technical-data flex items-start gap-2">
                                  <AlertTriangle size={14} className="shrink-0 mt-0.5" />
                                  <span>{sig.evidence}</span>
                                </div>
                              ))}
                            </div>
                          </div>
                        ) : (
                          <div className="p-2.5 rounded bg-[#10b981]/10 border border-[#10b981]/20 text-xs text-[#059669] font-technical-data flex items-center gap-2">
                            <ShieldCheck size={16} />
                            <span>Sender activity strictly aligns with established organizational behavioral baseline.</span>
                          </div>
                        )}

                        {/* Baseline vs Observed Telemetry Grid */}
                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs font-technical-data bg-surface-container-low p-3 rounded-lg border border-outline-variant">
                          <div className="space-y-1">
                            <span className="text-on-surface-variant text-[11px] block font-bold">Observed Telemetry</span>
                            <div>• Sending Time: <strong className="text-on-background">{analysisResult.sender_behavior.observed?.sending_hour || 'N/A'}</strong></div>
                            <div>• Target Domains: <strong className="text-primary">{analysisResult.sender_behavior.observed?.destination_domains?.join(', ') || 'None'}</strong></div>
                            <div>• Credential URL: <strong className="text-on-background">{analysisResult.sender_behavior.observed?.credential_url_present ? 'Yes' : 'No'}</strong></div>
                          </div>

                          <div className="space-y-1 border-t sm:border-t-0 sm:border-l border-outline-variant pt-2 sm:pt-0 sm:pl-3">
                            <span className="text-on-surface-variant text-[11px] block font-bold">Organisational Profile ({analysisResult.sender_behavior.role})</span>
                            <div>• Operational Hours: <strong className="text-on-background">{analysisResult.sender_behavior.baseline?.allowed_hours}</strong></div>
                            <div>• Typical Domains: <strong className="text-on-background">{analysisResult.sender_behavior.baseline?.typical_domains?.join(', ')}</strong></div>
                            <div>• Link Usage Profile: <strong className="text-on-background">{analysisResult.sender_behavior.baseline?.url_frequency}</strong></div>
                          </div>
                        </div>
                      </div>
                    ) : (
                      <p className="text-xs text-on-surface-variant font-technical-data">
                        External sender account (<code className="text-primary">{analysisResult.sender_behavior.sender}</code>) does not possess an internal organizational baseline profile. Analysis relies on payload IOCs, domain intelligence, and visual verification.
                      </p>
                    )}
                  </div>
                )}

                {/* Reasoning Bullet Points */}
                {analysisResult.reasoning && analysisResult.reasoning.length > 0 && (
                  <div className="space-y-2">
                    <h4 className="font-headline-md text-xs font-label-caps text-on-surface-variant">
                      Explainable Security Reasoning
                    </h4>
                    <div className="bg-surface p-4 rounded-xl border border-outline-variant space-y-2">
                      {analysisResult.reasoning.map((r, idx) => (
                        <div key={idx} className="flex items-start gap-2 text-xs text-on-background leading-relaxed">
                          <span className="text-primary font-bold">•</span>
                          <span>{r}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* ── DEDICATED GOOGLE GEMINI 2.5 FLASH-LITE AI INSIGHT SECTION ── */}
                <div id="ai-insight-section" className="bg-surface border border-primary/40 rounded-xl p-5 space-y-4 shadow-sm">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-outline-variant pb-3">
                    <div>
                      <h4 className="font-headline-md text-xs font-bold text-on-background flex items-center gap-2">
                        <Sparkles size={16} className="text-primary" />
                        <span>AI INVESTIGATION INSIGHT</span>
                      </h4>
                      <div className="flex items-center gap-3 text-[11px] font-technical-data text-on-surface-variant mt-0.5">
                        <span>Provider: <strong className="text-on-background">Google Gemini</strong></span>
                        <span>•</span>
                        <span>Model: <strong className="text-primary">gemini-2.5-flash-lite</strong></span>
                        <span>•</span>
                        <span>Status: <strong className={aiInsightState.status === 'COMPLETE' ? 'text-[#059669]' : aiInsightState.status === 'RUNNING' ? 'text-primary' : 'text-on-surface-variant'}>{aiInsightState.status}</strong></span>
                      </div>
                    </div>

                    {/* ✨ GET AI INSIGHT BUTTON */}
                    <button
                      type="button"
                      onClick={handleFetchAIInsight}
                      disabled={aiInsightState.status === 'RUNNING'}
                      className="btn-primary py-2.5 px-5 rounded-lg text-xs font-bold inline-flex items-center gap-2 shadow-xs shrink-0 disabled:opacity-50"
                    >
                      {aiInsightState.status === 'RUNNING' ? (
                        <>
                          <Loader2 size={14} className="animate-spin text-on-primary" />
                          <span>Generating Gemini Insight...</span>
                        </>
                      ) : aiInsightState.status === 'COMPLETE' ? (
                        <>
                          <RefreshCw size={14} />
                          <span>Regenerate AI Insight</span>
                        </>
                      ) : (
                        <>
                          <Sparkles size={14} />
                          <span>✨ GET AI INSIGHT</span>
                        </>
                      )}
                    </button>
                  </div>

                  {/* AI INSIGHT CONTENT */}
                  {aiInsightState.status === 'NOT_RUN' && (
                    <p className="text-xs text-on-surface-variant font-technical-data">
                      Click <strong className="text-primary">✨ GET AI INSIGHT</strong> above to trigger user-initiated Google Gemini 2.5 Flash-Lite reasoning over normalized investigation evidence.
                    </p>
                  )}

                  {aiInsightState.status === 'FAILED' && (
                    <div className="p-3.5 rounded-lg bg-error/10 border border-error/30 text-xs text-error space-y-1 font-technical-data">
                      <span className="font-bold block">AI INSIGHT UNAVAILABLE</span>
                      <p>{aiInsightState.error || 'Gemini AI provider unavailable. Operating with deterministic engine.'}</p>
                    </div>
                  )}

                  {aiInsightState.status === 'COMPLETE' && aiInsightState.data && (
                    <div className="space-y-4 text-xs font-technical-data animate-fade-in">
                      <div className="p-3.5 rounded-lg bg-surface-container-low border border-outline-variant space-y-1">
                        <span className="font-bold text-primary block text-[11px] uppercase">EXECUTIVE SUMMARY</span>
                        <p className="text-on-background leading-relaxed">{aiInsightState.data.summary}</p>
                      </div>

                      <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-3 text-xs">
                        <div className="bg-surface p-2.5 rounded border border-outline-variant">
                          <span className="text-[10px] text-on-surface-variant block uppercase font-bold">CLASSIFICATION</span>
                          <strong className="text-error block">{aiInsightState.data.classification || 'PHISHING'}</strong>
                        </div>
                        <div className="bg-surface p-2.5 rounded border border-outline-variant">
                          <span className="text-[10px] text-on-surface-variant block uppercase font-bold">CONFIDENCE</span>
                          <strong className="text-primary block">{Math.round((aiInsightState.data.confidence || 0.95) * 100)}%</strong>
                        </div>
                        <div className="bg-surface p-2.5 rounded border border-outline-variant">
                          <span className="text-[10px] text-on-surface-variant block uppercase font-bold">RECOMMENDED ACTION</span>
                          <strong className="text-error block">{aiInsightState.data.recommended_action || 'BLOCK'}</strong>
                        </div>
                        <div className="bg-surface p-2.5 rounded border border-outline-variant">
                          <span className="text-[10px] text-on-surface-variant block uppercase font-bold">REASONING SOURCE</span>
                          <strong className="text-on-background block">{aiInsightState.data.provider || 'Google Gemini'}</strong>
                        </div>
                      </div>

                      <div className="space-y-2">
                        <span className="font-bold text-on-background block text-[11px] uppercase">ATTACK HYPOTHESIS</span>
                        <p className="p-3 rounded bg-surface border border-outline-variant text-on-surface-variant leading-relaxed">
                          {aiInsightState.data.attack_hypothesis}
                        </p>
                      </div>

                      {aiInsightState.data.supporting_evidence && aiInsightState.data.supporting_evidence.length > 0 && (
                        <div className="space-y-2">
                          <span className="font-bold text-on-background block text-[11px] uppercase">SUPPORTING EVIDENCE</span>
                          <div className="space-y-1.5">
                            {aiInsightState.data.supporting_evidence.map((ev, idx) => (
                              <div key={idx} className="p-2.5 rounded bg-surface border border-outline-variant text-xs text-on-background flex items-start gap-2">
                                <span className="text-primary font-bold">•</span>
                                <span>{typeof ev === 'string' ? ev : ev.evidence || JSON.stringify(ev)}</span>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  )}
                </div>

                {/* Extracted IOCs Summary */}
                <div className="bg-primary/5 border border-primary/20 rounded-xl p-4 space-y-3">
                  <div className="flex items-center justify-between">
                    <h4 className="font-headline-md text-xs font-bold text-on-background flex items-center gap-1.5">
                      <Sparkles size={14} className="text-primary" />
                      Extracted Threat Indicators (IOCs)
                    </h4>
                    <span className="text-[11px] text-primary font-semibold font-technical-data">
                      {analysisResult.extracted_domain ? `Target Domain: ${analysisResult.extracted_domain}` : 'No target domain extracted'}
                    </span>
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs font-technical-data">
                    <div className="bg-surface p-2.5 rounded border border-outline-variant">
                      <span className="text-on-surface-variant text-[11px] block">Extracted Domains ({analysisResult.indicators?.domains?.length || 0})</span>
                      <span className="font-bold text-primary truncate block">
                        {analysisResult.indicators?.domains?.join(', ') || 'None'}
                      </span>
                    </div>
                    <div className="bg-surface p-2.5 rounded border border-outline-variant">
                      <span className="text-on-surface-variant text-[11px] block">Extracted URLs ({analysisResult.indicators?.urls?.length || 0})</span>
                      <span className="font-semibold text-on-background truncate block">
                        {analysisResult.indicators?.urls?.join(', ') || 'None'}
                      </span>
                    </div>
                  </div>
                </div>

                {/* Safe Static Payload Inspection & QR Code Inspector (PHASE 3) */}
                <div className="bg-surface border border-outline-variant rounded-xl p-5 space-y-4">
                  <div className="flex items-center justify-between border-b border-outline-variant pb-3">
                    <h4 className="font-headline-md text-xs font-bold text-on-background flex items-center gap-2">
                      <QrCode size={16} className="text-primary" />
                      <span>Safe Static Payload &amp; QR Code Inspector</span>
                    </h4>
                    <span className="text-[10px] font-technical-data bg-primary/10 text-primary px-2 py-0.5 rounded font-bold">
                      NON-EXECUTABLE PARSING
                    </span>
                  </div>

                  <p className="text-xs text-on-surface-variant leading-relaxed">
                    Upload suspicious email attachments, QR code screenshots, or HTML files for isolated static inspection. Extracts QR embedded links, form action targets, password fields, PDF text, and archive metadata without executing DOM or scripts.
                  </p>

                  <div className="flex items-center gap-3">
                    <label className="btn-secondary py-2 px-4 rounded-lg text-xs font-bold inline-flex items-center gap-2 cursor-pointer border border-outline-variant hover:border-primary">
                      {payloadUploading ? (
                        <>
                          <Loader2 size={14} className="animate-spin text-primary" />
                          <span>Inspecting File...</span>
                        </>
                      ) : (
                        <>
                          <Upload size={14} className="text-primary" />
                          <span>Upload File / QR Code</span>
                        </>
                      )}
                      <input
                        type="file"
                        className="hidden"
                        accept="image/*,.html,.htm,.pdf,.docx,.zip"
                        onChange={handleFileUpload}
                        disabled={payloadUploading}
                      />
                    </label>
                    <span className="text-[11px] text-on-surface-variant font-technical-data">
                      Supports PNG/JPG QR images, HTML forms, PDF, DOCX, ZIP archives (max 10MB)
                    </span>
                  </div>

                  {/* Inspection Results Card */}
                  {payloadResult && (
                    <div className="bg-surface-container-low p-4 rounded-xl border border-primary/30 space-y-3 font-technical-data animate-arrive-1">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <CheckCircle2 size={16} className="text-[#10b981]" />
                          <span className="text-xs font-bold text-on-background">
                            File: {payloadResult.filename} ({payloadResult.file_type})
                          </span>
                        </div>
                        <div className="flex items-center gap-2">
                          <span className="text-[10px] text-on-surface-variant">
                            SHA256: <code className="text-primary font-bold">{payloadResult.sha256.slice(0, 16)}...</code>
                          </span>
                          <span className={`text-[10px] px-2 py-0.5 rounded font-bold ${
                            payloadResult.risk_score >= 70 ? 'bg-error/10 text-error' : 'bg-[#10b981]/10 text-[#059669]'
                          }`}>
                            Risk Score: {payloadResult.risk_score}/100
                          </span>
                        </div>
                      </div>

                      {/* QR Code Decoded Result */}
                      {payloadResult.qr_detected && (
                        <div className="p-3 bg-primary/10 border border-primary/30 rounded-lg space-y-2">
                          <div className="flex items-center justify-between">
                            <span className="text-xs font-bold text-primary flex items-center gap-1.5">
                              <QrCode size={14} /> QR Code URL Decoded
                            </span>
                            <span className="text-[10px] text-primary font-bold">STRICT STATIC DECODE</span>
                          </div>
                          <code className="block text-xs font-mono font-bold text-on-background break-all bg-surface p-2 rounded border border-outline-variant">
                            {payloadResult.qr_decoded_url}
                          </code>
                          <div className="flex justify-end">
                            <button
                              type="button"
                              onClick={() => {
                                const cleanUrl = sanitizeCanonicalUrl(payloadResult.qr_decoded_url);
                                handleLaunchInvestigation();
                              }}
                              className="btn-primary py-1.5 px-3 rounded text-[11px] font-bold inline-flex items-center gap-1.5"
                            >
                              <span>Transfer QR URL to Threat Intelligence</span>
                              <ArrowRight size={13} />
                            </button>
                          </div>
                        </div>
                      )}

                      {/* HTML Static Analysis Result */}
                      {payloadResult.file_type === 'html' && payloadResult.html_analysis && (
                        <div className="p-3 bg-surface border border-outline-variant rounded-lg space-y-2">
                          <span className="text-xs font-bold text-on-background block">HTML Static Form Inspection</span>
                          <div className="grid grid-cols-2 gap-2 text-xs">
                            <div>• Form Action URLs: <strong>{payloadResult.html_analysis.form_actions?.length || 0}</strong></div>
                            <div>• Password Input Fields: <strong className={payloadResult.html_analysis.password_inputs_found ? 'text-error' : 'text-on-background'}>{payloadResult.html_analysis.password_inputs_found ? 'DETECTED' : 'None'}</strong></div>
                            <div>• External Scripts: <strong>{payloadResult.html_analysis.external_scripts?.length || 0}</strong></div>
                            <div>• Extracted Links: <strong>{payloadResult.html_analysis.extracted_links?.length || 0}</strong></div>
                          </div>
                          {payloadResult.html_analysis.form_actions?.length > 0 && (
                            <div className="text-[11px] text-on-surface-variant">
                              Form Action Targets: <code className="text-primary font-bold">{payloadResult.html_analysis.form_actions.join(', ')}</code>
                            </div>
                          )}
                        </div>
                      )}

                      {/* PDF Analysis Result */}
                      {payloadResult.file_type === 'pdf' && payloadResult.pdf_analysis && (
                        <div className="p-3 bg-surface border border-outline-variant rounded-lg space-y-1 text-xs">
                          <span className="font-bold text-on-background block">PDF Text &amp; Embedded Link Extraction</span>
                          <div>• Pages Parsed: <strong>{payloadResult.pdf_analysis.page_count}</strong></div>
                          <div>• Extracted Links: <strong>{payloadResult.pdf_analysis.extracted_links?.join(', ') || 'None'}</strong></div>
                          {payloadResult.pdf_analysis.text_sample && (
                            <div className="text-[11px] text-on-surface-variant bg-surface-container p-2 rounded italic">
                              &quot;{payloadResult.pdf_analysis.text_sample.slice(0, 150)}...&quot;
                            </div>
                          )}
                        </div>
                      )}

                      {/* ZIP Archive Result */}
                      {payloadResult.file_type === 'archive' && payloadResult.zip_analysis && (
                        <div className="p-3 bg-surface border border-outline-variant rounded-lg space-y-1 text-xs">
                          <span className="font-bold text-on-background block">ZIP Archive Metadata Inspection</span>
                          <div>• Total Files: <strong>{payloadResult.zip_analysis.total_files}</strong></div>
                          <div>• Executable Entries: <strong className={payloadResult.zip_analysis.suspicious_executables ? 'text-error' : 'text-on-background'}>{payloadResult.zip_analysis.suspicious_executables ? 'DETECTED' : 'None'}</strong></div>
                          <div>• Decompressed Size: <strong>{payloadResult.zip_analysis.total_decompressed_size_bytes} bytes</strong></div>
                        </div>
                      )}

                      {/* Detected Threat Indicators */}
                      {payloadResult.threat_indicators?.length > 0 && (
                        <div className="space-y-1">
                          <span className="text-[11px] font-bold text-error block font-label-caps">Detected Threat Signals</span>
                          <div className="flex flex-wrap gap-1.5">
                            {payloadResult.threat_indicators.map((ind, idx) => (
                              <span key={idx} className="px-2 py-0.5 rounded bg-error/10 text-error text-[10px] font-bold border border-error/20">
                                {ind}
                              </span>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default EmailThreatInboxTab;
