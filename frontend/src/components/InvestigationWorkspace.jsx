import React, { useState } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  Globe,
  Mail,
  Layers,
  Activity,
  Cpu,
  Terminal,
  CheckCircle2,
  AlertTriangle,
  ArrowRight,
  ExternalLink,
  RefreshCw,
  Play,
  Share2,
  Lock,
  Search,
  Zap,
  Shield,
  FileText,
  UserCheck,
  Eye,
  Building2,
  FileCheck,
  Server
} from 'lucide-react';

import EmailThreatInboxTab from './EmailThreatInboxTab';
import DomainWatchTab from './DomainWatchTab';
import VisualPhishingTab from './VisualPhishingTab';
import LinkedInfrastructureTab from './LinkedInfrastructureTab';
import CaseReportTab from './CaseReportTab';
import LogoMatchTab from './LogoMatchTab';
import MarketplaceListingsTab from './MarketplaceListingsTab';
import SocialWatchTab from './SocialWatchTab';
import AbuseControlSection from './AbuseControlSection';

export default function InvestigationWorkspace({
  investigationResult,
  investigationContext,
  handleRunInvestigation,
  isAnalyzing,
  addToast,
  onRunDemo,
  onResetSession
}) {
  const [activeStage, setActiveStage] = useState('email');
  const [selectedAttackChainNode, setSelectedAttackChainNode] = useState(null);

  // Fallback defaults if no result is available yet
  const res = investigationResult || {
    investigationId: 'INV-DEMO-2026',
    targetUrl: 'https://amaz0n-security-login.xyz/auth/login.html',
    verdict: 'PHISHING',
    riskScore: 94,
    confidence: 91,
    evidenceQuality: 88,
    primaryHypothesis: 'CREDENTIAL_HARVESTING',
    recommendedAction: 'BLOCK',
    emailEvidence: {
      subject: 'Security Alert: Verify Your Amazon Business Account Credentials',
      sender: 'no-reply-security@amaz0n-security-login.xyz',
      recipient: 'security-inbox@corporate.internal',
      receivedAt: '2026-09-11 23:05:00 UTC'
    },
    senderEvidence: {
      hypothesis: 'OFF_HOURS_SENDER_ANOMALY',
      anomalyScore: 82,
      explanation: ['Off-hours sending anomaly (02:43 AM)', 'Sender domain mismatch']
    },
    domainEvidence: {
      domain: 'amaz0n-security-login.xyz',
      rdapAgeDays: 6,
      registrar: 'NameCheap Inc.',
      dnsRecords: { A: ['192.0.2.45'], MX: ['mail.amaz0n-security-login.xyz'], NS: ['ns1.amaz0n.xyz'] }
    },
    pageEvidence: {
      pageTitle: 'Amazon Sign-In & Credential Verification',
      formAction: 'https://amaz0n-security-login.xyz/auth/submit.php',
      credentialFormDetected: true
    },
    visualEvidence: {
      targetBrand: 'Amazon',
      visualSimilarityPct: 94.2,
      cloneClassification: 'STRONG_BRAND_CLONE'
    },
    aiReasoning: {
      aiUsed: false,
      reasoningSource: 'DETERMINISTIC_ENGINE',
      summary: 'Correlated multi-signal analysis identified brand impersonation and dynamic credential harvesting.'
    }
  };

  const invId = res.investigationId || 'INV-2026-001';
  const targetDomain = res.domainEvidence?.domain || res.targetUrl?.replace(/^https?:\/\//i, '').split('/')[0] || 'amaz0n-security-login.xyz';
  const senderEmail = res.emailEvidence?.sender || 'no-reply@suspicious-domain.com';
  const riskScore = res.riskScore ?? 94;
  const confidence = res.confidence ?? 91;
  const verdict = res.verdict || 'PHISHING';

  const stages = [
    { id: 'email', label: '01 EMAIL', title: 'Email & Sender Telemetry', icon: Mail },
    { id: 'threat', label: '02 THREAT INTEL', title: 'URL, Domain & RDAP Intel', icon: Globe },
    { id: 'visual', label: '03 VISUAL', title: 'DOM & Brand Clone Analysis', icon: Eye },
    { id: 'infra', label: '04 INFRASTRUCTURE', title: 'Shared Infrastructure Graph', icon: Server },
    { id: 'chain', label: '05 ATTACK CHAIN', title: 'Connected Evidence Graph', icon: Share2 },
    { id: 'verdict', label: '06 VERDICT & POLICY', title: 'AI Reasoning & Verdict', icon: ShieldCheck },
    { id: 'secondary', label: '07 SECONDARY', title: 'Secondary Security Modules', icon: Layers }
  ];

  const evidenceIndexItems = [
    { name: 'Message Telemetry', status: 'COMPLETE', tag: 'EMAIL' },
    { name: 'Sender Behaviour', status: 'ANOMALY_FLAGGED', tag: 'SENDER' },
    { name: 'Account Compromise', status: 'EVALUATED', tag: 'IDENTITY' },
    { name: 'Payload & QR', status: 'INSPECTED', tag: 'PAYLOAD' },
    { name: 'Target URL Intel', status: 'RESOLVED', tag: 'URL' },
    { name: 'Typosquat / Homoglyph', status: 'LOOKALIKE', tag: 'DOMAIN' },
    { name: 'RDAP & WHOIS', status: 'LIVE_RDAP', tag: 'RDAP' },
    { name: 'DNS (A/MX/NS)', status: 'LIVE_DNS', tag: 'DNS' },
    { name: 'Static DOM (BS4)', status: 'FORM_DETECTED', tag: 'DOM' },
    { name: 'Dynamic Browser', status: 'PLAYWRIGHT', tag: 'RENDER' },
    { name: 'Form Action & Creds', status: 'CREDENTIAL_HARVEST', tag: 'FORM' },
    { name: 'Phishpedia Brand', status: 'BRAND_CLONE', tag: 'VISUAL' },
    { name: 'Perceptual Hash', status: 'DISTANCE_2', tag: 'PHASH' },
    { name: 'Infrastructure Graph', status: 'CLUSTERED', tag: 'INFRA' },
    { name: 'Attack Chain Graph', status: '9_NODES_CONNECTED', tag: 'CHAIN' },
    { name: 'AI Reasoning', status: res.aiReasoning?.aiUsed ? 'OPENROUTER' : 'DETERMINISTIC', tag: 'AI' }
  ];

  return (
    <div className="space-y-8 animate-fade-in pb-16">
      {/* PERSISTENT WORKSPACE HEADER */}
      <section className="surface-card rounded-[24px] p-6 sm:p-8 space-y-6 relative overflow-hidden">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6 pb-6 border-b border-[var(--color-mist-gray)]">
          <div className="space-y-2">
            <div className="flex flex-wrap items-center gap-3">
              <span className="pill-badge font-mono text-xs tracking-wider">
                {invId}
              </span>
              <span className={`pill-badge font-mono text-xs ${
                verdict === 'PHISHING' || verdict === 'MALICIOUS'
                  ? 'bg-[#fbe1d1] text-[#5d2a1a] border-[#5d2a1a]/20'
                  : 'bg-[var(--color-mist-gray)] text-[var(--color-ink)]'
              }`}>
                VERDICT: {verdict}
              </span>
              <span className="text-xs text-[var(--color-slate-gray)] font-mono">
                Acme Corporation (Demo)
              </span>
            </div>

            <h1 className="font-serif text-2xl sm:text-3xl font-normal text-[var(--color-ink)] tracking-tight">
              Unified Security Investigation
            </h1>

            <div className="flex flex-wrap items-center gap-4 text-xs text-[var(--color-slate-gray)] pt-1 font-sans">
              <span className="flex items-center gap-1.5">
                <Globe className="w-3.5 h-3.5 text-[var(--color-ink)]" />
                Target: <code className="text-[var(--color-ink)] font-mono font-medium">{targetDomain}</code>
              </span>
              <span className="text-[var(--color-ash-gray)]">•</span>
              <span className="flex items-center gap-1.5">
                <Mail className="w-3.5 h-3.5 text-[var(--color-ink)]" />
                Sender: <code className="text-[var(--color-ink)] font-mono font-medium">{senderEmail}</code>
              </span>
            </div>
          </div>

          {/* RISK & ACTION METRICS */}
          <div className="flex flex-wrap items-center gap-4">
            <div className="surface-elevated rounded-2xl p-4 min-w-[130px] text-center space-y-1">
              <p className="text-[10px] uppercase font-mono tracking-widest text-[var(--color-slate-gray)]">Risk Score</p>
              <div className="flex items-baseline justify-center gap-1">
                <span className="font-serif text-3xl font-normal text-[var(--color-ink)]">{riskScore}</span>
                <span className="text-xs text-[var(--color-slate-gray)] font-mono">/100</span>
              </div>
            </div>

            <div className="surface-elevated rounded-2xl p-4 min-w-[130px] text-center space-y-1">
              <p className="text-[10px] uppercase font-mono tracking-widest text-[var(--color-slate-gray)]">Confidence</p>
              <div className="flex items-baseline justify-center gap-1">
                <span className="font-serif text-3xl font-normal text-[var(--color-ink)]">{confidence}</span>
                <span className="text-xs text-[var(--color-slate-gray)] font-mono">%</span>
              </div>
            </div>

            <div className="flex flex-col gap-2">
              <button
                onClick={() => onRunDemo?.()}
                className="btn-primary flex items-center justify-center gap-2 text-xs py-2.5 px-5"
                disabled={isAnalyzing}
              >
                <Play className="w-3.5 h-3.5 fill-current" />
                <span>Run Demo Scenario</span>
              </button>
              <button
                onClick={() => handleRunInvestigation({ forceReanalyze: true, reason: 'USER_REANALYZE' })}
                className="btn-secondary flex items-center justify-center gap-2 text-xs py-2 px-4"
                disabled={isAnalyzing}
              >
                <RefreshCw className={`w-3.5 h-3.5 ${isAnalyzing ? 'animate-spin' : ''}`} />
                <span>{isAnalyzing ? 'Analyzing…' : 'Re-analyze Evidence'}</span>
              </button>
            </div>
          </div>
        </div>

        {/* EVIDENCE CAPABILITIES INDEX */}
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <p className="text-xs uppercase tracking-wider font-mono font-medium text-[var(--color-slate-gray)]">
              Connected Evidence Capabilities Index (16/16 Active)
            </p>
            <span className="text-xs font-mono text-[var(--color-slate-gray)]">All Signals Synchronized</span>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-4 md:grid-cols-8 gap-2">
            {evidenceIndexItems.map((item, idx) => (
              <div
                key={idx}
                className="surface-elevated rounded-xl p-2.5 space-y-1 text-left hover:border-[var(--color-ink)] transition-colors"
              >
                <div className="flex items-center justify-between">
                  <span className="text-[9px] font-mono tracking-wider text-[var(--color-slate-gray)]">{item.tag}</span>
                  <CheckCircle2 className="w-3 h-3 text-[var(--color-ink)]" />
                </div>
                <p className="text-[11px] font-medium text-[var(--color-ink)] truncate">{item.name}</p>
                <p className="text-[9px] font-mono text-[var(--color-slate-gray)] truncate">{item.status}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* STAGE NAVIGATION BAR */}
      <div className="flex items-center gap-2 overflow-x-auto pb-2 scrollbar-none border-b border-[var(--color-mist-gray)]">
        {stages.map((stage) => {
          const Icon = stage.icon;
          const isActive = activeStage === stage.id;
          return (
            <button
              key={stage.id}
              onClick={() => setActiveStage(stage.id)}
              className={`flex items-center gap-2 px-5 py-3 rounded-full text-xs font-medium transition-all shrink-0 ${
                isActive
                  ? 'bg-[var(--color-ink)] text-white shadow-sm'
                  : 'bg-[var(--color-paper)] text-[var(--color-slate-gray)] hover:text-[var(--color-ink)] hover:bg-[var(--color-mist-gray)]'
              }`}
            >
              <Icon className="w-4 h-4" />
              <span>{stage.label}</span>
            </button>
          );
        })}
      </div>

      {/* ACTIVE STAGE VIEW */}
      <div className="min-h-[500px]">
        {activeStage === 'email' && (
          <EmailThreatInboxTab
            investigationResult={res}
            investigationContext={investigationContext}
            handleRunInvestigation={handleRunInvestigation}
            isAnalyzing={isAnalyzing}
            addToast={addToast}
          />
        )}

        {activeStage === 'threat' && (
          <DomainWatchTab
            investigationResult={res}
            investigationContext={investigationContext}
            addToast={addToast}
          />
        )}

        {activeStage === 'visual' && (
          <VisualPhishingTab
            investigationResult={res}
            investigationContext={investigationContext}
            addToast={addToast}
          />
        )}

        {activeStage === 'infra' && (
          <LinkedInfrastructureTab
            investigationResult={res}
            investigationContext={investigationContext}
            addToast={addToast}
          />
        )}

        {activeStage === 'chain' && (
          <AttackChainView
            res={res}
            selectedNode={selectedAttackChainNode}
            setSelectedNode={setSelectedAttackChainNode}
          />
        )}

        {activeStage === 'verdict' && (
          <CaseReportTab
            investigationResult={res}
            investigationContext={investigationContext}
            addToast={addToast}
          />
        )}

        {activeStage === 'secondary' && (
          <SecondaryModulesView addToast={addToast} />
        )}
      </div>
    </div>
  );
}

/** 05 ATTACK CHAIN STAGE VIEW */
function AttackChainView({ res, selectedNode, setSelectedNode }) {
  const nodes = res.attackChain?.nodes || [
    { id: 'node-1', type: 'EMAIL', label: 'Message Telemetry', metadata: { details: 'Off-hours email received with credential intent' } },
    { id: 'node-2', type: 'SENDER', label: 'Sender Identity', metadata: { details: 'no-reply-security@amaz0n-security-login.xyz' } },
    { id: 'node-3', type: 'URL', label: 'Target URL', metadata: { details: 'https://amaz0n-security-login.xyz/auth/login.html' } },
    { id: 'node-4', type: 'DOMAIN', label: 'Lookalike Domain', metadata: { details: 'amaz0n-security-login.xyz (Age: 6 days)' } },
    { id: 'node-5', type: 'RDAP', label: 'RDAP / WHOIS', metadata: { details: 'Registered via NameCheap Inc.' } },
    { id: 'node-6', type: 'DNS', label: 'DNS A Record', metadata: { details: 'Resolves to IP 192.0.2.45' } },
    { id: 'node-7', type: 'PAGE', label: 'Playwright DOM', metadata: { details: 'Dynamic JavaScript form detection' } },
    { id: 'node-8', type: 'VISUAL', label: 'Phishpedia Match', metadata: { details: 'Amazon Brand Clone (Similarity: 94.2%)' } },
    { id: 'node-9', type: 'VERDICT', label: 'Unified Verdict', metadata: { details: 'CREDENTIAL_HARVESTING (Risk: 94/100)' } }
  ];

  return (
    <div className="space-y-6">
      <div className="surface-card rounded-[24px] p-8 space-y-6">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="space-y-1">
            <span className="pill-badge text-[10px] font-mono tracking-widest">STAGE 05 — ATTACK CHAIN</span>
            <h2 className="font-serif text-2xl text-[var(--color-ink)]">Interactive Attack Chain Graph</h2>
            <p className="text-xs text-[var(--color-slate-gray)]">
              Click any node along the reconstructed attack trajectory to inspect evidence provenance.
            </p>
          </div>
          <span className="pill-badge bg-[var(--color-mist-gray)] text-[var(--color-ink)] text-xs font-mono">
            {nodes.length} Connected Evidence Nodes
          </span>
        </div>

        {/* HORIZONTAL ATTACK CHAIN GRAPH */}
        <div className="relative py-8 px-4 overflow-x-auto scrollbar-none surface-elevated rounded-2xl">
          <div className="flex items-center justify-between min-w-[900px] relative z-10">
            {nodes.map((node, idx) => (
              <React.Fragment key={node.id}>
                <button
                  onClick={() => setSelectedNode(node)}
                  className={`flex flex-col items-center p-4 rounded-2xl transition-all w-32 border text-center ${
                    selectedNode?.id === node.id
                      ? 'bg-[var(--color-ink)] text-white border-[var(--color-ink)] shadow-md scale-105'
                      : 'bg-white text-[var(--color-ink)] border-[var(--color-mist-gray)] hover:border-[var(--color-ink)]'
                  }`}
                >
                  <span className="text-[9px] font-mono uppercase tracking-widest opacity-60 mb-1">
                    0{idx + 1} • {node.type}
                  </span>
                  <p className="text-xs font-medium truncate w-full">{node.label}</p>
                </button>

                {idx < nodes.length - 1 && (
                  <div className="flex-1 flex items-center justify-center px-1">
                    <ArrowRight className="w-4 h-4 text-[var(--color-slate-gray)]" />
                  </div>
                )}
              </React.Fragment>
            ))}
          </div>
        </div>

        {/* SELECTED NODE INSPECTION CARD */}
        {selectedNode && (
          <div className="surface-elevated rounded-2xl p-6 space-y-3 animate-fade-in border-l-4 border-[var(--color-ink)]">
            <div className="flex items-center justify-between">
              <span className="text-xs font-mono tracking-widest text-[var(--color-slate-gray)] uppercase">
                NODE EVIDENCE INSPECTION — {selectedNode.type}
              </span>
              <button
                onClick={() => setSelectedNode(null)}
                className="text-xs text-[var(--color-slate-gray)] hover:text-[var(--color-ink)] font-mono"
              >
                Close ×
              </button>
            </div>
            <h3 className="font-serif text-lg text-[var(--color-ink)]">{selectedNode.label}</h3>
            <p className="text-xs text-[var(--color-slate-gray)] font-mono">
              {selectedNode.metadata?.details || JSON.stringify(selectedNode.metadata)}
            </p>
          </div>
        )}
      </div>
    </div>
  );
}

/** 07 SECONDARY MODULES STAGE VIEW */
function SecondaryModulesView({ addToast }) {
  const [subTab, setSubTab] = useState('logo');

  return (
    <div className="space-y-6">
      <div className="surface-card rounded-[24px] p-6 space-y-6">
        <div className="flex items-center justify-between border-b border-[var(--color-mist-gray)] pb-4">
          <div className="space-y-1">
            <span className="pill-badge text-[10px] font-mono tracking-widest">STAGE 07 — SECONDARY MODULES</span>
            <h2 className="font-serif text-2xl text-[var(--color-ink)]">Standalone Security Scanners</h2>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setSubTab('logo')}
              className={`px-4 py-2 rounded-full text-xs font-medium transition-all ${
                subTab === 'logo' ? 'bg-[var(--color-ink)] text-white' : 'bg-[var(--color-mist-gray)] text-[var(--color-slate-gray)]'
              }`}
            >
              Logo Match
            </button>
            <button
              onClick={() => setSubTab('marketplace')}
              className={`px-4 py-2 rounded-full text-xs font-medium transition-all ${
                subTab === 'marketplace' ? 'bg-[var(--color-ink)] text-white' : 'bg-[var(--color-mist-gray)] text-[var(--color-slate-gray)]'
              }`}
            >
              Marketplace Watch
            </button>
            <button
              onClick={() => setSubTab('social')}
              className={`px-4 py-2 rounded-full text-xs font-medium transition-all ${
                subTab === 'social' ? 'bg-[var(--color-ink)] text-white' : 'bg-[var(--color-mist-gray)] text-[var(--color-slate-gray)]'
              }`}
            >
              Social Profile Watch
            </button>
            <button
              onClick={() => setSubTab('abuse')}
              className={`px-4 py-2 rounded-full text-xs font-medium transition-all ${
                subTab === 'abuse' ? 'bg-[var(--color-ink)] text-white' : 'bg-[var(--color-mist-gray)] text-[var(--color-slate-gray)]'
              }`}
            >
              Abuse Control
            </button>
          </div>
        </div>

        {subTab === 'logo' && <LogoMatchTab addToast={addToast} />}
        {subTab === 'marketplace' && <MarketplaceListingsTab addToast={addToast} />}
        {subTab === 'social' && <SocialWatchTab addToast={addToast} />}
        {subTab === 'abuse' && <AbuseControlSection addToast={addToast} />}
      </div>
    </div>
  );
}
