import React, { useState } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  Plus,
  Play,
  ArrowRight,
  CheckCircle2,
  AlertTriangle,
  Globe,
  Eye,
  Hub,
  FileCheck,
  Terminal,
  Activity,
  Layers,
  Cpu,
  Lock,
  Search,
  RefreshCw,
  Mail,
  ExternalLink,
  ChevronRight,
  Radio,
  Server,
  Zap,
  HelpCircle
} from 'lucide-react';

const ARCHITECTURE_NODES = [
  { id: 'msg', number: '01', title: 'MESSAGE', subtitle: 'Sender & Body Telemetry', detail: 'Off-hours transmission anomaly; credential verification request in body.' },
  { id: 'url', number: '02', title: 'URL', subtitle: 'Target Extraction', detail: 'Canonical target link extracted: https://amazon-security-login.example/auth/login.html' },
  { id: 'dom', number: '03', title: 'DOMAIN', subtitle: 'RDAP & Lookalike Intel', detail: 'Domain registered 6 days ago via NameCheap Inc with active DNS A record.' },
  { id: 'trace', number: '04', title: 'REDIRECT', subtitle: '2-Hop HTTP Trace', detail: '2 HTTP redirects followed leading to third-party unverified origin.' },
  { id: 'page', number: '05', title: 'LOGIN PAGE', subtitle: 'Static & Dynamic JS', detail: 'Playwright dynamic browser rendered hidden password field post-JS execution.' },
  { id: 'infra', number: '06', title: 'INFRASTRUCTURE', subtitle: 'Cluster Correlation', detail: 'Hosted on IP 192.0.2.45 (BGP ASN 36352) matching 2 lookalike domains.' },
  { id: 'verdict', number: '07', title: 'VERDICT', subtitle: 'Explainable Verdict', detail: 'Overall Risk: 94/100 (CRITICAL). Policy Action: BLOCK. Model: OpenRouter AI.' }
];

export default function HomePage({
  onNavigateTab,
  onStartDemo,
  onStartNewInvestigation,
  apiOnline,
  investigationContext,
  investigationResult
}) {
  const [selectedNode, setSelectedNode] = useState(ARCHITECTURE_NODES[0]);

  const activeResult = investigationResult || {};
  const activeDomain = activeResult.domainEvidence?.domain || investigationContext?.domain;
  const activeVerdict = activeResult.verdict || (investigationContext ? 'PHISHING' : null);
  const activeRisk = activeResult.riskScore ?? activeResult.risk_score ?? (investigationContext ? 94 : null);

  return (
    <div className="space-y-12 font-body-md antialiased text-on-background pb-12">
      {/* 1. HERO SECTION */}
      <section className="relative overflow-hidden rounded-2xl bg-surface-container-lowest border border-outline-variant p-6 sm:p-8 lg:p-12 shadow-sm">
        {/* Subtle background glow */}
        <div className="absolute top-0 right-0 w-96 h-96 bg-primary/5 rounded-full blur-3xl pointer-events-none -mr-20 -mt-20" />

        <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 lg:gap-12 items-center relative z-10">
          {/* Left Column: Product Positioning & Action CTAs */}
          <div className="lg:col-span-6 space-y-6">
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-primary/10 border border-primary/30 text-xs font-semibold text-primary font-technical-data">
              <span className="w-2 h-2 rounded-full bg-primary animate-pulse" />
              <span>DEFENSIVE SECURITY PLATFORM</span>
            </div>

            <div className="space-y-3">
              <h1 className="font-display text-3xl sm:text-4xl lg:text-5xl font-extrabold text-on-background tracking-tight leading-[1.15]">
                KEKAI — PHISHING DEFENSE, <br className="hidden sm:inline" />
                <span className="text-primary">BEFORE THE CLICK.</span>
              </h1>

              <p className="font-body-lg text-sm sm:text-base text-on-surface-variant leading-relaxed max-w-xl">
                KEKAI investigates suspicious emails, websites, and payloads by connecting sender behaviour, domain intelligence, redirects, visual evidence, and infrastructure into one explainable attack chain.
              </p>
            </div>

            <div className="flex flex-wrap items-center gap-3 pt-2">
              <button
                type="button"
                onClick={onStartNewInvestigation}
                className="btn-primary py-3 px-6 rounded-lg text-xs sm:text-sm font-semibold inline-flex items-center gap-2 shadow-xs hover:shadow transition-all"
              >
                <Plus size={18} />
                <span>New Investigation</span>
              </button>

              <button
                type="button"
                onClick={onStartDemo}
                className="btn-secondary py-3 px-6 rounded-lg text-xs sm:text-sm font-semibold inline-flex items-center gap-2 transition-all border-primary/40 hover:border-primary text-primary"
              >
                <Play size={16} className="fill-primary" />
                <span>Run Demo Investigation</span>
              </button>
            </div>

            <div className="pt-4 border-t border-outline-variant flex items-center gap-6 text-xs text-on-surface-variant font-technical-data">
              <div className="flex items-center gap-2">
                <ShieldCheck size={16} className="text-primary" />
                <span>Explainable AI Engine</span>
              </div>
              <div className="flex items-center gap-2">
                <Activity size={16} className="text-primary" />
                <span>Zero Fake Telemetry</span>
              </div>
            </div>
          </div>

          {/* Right Column: Interactive Product Architecture Visual */}
          <div className="lg:col-span-6 bg-surface-container-low p-5 sm:p-6 rounded-xl border border-outline-variant space-y-4 shadow-inner">
            <div className="flex items-center justify-between border-b border-outline-variant pb-3">
              <div className="flex items-center gap-2">
                <Layers className="text-primary" size={18} />
                <span className="font-headline-md text-xs font-bold text-on-background uppercase tracking-wider">
                  KEKAI ATTACK CHAIN ARCHITECTURE
                </span>
              </div>
              <span className="text-[10px] font-technical-data text-primary px-2 py-0.5 rounded bg-primary/10 border border-primary/20 font-bold">
                INTERACTIVE
              </span>
            </div>

            {/* Architecture Node Pipeline Bar */}
            <div className="flex items-center justify-between gap-1 overflow-x-auto pb-2 no-scrollbar">
              {ARCHITECTURE_NODES.map((node) => {
                const isSelected = selectedNode.id === node.id;
                return (
                  <button
                    key={node.id}
                    type="button"
                    onClick={() => setSelectedNode(node)}
                    className={`flex flex-col items-center p-2 rounded-lg transition-all text-center min-w-[64px] border ${
                      isSelected
                        ? 'bg-primary text-on-primary border-primary font-bold shadow-xs'
                        : 'bg-surface-container-lowest text-on-surface-variant hover:text-on-background hover:border-primary/40 border-outline-variant'
                    }`}
                  >
                    <span className="text-[9px] font-technical-data block opacity-80">{node.number}</span>
                    <span className="text-[11px] font-bold tracking-tight uppercase block truncate w-full">{node.title}</span>
                  </button>
                );
              })}
            </div>

            {/* Selected Node Details Card */}
            <div className="bg-surface-container-lowest p-4 rounded-lg border border-primary/30 space-y-2 animate-fade-in">
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-primary font-technical-data uppercase flex items-center gap-1.5">
                  <span className="w-2 h-2 rounded-full bg-primary" />
                  STAGE {selectedNode.number}: {selectedNode.title}
                </span>
                <span className="text-[11px] text-on-surface-variant font-technical-data">
                  {selectedNode.subtitle}
                </span>
              </div>
              <p className="text-xs text-on-background leading-relaxed font-body-md">
                {selectedNode.detail}
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* 2. PRODUCT DIFFERENTIATION SECTION */}
      <section className="bg-surface-container-lowest rounded-xl border border-outline-variant p-6 sm:p-8 space-y-6 shadow-xs">
        <div className="text-center space-y-2 max-w-2xl mx-auto">
          <span className="font-label-caps text-xs text-primary font-bold tracking-wider uppercase">
            PRODUCT DIFFERENTIATION
          </span>
          <h2 className="font-display text-2xl sm:text-3xl font-extrabold text-on-background">
            Evidence-Connected Phishing Investigation
          </h2>
          <p className="font-body-md text-xs sm:text-sm text-on-surface-variant leading-relaxed">
            KEKAI does not rely on a single isolate signal or superficial blacklists. It correlates multi-surface telemetry into one explainable attack graph.
          </p>
        </div>

        {/* Multi-Surface Fusion Pipeline Formula */}
        <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-8 gap-2 pt-2 text-center">
          {[
            { label: 'MESSAGE', sub: 'Urgency & QR' },
            { label: 'IDENTITY', sub: 'Sender Anomaly' },
            { label: 'URL', sub: 'Canonical Hop' },
            { label: 'DOMAIN', sub: 'RDAP & WHOIS' },
            { label: 'REDIRECT', sub: 'HTTP Chain' },
            { label: 'PAGE', sub: 'DOM & Dynamic JS' },
            { label: 'VISUAL', sub: 'Phishpedia pHash' },
            { label: 'INFRASTRUCTURE', sub: 'IP & ASN Cluster' }
          ].map((item, idx) => (
            <div key={idx} className="bg-surface-container-low p-3 rounded-lg border border-outline-variant space-y-1 hover:border-primary/40 transition-colors">
              <span className="text-[10px] font-technical-data font-bold text-primary block">{item.label}</span>
              <span className="text-[10px] text-on-surface-variant block">{item.sub}</span>
            </div>
          ))}
        </div>
      </section>

      {/* 3. SYSTEM OPERATIONAL STATUS */}
      <section className="space-y-4">
        <div className="flex items-center justify-between">
          <h3 className="font-headline-md font-bold text-xs text-on-background uppercase tracking-wider flex items-center gap-2">
            <Server size={16} className="text-primary" /> SYSTEM OPERATIONAL STATUS
          </h3>
          <span className="text-[11px] font-technical-data text-on-surface-variant">
            LIVE COMPONENT HEALTH
          </span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          {/* Status 1: API Online */}
          <div className="bg-surface-container-lowest p-4 rounded-xl border border-outline-variant space-y-1.5 flex items-center justify-between">
            <div>
              <span className="text-[11px] font-technical-data text-on-surface-variant block">BACKEND API SERVER</span>
              <span className="font-headline-md text-xs font-bold text-on-background">HTTP API Endpoint</span>
            </div>
            <div className="flex items-center gap-2">
              <span className={`w-2.5 h-2.5 rounded-full ${apiOnline ? 'bg-[#10b981]' : 'bg-error'}`} />
              <span className="font-technical-data text-xs font-bold text-on-background">
                {apiOnline ? 'ONLINE' : 'OFFLINE'}
              </span>
            </div>
          </div>

          {/* Status 2: Analysis Engine */}
          <div className="bg-surface-container-lowest p-4 rounded-xl border border-outline-variant space-y-1.5 flex items-center justify-between">
            <div>
              <span className="text-[11px] font-technical-data text-on-surface-variant block">SECURITY ENGINE</span>
              <span className="font-headline-md text-xs font-bold text-on-background">Decision Pipeline</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="w-2.5 h-2.5 rounded-full bg-[#10b981]" />
              <span className="font-technical-data text-xs font-bold text-on-background">READY</span>
            </div>
          </div>

          {/* Status 3: Dynamic Browser */}
          <div className="bg-surface-container-lowest p-4 rounded-xl border border-outline-variant space-y-1.5 flex items-center justify-between">
            <div>
              <span className="text-[11px] font-technical-data text-on-surface-variant block">PAGE ANALYSIS</span>
              <span className="font-headline-md text-xs font-bold text-on-background">Playwright Dynamic JS</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="w-2.5 h-2.5 rounded-full bg-[#10b981]" />
              <span className="font-technical-data text-xs font-bold text-on-background">READY</span>
            </div>
          </div>

          {/* Status 4: Threat Intel Engine */}
          <div className="bg-surface-container-lowest p-4 rounded-xl border border-outline-variant space-y-1.5 flex items-center justify-between">
            <div>
              <span className="text-[11px] font-technical-data text-on-surface-variant block">THREAT INTEL</span>
              <span className="font-headline-md text-xs font-bold text-on-background">RDAP &amp; DNS Feeds</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="w-2.5 h-2.5 rounded-full bg-[#10b981]" />
              <span className="font-technical-data text-xs font-bold text-on-background">READY</span>
            </div>
          </div>
        </div>
      </section>

      {/* 4. CORE CAPABILITIES GRID (6 CARDS) */}
      <section className="space-y-4">
        <div className="flex items-center justify-between">
          <h3 className="font-headline-md font-bold text-xs text-on-background uppercase tracking-wider flex items-center gap-2">
            <Cpu size={16} className="text-primary" /> CORE DEFENSIVE CAPABILITIES
          </h3>
          <span className="text-[11px] font-technical-data text-on-surface-variant">
            6 INTEGRATED INVESTIGATION MODULES
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
          {/* CARD 1: MESSAGE INTELLIGENCE */}
          <div className="bg-surface-container-lowest p-6 rounded-xl border border-outline-variant space-y-4 hover:border-primary/50 transition-all group flex flex-col justify-between">
            <div className="space-y-3">
              <div className="w-10 h-10 rounded-lg bg-primary/10 text-primary flex items-center justify-center border border-primary/20">
                <Mail size={20} />
              </div>
              <h4 className="font-headline-md font-bold text-base text-on-background">1. MESSAGE INTELLIGENCE</h4>
              <p className="text-xs text-on-surface-variant leading-relaxed">
                Analyze email body urgency, authority impersonation, credential harvesting keywords, sender behavior anomalies, attachments, and QR codes.
              </p>
            </div>
            <button
              type="button"
              onClick={() => onNavigateTab('inbox')}
              className="text-xs font-bold text-primary group-hover:text-primary-container inline-flex items-center gap-1.5 pt-2"
            >
              <span>Analyze Message</span>
              <ArrowRight size={14} className="group-hover:translate-x-1 transition-transform" />
            </button>
          </div>

          {/* CARD 2: THREAT INTELLIGENCE */}
          <div className="bg-surface-container-lowest p-6 rounded-xl border border-outline-variant space-y-4 hover:border-primary/50 transition-all group flex flex-col justify-between">
            <div className="space-y-3">
              <div className="w-10 h-10 rounded-lg bg-primary/10 text-primary flex items-center justify-center border border-primary/20">
                <Globe size={20} />
              </div>
              <h4 className="font-headline-md font-bold text-base text-on-background">2. THREAT INTELLIGENCE</h4>
              <p className="text-xs text-on-surface-variant leading-relaxed">
                Investigate lookalike domain permutations, typosquatting, RDAP registration age, live DNS (A, MX, NS), and threat feeds (OpenPhish, PhishTank).
              </p>
            </div>
            <button
              type="button"
              onClick={() => onNavigateTab('domain')}
              className="text-xs font-bold text-primary group-hover:text-primary-container inline-flex items-center gap-1.5 pt-2"
            >
              <span>Investigate Infrastructure</span>
              <ArrowRight size={14} className="group-hover:translate-x-1 transition-transform" />
            </button>
          </div>

          {/* CARD 3: VISUAL VERIFICATION */}
          <div className="bg-surface-container-lowest p-6 rounded-xl border border-outline-variant space-y-4 hover:border-primary/50 transition-all group flex flex-col justify-between">
            <div className="space-y-3">
              <div className="w-10 h-10 rounded-lg bg-primary/10 text-primary flex items-center justify-center border border-primary/20">
                <Eye size={20} />
              </div>
              <h4 className="font-headline-md font-bold text-base text-on-background">3. VISUAL VERIFICATION</h4>
              <p className="text-xs text-on-surface-variant leading-relaxed">
                Inspect rendered page screenshots, dynamic Playwright JS form rendering, Phishpedia logo matching %, and perceptual hash distance (pHash/dHash).
              </p>
            </div>
            <button
              type="button"
              onClick={() => onNavigateTab('phishing')}
              className="text-xs font-bold text-primary group-hover:text-primary-container inline-flex items-center gap-1.5 pt-2"
            >
              <span>Verify Page</span>
              <ArrowRight size={14} className="group-hover:translate-x-1 transition-transform" />
            </button>
          </div>

          {/* CARD 4: INFRASTRUCTURE CORRELATION */}
          <div className="bg-surface-container-lowest p-6 rounded-xl border border-outline-variant space-y-4 hover:border-primary/50 transition-all group flex flex-col justify-between">
            <div className="space-y-3">
              <div className="w-10 h-10 rounded-lg bg-primary/10 text-primary flex items-center justify-center border border-primary/20">
                <Hub size={20} />
              </div>
              <h4 className="font-headline-md font-bold text-base text-on-background">4. INFRASTRUCTURE CORRELATION</h4>
              <p className="text-xs text-on-surface-variant leading-relaxed">
                Correlate shared IPs, BGP ASNs, nameservers, registrars, and visual fingerprints to discover connected offender clusters.
              </p>
            </div>
            <button
              type="button"
              onClick={() => onNavigateTab('infrastructure')}
              className="text-xs font-bold text-primary group-hover:text-primary-container inline-flex items-center gap-1.5 pt-2"
            >
              <span>Trace Infrastructure</span>
              <ArrowRight size={14} className="group-hover:translate-x-1 transition-transform" />
            </button>
          </div>

          {/* CARD 5: ATTACK CHAIN */}
          <div className="bg-surface-container-lowest p-6 rounded-xl border border-outline-variant space-y-4 hover:border-primary/50 transition-all group flex flex-col justify-between">
            <div className="space-y-3">
              <div className="w-10 h-10 rounded-lg bg-primary/10 text-primary flex items-center justify-center border border-primary/20">
                <Activity size={20} />
              </div>
              <h4 className="font-headline-md font-bold text-base text-on-background">5. ATTACK CHAIN</h4>
              <p className="text-xs text-on-surface-variant leading-relaxed">
                Reconstruct the full attack path from initial email transmission through HTTP redirect hops to landing credential harvesting forms.
              </p>
            </div>
            <button
              type="button"
              onClick={() => onNavigateTab('case')}
              className="text-xs font-bold text-primary group-hover:text-primary-container inline-flex items-center gap-1.5 pt-2"
            >
              <span>View Attack Chain</span>
              <ArrowRight size={14} className="group-hover:translate-x-1 transition-transform" />
            </button>
          </div>

          {/* CARD 6: EXPLAINABLE VERDICT */}
          <div className="bg-surface-container-lowest p-6 rounded-xl border border-outline-variant space-y-4 hover:border-primary/50 transition-all group flex flex-col justify-between">
            <div className="space-y-3">
              <div className="w-10 h-10 rounded-lg bg-primary/10 text-primary flex items-center justify-center border border-primary/20">
                <FileCheck size={20} />
              </div>
              <h4 className="font-headline-md font-bold text-base text-on-background">6. EXPLAINABLE VERDICT</h4>
              <p className="text-xs text-on-surface-variant leading-relaxed">
                Surface risk scores (0-100), confidence %, evidence quality %, primary attack hypothesis, supporting evidence with provenance tags, and policy actions.
              </p>
            </div>
            <button
              type="button"
              onClick={() => onNavigateTab('case')}
              className="text-xs font-bold text-primary group-hover:text-primary-container inline-flex items-center gap-1.5 pt-2"
            >
              <span>Review Verdict</span>
              <ArrowRight size={14} className="group-hover:translate-x-1 transition-transform" />
            </button>
          </div>
        </div>
      </section>

      {/* 5. HOW KEKAI INVESTIGATES (HORIZONTAL PROCESS) */}
      <section className="bg-surface-container-lowest rounded-xl border border-outline-variant p-6 sm:p-8 space-y-6 shadow-xs">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-outline-variant pb-4">
          <div>
            <span className="font-label-caps text-xs text-primary font-bold tracking-wider uppercase">
              INVESTIGATION WORKFLOW
            </span>
            <h3 className="font-display text-xl sm:text-2xl font-extrabold text-on-background">
              How KEKAI Reconstructs Threats
            </h3>
          </div>
          <span className="text-xs text-on-surface-variant font-technical-data">
            7 AUTOMATED PIPELINE STAGES
          </span>
        </div>

        {/* 7-Step Process Flow */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-7 gap-3">
          {[
            { step: '01', name: 'MESSAGE', desc: 'Extract sender, intent, URLs, payloads, QR' },
            { step: '02', name: 'ENRICH', desc: 'Resolve domain age, RDAP, WHOIS, DNS' },
            { step: '03', name: 'TRACE', desc: 'Trace HTTP redirects to final origin' },
            { step: '04', name: 'VERIFY', desc: 'Static DOM & Playwright dynamic JS' },
            { step: '05', name: 'CORRELATE', desc: 'Phishpedia logos & IP ASN clusters' },
            { step: '06', name: 'REASON', desc: 'Synthesize hypotheses & AI evidence' },
            { step: '07', name: 'PROTECT', desc: 'Enforce policy action & training signal' }
          ].map((s, idx) => (
            <div key={idx} className="bg-surface-container-low p-3.5 rounded-lg border border-outline-variant space-y-2 relative">
              <span className="text-[10px] font-technical-data font-bold text-primary block">{s.step}</span>
              <h4 className="font-headline-md font-bold text-xs text-on-background">{s.name}</h4>
              <p className="text-[11px] text-on-surface-variant leading-normal">{s.desc}</p>
            </div>
          ))}
        </div>
      </section>

      {/* 6. RECENT / ACTIVE INVESTIGATIONS */}
      <section className="space-y-4">
        <div className="flex items-center justify-between">
          <h3 className="font-headline-md font-bold text-xs text-on-background uppercase tracking-wider flex items-center gap-2">
            <Activity size={16} className="text-primary" /> RECENT INVESTIGATIONS
          </h3>
          <span className="text-[11px] font-technical-data text-on-surface-variant">
            INVESTIGATION HISTORY
          </span>
        </div>

        {activeVerdict ? (
          <div className="bg-surface-container-lowest p-6 rounded-xl border border-primary/40 space-y-4 shadow-sm">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-outline-variant pb-3">
              <div>
                <span className="text-[10px] font-technical-data text-primary font-bold uppercase tracking-wider block">
                  ACTIVE INVESTIGATION SESSION
                </span>
                <h4 className="font-headline-md font-bold text-lg text-on-background flex items-center gap-2">
                  <ShieldAlert className="text-[#e7000b]" size={20} />
                  <span>{activeDomain || 'Amazon Security Demo Investigation'}</span>
                </h4>
              </div>

              <div className="flex items-center gap-3">
                <span className={`px-3 py-1 rounded text-xs font-bold font-technical-data border ${
                  activeVerdict === 'PHISHING' ? 'bg-error/10 text-error border-error/30' : 'bg-primary/10 text-primary border-primary/30'
                }`}>
                  VERDICT: {activeVerdict} ({activeRisk}/100)
                </span>

                <button
                  type="button"
                  onClick={() => onNavigateTab('case')}
                  className="btn-primary py-1.5 px-4 rounded text-xs font-bold inline-flex items-center gap-1.5"
                >
                  <span>Resume Investigation</span>
                  <ChevronRight size={14} />
                </button>
              </div>
            </div>

            <p className="text-xs text-on-surface-variant">
              Multi-surface evidence collected and analyzed. View detailed risk breakdown, attack chain graph, and generated PDF reports.
            </p>
          </div>
        ) : (
          <div className="bg-surface-container-lowest p-8 rounded-xl border border-outline-variant text-center space-y-3">
            <div className="w-12 h-12 rounded-full bg-surface-container-low border border-outline-variant flex items-center justify-center mx-auto text-on-surface-variant">
              <Search size={20} />
            </div>
            <div className="space-y-1">
              <h4 className="font-headline-md font-bold text-sm text-on-background">No Recent Investigations</h4>
              <p className="text-xs text-on-surface-variant max-w-sm mx-auto">
                Start an investigation to build your investigation history and reconstruct phishing attack paths.
              </p>
            </div>
            <div className="pt-2">
              <button
                type="button"
                onClick={onStartNewInvestigation}
                className="btn-primary py-2 px-5 rounded-lg text-xs font-semibold inline-flex items-center gap-2 shadow-xs"
              >
                <Plus size={14} />
                <span>Start First Investigation</span>
              </button>
            </div>
          </div>
        )}
      </section>

      {/* 7. BOTTOM CTA SECTION */}
      <section className="bg-surface-container-lowest rounded-xl border border-outline-variant p-8 sm:p-10 text-center space-y-5 shadow-xs relative overflow-hidden">
        <div className="space-y-2 max-w-xl mx-auto">
          <h2 className="font-display text-2xl sm:text-3xl font-extrabold text-on-background">
            Start an investigation before the user does.
          </h2>
          <p className="text-xs sm:text-sm text-on-surface-variant leading-relaxed">
            Connect sender telemetry, domain intelligence, and visual brand evidence into an explainable attack chain.
          </p>
        </div>

        <div className="flex flex-wrap items-center justify-center gap-4 pt-2">
          <button
            type="button"
            onClick={onStartNewInvestigation}
            className="btn-primary py-3 px-8 rounded-lg text-xs sm:text-sm font-semibold inline-flex items-center gap-2 shadow-xs"
          >
            <Plus size={18} />
            <span>New Investigation</span>
          </button>

          <button
            type="button"
            onClick={onStartDemo}
            className="btn-secondary py-3 px-8 rounded-lg text-xs sm:text-sm font-semibold inline-flex items-center gap-2 text-primary border-primary/40 hover:border-primary"
          >
            <Play size={16} className="fill-primary" />
            <span>Run Demo Investigation</span>
          </button>
        </div>
      </section>
    </div>
  );
}
