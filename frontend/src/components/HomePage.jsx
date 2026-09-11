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
  Share2,
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
  HelpCircle,
  Shield,
  CornerDownRight,
  FileText
} from 'lucide-react';

export default function HomePage({
  onNavigateTab,
  onStartDemo,
  onStartNewInvestigation,
  apiOnline,
  investigationContext,
  investigationResult
}) {
  const [activeTabSection, setActiveTabSection] = useState('overview');

  const activeResult = investigationResult || {};
  const activeDomain = activeResult.domainEvidence?.domain || investigationContext?.domain;
  const activeVerdict = activeResult.verdict || (investigationContext ? 'PHISHING' : null);
  const activeRisk = activeResult.riskScore ?? activeResult.risk_score ?? (investigationContext ? 94 : null);

  return (
    <div className="min-h-screen bg-[#fafafb] text-[#0a0a0a] font-sans antialiased selection:bg-[#fbe1d1] selection:text-[#5d2a1a] pb-24">
      {/* MINIMAL EDITORIAL NAVIGATION BAR */}
      <nav className="w-full max-w-[1200px] mx-auto px-4 sm:px-6 py-6 flex items-center justify-between border-b border-[#e5e5e5]/60">
        <div className="flex items-center gap-8">
          {/* KEKAI Mark */}
          <button
            type="button"
            onClick={() => onNavigateTab('home')}
            className="flex items-center gap-2 text-left group"
          >
            <span className="w-8 h-8 rounded-full bg-[#0a0a0a] text-white flex items-center justify-center text-xs font-semibold tracking-wider">
              K
            </span>
            <span className="font-serif text-xl tracking-tight font-normal text-[#0a0a0a]">
              KEKAI
            </span>
          </button>

          {/* Navigation Links */}
          <div className="hidden md:flex items-center gap-6 text-xs font-medium text-[#737373]">
            <button
              type="button"
              onClick={() => onNavigateTab('home')}
              className="text-[#0a0a0a] hover:text-[#0a0a0a] transition-colors"
            >
              Product
            </button>
            <button
              type="button"
              onClick={() => onNavigateTab('domain')}
              className="hover:text-[#0a0a0a] transition-colors"
            >
              How KEKAI Works
            </button>
            <button
              type="button"
              onClick={() => onNavigateTab('phishing')}
              className="hover:text-[#0a0a0a] transition-colors"
            >
              Capabilities
            </button>
            <button
              type="button"
              onClick={() => onNavigateTab('case')}
              className="hover:text-[#0a0a0a] transition-colors"
            >
              Investigation
            </button>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <button
            type="button"
            onClick={onStartDemo}
            className="bg-[#0a0a0a] text-white hover:bg-[#171717] px-4 py-2 rounded-full text-xs font-medium transition-all shadow-sm flex items-center gap-1.5"
          >
            <Play size={12} className="fill-white" />
            <span>Run Demo</span>
          </button>

          <button
            type="button"
            onClick={onStartNewInvestigation}
            className="bg-transparent text-[#0a0a0a] border border-[#0a0a0a] hover:bg-[#f5f5f5] px-4 py-2 rounded-full text-xs font-medium transition-all flex items-center gap-1.5"
          >
            <Plus size={14} />
            <span className="hidden sm:inline">New Investigation</span>
          </button>
        </div>
      </nav>

      <main className="w-full max-w-[1200px] mx-auto px-4 sm:px-6 space-y-20 pt-12 sm:pt-16">
        {/* 1. HERO SECTION — STEEP-INSPIRED EDITORIAL HERO WITH FLOATING UI ARTIFACTS */}
        <section className="relative pt-4 pb-12">
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-12 items-center">
            {/* Left Column: Editorial Serif Copy & Pill CTAs */}
            <div className="lg:col-span-6 space-y-6">
              <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-[#f5f5f5] border border-[#e5e5e5] text-xs font-medium text-[#737373]">
                <span className="w-1.5 h-1.5 rounded-full bg-[#0a0a0a]" />
                <span>DEFENSIVE SECURITY PLATFORM</span>
              </div>

              <div className="space-y-4">
                <h1 className="font-serif text-4xl sm:text-5xl lg:text-6xl font-normal text-[#0a0a0a] tracking-tight leading-[1.08]">
                  PHISHING DEFENSE, <br />
                  <span className="italic text-[#737373]">BEFORE THE CLICK.</span>
                </h1>

                <p className="text-sm sm:text-base text-[#737373] leading-relaxed max-w-lg font-normal">
                  KEKAI connects signals across messages, identities, URLs, domains, redirects, rendered pages and infrastructure to reconstruct phishing attacks before users interact with them.
                </p>
              </div>

              <div className="flex flex-wrap items-center gap-3 pt-2">
                <button
                  type="button"
                  onClick={onStartDemo}
                  className="bg-[#0a0a0a] text-white hover:bg-[#171717] px-6 py-3 rounded-full text-xs sm:text-sm font-medium transition-all shadow-sm inline-flex items-center gap-2"
                >
                  <Play size={14} className="fill-white" />
                  <span>Run Demo Investigation</span>
                </button>

                <button
                  type="button"
                  onClick={onStartNewInvestigation}
                  className="bg-transparent text-[#0a0a0a] border border-[#0a0a0a] hover:bg-[#f5f5f5] px-6 py-3 rounded-full text-xs sm:text-sm font-medium transition-all inline-flex items-center gap-2"
                >
                  <Plus size={16} />
                  <span>New Investigation</span>
                </button>
              </div>
            </div>

            {/* Right Column: Floating Product UI Artifact Collage */}
            <div className="lg:col-span-6 relative min-h-[420px] flex items-center justify-center">
              {/* Artifact 1: Threat Signal (Top Left) */}
              <div className="absolute -top-4 left-0 w-64 bg-white p-4 rounded-[20px] border border-[#e5e5e5] shadow-sm space-y-2.5 z-20 hover:-translate-y-1 transition-transform">
                <div className="flex items-center justify-between">
                  <span className="text-[10px] font-semibold text-[#737373] tracking-wider uppercase flex items-center gap-1.5">
                    <Mail size={12} className="text-[#0a0a0a]" /> THREAT SIGNAL
                  </span>
                  <span className="px-2 py-0.5 rounded-full text-[9px] font-semibold bg-[#e7000b]/10 text-[#e7000b]">
                    HIGH SEV
                  </span>
                </div>
                <div className="space-y-1">
                  <p className="text-xs font-medium text-[#0a0a0a] truncate">URGENT: Vendor Account Login</p>
                  <p className="text-[11px] text-[#737373] truncate">From: finance@acme.example</p>
                </div>
                <div className="pt-1 border-t border-[#f5f5f5] text-[10px] text-[#737373] flex justify-between">
                  <span>Off-hours transmission</span>
                  <span>Credential link</span>
                </div>
              </div>

              {/* Artifact 2: Domain Intelligence (Top Right) */}
              <div className="absolute top-8 right-0 w-64 bg-white p-4 rounded-[20px] border border-[#e5e5e5] shadow-sm space-y-2.5 z-10 hover:-translate-y-1 transition-transform">
                <div className="flex items-center justify-between">
                  <span className="text-[10px] font-semibold text-[#737373] tracking-wider uppercase flex items-center gap-1.5">
                    <Globe size={12} className="text-[#0a0a0a]" /> DOMAIN INTEL
                  </span>
                  <span className="text-[10px] font-mono text-[#0a0a0a]">LOOKALIKE</span>
                </div>
                <div className="space-y-1">
                  <p className="text-xs font-mono font-medium text-[#0a0a0a] truncate">amazon-security-login.example</p>
                  <p className="text-[11px] text-[#737373]">RDAP Age: <strong>6 days old</strong></p>
                </div>
                <div className="pt-1 border-t border-[#f5f5f5] text-[10px] text-[#737373] flex justify-between">
                  <span>Registrar: NameCheap</span>
                  <span>DNS A: Active</span>
                </div>
              </div>

              {/* Artifact 3: Blush Peach Editorial Accent Artifact (Center Highlight) */}
              <div className="w-72 bg-[#fbe1d1] p-5 rounded-[20px] border border-[#5d2a1a]/20 shadow-sm space-y-3 z-30 transform hover:scale-[1.02] transition-transform">
                <div className="flex items-center justify-between">
                  <span className="text-[10px] font-semibold text-[#5d2a1a] tracking-wider uppercase">
                    EVIDENCE CONNECTED
                  </span>
                  <span className="w-2 h-2 rounded-full bg-[#5d2a1a]" />
                </div>
                <h4 className="font-serif text-lg text-[#5d2a1a] font-normal leading-snug">
                  ONE THREAT. <br />
                  EVERY SIGNAL CONNECTED.
                </h4>
                <p className="text-xs text-[#5d2a1a]/80 leading-normal">
                  8 telemetry streams fused into 1 explainable attack graph before interaction.
                </p>
              </div>

              {/* Artifact 4: Explainable Verdict (Bottom Right) */}
              <div className="absolute -bottom-4 right-4 w-68 bg-white p-4 rounded-[20px] border border-[#e5e5e5] shadow-sm space-y-2.5 z-20 hover:-translate-y-1 transition-transform">
                <div className="flex items-center justify-between">
                  <span className="text-[10px] font-semibold text-[#737373] tracking-wider uppercase flex items-center gap-1.5">
                    <FileCheck size={12} className="text-[#0a0a0a]" /> EXPLAINABLE VERDICT
                  </span>
                  <span className="px-2 py-0.5 rounded-full text-[10px] font-semibold bg-[#0a0a0a] text-white">
                    BLOCK
                  </span>
                </div>
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-xs font-semibold text-[#0a0a0a]">CREDENTIAL HARVESTING</p>
                    <p className="text-[10px] text-[#737373]">Confidence: 91% | Quality: 96%</p>
                  </div>
                  <span className="text-xl font-mono font-bold text-[#e7000b]">94</span>
                </div>
              </div>
            </div>
          </div>
        </section>

        {/* 2. CORE DIFFERENTIATOR — ONE THREAT. EVERY SIGNAL CONNECTED. */}
        <section className="bg-white rounded-[24px] border border-[#e5e5e5] p-8 sm:p-12 space-y-8 shadow-xs">
          <div className="max-w-2xl space-y-3">
            <span className="text-xs font-semibold text-[#737373] uppercase tracking-wider">
              PRODUCT THESIS
            </span>
            <h2 className="font-serif text-3xl sm:text-4xl font-normal text-[#0a0a0a] tracking-tight">
              ONE THREAT. EVERY SIGNAL CONNECTED.
            </h2>
            <p className="text-sm text-[#737373] leading-relaxed">
              KEKAI does not stop at a suspicious email. It follows the evidence across identity, URLs, domains, redirects, pages and infrastructure until the attack path becomes explainable.
            </p>
          </div>

          {/* Connected Evidence Pipeline */}
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-9 gap-2 pt-2 text-center text-xs">
            {[
              { label: 'MESSAGE', sub: 'Urgency & QR' },
              { label: 'IDENTITY', sub: 'Sender Anomaly' },
              { label: 'URL', sub: 'Canonical Hop' },
              { label: 'DOMAIN', sub: 'RDAP & WHOIS' },
              { label: 'REDIRECT', sub: 'HTTP Trace' },
              { label: 'PAGE', sub: 'DOM & JS Form' },
              { label: 'VISUAL', sub: 'Phishpedia pHash' },
              { label: 'INFRASTRUCTURE', sub: 'IP & ASN Cluster' },
              { label: 'VERDICT', sub: 'Explainable AI' }
            ].map((step, idx) => (
              <div key={idx} className="bg-[#fafafa] p-3 rounded-xl border border-[#e5e5e5] space-y-1 hover:border-[#0a0a0a] transition-colors">
                <span className="text-[11px] font-semibold text-[#0a0a0a] block">{step.label}</span>
                <span className="text-[10px] text-[#737373] block">{step.sub}</span>
              </div>
            ))}
          </div>
        </section>

        {/* 3. 4 PRODUCT PILLARS — 2-COLUMN EDITORIAL SHOWCASE */}
        <section className="space-y-8">
          <div className="flex flex-col md:flex-row md:items-end justify-between gap-4">
            <div className="space-y-2">
              <span className="text-xs font-semibold text-[#737373] uppercase tracking-wider">
                CORE CAPABILITIES
              </span>
              <h2 className="font-serif text-3xl sm:text-4xl font-normal text-[#0a0a0a] tracking-tight">
                From one suspicious message <br className="hidden sm:inline" />
                to a complete attack chain.
              </h2>
            </div>
            <p className="text-xs text-[#737373] max-w-xs leading-relaxed">
              Integrated defensive modules designed to analyze, trace, correlate, and enforce security policies.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* PILLAR 1: DETECT */}
            <div className="bg-white p-8 rounded-[24px] border border-[#e5e5e5] space-y-5 hover:shadow-sm transition-shadow flex flex-col justify-between">
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-mono font-semibold text-[#737373]">01</span>
                  <span className="text-[11px] font-medium text-[#737373] bg-[#fafafa] px-2.5 py-1 rounded-full border border-[#e5e5e5]">
                    MESSAGE TELEMETRY
                  </span>
                </div>
                <h3 className="font-serif text-2xl font-normal text-[#0a0a0a]">01 DETECT</h3>
                <p className="text-xs sm:text-sm text-[#737373] leading-relaxed">
                  Analyze message body urgency, authority impersonation, credential harvesting keywords, sender behavior anomalies, attachments, and QR code payloads.
                </p>
              </div>
              <button
                type="button"
                onClick={() => onNavigateTab('inbox')}
                className="text-xs font-semibold text-[#0a0a0a] inline-flex items-center gap-1.5 pt-4 hover:underline"
              >
                <span>Analyze Message</span>
                <ArrowRight size={14} />
              </button>
            </div>

            {/* PILLAR 2: INVESTIGATE */}
            <div className="bg-white p-8 rounded-[24px] border border-[#e5e5e5] space-y-5 hover:shadow-sm transition-shadow flex flex-col justify-between">
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-mono font-semibold text-[#737373]">02</span>
                  <span className="text-[11px] font-medium text-[#737373] bg-[#fafafa] px-2.5 py-1 rounded-full border border-[#e5e5e5]">
                    DOMAIN &amp; REDIRECT INTEL
                  </span>
                </div>
                <h3 className="font-serif text-2xl font-normal text-[#0a0a0a]">02 INVESTIGATE</h3>
                <p className="text-xs sm:text-sm text-[#737373] leading-relaxed">
                  Investigate lookalike domain permutations, typosquatting, RDAP registration age, live DNS A/MX/NS records, HTTP redirect chains, and threat feeds.
                </p>
              </div>
              <button
                type="button"
                onClick={() => onNavigateTab('domain')}
                className="text-xs font-semibold text-[#0a0a0a] inline-flex items-center gap-1.5 pt-4 hover:underline"
              >
                <span>Investigate Infrastructure</span>
                <ArrowRight size={14} />
              </button>
            </div>

            {/* PILLAR 3: CORRELATE */}
            <div className="bg-white p-8 rounded-[24px] border border-[#e5e5e5] space-y-5 hover:shadow-sm transition-shadow flex flex-col justify-between">
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-mono font-semibold text-[#737373]">03</span>
                  <span className="text-[11px] font-medium text-[#737373] bg-[#fafafa] px-2.5 py-1 rounded-full border border-[#e5e5e5]">
                    VISUAL &amp; INFRASTRUCTURE
                  </span>
                </div>
                <h3 className="font-serif text-2xl font-normal text-[#0a0a0a]">03 CORRELATE</h3>
                <p className="text-xs sm:text-sm text-[#737373] leading-relaxed">
                  Inspect Playwright dynamic JS browser behaviour, Phishpedia logo matching %, pHash/dHash similarity, and correlate shared hosting IP clusters.
                </p>
              </div>
              <button
                type="button"
                onClick={() => onNavigateTab('phishing')}
                className="text-xs font-semibold text-[#0a0a0a] inline-flex items-center gap-1.5 pt-4 hover:underline"
              >
                <span>Verify Page &amp; Correlate</span>
                <ArrowRight size={14} />
              </button>
            </div>

            {/* PILLAR 4: DECIDE */}
            <div className="bg-white p-8 rounded-[24px] border border-[#e5e5e5] space-y-5 hover:shadow-sm transition-shadow flex flex-col justify-between">
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-mono font-semibold text-[#737373]">04</span>
                  <span className="text-[11px] font-medium text-[#737373] bg-[#fafafa] px-2.5 py-1 rounded-full border border-[#e5e5e5]">
                    REASONING &amp; POLICY
                  </span>
                </div>
                <h3 className="font-serif text-2xl font-normal text-[#0a0a0a]">04 DECIDE</h3>
                <p className="text-xs sm:text-sm text-[#737373] leading-relaxed">
                  Synthesize multi-surface evidence into explainable attack hypotheses, supporting/contradicting evidence lists, automated policy actions (`BLOCK`), and analyst learning signals.
                </p>
              </div>
              <button
                type="button"
                onClick={() => onNavigateTab('case')}
                className="text-xs font-semibold text-[#0a0a0a] inline-flex items-center gap-1.5 pt-4 hover:underline"
              >
                <span>Review Explainable Verdict</span>
                <ArrowRight size={14} />
              </button>
            </div>
          </div>
        </section>

        {/* 4. HOW KEKAI INVESTIGATES — FULL-WIDTH EDITORIAL PROCESS SECTION */}
        <section className="bg-white rounded-[24px] border border-[#e5e5e5] p-8 sm:p-12 space-y-8 shadow-xs">
          <div className="flex flex-col sm:flex-row sm:items-end justify-between gap-4 border-b border-[#e5e5e5] pb-6">
            <div className="space-y-1">
              <span className="text-xs font-semibold text-[#737373] uppercase tracking-wider">
                PIPELINE EXECUTION
              </span>
              <h2 className="font-serif text-3xl font-normal text-[#0a0a0a]">
                HOW KEKAI INVESTIGATES
              </h2>
            </div>
            <span className="text-xs text-[#737373] font-mono">
              7 AUTOMATED DEFENSIVE STAGES
            </span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-7 gap-4">
            {[
              { step: '01', name: 'DETECT', desc: 'Extract sender, intent, URLs, attachments, and QR codes.' },
              { step: '02', name: 'ENRICH', desc: 'Resolve domain age, RDAP, WHOIS, DNS A/MX/NS records.' },
              { step: '03', name: 'TRACE', desc: 'Follow HTTP redirect chains to final landing origin.' },
              { step: '04', name: 'VERIFY', desc: 'Analyze static DOM and Playwright dynamic JS forms.' },
              { step: '05', name: 'CORRELATE', desc: 'Match Phishpedia logo similarity & IP ASN clusters.' },
              { step: '06', name: 'REASON', desc: 'Synthesize multi-surface evidence into hypotheses.' },
              { step: '07', name: 'PROTECT', desc: 'Enforce policy action & analyst training signals.' }
            ].map((s, idx) => (
              <div key={idx} className="bg-[#fafafa] p-4 rounded-xl border border-[#e5e5e5] space-y-2">
                <span className="text-xs font-mono font-semibold text-[#737373] block">{s.step}</span>
                <h4 className="font-semibold text-xs text-[#0a0a0a]">{s.name}</h4>
                <p className="text-[11px] text-[#737373] leading-relaxed">{s.desc}</p>
              </div>
            ))}
          </div>
        </section>

        {/* 5. AI REASONING POSITIONING & ARTIFACT */}
        <section className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-center">
          <div className="lg:col-span-6 space-y-4">
            <span className="text-xs font-semibold text-[#737373] uppercase tracking-wider">
              AI POSITIONING
            </span>
            <h2 className="font-serif text-3xl sm:text-4xl font-normal text-[#0a0a0a] leading-tight">
              AI does not replace the investigation. <br />
              <span className="italic text-[#737373]">It reasons over the evidence produced.</span>
            </h2>
            <p className="text-sm text-[#737373] leading-relaxed">
              KEKAI uses OpenRouter AI reasoning to evaluate correlated evidence, weight supporting vs contradicting signals, and construct human-auditable attack summaries.
            </p>
          </div>

          {/* AI Investigation Summary Artifact */}
          <div className="lg:col-span-6 bg-white p-6 rounded-[24px] border border-[#e5e5e5] shadow-xs space-y-4">
            <div className="flex items-center justify-between border-b border-[#e5e5e5] pb-3">
              <span className="text-xs font-semibold text-[#737373] uppercase tracking-wider flex items-center gap-2">
                <ShieldCheck size={14} className="text-[#0a0a0a]" /> AI INVESTIGATION SUMMARY
              </span>
              <span className="text-[11px] font-mono text-[#0a0a0a]">OPENROUTER AI</span>
            </div>

            <div className="space-y-3 text-xs">
              <div>
                <span className="text-[11px] text-[#737373] block">Primary Attack Hypothesis:</span>
                <p className="font-semibold text-[#0a0a0a] text-sm">CREDENTIAL HARVESTING</p>
              </div>

              <div className="space-y-1 bg-[#fafafa] p-3 rounded-xl border border-[#e5e5e5]">
                <span className="text-[11px] font-semibold text-[#0a0a0a] block">Supporting Evidence (+):</span>
                <ul className="space-y-1 text-[11px] text-[#737373]">
                  <li>+ Registered typosquat lookalike domain (6 days old)</li>
                  <li>+ 2-hop HTTP redirect chain leading to third-party origin</li>
                  <li>+ Playwright dynamic JS rendered hidden password field</li>
                  <li>+ Phishpedia logo matched 94% visual brand similarity</li>
                </ul>
              </div>

              <div className="text-[11px] text-[#737373] pt-1">
                <strong className="text-[#0a0a0a]">Key Insight:</strong> Evidence remains stronger than the absence of a threat-feed match.
              </div>
            </div>
          </div>
        </section>

        {/* 6. DEFENSIVE BY DESIGN & OPERATIONAL SYSTEM STATUS */}
        <section className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {/* Defensive By Design */}
          <div className="bg-white p-8 rounded-[24px] border border-[#e5e5e5] space-y-4 shadow-xs">
            <span className="text-xs font-semibold text-[#737373] uppercase tracking-wider">
              SECURITY ARCHITECTURE
            </span>
            <h3 className="font-serif text-2xl font-normal text-[#0a0a0a]">DEFENSIVE BY DESIGN</h3>
            <ul className="space-y-2 text-xs text-[#737373]">
              <li className="flex items-start gap-2">
                <span className="text-[#0a0a0a] font-bold">•</span>
                <span>Automatic analysis runs before user clicks or interacts.</span>
              </li>
              <li className="flex items-start gap-2">
                <span className="text-[#0a0a0a] font-bold">•</span>
                <span>Explicit provenance tags attached to every evidence signal.</span>
              </li>
              <li className="flex items-start gap-2">
                <span className="text-[#0a0a0a] font-bold">•</span>
                <span>Deterministic engine fallback protects against AI quota limits.</span>
              </li>
              <li className="flex items-start gap-2">
                <span className="text-[#0a0a0a] font-bold">•</span>
                <span>Analyst feedback loop generates immutable training vectors.</span>
              </li>
            </ul>
          </div>

          {/* Operational System Status */}
          <div className="bg-white p-8 rounded-[24px] border border-[#e5e5e5] space-y-4 shadow-xs flex flex-col justify-between">
            <div>
              <span className="text-xs font-semibold text-[#737373] uppercase tracking-wider">
                OPERATIONAL HEALTH
              </span>
              <h3 className="font-serif text-2xl font-normal text-[#0a0a0a]">SYSTEM STATUS</h3>
            </div>

            <div className="grid grid-cols-2 gap-3 text-xs">
              <div className="bg-[#fafafa] p-3 rounded-xl border border-[#e5e5e5] flex items-center justify-between">
                <span className="text-[#737373]">API Server</span>
                <span className="font-mono font-semibold text-[#0a0a0a]">{apiOnline ? 'ONLINE' : 'OFFLINE'}</span>
              </div>
              <div className="bg-[#fafafa] p-3 rounded-xl border border-[#e5e5e5] flex items-center justify-between">
                <span className="text-[#737373]">Decision Engine</span>
                <span className="font-mono font-semibold text-[#0a0a0a]">READY</span>
              </div>
              <div className="bg-[#fafafa] p-3 rounded-xl border border-[#e5e5e5] flex items-center justify-between">
                <span className="text-[#737373]">Playwright JS</span>
                <span className="font-mono font-semibold text-[#0a0a0a]">READY</span>
              </div>
              <div className="bg-[#fafafa] p-3 rounded-xl border border-[#e5e5e5] flex items-center justify-between">
                <span className="text-[#737373]">RDAP / DNS</span>
                <span className="font-mono font-semibold text-[#0a0a0a]">READY</span>
              </div>
            </div>
          </div>
        </section>

        {/* 7. RECENT / ACTIVE INVESTIGATIONS */}
        <section className="space-y-4">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-[#737373] uppercase tracking-wider">
              INVESTIGATION HISTORY
            </span>
          </div>

          {activeVerdict ? (
            <div className="bg-white p-6 sm:p-8 rounded-[24px] border border-[#e5e5e5] space-y-4 shadow-xs">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-[#e5e5e5] pb-4">
                <div>
                  <span className="text-[10px] font-mono text-[#737373] uppercase block">
                    ACTIVE INVESTIGATION SESSION
                  </span>
                  <h4 className="font-serif text-2xl font-normal text-[#0a0a0a]">
                    {activeDomain || 'Amazon Security Demo Investigation'}
                  </h4>
                </div>

                <div className="flex items-center gap-3">
                  <span className="px-3 py-1 rounded-full text-xs font-mono font-semibold bg-[#0a0a0a] text-white">
                    VERDICT: {activeVerdict} ({activeRisk}/100)
                  </span>

                  <button
                    type="button"
                    onClick={() => onNavigateTab('case')}
                    className="bg-[#0a0a0a] text-white hover:bg-[#171717] px-4 py-2 rounded-full text-xs font-medium transition-all"
                  >
                    Resume Investigation
                  </button>
                </div>
              </div>

              <p className="text-xs text-[#737373]">
                Multi-surface evidence collected and analyzed. View detailed risk breakdown, attack chain graph, and generated PDF reports.
              </p>
            </div>
          ) : (
            <div className="bg-white p-12 rounded-[24px] border border-[#e5e5e5] text-center space-y-4 shadow-xs">
              <div className="w-12 h-12 rounded-full bg-[#fafafa] border border-[#e5e5e5] flex items-center justify-center mx-auto text-[#737373]">
                <Search size={20} />
              </div>
              <div className="space-y-1">
                <h4 className="font-serif text-xl font-normal text-[#0a0a0a]">No Recent Investigations Yet</h4>
                <p className="text-xs text-[#737373] max-w-sm mx-auto">
                  Start an investigation to build your investigation history and reconstruct phishing attack paths.
                </p>
              </div>
              <div className="pt-2">
                <button
                  type="button"
                  onClick={onStartNewInvestigation}
                  className="bg-[#0a0a0a] text-white hover:bg-[#171717] px-6 py-2.5 rounded-full text-xs font-medium transition-all shadow-sm inline-flex items-center gap-2"
                >
                  <Plus size={14} />
                  <span>Start First Investigation</span>
                </button>
              </div>
            </div>
          )}
        </section>

        {/* 8. FINAL EDITORIAL CTA SECTION */}
        <section className="bg-white rounded-[24px] border border-[#e5e5e5] p-10 sm:p-16 text-center space-y-6 shadow-xs">
          <div className="space-y-3 max-w-xl mx-auto">
            <h2 className="font-serif text-4xl sm:text-5xl font-normal text-[#0a0a0a] tracking-tight">
              DON'T WAIT FOR THE CLICK.
            </h2>
            <p className="text-xs sm:text-sm text-[#737373] leading-relaxed">
              Investigate suspicious messages, trace the attack path and understand the evidence before users interact with the threat.
            </p>
          </div>

          <div className="flex flex-wrap items-center justify-center gap-3 pt-2">
            <button
              type="button"
              onClick={onStartDemo}
              className="bg-[#0a0a0a] text-white hover:bg-[#171717] px-6 py-3 rounded-full text-xs sm:text-sm font-medium transition-all shadow-sm inline-flex items-center gap-2"
            >
              <Play size={14} className="fill-white" />
              <span>Run Demo Investigation</span>
            </button>

            <button
              type="button"
              onClick={onStartNewInvestigation}
              className="bg-transparent text-[#0a0a0a] border border-[#0a0a0a] hover:bg-[#f5f5f5] px-6 py-3 rounded-full text-xs sm:text-sm font-medium transition-all inline-flex items-center gap-2"
            >
              <Plus size={16} />
              <span>New Investigation</span>
            </button>
          </div>
        </section>
      </main>

      {/* SIMPLE EDITORIAL FOOTER */}
      <footer className="w-full max-w-[1200px] mx-auto px-4 sm:px-6 pt-12 border-t border-[#e5e5e5] flex flex-col sm:flex-row items-center justify-between gap-4 text-xs text-[#737373]">
        <div className="flex items-center gap-3">
          <span className="font-serif text-base text-[#0a0a0a]">KEKAI</span>
          <span className="text-[#e5e5e5]">|</span>
          <span>Phishing defense through connected evidence.</span>
        </div>

        <div className="flex items-center gap-6">
          <button type="button" onClick={() => onNavigateTab('home')} className="hover:text-[#0a0a0a] transition-colors">Home</button>
          <button type="button" onClick={() => onNavigateTab('inbox')} className="hover:text-[#0a0a0a] transition-colors">Threat Inbox</button>
          <button type="button" onClick={() => onNavigateTab('domain')} className="hover:text-[#0a0a0a] transition-colors">Threat Intel</button>
          <button type="button" onClick={() => onNavigateTab('case')} className="hover:text-[#0a0a0a] transition-colors">Verdict</button>
        </div>
      </footer>
    </div>
  );
}
