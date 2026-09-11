import React, { useState, useEffect, useRef } from 'react';
import ErrorBoundary from './components/ErrorBoundary';
import Toast from './components/Toast';
import Footer from './components/Footer';
import OnboardingPage from './components/OnboardingPage';
import HomePage from './components/HomePage';
import EmailThreatInboxTab from './components/EmailThreatInboxTab';
import DomainWatchTab from './components/DomainWatchTab';
import LogoMatchTab from './components/LogoMatchTab';
import CaseReportTab from './components/CaseReportTab';
import VisualPhishingTab from './components/VisualPhishingTab';
import LinkedInfrastructureTab from './components/LinkedInfrastructureTab';
import MarketplaceListingsTab from './components/MarketplaceListingsTab';
import SocialWatchTab from './components/SocialWatchTab';
import AbuseControlSection from './components/AbuseControlSection';
import WorkflowAutomationTab from './components/WorkflowAutomationTab';
import DemoControllerBar from './components/DemoControllerBar';
import DemoScenarioModal from './components/DemoScenarioModal';
import InvestigationWorkspace from './components/InvestigationWorkspace';
import { apiFetch } from './api';
import { analyzeInvestigation, normalizeInvestigationResult } from './services/investigationService';
import { ShieldAlert, Image as ImageIcon, FileCheck, Eye, Activity, Shield, Network, ShoppingBag, Share2, WifiOff, Plus } from 'lucide-react';

const API_BASE_URL = 'http://localhost:8000';

function Dashboard() {
  const [theme, setTheme] = useState(() => {
    return localStorage.getItem('keikai-theme') || 'light';
  });

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
    document.documentElement.classList.toggle('dark', theme === 'dark');
    try {
      localStorage.setItem('keikai-theme', theme);
    } catch {}
  }, [theme]);

  const toggleTheme = () => {
    setTheme((prev) => (prev === 'light' ? 'dark' : 'light'));
  };

  const [activeTab, setActiveTab] = useState('home');
  const [toasts, setToasts] = useState([]);
  const [apiOnline, setApiOnline] = useState(true);
  
  // Shared state for compiled case report items with localStorage persistence
  const [selectedDomains, setSelectedDomains] = useState(() => {
    try {
      const saved = localStorage.getItem('bp_selected_domains');
      return saved ? JSON.parse(saved) : [];
    } catch { return []; }
  });

  const [selectedLogos, setSelectedLogos] = useState(() => {
    try {
      const saved = localStorage.getItem('bp_selected_logos');
      return saved ? JSON.parse(saved) : [];
    } catch { return []; }
  });

  const [selectedVisualPhishing, setSelectedVisualPhishing] = useState(() => {
    try {
      const saved = localStorage.getItem('bp_selected_visual_phishing');
      return saved ? JSON.parse(saved) : [];
    } catch { return []; }
  });

  const [selectedListings, setSelectedListings] = useState(() => {
    try {
      const saved = localStorage.getItem('bp_selected_listings');
      return saved ? JSON.parse(saved) : [];
    } catch { return []; }
  });

  const [selectedSocialProfiles, setSelectedSocialProfiles] = useState(() => {
    try {
      const saved = localStorage.getItem('bp_selected_social_profiles');
      return saved ? JSON.parse(saved) : [];
    } catch { return []; }
  });

  const [brandName, setBrandName] = useState(() => {
    return localStorage.getItem('bp_brand_name') || '';
  });

  const [investigationState, setInvestigationState] = useState(() => {
    try {
      const init = localStorage.getItem('keikai_investigation_initialized') === 'true' || localStorage.getItem('ikigai_investigation_initialized') === 'true';
      return {
        isInitialized: init,
        investigationId: localStorage.getItem('keikai_investigation_id') || localStorage.getItem('ikigai_investigation_id') || '',
        brandName: localStorage.getItem('bp_brand_name') || '',
        officialDomain: localStorage.getItem('keikai_official_domain') || localStorage.getItem('ikigai_official_domain') || '',
        source: 'domain_monitoring'
      };
    } catch {
      return { isInitialized: false, investigationId: '', brandName: '', officialDomain: '', source: 'domain_monitoring' };
    }
  });

  const [investigationContext, setInvestigationContext] = useState(() => {
    try {
      const saved = localStorage.getItem('keikai_investigation_context');
      return saved ? JSON.parse(saved) : null;
    } catch { return null; }
  });

  const [investigationResult, setInvestigationResult] = useState(() => {
    try {
      const saved = localStorage.getItem('keikai_investigation_result');
      return saved ? JSON.parse(saved) : null;
    } catch { return null; }
  });

  const [isAnalyzing, setIsAnalyzing] = useState(false);

  useEffect(() => {
    if (investigationContext) {
      try {
        localStorage.setItem('keikai_investigation_context', JSON.stringify(investigationContext));
      } catch {}
    }
  }, [investigationContext]);

  useEffect(() => {
    if (investigationResult) {
      try {
        localStorage.setItem('keikai_investigation_result', JSON.stringify(investigationResult));
      } catch {}
    }
  }, [investigationResult]);

  const handleRunInvestigation = async (params = {}) => {
    const invId = params.investigationId || investigationState.investigationId || `INV-${Date.now()}`;
    const emailData = params.emailData || null;
    const targetUrl = params.targetUrl || investigationContext?.url || '';

    setIsAnalyzing(true);
    try {
      const result = await analyzeInvestigation({
        investigationId: invId,
        emailData,
        targetUrl,
        reason: params.reason || 'USER_ANALYZE_CLICK',
        forceReanalyze: params.forceReanalyze || false
      });

      setInvestigationResult(result);
      if (addToast) {
        addToast('Analysis Complete', `Unified security verdict: ${result.verdict} (Risk: ${result.riskScore}/100)`, 'success');
      }
      return result;
    } catch (err) {
      console.error('[KEIKAI] Investigation analysis failed:', err);
      if (addToast) {
        addToast('Analysis Error', err.message || 'Failed to complete investigation analysis', 'error');
      }
    } finally {
      setIsAnalyzing(false);
    }
  };

  const [notes, setNotes] = useState(() => {
    return localStorage.getItem('bp_notes') || 'Flagged typosquatting domain lookalikes, logo misuse, counterfeit marketplace listings, and social media impersonation for executive review.';
  });

  // Save selected listings & social profiles to localStorage
  useEffect(() => {
    try {
      localStorage.setItem('bp_selected_listings', JSON.stringify(selectedListings));
    } catch {}
  }, [selectedListings]);

  useEffect(() => {
    try {
      localStorage.setItem('bp_selected_social_profiles', JSON.stringify(selectedSocialProfiles));
    } catch {}
  }, [selectedSocialProfiles]);

  const toggleSelectProfile = (item) => {
    setSelectedSocialProfiles((prev) => {
      const exists = prev.some((s) => s.profile_id === item.profile_id);
      if (exists) {
        addToast('Removed from Case', `Removed social profile ${item.handle}`, 'info');
        return prev.filter((s) => s.profile_id !== item.profile_id);
      } else {
        addToast('Added to Case Report', `Social profile ${item.handle} added to case.`, 'success');
        return [...prev, item];
      }
    });
  };

  // Save selected listings to localStorage
  useEffect(() => {
    try {
      localStorage.setItem('bp_selected_listings', JSON.stringify(selectedListings));
    } catch {}
  }, [selectedListings]);

  const toggleSelectListing = (item) => {
    setSelectedListings((prev) => {
      const exists = prev.some((l) => l.listing_id === item.listing_id);
      if (exists) {
        addToast('Removed from Case', `Removed listing ${item.title}`, 'info');
        return prev.filter((l) => l.listing_id !== item.listing_id);
      } else {
        addToast('Added to Case Report', `Listing ${item.title} added to case.`, 'success');
        return [...prev, item];
      }
    });
  };

  // Persistent tab states for Domain Watch & Logo Match
  const [domainScanState, setDomainScanState] = useState({
    domainInput: '',
    quickMode: true,
    results: null,
    searchFilter: '',
    statusFilter: 'all',
    riskFilter: 'all',
    fuzzerFilter: 'all',
    sortField: 'risk',
    sortAsc: false,
    currentPage: 1,
    pageSize: 25
  });

  const [logoMatchState, setLogoMatchState] = useState({
    refFile: null,
    candidateFiles: [],
    threshold: 10,
    batchResults: null
  });

  const handleStartInvestigation = (params) => {
    const { investigationId, brandName, officialDomain, logoFile, logoPreview, source } = params;

    // Save to localStorage
    localStorage.setItem('keikai_investigation_initialized', 'true');
    localStorage.setItem('keikai_investigation_id', investigationId);
    localStorage.setItem('bp_brand_name', brandName);
    localStorage.setItem('keikai_official_domain', officialDomain);

    // Clear old evidence items for fresh investigation
    setSelectedDomains([]);
    setSelectedLogos([]);
    setSelectedVisualPhishing([]);
    setSelectedListings([]);
    setSelectedSocialProfiles([]);
    try {
      localStorage.removeItem('bp_selected_domains');
      localStorage.removeItem('bp_selected_logos');
      localStorage.removeItem('bp_selected_visual_phishing');
      localStorage.removeItem('bp_selected_listings');
      localStorage.removeItem('bp_selected_social_profiles');
    } catch (e) {}

    setInvestigationState({
      isInitialized: true,
      investigationId,
      brandName,
      officialDomain,
      source: source || 'domain_monitoring'
    });

    setBrandName(brandName);

    // Pre-populate domain input in Domain Watch
    setDomainScanState((prev) => ({
      ...prev,
      domainInput: officialDomain,
      results: null
    }));

    if (logoFile) {
      setLogoMatchState((prev) => ({
        ...prev,
        refFile: logoFile
      }));
    }

    setActiveTab('domain');
    addToast('Investigation Created', `Initialized ${investigationId} for brand '${brandName}'.`, 'success');
  };

  // Sync case state to localStorage
  useEffect(() => {
    try {
      localStorage.setItem('bp_selected_domains', JSON.stringify(selectedDomains));
    } catch (e) { console.error('Failed to save domains:', e); }
  }, [selectedDomains]);

  useEffect(() => {
    try {
      localStorage.setItem('bp_selected_logos', JSON.stringify(selectedLogos));
    } catch (e) { console.error('Failed to save logos:', e); }
  }, [selectedLogos]);

  useEffect(() => {
    try {
      localStorage.setItem('bp_selected_visual_phishing', JSON.stringify(selectedVisualPhishing));
    } catch (e) { console.error('Failed to save visual phishing:', e); }
  }, [selectedVisualPhishing]);

  useEffect(() => {
    localStorage.setItem('bp_brand_name', brandName);
  }, [brandName]);

  useEffect(() => {
    localStorage.setItem('bp_notes', notes);
  }, [notes]);

  const toastHistoryRef = React.useRef([]);

  const addToast = (title, message, type = 'info', duration = 5000) => {
    const now = Date.now();
    const isDuplicate = toastHistoryRef.current.some(
      (t) => t.title === title && t.message === message && now - t.timestamp < 2500
    );
    if (isDuplicate) return;

    toastHistoryRef.current.push({ title, message, timestamp: now });
    if (toastHistoryRef.current.length > 20) {
      toastHistoryRef.current.shift();
    }

    const id = now + Math.random().toString(36).substring(2, 5);
    setToasts((prev) => [...prev, { id, title, message, type, duration }]);
  };

  const removeToast = (id) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  };

  // Health check — runs on mount, and retries every 8s while offline so
  // the banner self-heals the moment the backend comes back up.
  const healthRetryRef = useRef(null);

  const checkHealth = async () => {
    try {
      const res = await apiFetch(`${API_BASE_URL}/api/health`);
      const data = await res.json();
      const online = data.status === 'success';
      setApiOnline(online);

      if (online && data.data?.server_instance_id) {
        const currentInstance = data.data.server_instance_id;
        const storedInstance = sessionStorage.getItem('keikai_server_instance_id');
        if (storedInstance && storedInstance !== currentInstance) {
          console.log('[KEIKAI] Server restart detected! Initializing fresh investigation session.');
          try {
            localStorage.removeItem('keikai_investigation_initialized');
            localStorage.removeItem('ikigai_investigation_initialized');
            localStorage.removeItem('keikai_investigation_id');
            localStorage.removeItem('ikigai_investigation_id');
            localStorage.removeItem('bp_brand_name');
            localStorage.removeItem('keikai_official_domain');
            localStorage.removeItem('ikigai_official_domain');
            localStorage.removeItem('bp_selected_domains');
            localStorage.removeItem('bp_selected_logos');
            localStorage.removeItem('bp_selected_visual_phishing');
            localStorage.removeItem('bp_selected_listings');
            localStorage.removeItem('bp_selected_social_profiles');
          } catch {}

          setSelectedDomains([]);
          setSelectedLogos([]);
          setSelectedVisualPhishing([]);
          setSelectedListings([]);
          setSelectedSocialProfiles([]);
          setBrandName('');
          setInvestigationState({
            isInitialized: false,
            investigationId: '',
            brandName: '',
            officialDomain: '',
            source: 'domain_monitoring'
          });
          setActiveTab('inbox');
        }
        sessionStorage.setItem('keikai_server_instance_id', currentInstance);
      }

      if (online && healthRetryRef.current) {
        clearInterval(healthRetryRef.current);
        healthRetryRef.current = null;
      }
    } catch (err) {
      console.warn('Backend API health check failed:', err.message);
      setApiOnline(false);
      // Start polling every 8 s to auto-recover without a full page refresh
      if (!healthRetryRef.current) {
        healthRetryRef.current = setInterval(checkHealth, 8000);
      }
    }
  };

  useEffect(() => {
    checkHealth();
    return () => {
      if (healthRetryRef.current) clearInterval(healthRetryRef.current);
    };
  }, []);

  const logRemoteEvent = (eventType, description) => {
    fetch(`${API_BASE_URL}/api/case/default/event`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ event_type: eventType, description })
    }).catch((err) => console.warn('Failed to log remote timeline event:', err));
  };

  const toggleSelectDomain = (item) => {
    setSelectedDomains((prev) => {
      const exists = prev.some((d) => d.domain === item.domain);
      if (exists) {
        addToast('Removed from Case', `Removed domain ${item.domain}`, 'info');
        return prev.filter((d) => d.domain !== item.domain);
      } else {
        addToast('Added to Case Report', `Flagged domain ${item.domain} added to case.`, 'success');
        logRemoteEvent('evidence_added', `Domain evidence added: ${item.domain} (Fuzzer: ${item.fuzzer || 'homoglyph'})`);
        return [...prev, item];
      }
    });
  };

  const toggleSelectLogo = (item) => {
    setSelectedLogos((prev) => {
      const exists = prev.some((l) => l.candidate_filename === item.candidate_filename);
      if (exists) {
        addToast('Removed from Case', `Removed logo match ${item.candidate_filename}`, 'info');
        return prev.filter((l) => l.candidate_filename !== item.candidate_filename);
      } else {
        addToast('Added to Case Report', `Flagged logo ${item.candidate_filename} added to case.`, 'success');
        logRemoteEvent('evidence_added', `Logo match evidence added: ${item.candidate_filename} (${item.combined_similarity_percentage?.toFixed(1)}% sim)`);
        return [...prev, item];
      }
    });
  };

  const toggleSelectVisualPhishing = (item) => {
    setSelectedVisualPhishing((prev) => {
      const key = item.key || item.id || item.url;
      const exists = prev.some((vp) => (vp.key || vp.id || vp.url) === key);
      if (exists) {
        addToast('Removed from Case', `Removed visual phishing evidence for ${item.url}`, 'info');
        return prev.filter((vp) => (vp.key || vp.id || vp.url) !== key);
      } else {
        addToast('Added to Case Report', `Visual phishing evidence for ${item.url} added to case.`, 'success');
        logRemoteEvent('evidence_added', `Visual phishing evidence added for ${item.url} (Target: ${item.target_brand || 'Threat'})`);
        return [...prev, item];
      }
    });
  };

  // Add all cluster assets to Case Report in one click
  const handleAddClusterToCase = (cluster) => {
    if (!cluster || !cluster.assets) return;

    logRemoteEvent('cluster_linked', `Offender cluster ${cluster.cluster_id} linked with ${cluster.asset_count} assets (${cluster.confidence} confidence).`);

    const newDomains = [...selectedDomains];
    const newLogos = [...selectedLogos];
    const newPhish = [...selectedVisualPhishing];

    cluster.assets.forEach((a) => {
      if (a.asset_type === 'domain' && !newDomains.some((d) => d.domain === a.asset_id)) {
        newDomains.push({
          domain: a.asset_id,
          fuzzer: 'cluster_linked',
          isRegistered: true,
          riskScore: 85,
          dns_a: a.ip_address ? [a.ip_address] : []
        });
      } else if (a.asset_type === 'logo' && !newLogos.some((l) => l.candidate_filename === a.asset_id)) {
        newLogos.push({
          candidate_filename: a.asset_id,
          phash_distance: 2,
          dhash_distance: 3,
          combined_similarity_percentage: 88.5,
          likely_match: true
        });
      } else if (a.asset_type === 'visual_phishing' && !newPhish.some((vp) => vp.url === a.asset_id)) {
        const itemKey = `vp-${a.asset_id}-cluster`;
        newPhish.push({
          id: itemKey,
          key: itemKey,
          type: 'visual_phishing',
          url: a.asset_id,
          verdict: 'Phishing',
          target_brand: a.target_brand || 'Threat Operator',
          confidence: 90.0,
          matched_domain: null,
          isFallback: false,
          timestamp: new Date().toISOString()
        });
      }
    });

    setSelectedDomains(newDomains);
    setSelectedLogos(newLogos);
    setSelectedVisualPhishing(newPhish);
  };

  const handleClearCase = () => {
    setSelectedDomains([]);
    setSelectedLogos([]);
    setSelectedVisualPhishing([]);
    setBrandName('Acme Corporate Brand');
    setNotes('');
    try {
      localStorage.removeItem('bp_selected_domains');
      localStorage.removeItem('bp_selected_logos');
      localStorage.removeItem('bp_selected_visual_phishing');
      localStorage.removeItem('bp_brand_name');
      localStorage.removeItem('bp_notes');
    } catch {}
    addToast('Case Cleared', 'All compiled evidence items and investigator notes have been reset.', 'info');
  };

  const totalSelectedCount = selectedDomains.length + selectedLogos.length + selectedVisualPhishing.length;

  const hasDomain = selectedDomains.length > 0;
  const hasLogo = selectedLogos.length > 0;
  const hasPhish = selectedVisualPhishing.length > 0;
  const hasNotes = notes.trim().length > 0;
  const categoriesCount = (hasDomain ? 1 : 0) + (hasLogo ? 1 : 0) + (hasPhish ? 1 : 0) + (hasNotes ? 1 : 0);
  const completenessPercent = Math.round((categoriesCount / 4) * 100);

  // DEMO MODE STATE
  const [isDemoRunning, setIsDemoRunning] = useState(false);
  const [demoStage, setDemoStage] = useState(-1); // -1 = closed, 0 = intro launcher, 1..6 = stages, 7 = summary
  const [isDemoPaused, setIsDemoPaused] = useState(false);

  const handleRunFullDemoScenario = () => {
    // Open Launcher Modal Stage 0
    setDemoStage(0);
  };

  const handleStartDemo = () => {
    // Initialize Amazon Demo Scenario
    setBrandName('Amazon');
    const demoInvId = 'CASE-AMAZON-DEMO-092';
    setInvestigationState({
      isInitialized: true,
      investigationId: demoInvId,
      brandName: 'Amazon',
      officialDomain: 'amazon.com',
      source: 'Domain Monitoring',
      timestamp: new Date().toISOString()
    });

    const demoResult = normalizeInvestigationResult({
      investigation_id: demoInvId,
      organisation_id: 'org_acme_01',
      verdict: 'PHISHING',
      risk_score: 94,
      confidence: 91,
      evidence_quality: 96,
      primary_hypothesis: 'CREDENTIAL_HARVESTING',
      recommended_action: 'BLOCK',
      primary_reasons: [
        'Sender behavior anomaly: finance sender transmitting off-hours to external recipient',
        'Registered typosquat lookalike domain amazon-security-login.example (6 days old)',
        'Extracted HTTP redirect chain: 2 hops leading to non-official origin',
        'Dynamic JavaScript execution rendered hidden password harvesting form',
        'Phishpedia model matched 94% visual brand similarity to Amazon'
      ],
      supporting_evidence: [
        { source: 'sender_behavior', signal: 'possible_account_compromise', value: 'Internal account anomaly: off-hours transmission to external recipient', severity: 40, confidence: 0.85 },
        { source: 'email_content', signal: 'credential_request', value: 'Urgent authentication or credential harvesting keywords in body', severity: 30, confidence: 0.85 },
        { source: 'domain_intelligence', signal: 'lookalike_domain_permutation', value: 'Domain amazon-security-login.example registered 6 days ago via NameCheap', severity: 40, confidence: 0.95 },
        { source: 'page_analysis', signal: 'dynamic_password_form', value: 'Password input field appeared dynamically after JS execution', severity: 45, confidence: 0.95 },
        { source: 'visual_analysis', signal: 'brand_clone_detection', value: '94% visual brand similarity to Amazon official login portal', severity: 45, confidence: 0.95 }
      ],
      contradicting_evidence: [
        { source: 'openphish', signal: 'no_openphish_match', value: 'No match in OpenPhish community database', severity: 0, confidence: 0.7 }
      ],
      ai_reasoning: {
        ai_used: true,
        reasoning_source: 'openrouter',
        model: 'openrouter/free',
        summary: 'High-risk credential harvesting campaign targeting Amazon credentials. Impersonates corporate security portal via a newly-registered lookalike domain.',
        key_evidence: [
          'Off-hours transmission from finance sender with credential link',
          'Domain amazon-security-login.example registered 6 days ago',
          'Dynamic JavaScript execution rendered credential input fields',
          '94% visual brand clone match to Amazon'
        ]
      },
      stage_results: {
        email: { subject: 'URGENT: Corporate Vendor Account Login Verification Required', sender: 'finance@acme.example', threat_type: 'phishing', risk_score: 92 },
        sender_behavior: { hypothesis: 'POSSIBLE_ACCOUNT_COMPROMISE', anomaly_score: 92, profile_available: true },
        payload: { filename: 'login_verification.pdf', sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', is_html_form: true, qr_decoded_url: 'https://amazon-security-login.example/auth/login.html' },
        domain: { domain: 'amazon-security-login.example', relationship: 'LOOKALIKE', is_lookalike: true, rdap_age_days: 6, registrar: 'NameCheap Inc.', threat_feeds: { openphish: false, phishtank: false, dnstwist: true } },
        page_analysis: { title: 'Amazon Security Verification Portal', form_action: 'https://amazon-security-login.example/submit.php', matched_brand: 'Amazon', visual_similarity_percentage: 94.2, clone_classification: 'STRONG_BRAND_CLONE' }
      }
    });

    setInvestigationResult(demoResult);

    // Seed deterministic evidence items for Amazon
    const demoDomains = [{
      domain: 'amazon-security-login.example',
      risk_score: 92,
      risk_category: 'CRITICAL',
      evidence_quality: 91,
      investigation_quality: 'COMPLETE',
      relationship: 'LOOKALIKE',
      phishpedia_confidence: 0.968,
      ocr_matched: true,
      threat_feeds: ['dnstwist', 'openphish', 'phishtank'],
      timestamp: new Date().toISOString()
    }];

    setSelectedDomains(demoDomains);
    setSelectedLogos([]);
    setSelectedVisualPhishing([]);
    setIsDemoRunning(true);
    setDemoStage(1);
    setIsDemoPaused(false);
    setActiveTab('domain');
    addToast('Demo Started', 'Live investigation simulation initialized for Amazon (amazon.com).', 'info');
  };

  const handleNextDemoStage = () => {
    if (demoStage < 6) {
      const next = demoStage + 1;
      setDemoStage(next);
      if (next === 4) setActiveTab('phishing');
      if (next === 5) setActiveTab('case');
      if (next === 6) setActiveTab('case');
    } else if (demoStage === 6) {
      setDemoStage(7); // Show final summary screen
    }
  };

  return (
    <div className="min-h-screen bg-background text-on-background flex flex-col font-body-md antialiased">
      {/* Top Notification Toast Container */}
      <Toast toasts={toasts} removeToast={removeToast} />

      <div className="flex-1">
        {/* Stitch Top Navigation Bar */}
        <nav className="bg-surface-container-lowest border-b border-outline-variant sticky top-0 z-50">
          <div className="max-w-[1440px] mx-auto w-full px-4 sm:px-6 lg:px-8 flex justify-between items-center h-[64px]">
            <div className="flex items-center gap-4 lg:gap-6 min-w-0">
              {/* Clickable Brand Home Button */}
              <button
                type="button"
                onClick={() => setActiveTab('home')}
                className="flex items-center gap-2 hover:opacity-80 transition-opacity cursor-pointer text-left shrink-0"
                title="Return to Security Command Center"
              >
                <span className="material-symbols-outlined text-primary text-[28px] fill-icon">shield</span>
                <span className="font-headline-md text-[20px] font-bold text-primary tracking-tight">KEKAI</span>
              </button>

              <div className="hidden md:flex items-center gap-2 lg:gap-4 h-[64px] min-w-0">
                {/* Home Button */}
                <button
                  type="button"
                  onClick={() => setActiveTab('home')}
                  className={`h-full flex items-center gap-1.5 px-3 text-xs lg:text-sm font-medium transition-all whitespace-nowrap ${
                    activeTab === 'home'
                      ? 'text-[var(--color-ink)] border-b-2 border-[var(--color-ink)] font-semibold'
                      : 'text-[var(--color-slate-gray)] hover:text-[var(--color-ink)]'
                  }`}
                >
                  <span className="material-symbols-outlined text-[18px]">home</span>
                  <span>Home</span>
                </button>

                {/* Investigation Workspace Button */}
                <button
                  type="button"
                  onClick={() => setActiveTab('workspace')}
                  className={`h-full flex items-center gap-1.5 px-3 text-xs lg:text-sm font-medium transition-all whitespace-nowrap ${
                    activeTab !== 'home'
                      ? 'text-[var(--color-ink)] border-b-2 border-[var(--color-ink)] font-semibold'
                      : 'text-[var(--color-slate-gray)] hover:text-[var(--color-ink)]'
                  }`}
                >
                  <span className="material-symbols-outlined text-[18px]">security</span>
                  <span>Investigation Workspace</span>
                </button>
              </div>

                {/* Supporting Modules Select Dropdown */}
                <div className="relative group flex items-center h-full">
                  <select
                    value={['logo', 'takedown', 'workflows', 'listings', 'social'].includes(activeTab) ? activeTab : ''}
                    onChange={(e) => {
                      if (e.target.value) setActiveTab(e.target.value);
                    }}
                    className={`h-8 px-2 bg-surface-container-low border rounded text-xs font-semibold cursor-pointer outline-none transition-all ${
                      ['logo', 'takedown', 'workflows', 'listings', 'social'].includes(activeTab)
                        ? 'border-primary text-primary font-bold'
                        : 'border-outline-variant text-on-surface-variant hover:border-primary'
                    }`}
                  >
                    <option value="" disabled>Secondary Modules ▾</option>
                    <option value="logo">Logo Fingerprinting</option>
                    <option value="takedown">Abuse &amp; Takedown Plane</option>
                    <option value="workflows">viaSocket Workflows</option>
                    <option value="listings">Marketplace Protection</option>
                    <option value="social">Social Watch</option>
                  </select>
                </div>
              </div>

            <div className="flex items-center gap-2.5 shrink-0">
              {/* New Investigation Button in Navbar */}
              <button
                type="button"
                onClick={() => {
                  setInvestigationState((prev) => ({ ...prev, isInitialized: false }));
                  setActiveTab('inbox');
                }}
                className="btn-secondary text-xs font-semibold py-1.5 px-3 rounded-full flex items-center gap-1.5 whitespace-nowrap"
                title="Start a new investigation"
              >
                <Plus size={14} />
                <span className="hidden sm:inline">New Investigation</span>
              </button>

              {/* Demo Scenario Button */}
              <button
                type="button"
                onClick={handleRunFullDemoScenario}
                className="btn-primary text-xs font-semibold py-1.5 px-3 rounded-full flex items-center gap-1.5 shadow-xs whitespace-nowrap"
              >
                <span className="material-symbols-outlined text-[16px]">play_circle</span>
                <span className="hidden lg:inline">Run Demo Scenario</span>
              </button>

              {/* API Status Indicator Pill */}
              <div className="hidden xl:flex items-center gap-1.5 px-2.5 py-1 bg-surface-container-low rounded-full border border-outline-variant text-xs shrink-0">
                <span className={`w-2 h-2 rounded-full ${apiOnline ? 'bg-[#10B981]' : 'bg-error'}`}></span>
                <span className="text-on-surface-variant font-technical-data text-[11px]">
                  API: {apiOnline ? 'Online' : 'Offline'}
                </span>
              </div>

              {/* Global Theme Toggle Button */}
              <button
                type="button"
                onClick={toggleTheme}
                className="p-1.5 text-on-surface-variant hover:bg-surface-container-low rounded-full transition-all flex items-center justify-center"
                title={`Switch to ${theme === 'light' ? 'Dark' : 'Light'} Mode`}
              >
                <span className="material-symbols-outlined text-[20px]">{theme === 'light' ? 'dark_mode' : 'light_mode'}</span>
              </button>
            </div>
          </div>
        </nav>

        {/* Persistent Backend Unreachable Banner */}
        {!apiOnline && (
          <div className="bg-[#fff7ed] border-b border-[#fed7aa] px-4 sm:px-6 lg:px-8 py-2">
            <div className="max-w-[1440px] mx-auto flex items-center justify-between gap-4 text-xs">
              <div className="flex items-center gap-2 text-[#c2410c] font-semibold">
                <span className="material-symbols-outlined text-[16px]">wifi_off</span>
                <span>Backend Unreachable &mdash; Cannot connect to API server. Auto-retrying...</span>
              </div>
              <button
                onClick={checkHealth}
                className="px-3 py-1 bg-white border border-[#fed7aa] hover:bg-[#fff7ed] text-[#c2410c] rounded text-xs font-semibold"
              >
                Retry Now
              </button>
            </div>
          </div>
        )}

        <main className="max-w-[1440px] mx-auto w-full px-4 sm:px-6 lg:px-8 py-6 flex flex-col gap-6">
          {activeTab === 'home' ? (
            <HomePage
              onNavigateTab={setActiveTab}
              onStartDemo={handleRunFullDemoScenario}
              onStartNewInvestigation={() => {
                setInvestigationState((prev) => ({ ...prev, isInitialized: false }));
                setActiveTab('workspace');
              }}
              apiOnline={apiOnline}
              investigationContext={investigationContext}
              investigationResult={investigationResult}
            />
          ) : (
            <InvestigationWorkspace
              investigationResult={investigationResult}
              investigationContext={investigationContext}
              handleRunInvestigation={handleRunInvestigation}
              isAnalyzing={isAnalyzing}
              addToast={addToast}
              onRunDemo={handleRunFullDemoScenario}
              onResetSession={() => {
                setInvestigationState((prev) => ({ ...prev, isInitialized: false }));
                setInvestigationResult(null);
                setInvestigationContext(null);
                try {
                  localStorage.removeItem('keikai_investigation_result');
                  localStorage.removeItem('keikai_investigation_context');
                } catch {}
              }}
            />
          )}


        </main>

        {/* DEMO SCENARIO OVERLAYS */}
        {demoStage >= 0 && (
          <DemoScenarioModal
            stage={demoStage}
            onStartDemo={handleStartDemo}
            onClose={() => { setDemoStage(-1); setIsDemoRunning(false); }}
            onNextStage={handleNextDemoStage}
            onNavigateTab={setActiveTab}
          />
        )}

        {isDemoRunning && (
          <DemoControllerBar
            currentStage={demoStage > 0 && demoStage <= 6 ? demoStage : 1}
            totalStages={6}
            isPaused={isDemoPaused}
            onTogglePause={() => setIsDemoPaused(!isDemoPaused)}
            onNextStage={handleNextDemoStage}
            onRestart={handleStartDemo}
            onExit={() => { setIsDemoRunning(false); setDemoStage(-1); }}
          />
        )}
      </div>
    </div>
  );
}

export default function App() {
  return (
    <ErrorBoundary>
      <Dashboard />
    </ErrorBoundary>
  );
}
