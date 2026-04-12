"use client";

import { useState, useEffect, useRef } from "react";
import {
  Shield, Scan, Zap, Bot, ArrowRight, Check, ChevronRight, Network,
  Lock, Eye, Database, Layers, Terminal, AlertTriangle, Activity,
  X, Sparkles, FileJson, Building2, HeartPulse, TrendingUp, Cloud,
} from "lucide-react";

/* ── ANIMATION HOOK ── */
function useInView(threshold = 0.15) {
  const ref = useRef<HTMLDivElement>(null);
  const [inView, setInView] = useState(false);
  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const obs = new IntersectionObserver(([e]) => { if (e.isIntersecting) { setInView(true); obs.disconnect(); } }, { threshold });
    obs.observe(el);
    return () => obs.disconnect();
  }, [threshold]);
  return { ref, inView };
}

/* ── NAVBAR ── */
function Navbar() {
  const [scrolled, setScrolled] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);
  useEffect(() => { const h = () => setScrolled(window.scrollY > 40); window.addEventListener("scroll", h, { passive: true }); return () => window.removeEventListener("scroll", h); }, []);
  const links = [
    { label: "How It Works", href: "#how-it-works" },
    { label: "Sectors", href: "#sectors" },
    { label: "Intelligence", href: "#intelligence" },
  ];
  return (
    <nav className={`fixed top-0 w-full z-50 transition-all duration-300 ${scrolled ? "bg-vektor-bg/90 backdrop-blur-xl border-b border-vektor-border" : "bg-transparent"}`}>
      <div className="max-w-7xl mx-auto px-6 h-16 flex items-center justify-between">
        <a href="#" className="flex items-center gap-2 group">
          <img src="/vektor-logo.png" alt="Vektor" className="h-8 w-auto" />
          <span className="text-lg font-bold tracking-tight">vektor</span>
        </a>
        <div className="hidden md:flex items-center gap-8">
          {links.map((l) => (<a key={l.label} href={l.href} className="text-sm text-vektor-text-secondary hover:text-white transition-colors">{l.label}</a>))}
        </div>
        <div className="hidden md:flex items-center gap-4">
          <a href="/demo" className="text-sm px-4 py-2 rounded-lg bg-vektor-accent hover:bg-vektor-accent-hover text-white font-medium transition-colors">Request Demo</a>
        </div>
        <button className="md:hidden text-vektor-text-secondary" onClick={() => setMobileOpen(!mobileOpen)}>
          {mobileOpen ? <X className="w-5 h-5" /> : <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeWidth={2} d="M4 6h16M4 12h16M4 18h16" /></svg>}
        </button>
      </div>
      {mobileOpen && (
        <div className="md:hidden bg-vektor-bg border-b border-vektor-border px-6 py-4 space-y-3">
          {links.map((l) => (<a key={l.label} href={l.href} className="block text-sm text-vektor-text-secondary hover:text-white" onClick={() => setMobileOpen(false)}>{l.label}</a>))}
          <a href="/demo" className="block text-sm px-4 py-2 rounded-lg bg-vektor-accent text-white text-center font-medium">Request Demo</a>
        </div>
      )}
    </nav>
  );
}

/* ── HERO ── */
function Hero() {
  return (
    <section className="relative min-h-screen flex items-center justify-center overflow-hidden">
      <div className="absolute inset-0 bg-grid" />
      <div className="absolute inset-0 radial-glow" />
      <div className="absolute inset-0 noise-overlay" />
      <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-vektor-accent/5 rounded-full blur-3xl animate-pulse-slow" />
      <div className="absolute bottom-1/4 right-1/4 w-80 h-80 bg-vektor-green/5 rounded-full blur-3xl animate-pulse-slow" style={{ animationDelay: "1.5s" }} />

      <div className="relative z-10 max-w-5xl mx-auto px-6 text-center">
        <img src="/vektor-logo.png" alt="Vektor" className="w-32 sm:w-40 mx-auto mb-6 animate-fade-in" />

        <div className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full bg-vektor-accent/10 border border-vektor-accent/20 mb-8 animate-fade-in">
          <Sparkles className="w-3.5 h-3.5 text-vektor-accent" />
          <span className="text-xs font-medium text-vektor-accent tracking-wide uppercase">The Relational Entity Intelligence Platform</span>
        </div>

        <h1 className="text-4xl sm:text-5xl lg:text-6xl font-bold tracking-tight leading-[1.15] mb-6 animate-slide-up">
          AI-native intelligence for{" "}
          <span className="text-transparent bg-clip-text bg-gradient-to-r from-vektor-accent via-blue-400 to-vektor-green">
            every entity, every relationship, every agent.
          </span>
        </h1>

        <p className="text-lg sm:text-xl text-vektor-text-secondary max-w-2xl mx-auto mb-10 animate-slide-up" style={{ animationDelay: "0.15s" }}>
          Vektor turns entity-permission-resource relationships into feature vectors, detects risk with AI models, and writes the policies to fix it — across ERP, financial services, healthcare, and cloud infrastructure.
        </p>

        <div className="flex flex-col sm:flex-row items-center justify-center gap-4 animate-slide-up" style={{ animationDelay: "0.3s" }}>
          <a href="/demo" className="group flex items-center gap-2 px-6 py-3 rounded-lg bg-vektor-accent hover:bg-vektor-accent-hover text-white font-semibold transition-all hover:shadow-lg hover:shadow-vektor-accent/25">
            Request Demo <ArrowRight className="w-4 h-4 transition-transform group-hover:translate-x-0.5" />
          </a>
          <a href="#how-it-works" className="flex items-center gap-2 px-6 py-3 rounded-lg border border-vektor-border text-vektor-text-secondary hover:text-white hover:border-vektor-text-muted transition-all">See how it works</a>
        </div>

        {/* Sector badges */}
        <div className="mt-12 flex flex-wrap items-center justify-center gap-3 animate-fade-in" style={{ animationDelay: "0.5s" }}>
          {[
            { label: "ERP / Finance", color: "border-purple-400/40 text-purple-400" },
            { label: "Financial Services", color: "border-amber-400/40 text-amber-400" },
            { label: "Healthcare", color: "border-red-400/40 text-red-400" },
            { label: "Cloud IAM", color: "border-cyan-400/40 text-cyan-400" },
          ].map((s) => (
            <span key={s.label} className={`text-xs font-medium px-3 py-1 rounded-full border ${s.color}`}>{s.label}</span>
          ))}
        </div>

        <div className="mt-8 flex items-center justify-center gap-8 text-xs text-vektor-text-muted animate-fade-in" style={{ animationDelay: "0.6s" }}>
          <span className="flex items-center gap-1.5"><Shield className="w-3.5 h-3.5" /> SOX / SEC / HIPAA</span>
          <span className="flex items-center gap-1.5"><Eye className="w-3.5 h-3.5" /> Read-Only Access</span>
          <span className="flex items-center gap-1.5"><Bot className="w-3.5 h-3.5" /> Agent-as-Subject</span>
        </div>
      </div>
    </section>
  );
}

/* ── THE PROBLEM ── */
function ProblemSection() {
  const { ref, inView } = useInView();
  const problems = [
    { stat: "4+", label: "entity systems per company", desc: "IAM, ERP, EHR, trading platforms — each with its own roles, permissions, and blind spots. No cross-system intelligence.", icon: Database, color: "text-red-400" },
    { stat: "100s", label: "of hand-written rules", desc: "Static rules that break when roles change. Maintained by humans who can't keep up with entity sprawl across sectors.", icon: Terminal, color: "text-amber-400" },
    { stat: "45:1", label: "NHIs outnumber humans", desc: "AI agents in trading, clinical workflows, financial automation — accumulating permissions faster than any human can monitor.", icon: Bot, color: "text-purple-400" },
  ];
  return (
    <section className="py-24 relative" ref={ref}>
      <div className="max-w-7xl mx-auto px-6">
        <div className="text-center mb-16">
          <p className="text-sm font-medium text-red-400 tracking-wide uppercase mb-3">The Problem</p>
          <h2 className="text-3xl sm:text-4xl font-bold tracking-tight">Every system has entities with relationships to resources.<br />Nobody governs them with intelligence.</h2>
        </div>
        <div className="grid md:grid-cols-3 gap-6">
          {problems.map((p, i) => (
            <div key={p.label} className={`relative p-6 rounded-2xl bg-vektor-bg-card border border-vektor-border transition-all duration-500 ${inView ? "opacity-100 translate-y-0" : "opacity-0 translate-y-8"}`} style={{ transitionDelay: `${i * 120}ms` }}>
              <div className="flex items-center gap-3 mb-4">
                <div className="w-10 h-10 rounded-xl bg-red-400/10 flex items-center justify-center"><p.icon className={`w-5 h-5 ${p.color}`} /></div>
              </div>
              <div className={`text-4xl font-bold ${p.color} mb-1`}>{p.stat}</div>
              <div className="text-sm font-medium text-white mb-2">{p.label}</div>
              <p className="text-sm text-vektor-text-secondary leading-relaxed">{p.desc}</p>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}

/* ── HOW IT WORKS ── */
const CORE_STEPS = [
  { icon: Database, label: "Connect", title: "Unified entity graph", description: "Read-only adapters plug into any entity-permission-resource system — ERP, trading platforms, EHR, cloud IAM. Unified relational graph across all systems. Every human, service account, and AI agent.", color: "text-blue-400", bg: "bg-blue-400/10" },
  { icon: Scan, label: "Vectorize", title: "Feature vectors, not rules", description: "Every entity becomes a multi-dimensional feature vector — capturing permissions, centrality, drift, peer deviation, and cross-system relationships. Our AI models detect anomalous patterns in that vector space.", color: "text-vektor-green", bg: "bg-vektor-green/10" },
  { icon: Sparkles, label: "Govern", title: "Policies write themselves", description: "AI insights auto-generate policy recommendations. You approve with one click. A scoped model trains and starts detecting immediately. No YAML, no rule files, no maintenance — ever.", color: "text-amber-400", bg: "bg-amber-400/10" },
  { icon: Zap, label: "Execute", title: "Agentic remediation with rollback", description: "When a signal fires, AI agents execute remediation programmatically. Human approval gates for destructive actions. Full audit trail. Instant rollback if anything goes wrong.", color: "text-red-400", bg: "bg-red-400/10" },
];

function HowItWorks() {
  const { ref, inView } = useInView();
  return (
    <section id="how-it-works" className="py-32 bg-vektor-bg-light/50 relative" ref={ref}>
      <div className="max-w-7xl mx-auto px-6">
        <div className="text-center mb-16">
          <p className="text-sm font-medium text-vektor-accent tracking-wide uppercase mb-3">How Vektor Works</p>
          <h2 className="text-3xl sm:text-4xl font-bold tracking-tight">Connect → Vectorize → Govern → Execute</h2>
          <p className="mt-4 text-vektor-text-secondary max-w-xl mx-auto">One adapter per new system. Zero model changes. Domain-agnostic architecture.</p>
        </div>
        <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-6">
          {CORE_STEPS.map((step, i) => (
            <div key={step.label} className={`group relative p-6 rounded-2xl bg-vektor-bg-card border border-vektor-border hover:border-vektor-accent/30 transition-all duration-500 ${inView ? "opacity-100 translate-y-0" : "opacity-0 translate-y-8"}`} style={{ transitionDelay: `${i * 120}ms` }}>
              <div className="absolute -top-3 -left-1 text-[80px] font-bold text-vektor-border/50 select-none leading-none">{i + 1}</div>
              <div className={`w-10 h-10 rounded-xl ${step.bg} flex items-center justify-center mb-4 relative z-10`}><step.icon className={`w-5 h-5 ${step.color}`} /></div>
              <p className={`text-xs font-semibold ${step.color} tracking-wider uppercase mb-2`}>{step.label}</p>
              <h3 className="text-lg font-semibold mb-2">{step.title}</h3>
              <p className="text-sm text-vektor-text-secondary leading-relaxed">{step.description}</p>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}

/* ── FOUR SECTORS ── */
const SECTORS = [
  { name: "ERP / Finance", icon: Building2, compliance: "SOX, ITGC", color: "text-purple-400", bg: "bg-purple-400/10", border: "border-purple-400/20", entities: "Users, RPA bots, approval agents", violations: "SoD violations, unauthorized config, toxic role combos", agentRisk: "AI invoice processor with AP + GL + Procurement = fraud at machine speed" },
  { name: "Financial Services", icon: TrendingUp, compliance: "SEC, FINRA, MiFID", color: "text-amber-400", bg: "bg-amber-400/10", border: "border-amber-400/20", entities: "Traders, analysts, algo systems, AI research agents", violations: "Chinese wall breaches, MNPI access, front-running", agentRisk: "Algo with pre-trade analytics + order execution + client data = insider trading surface" },
  { name: "Healthcare", icon: HeartPulse, compliance: "HIPAA, HITECH", color: "text-red-400", bg: "bg-red-400/10", border: "border-red-400/20", entities: "Clinicians, staff, AI scribes, triage agents", violations: "Unauthorized record access, peer deviation, break-glass abuse", agentRisk: "AI scribe accessing patient records across departments it shouldn't see" },
  { name: "Cloud IAM / IdP", icon: Cloud, compliance: "NIST, CIS, Zero Trust", color: "text-cyan-400", bg: "bg-cyan-400/10", border: "border-cyan-400/20", entities: "Users, service accounts, CI/CD pipelines, AI coding agents", violations: "Privilege escalation, dormant access, permission creep", agentRisk: "Service account with admin across AWS + production DB = full blast radius" },
];

function SectorSection() {
  const { ref, inView } = useInView();
  return (
    <section id="sectors" className="py-32 relative" ref={ref}>
      <div className="max-w-7xl mx-auto px-6">
        <div className="text-center mb-16">
          <p className="text-sm font-medium text-vektor-green tracking-wide uppercase mb-3">Platform Reach</p>
          <h2 className="text-3xl sm:text-4xl font-bold tracking-tight">One platform. Four sectors. Every agent governed.</h2>
          <p className="mt-4 text-vektor-text-secondary max-w-2xl mx-auto">Same feature vectors, same AI models, same architecture — different adapters and compliance labels. That&apos;s why it&apos;s a platform, not a product.</p>
        </div>
        <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-5">
          {SECTORS.map((s, i) => (
            <div key={s.name} className={`p-6 rounded-2xl bg-vektor-bg-card border ${s.border} transition-all duration-500 hover:border-opacity-60 ${inView ? "opacity-100 translate-y-0" : "opacity-0 translate-y-8"}`} style={{ transitionDelay: `${i * 100}ms` }}>
              <div className={`w-10 h-10 rounded-xl ${s.bg} flex items-center justify-center mb-4`}><s.icon className={`w-5 h-5 ${s.color}`} /></div>
              <h3 className="text-base font-semibold mb-1">{s.name}</h3>
              <p className={`text-[11px] font-medium ${s.color} mb-4`}>{s.compliance}</p>

              <div className="space-y-3 text-xs">
                <div><span className="text-vektor-text-muted font-medium block mb-1">Entities</span><span className="text-vektor-text-secondary">{s.entities}</span></div>
                <div><span className="text-vektor-text-muted font-medium block mb-1">Key violations</span><span className="text-vektor-text-secondary">{s.violations}</span></div>
                <div><span className="text-red-400/70 font-medium block mb-1">Agent risk</span><span className="text-vektor-text-muted italic text-[11px]">{s.agentRisk}</span></div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}

/* ── CORE IP — WHY IT'S CALLED VEKTOR ── */
function CoreIP() {
  const { ref, inView } = useInView();
  return (
    <section className="py-32 bg-vektor-bg-light/50" ref={ref}>
      <div className="max-w-7xl mx-auto px-6">
        <div className="grid lg:grid-cols-2 gap-16 items-start">
          <div className={`transition-all duration-700 ${inView ? "opacity-100 translate-y-0" : "opacity-0 translate-y-8"}`}>
            <p className="text-sm font-medium text-vektor-accent tracking-wide uppercase mb-3">Core IP</p>
            <h2 className="text-3xl sm:text-4xl font-bold tracking-tight mb-6">The name is the product</h2>
            <p className="text-vektor-text-secondary mb-8 leading-relaxed">
              Every entity in every connected system gets represented as a multi-dimensional feature vector. These vectors capture the shape of an entity&apos;s relationship to its environment. Our AI models detect anomalous patterns in this vector space — making detection domain-agnostic across all four sectors.
            </p>

            <div className="space-y-3">
              {[
                { name: "Subject Features", desc: "Permissions, centrality, drift, usage patterns", color: "border-blue-400/30" },
                { name: "Permission Features", desc: "Risk score, scope breadth, holder count", color: "border-vektor-green/30" },
                { name: "Assignment Features", desc: "Age, staleness, justification, SoD membership", color: "border-amber-400/30" },
                { name: "Relationship Features", desc: "Cross-system consistency, peer deviation", color: "border-purple-400/30" },
              ].map((f) => (
                <div key={f.name} className={`p-4 rounded-xl bg-vektor-bg-card border-l-2 ${f.color} border border-vektor-border`}>
                  <p className="text-sm font-semibold mb-0.5">{f.name}</p>
                  <p className="text-xs text-vektor-text-muted">{f.desc}</p>
                </div>
              ))}
            </div>
          </div>

          <div className={`p-8 rounded-2xl bg-vektor-bg-card border border-vektor-accent/20 transition-all duration-700 ${inView ? "opacity-100 translate-y-0" : "opacity-0 translate-y-8"}`} style={{ transitionDelay: "200ms" }}>
            <h3 className="text-lg font-semibold text-vektor-accent mb-6">Why this matters</h3>
            <div className="space-y-6">
              {[
                "Same vector space works across ERP, trading, healthcare, and IAM.",
                "Models trained in one domain transfer signal to all domains — because the feature representation is universal.",
                "New sector = new adapter + domain labels. Core AI architecture unchanged.",
              ].map((t, i) => (
                <div key={i} className="flex items-start gap-3">
                  <Check className="w-4 h-4 text-vektor-green mt-0.5 flex-shrink-0" />
                  <p className="text-sm text-vektor-text-secondary leading-relaxed">{t}</p>
                </div>
              ))}
              <div className="pt-4 border-t border-vektor-border">
                <p className="text-sm font-semibold text-vektor-accent">Competitors build per-sector. We build once, deploy everywhere.</p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}

/* ── INTELLIGENCE — Tier 1 + Tier 2 + Signal Output ── */
const MODEL_CATEGORIES = [
  { name: "SOX Compliance", count: 5, icon: Shield, models: ["Segregation of Duties", "Unauthorized Config Change", "Access Without Justification", "Break-Glass Abuse", "Toxic Role Combos"], color: "text-red-400", bg: "bg-red-400/10", border: "border-red-400/20" },
  { name: "Zero Trust", count: 6, icon: Lock, models: ["Excessive Privilege", "Dormant Access", "Orphaned Accounts", "Permission Creep", "Open Trust Policies", "Missing MFA"], color: "text-blue-400", bg: "bg-blue-400/10", border: "border-blue-400/20" },
  { name: "Anomaly Detection", count: 4, icon: Activity, models: ["Behavioral Anomaly", "Graph Structural Anomaly", "Cross-System Inconsistency", "Peer Group Deviation"], color: "text-vektor-green", bg: "bg-vektor-green/10", border: "border-vektor-green/20" },
  { name: "Agent Governance", count: 4, icon: Bot, models: ["Agent Privilege Excess", "Agent Scope Drift", "Agent SoD Violation", "Agent Cross-Boundary Reach"], color: "text-purple-400", bg: "bg-purple-400/10", border: "border-purple-400/20" },
  { name: "Cross-Boundary", count: 3, icon: Network, models: ["IAM-to-Financial Bypass", "Cross-System SoD", "Service Account Financial Reach"], color: "text-amber-400", bg: "bg-amber-400/10", border: "border-amber-400/20" },
];

function IntelligenceSection() {
  const { ref, inView } = useInView();
  const [expandedCat, setExpandedCat] = useState<number | null>(null);
  return (
    <section id="intelligence" className="py-32 relative" ref={ref}>
      <div className="max-w-7xl mx-auto px-6">
        <div className="text-center mb-16">
          <p className="text-sm font-medium text-vektor-accent tracking-wide uppercase mb-3">Two-Tier Intelligence</p>
          <h2 className="text-3xl sm:text-4xl font-bold tracking-tight">AI-powered models. Zero rule files.</h2>
          <p className="mt-4 text-vektor-text-secondary max-w-2xl mx-auto">Tier 1 models detect risk with confidence-scored signals across all sectors. Tier 2 uses those signals to generate new policies automatically — no human writes a single rule.</p>
        </div>
        <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-4 mb-12">
          {MODEL_CATEGORIES.map((cat, i) => (
            <button key={cat.name} onClick={() => setExpandedCat(expandedCat === i ? null : i)} className={`text-left p-5 rounded-xl border transition-all duration-500 ${expandedCat === i ? `bg-vektor-bg-card ${cat.border} border-opacity-100` : "bg-vektor-bg-card/50 border-vektor-border hover:border-vektor-text-muted"} ${inView ? "opacity-100 translate-y-0" : "opacity-0 translate-y-6"}`} style={{ transitionDelay: `${i * 80}ms` }}>
              <div className="flex items-center justify-between mb-3">
                <div className="flex items-center gap-3">
                  <div className={`w-8 h-8 rounded-lg ${cat.bg} flex items-center justify-center`}><cat.icon className={`w-4 h-4 ${cat.color}`} /></div>
                  <div><h3 className="text-sm font-semibold">{cat.name}</h3><p className="text-xs text-vektor-text-muted">{cat.count} models</p></div>
                </div>
                <ChevronRight className={`w-4 h-4 text-vektor-text-muted transition-transform ${expandedCat === i ? "rotate-90" : ""}`} />
              </div>
              {expandedCat === i && (
                <div className="mt-3 pt-3 border-t border-vektor-border space-y-1.5">
                  {cat.models.map((m) => (<div key={m} className="flex items-center gap-2 text-xs text-vektor-text-secondary"><div className={`w-1.5 h-1.5 rounded-full ${cat.bg.replace("/10", "/40")}`} />{m}</div>))}
                </div>
              )}
            </button>
          ))}
          <div className={`p-5 rounded-xl border border-dashed border-vektor-accent/30 bg-vektor-accent/5 transition-all duration-500 ${inView ? "opacity-100 translate-y-0" : "opacity-0 translate-y-6"}`} style={{ transitionDelay: "400ms" }}>
            <div className="flex items-center gap-3 mb-3">
              <div className="w-8 h-8 rounded-lg bg-vektor-accent/15 flex items-center justify-center"><Sparkles className="w-4 h-4 text-vektor-accent" /></div>
              <div><h3 className="text-sm font-semibold">Tier 2: Self-Writing Policies</h3><p className="text-xs text-vektor-text-muted">Fully autonomous after approval</p></div>
            </div>
            <p className="text-xs text-vektor-text-secondary leading-relaxed">Tier 1 signals feed an AI agent that generates policy recommendations. You approve or reject — that&apos;s your only input. The platform creates a scoped model, starts detecting, and improves with every decision.</p>
          </div>
        </div>

        {/* Signal Output */}
        <div className={`rounded-2xl border border-vektor-border bg-vektor-bg-card p-8 transition-all duration-700 ${inView ? "opacity-100 translate-y-0" : "opacity-0 translate-y-8"}`} style={{ transitionDelay: "500ms" }}>
          <div className="grid lg:grid-cols-2 gap-8 items-center">
            <div>
              <div className="flex items-center gap-2 mb-3"><FileJson className="w-5 h-5 text-vektor-accent" /><p className="text-sm font-medium text-vektor-accent tracking-wide uppercase">Structured Signal Output</p></div>
              <h3 className="text-2xl font-bold mb-3">Intelligence your agents can consume</h3>
              <p className="text-sm text-vektor-text-secondary leading-relaxed mb-4">Every signal is a structured object — confidence-scored, with blast radius, evidence chain, remediation steps, and compliance mapping (SOX, SEC, HIPAA, NIST). Your SIEM, your SOAR, your AI agents — they all consume the same output.</p>
              <div className="space-y-2">
                {["Confidence score + violation class per entity", "Blast radius — systems, permissions, downstream impact", "Pre-computed remediation with rollback plan", "SOX / SEC / HIPAA / NIST control mapping", "Feature snapshot for audit trail"].map((item) => (
                  <div key={item} className="flex items-start gap-2"><Check className="w-3.5 h-3.5 text-vektor-green mt-0.5 flex-shrink-0" /><span className="text-xs text-vektor-text-secondary">{item}</span></div>
                ))}
              </div>
            </div>
            <div className="bg-vektor-bg rounded-xl border border-vektor-border p-5 font-mono text-xs overflow-hidden">
              <div className="text-vektor-text-muted mb-2">// Tier 1 signal output — any sector</div>
              <div className="space-y-0.5 text-vektor-text-secondary">
                <div>{"{"}</div>
                <div className="pl-4"><span className="text-vektor-accent">&quot;signal_id&quot;</span>: <span className="text-vektor-green">&quot;SIG-2026-00847&quot;</span>,</div>
                <div className="pl-4"><span className="text-vektor-accent">&quot;subject&quot;</span>: <span className="text-vektor-green">&quot;maria.gonzalez&quot;</span>,</div>
                <div className="pl-4"><span className="text-vektor-accent">&quot;sector&quot;</span>: <span className="text-vektor-green">&quot;erp_finance&quot;</span>,</div>
                <div className="pl-4"><span className="text-vektor-accent">&quot;violation&quot;</span>: <span className="text-vektor-green">&quot;sod_violation&quot;</span>,</div>
                <div className="pl-4"><span className="text-vektor-accent">&quot;confidence&quot;</span>: <span className="text-amber-400">0.98</span>,</div>
                <div className="pl-4"><span className="text-vektor-accent">&quot;blast_radius&quot;</span>: {"{"} <span className="text-vektor-text-muted">...</span> {"}"},</div>
                <div className="pl-4"><span className="text-vektor-accent">&quot;remediation&quot;</span>: {"{"} <span className="text-vektor-text-muted">...</span> {"}"},</div>
                <div className="pl-4"><span className="text-vektor-accent">&quot;compliance&quot;</span>: <span className="text-vektor-green">&quot;ITGC-AP-03&quot;</span></div>
                <div>{"}"}</div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}

/* ── CONNECTORS ── */
const CONNECTORS = [
  { name: "AWS IAM", type: "Cloud IAM", status: "GA" },
  { name: "Microsoft Entra ID", type: "Cloud IAM", status: "GA" },
  { name: "Okta", type: "Identity", status: "GA" },
  { name: "NetSuite", type: "ERP", status: "GA" },
  { name: "Epic / Cerner", type: "Healthcare", status: "Beta" },
  { name: "Bloomberg / FIX", type: "FinServ", status: "Beta" },
  { name: "SAP", type: "ERP", status: "Coming" },
  { name: "Snowflake", type: "Data", status: "Coming" },
];

function Connectors() {
  const { ref, inView } = useInView();
  return (
    <section className="py-32 bg-vektor-bg-light/50" ref={ref}>
      <div className="max-w-7xl mx-auto px-6 text-center">
        <p className="text-sm font-medium text-vektor-accent tracking-wide uppercase mb-3">Connectors</p>
        <h2 className="text-3xl sm:text-4xl font-bold tracking-tight mb-4">Read-only. Never see your business data.</h2>
        <p className="text-vektor-text-secondary max-w-xl mx-auto mb-12">We see who accessed it, when, and whether they should have. That&apos;s it.</p>
        <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-8 gap-3">
          {CONNECTORS.map((c, i) => (
            <div key={c.name} className={`p-4 rounded-xl bg-vektor-bg-card border border-vektor-border hover:border-vektor-accent/30 transition-all duration-500 ${inView ? "opacity-100 scale-100" : "opacity-0 scale-95"}`} style={{ transitionDelay: `${i * 50}ms` }}>
              <div className="w-8 h-8 rounded-lg bg-vektor-border/50 flex items-center justify-center mx-auto mb-2"><Layers className="w-4 h-4 text-vektor-text-muted" /></div>
              <p className="text-xs font-medium">{c.name}</p>
              <p className="text-[10px] text-vektor-text-muted mt-0.5">{c.type}</p>
              <span className={`inline-block mt-1.5 text-[9px] font-medium px-1.5 py-0.5 rounded-full ${c.status === "GA" ? "bg-vektor-green/15 text-vektor-green" : c.status === "Beta" ? "bg-amber-400/15 text-amber-400" : "bg-vektor-border text-vektor-text-muted"}`}>{c.status}</span>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}

/* ── COMPETITIVE COMPARISON ── */
const COMPARISON_ROWS = [
  { dim: "Detection", veza: "Heuristics + AI", pathlock: "Hand-written rules", oasis: "Rules only", vektor: "AI — feature vectors" },
  { dim: "Sectors", veza: "IAM only", pathlock: "ERP (SAP)", oasis: "NHI only", vektor: "4 sectors, 1 architecture" },
  { dim: "FinServ / Trading", veza: "—", pathlock: "—", oasis: "—", vektor: "SEC / FINRA models" },
  { dim: "Healthcare", veza: "—", pathlock: "Partial", oasis: "—", vektor: "HIPAA models" },
  { dim: "Agent Governance", veza: "New (Dec '25)", pathlock: "—", oasis: "Partial (NHI)", vektor: "First-class, day one" },
  { dim: "Self-Writing Policies", veza: "—", pathlock: "—", oasis: "—", vektor: "Tier 2 lifecycle" },
  { dim: "Rule Maintenance", veza: "Ongoing", pathlock: "Ongoing", oasis: "Ongoing", vektor: "None — self-improving" },
];

function ComparisonSection() {
  const { ref, inView } = useInView();
  return (
    <section className="py-32" ref={ref}>
      <div className="max-w-5xl mx-auto px-6">
        <div className="text-center mb-12">
          <h2 className="text-3xl sm:text-4xl font-bold tracking-tight">No one provides AI entity intelligence across sectors</h2>
          <p className="mt-4 text-vektor-text-secondary">Others govern access in one sector. Vektor finds risk, writes the policy, and fixes it — across all four.</p>
        </div>
        <div className={`rounded-2xl border border-vektor-border overflow-hidden transition-all duration-700 ${inView ? "opacity-100 translate-y-0" : "opacity-0 translate-y-8"}`}>
          <div className="grid grid-cols-5 bg-vektor-bg-card text-xs font-semibold text-vektor-text-muted border-b border-vektor-border">
            <div className="p-4"></div>
            <div className="p-4 text-center">Veza / Saviynt</div>
            <div className="p-4 text-center">Pathlock</div>
            <div className="p-4 text-center">Oasis / Astrix</div>
            <div className="p-4 text-center text-vektor-accent">Vektor</div>
          </div>
          {COMPARISON_ROWS.map((row, i) => (
            <div key={row.dim} className={`grid grid-cols-5 text-sm border-b border-vektor-border last:border-b-0 ${i % 2 === 0 ? "bg-vektor-bg" : "bg-vektor-bg-card/30"}`}>
              <div className="p-4 font-medium text-vektor-text-secondary">{row.dim}</div>
              <div className="p-4 text-center text-vektor-text-muted text-xs">{row.veza}</div>
              <div className="p-4 text-center text-vektor-text-muted text-xs">{row.pathlock}</div>
              <div className="p-4 text-center text-vektor-text-muted text-xs">{row.oasis}</div>
              <div className="p-4 text-center text-vektor-accent text-xs font-medium">{row.vektor}</div>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}

/* ── CTA ── */
function CTA() {
  return (
    <section className="py-32 relative overflow-hidden">
      <div className="absolute inset-0 radial-glow" />
      <div className="relative z-10 max-w-3xl mx-auto px-6 text-center">
        <h2 className="text-3xl sm:text-4xl font-bold tracking-tight mb-4">
          AI-native intelligence for every entity, every relationship, every agent.
          <br /><span className="text-vektor-accent">Across every regulated sector.</span>
        </h2>
        <p className="text-vektor-text-secondary mb-8">See Vektor in action — live demo on public and synthetic data. 15 minutes.</p>
        <a href="/demo" className="inline-flex items-center gap-2 px-8 py-3.5 rounded-lg bg-vektor-accent hover:bg-vektor-accent-hover text-white font-semibold transition-all hover:shadow-lg hover:shadow-vektor-accent/25">
          Request Demo <ArrowRight className="w-4 h-4" />
        </a>
      </div>
    </section>
  );
}

/* ── FOOTER ── */
function Footer() {
  return (
    <footer className="border-t border-vektor-border py-12">
      <div className="max-w-7xl mx-auto px-6 flex flex-col sm:flex-row items-center justify-between gap-4">
        <div className="flex items-center gap-2">
          <img src="/vektor-logo.png" alt="Vektor" className="h-6 w-auto" />
          <span className="text-sm font-semibold">vektor</span>
        </div>
        <p className="text-xs text-vektor-text-muted">&copy; {new Date().getFullYear()} Vektor AI, Inc. All rights reserved.</p>
        <div className="flex items-center gap-6 text-xs text-vektor-text-muted">
          <a href="#" className="hover:text-white transition-colors">Privacy</a>
          <a href="#" className="hover:text-white transition-colors">Terms</a>
          <a href="#" className="hover:text-white transition-colors">Security</a>
        </div>
      </div>
    </footer>
  );
}

/* ── PAGE ── */
export default function HomePage() {
  return (
    <main>
      <Navbar />
      <Hero />
      <ProblemSection />
      <HowItWorks />
      <SectorSection />
      <CoreIP />
      <IntelligenceSection />
      <Connectors />
      <ComparisonSection />
      <CTA />
      <Footer />
    </main>
  );
}
