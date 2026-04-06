"use client";

import { useState, useEffect, useRef } from "react";
import {
  Shield,
  Scan,
  Zap,
  Bot,
  ArrowRight,
  Check,
  ChevronRight,
  Network,
  Lock,
  Eye,
  RotateCcw,
  Database,
  GitBranch,
  Layers,
  Terminal,
  AlertTriangle,
  Activity,
  TrendingUp,
  X,
} from "lucide-react";

/* ────────────────────────────────────────────
   ANIMATION HOOK
   ──────────────────────────────────────────── */

function useInView(threshold = 0.15) {
  const ref = useRef<HTMLDivElement>(null);
  const [inView, setInView] = useState(false);

  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const obs = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting) {
          setInView(true);
          obs.disconnect();
        }
      },
      { threshold }
    );
    obs.observe(el);
    return () => obs.disconnect();
  }, [threshold]);

  return { ref, inView };
}

/* ────────────────────────────────────────────
   NAVBAR
   ──────────────────────────────────────────── */

function Navbar() {
  const [scrolled, setScrolled] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);

  useEffect(() => {
    const handler = () => setScrolled(window.scrollY > 40);
    window.addEventListener("scroll", handler, { passive: true });
    return () => window.removeEventListener("scroll", handler);
  }, []);

  const links = [
    { label: "Platform", href: "#platform" },
    { label: "Intelligence", href: "#intelligence" },
    { label: "Connectors", href: "#connectors" },
    { label: "Pricing", href: "#pricing" },
  ];

  return (
    <nav
      className={`fixed top-0 w-full z-50 transition-all duration-300 ${
        scrolled
          ? "bg-vektor-bg/90 backdrop-blur-xl border-b border-vektor-border"
          : "bg-transparent"
      }`}
    >
      <div className="max-w-7xl mx-auto px-6 h-16 flex items-center justify-between">
        {/* Logo */}
        <a href="#" className="flex items-center gap-2.5 group">
          <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-vektor-accent to-blue-400 flex items-center justify-center">
            <Shield className="w-4.5 h-4.5 text-white" />
          </div>
          <span className="text-lg font-bold tracking-tight">
            Vektor<span className="text-vektor-accent">.ai</span>
          </span>
        </a>

        {/* Desktop links */}
        <div className="hidden md:flex items-center gap-8">
          {links.map((l) => (
            <a
              key={l.label}
              href={l.href}
              className="text-sm text-vektor-text-secondary hover:text-white transition-colors"
            >
              {l.label}
            </a>
          ))}
        </div>

        {/* CTA */}
        <div className="hidden md:flex items-center gap-4">
          <a
            href="#"
            className="text-sm text-vektor-text-secondary hover:text-white transition-colors"
          >
            Log in
          </a>
          <a
            href="#"
            className="text-sm px-4 py-2 rounded-lg bg-vektor-accent hover:bg-vektor-accent-hover text-white font-medium transition-colors"
          >
            Request Demo
          </a>
        </div>

        {/* Mobile toggle */}
        <button
          className="md:hidden text-vektor-text-secondary"
          onClick={() => setMobileOpen(!mobileOpen)}
        >
          {mobileOpen ? <X className="w-5 h-5" /> : (
            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeWidth={2} d="M4 6h16M4 12h16M4 18h16" />
            </svg>
          )}
        </button>
      </div>

      {/* Mobile menu */}
      {mobileOpen && (
        <div className="md:hidden bg-vektor-bg border-b border-vektor-border px-6 py-4 space-y-3">
          {links.map((l) => (
            <a
              key={l.label}
              href={l.href}
              className="block text-sm text-vektor-text-secondary hover:text-white"
              onClick={() => setMobileOpen(false)}
            >
              {l.label}
            </a>
          ))}
          <a
            href="#"
            className="block text-sm px-4 py-2 rounded-lg bg-vektor-accent text-white text-center font-medium"
          >
            Request Demo
          </a>
        </div>
      )}
    </nav>
  );
}

/* ────────────────────────────────────────────
   HERO
   ──────────────────────────────────────────── */

function Hero() {
  return (
    <section className="relative min-h-screen flex items-center justify-center overflow-hidden">
      {/* Background layers */}
      <div className="absolute inset-0 bg-grid" />
      <div className="absolute inset-0 radial-glow" />
      <div className="absolute inset-0 noise-overlay" />

      {/* Animated orbs */}
      <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-vektor-accent/5 rounded-full blur-3xl animate-pulse-slow" />
      <div className="absolute bottom-1/4 right-1/4 w-80 h-80 bg-vektor-green/5 rounded-full blur-3xl animate-pulse-slow" style={{ animationDelay: "1.5s" }} />

      <div className="relative z-10 max-w-5xl mx-auto px-6 text-center">
        {/* Badge */}
        <div className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full bg-vektor-accent/10 border border-vektor-accent/20 mb-8 animate-fade-in">
          <Bot className="w-3.5 h-3.5 text-vektor-accent" />
          <span className="text-xs font-medium text-vektor-accent tracking-wide uppercase">
            Agent vs. Agent Governance
          </span>
        </div>

        {/* Headline */}
        <h1 className="text-5xl sm:text-6xl lg:text-7xl font-bold tracking-tight leading-[1.1] mb-6 animate-slide-up">
          Identity intelligence
          <br />
          <span className="text-transparent bg-clip-text bg-gradient-to-r from-vektor-accent via-blue-400 to-vektor-green">
            for the agentic enterprise
          </span>
        </h1>

        {/* Subhead */}
        <p
          className="text-lg sm:text-xl text-vektor-text-secondary max-w-2xl mx-auto mb-10 animate-slide-up"
          style={{ animationDelay: "0.15s" }}
        >
          Map, score, govern, and remediate identity risk across cloud IAM and
          ERP systems. ML-native. 22 supervised models. Agentic execution with
          instant rollback.
        </p>

        {/* CTAs */}
        <div
          className="flex flex-col sm:flex-row items-center justify-center gap-4 animate-slide-up"
          style={{ animationDelay: "0.3s" }}
        >
          <a
            href="#"
            className="group flex items-center gap-2 px-6 py-3 rounded-lg bg-vektor-accent hover:bg-vektor-accent-hover text-white font-semibold transition-all hover:shadow-lg hover:shadow-vektor-accent/25"
          >
            Request Demo
            <ArrowRight className="w-4 h-4 transition-transform group-hover:translate-x-0.5" />
          </a>
          <a
            href="#platform"
            className="flex items-center gap-2 px-6 py-3 rounded-lg border border-vektor-border text-vektor-text-secondary hover:text-white hover:border-vektor-text-muted transition-all"
          >
            See how it works
          </a>
        </div>

        {/* Social proof */}
        <div
          className="mt-16 flex items-center justify-center gap-8 text-xs text-vektor-text-muted animate-fade-in"
          style={{ animationDelay: "0.5s" }}
        >
          <span className="flex items-center gap-1.5">
            <Lock className="w-3.5 h-3.5" /> SOC 2 Type II
          </span>
          <span className="flex items-center gap-1.5">
            <Shield className="w-3.5 h-3.5" /> SOX Compliant
          </span>
          <span className="flex items-center gap-1.5">
            <Eye className="w-3.5 h-3.5" /> Read-Only Access
          </span>
        </div>
      </div>
    </section>
  );
}

/* ────────────────────────────────────────────
   CORE LOOP — Connect → Score → Govern → Execute
   ──────────────────────────────────────────── */

const CORE_STEPS = [
  {
    icon: Database,
    label: "Connect",
    title: "Understand your identity landscape",
    description:
      "Read-only adapters connect to AWS IAM, Okta, Entra ID, NetSuite, and Snowflake. We build a unified identity graph across all sources — cloud IAM and ERP in one view.",
    color: "text-blue-400",
    bg: "bg-blue-400/10",
  },
  {
    icon: Scan,
    label: "Score",
    title: "ML models score every identity",
    description:
      "22 supervised ML models — not hardcoded rules — continuously score the graph. Confidence-scored signals with blast-radius mapping and pre-computed remediation plans.",
    color: "text-vektor-green",
    bg: "bg-vektor-green/10",
  },
  {
    icon: GitBranch,
    label: "Govern",
    title: "Policies that learn from you",
    description:
      "Tier 2 engine suggests policies from observed patterns. You approve or dismiss. The platform learns from every interaction. Enough cross-customer approvals graduate to Tier 1.",
    color: "text-amber-400",
    bg: "bg-amber-400/10",
  },
  {
    icon: Zap,
    label: "Execute",
    title: "Agentic remediation with rollback",
    description:
      "When a signal fires, AI agents execute remediation programmatically. Human approval gates for destructive actions. Full audit trail. Instant rollback if anything goes wrong.",
    color: "text-red-400",
    bg: "bg-red-400/10",
  },
];

function CoreLoop() {
  const { ref, inView } = useInView();

  return (
    <section id="platform" className="py-32 relative" ref={ref}>
      <div className="max-w-7xl mx-auto px-6">
        <div className="text-center mb-16">
          <p className="text-sm font-medium text-vektor-accent tracking-wide uppercase mb-3">
            How Vektor Works
          </p>
          <h2 className="text-3xl sm:text-4xl font-bold tracking-tight">
            Understand → Determine → Act
          </h2>
          <p className="mt-4 text-vektor-text-secondary max-w-xl mx-auto">
            Not another dashboard. We find the risk, score it with ML, and fix it
            with agentic execution.
          </p>
        </div>

        <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-6">
          {CORE_STEPS.map((step, i) => (
            <div
              key={step.label}
              className={`group relative p-6 rounded-2xl bg-vektor-bg-card border border-vektor-border hover:border-vektor-accent/30 transition-all duration-500 ${
                inView ? "opacity-100 translate-y-0" : "opacity-0 translate-y-8"
              }`}
              style={{ transitionDelay: `${i * 120}ms` }}
            >
              {/* Step number */}
              <div className="absolute -top-3 -left-1 text-[80px] font-bold text-vektor-border/50 select-none leading-none">
                {i + 1}
              </div>

              <div className={`w-10 h-10 rounded-xl ${step.bg} flex items-center justify-center mb-4 relative z-10`}>
                <step.icon className={`w-5 h-5 ${step.color}`} />
              </div>
              <p className={`text-xs font-semibold ${step.color} tracking-wider uppercase mb-2`}>
                {step.label}
              </p>
              <h3 className="text-lg font-semibold mb-2">{step.title}</h3>
              <p className="text-sm text-vektor-text-secondary leading-relaxed">
                {step.description}
              </p>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}

/* ────────────────────────────────────────────
   INTELLIGENCE SECTION — 22 Models + Tier 2
   ──────────────────────────────────────────── */

const MODEL_CATEGORIES = [
  {
    name: "SOX Compliance",
    count: 5,
    icon: Shield,
    models: ["Segregation of Duties", "Unauthorized Config Change", "Access Without Justification", "Break-Glass Abuse", "Toxic Role Combos"],
    color: "text-red-400",
    bg: "bg-red-400/10",
    border: "border-red-400/20",
  },
  {
    name: "Zero Trust",
    count: 6,
    icon: Lock,
    models: ["Excessive Privilege", "Dormant Access", "Orphaned Accounts", "Permission Creep", "Open Trust Policies", "Missing MFA"],
    color: "text-blue-400",
    bg: "bg-blue-400/10",
    border: "border-blue-400/20",
  },
  {
    name: "Anomaly Detection",
    count: 4,
    icon: Activity,
    models: ["Behavioral Anomaly", "Graph Structural Anomaly", "Cross-System Inconsistency", "Peer Group Deviation"],
    color: "text-vektor-green",
    bg: "bg-vektor-green/10",
    border: "border-vektor-green/20",
  },
  {
    name: "Agent Governance",
    count: 4,
    icon: Bot,
    models: ["Agent Privilege Excess", "Agent Scope Drift", "Agent SoD Violation", "Agent Cross-Boundary Reach"],
    color: "text-purple-400",
    bg: "bg-purple-400/10",
    border: "border-purple-400/20",
  },
  {
    name: "Cross-Boundary",
    count: 3,
    icon: Network,
    models: ["IAM-to-Financial Bypass", "Cross-System SoD", "Service Account Financial Reach"],
    color: "text-amber-400",
    bg: "bg-amber-400/10",
    border: "border-amber-400/20",
  },
];

function IntelligenceSection() {
  const { ref, inView } = useInView();
  const [expandedCat, setExpandedCat] = useState<number | null>(null);

  return (
    <section id="intelligence" className="py-32 bg-vektor-bg-light/50 relative" ref={ref}>
      <div className="max-w-7xl mx-auto px-6">
        <div className="text-center mb-16">
          <p className="text-sm font-medium text-vektor-accent tracking-wide uppercase mb-3">
            Two-Tier Intelligence
          </p>
          <h2 className="text-3xl sm:text-4xl font-bold tracking-tight">
            22 ML models. Not rules.
          </h2>
          <p className="mt-4 text-vektor-text-secondary max-w-2xl mx-auto">
            Supervised classifiers trained on labeled data, not hardcoded thresholds.
            Tier 2 learns from your environment and graduates the best detections to Tier 1.
          </p>
        </div>

        {/* Model grid */}
        <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-4 mb-12">
          {MODEL_CATEGORIES.map((cat, i) => (
            <button
              key={cat.name}
              onClick={() => setExpandedCat(expandedCat === i ? null : i)}
              className={`text-left p-5 rounded-xl border transition-all duration-500 ${
                expandedCat === i
                  ? `bg-vektor-bg-card ${cat.border} border-opacity-100`
                  : "bg-vektor-bg-card/50 border-vektor-border hover:border-vektor-text-muted"
              } ${inView ? "opacity-100 translate-y-0" : "opacity-0 translate-y-6"}`}
              style={{ transitionDelay: `${i * 80}ms` }}
            >
              <div className="flex items-center justify-between mb-3">
                <div className="flex items-center gap-3">
                  <div className={`w-8 h-8 rounded-lg ${cat.bg} flex items-center justify-center`}>
                    <cat.icon className={`w-4 h-4 ${cat.color}`} />
                  </div>
                  <div>
                    <h3 className="text-sm font-semibold">{cat.name}</h3>
                    <p className="text-xs text-vektor-text-muted">{cat.count} models</p>
                  </div>
                </div>
                <ChevronRight
                  className={`w-4 h-4 text-vektor-text-muted transition-transform ${
                    expandedCat === i ? "rotate-90" : ""
                  }`}
                />
              </div>

              {expandedCat === i && (
                <div className="mt-3 pt-3 border-t border-vektor-border space-y-1.5">
                  {cat.models.map((m) => (
                    <div key={m} className="flex items-center gap-2 text-xs text-vektor-text-secondary">
                      <div className={`w-1.5 h-1.5 rounded-full ${cat.bg.replace("/10", "/40")}`} />
                      {m}
                    </div>
                  ))}
                </div>
              )}
            </button>
          ))}

          {/* Tier 2 card */}
          <div
            className={`p-5 rounded-xl border border-dashed border-vektor-accent/30 bg-vektor-accent/5 transition-all duration-500 ${
              inView ? "opacity-100 translate-y-0" : "opacity-0 translate-y-6"
            }`}
            style={{ transitionDelay: "400ms" }}
          >
            <div className="flex items-center gap-3 mb-3">
              <div className="w-8 h-8 rounded-lg bg-vektor-accent/15 flex items-center justify-center">
                <TrendingUp className="w-4 h-4 text-vektor-accent" />
              </div>
              <div>
                <h3 className="text-sm font-semibold">Tier 2: Suggest → Learn</h3>
                <p className="text-xs text-vektor-text-muted">Customer-specific</p>
              </div>
            </div>
            <p className="text-xs text-vektor-text-secondary leading-relaxed">
              Vektor suggests policies based on your environment. You approve or
              dismiss. The platform learns. Enough approvals across customers →
              graduates to Tier 1.
            </p>
          </div>
        </div>
      </div>
    </section>
  );
}

/* ────────────────────────────────────────────
   CROSS-BOUNDARY — The "Vektor Unique" Moat
   ──────────────────────────────────────────── */

const CROSS_BOUNDARY_EXAMPLES = [
  {
    title: "IAM → Lambda → NetSuite AP",
    chain: ["iam:PassRole", "Lambda execution role", "NetSuite AP Module", "Create vendor + approve invoice"],
    risk: "Automated financial fraud via infrastructure chaining",
  },
  {
    title: "Snowflake → Okta → Financial Data",
    chain: ["ACCOUNTADMIN role", "Shared Okta access (3 humans)", "Financial reporting data modification"],
    risk: "Shared privileged access to financial reporting data",
  },
  {
    title: "AI Agent Accumulation",
    chain: ["AP Clerk access", "GL Accountant access", "Procurement access", "Complete automated fraud cycle"],
    risk: "Agent accumulates SoD-violating permission set",
  },
];

function CrossBoundary() {
  const { ref, inView } = useInView();

  return (
    <section className="py-32 relative" ref={ref}>
      <div className="max-w-7xl mx-auto px-6">
        <div className="grid lg:grid-cols-2 gap-16 items-center">
          {/* Left — Copy */}
          <div>
            <p className="text-sm font-medium text-amber-400 tracking-wide uppercase mb-3">
              Vektor Unique
            </p>
            <h2 className="text-3xl sm:text-4xl font-bold tracking-tight mb-6">
              Cloud IAM + ERP identity.
              <br />
              One unified graph.
            </h2>
            <p className="text-vektor-text-secondary mb-8 leading-relaxed">
              Nobody else unifies cloud IAM (AWS, Okta, Entra) and ERP identity
              (NetSuite, SAP) in a single graph. This is how we detect
              cross-boundary privilege escalation chains that no other platform
              can see.
            </p>

            <div className="space-y-3">
              {[
                "Cross-system SoD violations (IAM ↔ ERP)",
                "Escalation chains spanning infrastructure and finance",
                "AI agents with cross-boundary financial access",
                "Orphaned access after incomplete offboarding",
              ].map((item) => (
                <div key={item} className="flex items-start gap-3">
                  <Check className="w-4 h-4 text-vektor-green mt-0.5 flex-shrink-0" />
                  <span className="text-sm text-vektor-text-secondary">{item}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Right — Example cards */}
          <div className="space-y-4">
            {CROSS_BOUNDARY_EXAMPLES.map((ex, i) => (
              <div
                key={ex.title}
                className={`p-5 rounded-xl bg-vektor-bg-card border border-vektor-border transition-all duration-500 ${
                  inView ? "opacity-100 translate-x-0" : "opacity-0 translate-x-8"
                }`}
                style={{ transitionDelay: `${i * 150}ms` }}
              >
                <div className="flex items-center gap-2 mb-3">
                  <AlertTriangle className="w-4 h-4 text-amber-400" />
                  <h3 className="text-sm font-semibold">{ex.title}</h3>
                </div>

                {/* Chain visualization */}
                <div className="flex flex-wrap items-center gap-1.5 mb-3">
                  {ex.chain.map((step, j) => (
                    <span key={j} className="flex items-center gap-1.5">
                      <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-vektor-bg border border-vektor-border text-vektor-text-secondary">
                        {step}
                      </span>
                      {j < ex.chain.length - 1 && (
                        <ChevronRight className="w-3 h-3 text-vektor-text-muted" />
                      )}
                    </span>
                  ))}
                </div>

                <p className="text-xs text-red-400/80">{ex.risk}</p>
              </div>
            ))}
          </div>
        </div>
      </div>
    </section>
  );
}

/* ────────────────────────────────────────────
   CONNECTORS
   ──────────────────────────────────────────── */

const CONNECTORS = [
  { name: "AWS IAM", type: "Cloud IAM", status: "GA" },
  { name: "Microsoft Entra ID", type: "Cloud IAM", status: "GA" },
  { name: "Okta", type: "Cloud IAM", status: "GA" },
  { name: "NetSuite", type: "ERP", status: "GA" },
  { name: "Snowflake", type: "Data", status: "Beta" },
  { name: "SAP", type: "ERP", status: "Coming" },
];

function Connectors() {
  const { ref, inView } = useInView();

  return (
    <section id="connectors" className="py-32 bg-vektor-bg-light/50" ref={ref}>
      <div className="max-w-7xl mx-auto px-6 text-center">
        <p className="text-sm font-medium text-vektor-accent tracking-wide uppercase mb-3">
          Connectors
        </p>
        <h2 className="text-3xl sm:text-4xl font-bold tracking-tight mb-4">
          Read-only. Never see your business data.
        </h2>
        <p className="text-vektor-text-secondary max-w-xl mx-auto mb-12">
          We see who accessed it, when, and whether they should have. That&apos;s it.
        </p>

        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-4">
          {CONNECTORS.map((c, i) => (
            <div
              key={c.name}
              className={`p-4 rounded-xl bg-vektor-bg-card border border-vektor-border hover:border-vektor-accent/30 transition-all duration-500 ${
                inView ? "opacity-100 scale-100" : "opacity-0 scale-95"
              }`}
              style={{ transitionDelay: `${i * 60}ms` }}
            >
              <div className="w-10 h-10 rounded-lg bg-vektor-border/50 flex items-center justify-center mx-auto mb-3">
                <Layers className="w-5 h-5 text-vektor-text-muted" />
              </div>
              <p className="text-sm font-medium">{c.name}</p>
              <p className="text-[11px] text-vektor-text-muted mt-0.5">{c.type}</p>
              <span
                className={`inline-block mt-2 text-[10px] font-medium px-2 py-0.5 rounded-full ${
                  c.status === "GA"
                    ? "bg-vektor-green/15 text-vektor-green"
                    : c.status === "Beta"
                    ? "bg-amber-400/15 text-amber-400"
                    : "bg-vektor-border text-vektor-text-muted"
                }`}
              >
                {c.status}
              </span>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}

/* ────────────────────────────────────────────
   COMPETITIVE COMPARISON
   ──────────────────────────────────────────── */

const COMPARISON_ROWS = [
  { dim: "Core", veza: "Access graph", opal: "Access workflows", pathlock: "ERP SoD rules", vektor: "ML-native risk infra" },
  { dim: "IAM + ERP", veza: "Cloud + SaaS", opal: "Cloud only", pathlock: "ERP only", vektor: "Unified" },
  { dim: "Agent Governance", veza: "—", opal: "—", pathlock: "—", vektor: "First-class" },
  { dim: "Execution", veza: "Findings only", opal: "Manual workflows", pathlock: "Alerts", vektor: "Agentic + rollback" },
  { dim: "ML / AI", veza: "No ML", opal: "No ML", pathlock: "Static rules", vektor: "22 supervised models" },
];

function ComparisonSection() {
  const { ref, inView } = useInView();

  return (
    <section className="py-32" ref={ref}>
      <div className="max-w-5xl mx-auto px-6">
        <div className="text-center mb-12">
          <h2 className="text-3xl sm:text-4xl font-bold tracking-tight">
            Not another access tool
          </h2>
          <p className="mt-4 text-vektor-text-secondary">
            Vektor is identity <em>intelligence</em> — ML-native, cross-boundary, agentic.
          </p>
        </div>

        <div
          className={`rounded-2xl border border-vektor-border overflow-hidden transition-all duration-700 ${
            inView ? "opacity-100 translate-y-0" : "opacity-0 translate-y-8"
          }`}
        >
          {/* Header */}
          <div className="grid grid-cols-5 bg-vektor-bg-card text-xs font-semibold text-vektor-text-muted border-b border-vektor-border">
            <div className="p-4"></div>
            <div className="p-4 text-center">Veza</div>
            <div className="p-4 text-center">Opal</div>
            <div className="p-4 text-center">Pathlock</div>
            <div className="p-4 text-center text-vektor-accent">Vektor</div>
          </div>

          {/* Rows */}
          {COMPARISON_ROWS.map((row, i) => (
            <div
              key={row.dim}
              className={`grid grid-cols-5 text-sm border-b border-vektor-border last:border-b-0 ${
                i % 2 === 0 ? "bg-vektor-bg" : "bg-vektor-bg-card/30"
              }`}
            >
              <div className="p-4 font-medium text-vektor-text-secondary">{row.dim}</div>
              <div className="p-4 text-center text-vektor-text-muted text-xs">{row.veza}</div>
              <div className="p-4 text-center text-vektor-text-muted text-xs">{row.opal}</div>
              <div className="p-4 text-center text-vektor-text-muted text-xs">{row.pathlock}</div>
              <div className="p-4 text-center text-vektor-accent text-xs font-medium">{row.vektor}</div>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}

/* ────────────────────────────────────────────
   CTA
   ──────────────────────────────────────────── */

function CTA() {
  return (
    <section className="py-32 relative overflow-hidden">
      <div className="absolute inset-0 radial-glow" />
      <div className="relative z-10 max-w-3xl mx-auto px-6 text-center">
        <h2 className="text-3xl sm:text-4xl font-bold tracking-tight mb-4">
          Who has access. Who should.
          <br />
          <span className="text-vektor-accent">We fix the gap.</span>
        </h2>
        <p className="text-vektor-text-secondary mb-8">
          See Vektor in action on your own identity data. Read-only. 15 minutes.
          No commitment.
        </p>
        <a
          href="#"
          className="inline-flex items-center gap-2 px-8 py-3.5 rounded-lg bg-vektor-accent hover:bg-vektor-accent-hover text-white font-semibold transition-all hover:shadow-lg hover:shadow-vektor-accent/25"
        >
          Request Demo
          <ArrowRight className="w-4 h-4" />
        </a>
      </div>
    </section>
  );
}

/* ────────────────────────────────────────────
   FOOTER
   ──────────────────────────────────────────── */

function Footer() {
  return (
    <footer className="border-t border-vektor-border py-12">
      <div className="max-w-7xl mx-auto px-6 flex flex-col sm:flex-row items-center justify-between gap-4">
        <div className="flex items-center gap-2">
          <div className="w-6 h-6 rounded bg-gradient-to-br from-vektor-accent to-blue-400 flex items-center justify-center">
            <Shield className="w-3.5 h-3.5 text-white" />
          </div>
          <span className="text-sm font-semibold">
            Vektor<span className="text-vektor-accent">.ai</span>
          </span>
        </div>
        <p className="text-xs text-vektor-text-muted">
          &copy; {new Date().getFullYear()} Vektor AI, Inc. All rights reserved.
        </p>
        <div className="flex items-center gap-6 text-xs text-vektor-text-muted">
          <a href="#" className="hover:text-white transition-colors">Privacy</a>
          <a href="#" className="hover:text-white transition-colors">Terms</a>
          <a href="#" className="hover:text-white transition-colors">Security</a>
        </div>
      </div>
    </footer>
  );
}

/* ────────────────────────────────────────────
   PAGE
   ──────────────────────────────────────────── */

export default function HomePage() {
  return (
    <main>
      <Navbar />
      <Hero />
      <CoreLoop />
      <IntelligenceSection />
      <CrossBoundary />
      <Connectors />
      <ComparisonSection />
      <CTA />
      <Footer />
    </main>
  );
}
