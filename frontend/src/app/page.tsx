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
  Database,
  Layers,
  Terminal,
  AlertTriangle,
  Activity,
  X,
  Sparkles,
  FileJson,
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
    { label: "How It Works", href: "#how-it-works" },
    { label: "Intelligence", href: "#intelligence" },
    { label: "Connectors", href: "#connectors" },
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
        <a href="#" className="flex items-center gap-2 group">
          <img src="/vektor-logo.png" alt="Vektor" className="h-8 w-auto" />
          <span className="text-lg font-bold tracking-tight">vektor</span>
        </a>

        <div className="hidden md:flex items-center gap-8">
          {links.map((l) => (
            <a key={l.label} href={l.href} className="text-sm text-vektor-text-secondary hover:text-white transition-colors">
              {l.label}
            </a>
          ))}
        </div>

        <div className="hidden md:flex items-center gap-4">
          <a href="/demo" className="text-sm px-4 py-2 rounded-lg bg-vektor-accent hover:bg-vektor-accent-hover text-white font-medium transition-colors">
            Request Demo
          </a>
        </div>

        <button className="md:hidden text-vektor-text-secondary" onClick={() => setMobileOpen(!mobileOpen)}>
          {mobileOpen ? <X className="w-5 h-5" /> : (
            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeWidth={2} d="M4 6h16M4 12h16M4 18h16" />
            </svg>
          )}
        </button>
      </div>

      {mobileOpen && (
        <div className="md:hidden bg-vektor-bg border-b border-vektor-border px-6 py-4 space-y-3">
          {links.map((l) => (
            <a key={l.label} href={l.href} className="block text-sm text-vektor-text-secondary hover:text-white" onClick={() => setMobileOpen(false)}>
              {l.label}
            </a>
          ))}
          <a href="/demo" className="block text-sm px-4 py-2 rounded-lg bg-vektor-accent text-white text-center font-medium">
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
      <div className="absolute inset-0 bg-grid" />
      <div className="absolute inset-0 radial-glow" />
      <div className="absolute inset-0 noise-overlay" />
      <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-vektor-accent/5 rounded-full blur-3xl animate-pulse-slow" />
      <div className="absolute bottom-1/4 right-1/4 w-80 h-80 bg-vektor-green/5 rounded-full blur-3xl animate-pulse-slow" style={{ animationDelay: "1.5s" }} />

      <div className="relative z-10 max-w-5xl mx-auto px-6 text-center">
        <img src="/vektor-logo.png" alt="Vektor" className="w-32 sm:w-40 mx-auto mb-6 animate-fade-in" />

        <div className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full bg-vektor-accent/10 border border-vektor-accent/20 mb-8 animate-fade-in">
          <Bot className="w-3.5 h-3.5 text-vektor-accent" />
          <span className="text-xs font-medium text-vektor-accent tracking-wide uppercase">
            AI-Native Identity Intelligence
          </span>
        </div>

        <h1 className="text-4xl sm:text-5xl lg:text-6xl font-bold tracking-tight leading-[1.15] mb-6 animate-slide-up">
          See every identity risk — human and machine.{" "}
          <span className="text-transparent bg-clip-text bg-gradient-to-r from-vektor-accent via-blue-400 to-vektor-green">
            Fix it without writing a single rule.
          </span>
          <br />
          Govern autonomously.
        </h1>

        <p
          className="text-lg sm:text-xl text-vektor-text-secondary max-w-2xl mx-auto mb-10 animate-slide-up"
          style={{ animationDelay: "0.15s" }}
        >
          Vektor finds identity risk across every system — human, service account, and AI agent.
          Then our ML models write the policies to fix it. Not a single rule file to maintain.
        </p>

        <div
          className="flex flex-col sm:flex-row items-center justify-center gap-4 animate-slide-up"
          style={{ animationDelay: "0.3s" }}
        >
          <a href="/demo" className="group flex items-center gap-2 px-6 py-3 rounded-lg bg-vektor-accent hover:bg-vektor-accent-hover text-white font-semibold transition-all hover:shadow-lg hover:shadow-vektor-accent/25">
            Request Demo
            <ArrowRight className="w-4 h-4 transition-transform group-hover:translate-x-0.5" />
          </a>
          <a href="#how-it-works" className="flex items-center gap-2 px-6 py-3 rounded-lg border border-vektor-border text-vektor-text-secondary hover:text-white hover:border-vektor-text-muted transition-all">
            See how it works
          </a>
        </div>

        <div
          className="mt-16 flex items-center justify-center gap-8 text-xs text-vektor-text-muted animate-fade-in"
          style={{ animationDelay: "0.5s" }}
        >
          <span className="flex items-center gap-1.5"><Lock className="w-3.5 h-3.5" /> SOC 2 Type II</span>
          <span className="flex items-center gap-1.5"><Shield className="w-3.5 h-3.5" /> SOX Compliant</span>
          <span className="flex items-center gap-1.5"><Eye className="w-3.5 h-3.5" /> Read-Only Access</span>
        </div>
      </div>
    </section>
  );
}

/* ────────────────────────────────────────────
   THE PROBLEM
   ──────────────────────────────────────────── */

function ProblemSection() {
  const { ref, inView } = useInView();

  const problems = [
    { stat: "3+", label: "identity systems per company", desc: "IAM, ERP, IdP — each with its own roles, permissions, and blind spots. No cross-system visibility into who can do what.", icon: Database, color: "text-red-400" },
    { stat: "100s", label: "of hand-written rules", desc: "Static YAML files that break when roles change. Maintained by humans who can't keep up with identity sprawl.", icon: Terminal, color: "text-amber-400" },
    { stat: "0", label: "tools governing AI agents", desc: "AI agents get admin credentials by default. No scope limits, no drift detection, no SoD enforcement.", icon: Bot, color: "text-purple-400" },
  ];

  return (
    <section className="py-24 relative" ref={ref}>
      <div className="max-w-7xl mx-auto px-6">
        <div className="text-center mb-16">
          <p className="text-sm font-medium text-red-400 tracking-wide uppercase mb-3">The Problem</p>
          <h2 className="text-3xl sm:text-4xl font-bold tracking-tight">Identity governance is broken</h2>
          <p className="mt-4 text-vektor-text-secondary max-w-2xl mx-auto">
            Enterprises run identity across 3+ systems, maintain hundreds of hand-written detection rules,
            and have zero visibility into what their AI agents can access.
          </p>
        </div>

        <div className="grid md:grid-cols-3 gap-6">
          {problems.map((p, i) => (
            <div
              key={p.label}
              className={`relative p-6 rounded-2xl bg-vektor-bg-card border border-vektor-border transition-all duration-500 ${
                inView ? "opacity-100 translate-y-0" : "opacity-0 translate-y-8"
              }`}
              style={{ transitionDelay: `${i * 120}ms` }}
            >
              <div className="flex items-center gap-3 mb-4">
                <div className="w-10 h-10 rounded-xl bg-red-400/10 flex items-center justify-center">
                  <p.icon className={`w-5 h-5 ${p.color}`} />
                </div>
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

/* ────────────────────────────────────────────
   HOW IT WORKS
   ──────────────────────────────────────────── */

const CORE_STEPS = [
  {
    icon: Database, label: "Connect", title: "Unified identity graph",
    description: "Read-only adapters connect to AWS IAM, Okta, Entra ID, and NetSuite. We build a cross-system identity graph — cloud IAM and ERP permissions in one view. Every human, service account, and AI agent.",
    color: "text-blue-400", bg: "bg-blue-400/10",
  },
  {
    icon: Scan, label: "Detect", title: "22 ML models, not rules",
    description: "Supervised classifiers score every identity across 15 violation classes — SOX compliance, Zero Trust, anomaly detection, agent governance, and cross-boundary risk. Confidence-scored signals with blast radius and evidence.",
    color: "text-vektor-green", bg: "bg-vektor-green/10",
  },
  {
    icon: Sparkles, label: "Govern", title: "Policies write themselves",
    description: "Our system surfaces intelligent policy suggestions directly to your dashboard. With a single click to approve, the platform instantly activates new detection capabilities across your environment. No manual configuration, no YAML, and zero rule-writing required—ever.Ever.",
    color: "text-amber-400", bg: "bg-amber-400/10",
  },
  {
    icon: Zap, label: "Execute", title: "Agentic remediation with rollback",
    description: "When a signal fires, AI agents execute remediation programmatically. Human approval gates for destructive actions. Full audit trail. Instant rollback if anything goes wrong.",
    color: "text-red-400", bg: "bg-red-400/10",
  },
];

function HowItWorks() {
  const { ref, inView } = useInView();

  return (
    <section id="how-it-works" className="py-32 bg-vektor-bg-light/50 relative" ref={ref}>
      <div className="max-w-7xl mx-auto px-6">
        <div className="text-center mb-16">
          <p className="text-sm font-medium text-vektor-accent tracking-wide uppercase mb-3">How Vektor Works</p>
          <h2 className="text-3xl sm:text-4xl font-bold tracking-tight">Connect → Detect → Govern → Execute</h2>
          <p className="mt-4 text-vektor-text-secondary max-w-xl mx-auto">
            From identity sprawl to autonomous governance. No hand-written rules at any step.
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
              <div className="absolute -top-3 -left-1 text-[80px] font-bold text-vektor-border/50 select-none leading-none">{i + 1}</div>
              <div className={`w-10 h-10 rounded-xl ${step.bg} flex items-center justify-center mb-4 relative z-10`}>
                <step.icon className={`w-5 h-5 ${step.color}`} />
              </div>
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

/* ────────────────────────────────────────────
   INTELLIGENCE — Tier 1 + Tier 2 + Signal Output
   ──────────────────────────────────────────── */

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
          <h2 className="text-3xl sm:text-4xl font-bold tracking-tight">22 ML models. Zero rule files.</h2>
          <p className="mt-4 text-vektor-text-secondary max-w-2xl mx-auto">
            Tier 1 models detect risk with confidence-scored signals. Tier 2 uses those signals
            to generate new policies automatically — no human writes a single rule.
          </p>
        </div>

        <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-4 mb-12">
          {MODEL_CATEGORIES.map((cat, i) => (
            <button
              key={cat.name}
              onClick={() => setExpandedCat(expandedCat === i ? null : i)}
              className={`text-left p-5 rounded-xl border transition-all duration-500 ${
                expandedCat === i ? `bg-vektor-bg-card ${cat.border} border-opacity-100` : "bg-vektor-bg-card/50 border-vektor-border hover:border-vektor-text-muted"
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
                <ChevronRight className={`w-4 h-4 text-vektor-text-muted transition-transform ${expandedCat === i ? "rotate-90" : ""}`} />
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

          {/* Tier 2 — self-writing policies */}
          <div
            className={`p-5 rounded-xl border border-dashed border-vektor-accent/30 bg-vektor-accent/5 transition-all duration-500 ${
              inView ? "opacity-100 translate-y-0" : "opacity-0 translate-y-6"
            }`}
            style={{ transitionDelay: "400ms" }}
          >
            <div className="flex items-center gap-3 mb-3">
              <div className="w-8 h-8 rounded-lg bg-vektor-accent/15 flex items-center justify-center">
                <Sparkles className="w-4 h-4 text-vektor-accent" />
              </div>
              <div>
                <h3 className="text-sm font-semibold">Tier 2: Self-Writing Policies</h3>
                <p className="text-xs text-vektor-text-muted">Fully autonomous after approval</p>
              </div>
            </div>
            <p className="text-xs text-vektor-text-secondary leading-relaxed">
              Tier 1 signals feed an AI agent that generates policy recommendations.
              You approve or reject — that&apos;s your only input. The platform creates a scoped ML model,
              starts detecting, and improves with every decision. High-confidence policies graduate to Tier 1.
            </p>
          </div>
        </div>

        {/* Signal Output */}
        <div
          className={`rounded-2xl border border-vektor-border bg-vektor-bg-card p-8 transition-all duration-700 ${
            inView ? "opacity-100 translate-y-0" : "opacity-0 translate-y-8"
          }`}
          style={{ transitionDelay: "500ms" }}
        >
          <div className="grid lg:grid-cols-2 gap-8 items-center">
            <div>
              <div className="flex items-center gap-2 mb-3">
                <FileJson className="w-5 h-5 text-vektor-accent" />
                <p className="text-sm font-medium text-vektor-accent tracking-wide uppercase">Structured Signal Output</p>
              </div>
              <h3 className="text-2xl font-bold mb-3">Intelligence your agents can consume</h3>
              <p className="text-sm text-vektor-text-secondary leading-relaxed mb-4">
                Every signal is a structured object — confidence-scored, with blast radius,
                evidence chain, remediation steps, and SOX control mapping. Your SIEM, your SOAR,
                your AI agents — they all consume the same structured output.
              </p>
              <div className="space-y-2">
                {[
                  "Confidence score + violation class per identity",
                  "Blast radius — systems, permissions, and downstream impact",
                  "Pre-computed remediation with rollback plan",
                  "SOX / NIST / CIS control mapping",
                  "Feature snapshot for audit trail",
                ].map((item) => (
                  <div key={item} className="flex items-start gap-2">
                    <Check className="w-3.5 h-3.5 text-vektor-green mt-0.5 flex-shrink-0" />
                    <span className="text-xs text-vektor-text-secondary">{item}</span>
                  </div>
                ))}
              </div>
            </div>

            <div className="bg-vektor-bg rounded-xl border border-vektor-border p-5 font-mono text-xs overflow-hidden">
              <div className="text-vektor-text-muted mb-2">// Tier 1 signal output</div>
              <div className="space-y-0.5 text-vektor-text-secondary">
                <div>{"{"}</div>
                <div className="pl-4"><span className="text-vektor-accent">&quot;signal_id&quot;</span>: <span className="text-vektor-green">&quot;SIG-2026-00847&quot;</span>,</div>
                <div className="pl-4"><span className="text-vektor-accent">&quot;subject&quot;</span>: <span className="text-vektor-green">&quot;maria.gonzalez&quot;</span>,</div>
                <div className="pl-4"><span className="text-vektor-accent">&quot;violation&quot;</span>: <span className="text-vektor-green">&quot;sod_violation_erp&quot;</span>,</div>
                <div className="pl-4"><span className="text-vektor-accent">&quot;confidence&quot;</span>: <span className="text-amber-400">0.98</span>,</div>
                <div className="pl-4"><span className="text-vektor-accent">&quot;blast_radius&quot;</span>: {"{"}</div>
                <div className="pl-8"><span className="text-vektor-accent">&quot;systems&quot;</span>: [<span className="text-vektor-green">&quot;netsuite&quot;</span>],</div>
                <div className="pl-8"><span className="text-vektor-accent">&quot;permissions_at_risk&quot;</span>: <span className="text-amber-400">4</span>,</div>
                <div className="pl-8"><span className="text-vektor-accent">&quot;downstream_subjects&quot;</span>: <span className="text-amber-400">2</span></div>
                <div className="pl-4">{"}"},</div>
                <div className="pl-4"><span className="text-vektor-accent">&quot;remediation&quot;</span>: {"{"}</div>
                <div className="pl-8"><span className="text-vektor-accent">&quot;action&quot;</span>: <span className="text-vektor-green">&quot;remove_role&quot;</span>,</div>
                <div className="pl-8"><span className="text-vektor-accent">&quot;target&quot;</span>: <span className="text-vektor-green">&quot;Vendor Manager&quot;</span>,</div>
                <div className="pl-8"><span className="text-vektor-accent">&quot;reversible&quot;</span>: <span className="text-amber-400">true</span></div>
                <div className="pl-4">{"}"},</div>
                <div className="pl-4"><span className="text-vektor-accent">&quot;sox_control&quot;</span>: <span className="text-vektor-green">&quot;ITGC-AP-03&quot;</span></div>
                <div>{"}"}</div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}

/* ────────────────────────────────────────────
   CROSS-BOUNDARY
   ──────────────────────────────────────────── */

const CROSS_BOUNDARY_EXAMPLES = [
  { title: "IAM → Lambda → NetSuite AP", chain: ["iam:PassRole", "Lambda execution role", "NetSuite AP Module", "Create vendor + approve invoice"], risk: "Automated financial fraud via infrastructure chaining" },
  { title: "Snowflake → Okta → Financial Data", chain: ["ACCOUNTADMIN role", "Shared Okta access (3 humans)", "Financial reporting data modification"], risk: "Shared privileged access to financial reporting data" },
  { title: "AI Agent Accumulation", chain: ["AP Clerk access", "GL Accountant access", "Procurement access", "Complete automated fraud cycle"], risk: "Agent accumulates SoD-violating permission set" },
];

function CrossBoundary() {
  const { ref, inView } = useInView();

  return (
    <section className="py-32 bg-vektor-bg-light/50 relative" ref={ref}>
      <div className="max-w-7xl mx-auto px-6">
        <div className="grid lg:grid-cols-2 gap-16 items-center">
          <div>
            <p className="text-sm font-medium text-amber-400 tracking-wide uppercase mb-3">Vektor Unique</p>
            <h2 className="text-3xl sm:text-4xl font-bold tracking-tight mb-6">
              Cloud IAM + ERP identity.
              <br />One unified graph.
            </h2>
            <p className="text-vektor-text-secondary mb-8 leading-relaxed">
              Nobody else unifies cloud IAM (AWS, Okta, Entra) and ERP identity
              (NetSuite, SAP) in a single graph. This is how we detect
              cross-boundary privilege escalation chains that no other platform
              can see — and why our ML models can write policies that no rule library can match.
            </p>
            <div className="space-y-3">
              {["Cross-system SoD violations (IAM ↔ ERP)", "Escalation chains spanning infrastructure and finance", "AI agents with cross-boundary financial access", "Orphaned access after incomplete offboarding"].map((item) => (
                <div key={item} className="flex items-start gap-3">
                  <Check className="w-4 h-4 text-vektor-green mt-0.5 flex-shrink-0" />
                  <span className="text-sm text-vektor-text-secondary">{item}</span>
                </div>
              ))}
            </div>
          </div>

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
                <div className="flex flex-wrap items-center gap-1.5 mb-3">
                  {ex.chain.map((step, j) => (
                    <span key={j} className="flex items-center gap-1.5">
                      <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-vektor-bg border border-vektor-border text-vektor-text-secondary">{step}</span>
                      {j < ex.chain.length - 1 && <ChevronRight className="w-3 h-3 text-vektor-text-muted" />}
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
    <section id="connectors" className="py-32" ref={ref}>
      <div className="max-w-7xl mx-auto px-6 text-center">
        <p className="text-sm font-medium text-vektor-accent tracking-wide uppercase mb-3">Connectors</p>
        <h2 className="text-3xl sm:text-4xl font-bold tracking-tight mb-4">Read-only. Never see your business data.</h2>
        <p className="text-vektor-text-secondary max-w-xl mx-auto mb-12">We see who accessed it, when, and whether they should have. That&apos;s it.</p>

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
              <span className={`inline-block mt-2 text-[10px] font-medium px-2 py-0.5 rounded-full ${
                c.status === "GA" ? "bg-vektor-green/15 text-vektor-green" : c.status === "Beta" ? "bg-amber-400/15 text-amber-400" : "bg-vektor-border text-vektor-text-muted"
              }`}>{c.status}</span>
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
  { dim: "Detection", veza: "Access graph", opal: "Access workflows", pathlock: "Hand-written SoD rules", vektor: "22 supervised ML models" },
  { dim: "IAM + ERP", veza: "Cloud + SaaS", opal: "Cloud only", pathlock: "ERP only", vektor: "Unified graph" },
  { dim: "Agent Governance", veza: "—", opal: "—", pathlock: "—", vektor: "First-class" },
  { dim: "Policy Creation", veza: "Manual", opal: "Manual", pathlock: "Manual YAML", vektor: "ML-generated, autonomous" },
  { dim: "Rule Maintenance", veza: "Ongoing", opal: "Ongoing", pathlock: "Ongoing", vektor: "None — self-improving" },
  { dim: "Execution", veza: "Findings only", opal: "Manual workflows", pathlock: "Alerts", vektor: "Agentic + auto-rollback" },
];

function ComparisonSection() {
  const { ref, inView } = useInView();

  return (
    <section className="py-32 bg-vektor-bg-light/50" ref={ref}>
      <div className="max-w-5xl mx-auto px-6">
        <div className="text-center mb-12">
          <h2 className="text-3xl sm:text-4xl font-bold tracking-tight">Not another access tool</h2>
          <p className="mt-4 text-vektor-text-secondary">Others find access. Vektor finds risk, writes the policy, and fixes it — autonomously.</p>
        </div>

        <div className={`rounded-2xl border border-vektor-border overflow-hidden transition-all duration-700 ${inView ? "opacity-100 translate-y-0" : "opacity-0 translate-y-8"}`}>
          <div className="grid grid-cols-5 bg-vektor-bg-card text-xs font-semibold text-vektor-text-muted border-b border-vektor-border">
            <div className="p-4"></div>
            <div className="p-4 text-center">Veza</div>
            <div className="p-4 text-center">Opal</div>
            <div className="p-4 text-center">Pathlock</div>
            <div className="p-4 text-center text-vektor-accent">Vektor</div>
          </div>
          {COMPARISON_ROWS.map((row, i) => (
            <div key={row.dim} className={`grid grid-cols-5 text-sm border-b border-vektor-border last:border-b-0 ${i % 2 === 0 ? "bg-vektor-bg" : "bg-vektor-bg-card/30"}`}>
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
          See every identity risk — human and machine. Fix it without writing a single rule.
          <br /><span className="text-vektor-accent">Govern autonomously.</span>
        </h2>
        <p className="text-vektor-text-secondary mb-8">See Vektor in action on real identity data. Read-only. 15 minutes. No commitment.</p>
        <a href="/demo" className="inline-flex items-center gap-2 px-8 py-3.5 rounded-lg bg-vektor-accent hover:bg-vektor-accent-hover text-white font-semibold transition-all hover:shadow-lg hover:shadow-vektor-accent/25">
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

/* ────────────────────────────────────────────
   PAGE
   ──────────────────────────────────────────── */

export default function HomePage() {
  return (
    <main>
      <Navbar />
      <Hero />
      <ProblemSection />
      <HowItWorks />
      <IntelligenceSection />
      <CrossBoundary />
      <Connectors />
      <ComparisonSection />
      <CTA />
      <Footer />
    </main>
  );
}
