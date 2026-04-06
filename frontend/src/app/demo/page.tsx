"use client";

import { useState, useEffect } from "react";
import {
  Shield,
  AlertTriangle,
  Lock,
  Eye,
  ChevronRight,
  ArrowLeft,
  Activity,
  Network,
  Zap,
  Bot,
  TrendingUp,
  Check,
  X,
  Terminal,
  Database,
  Layers,
} from "lucide-react";

/* ────────────────────────────────────────────
   DEMO DATA — Real pipeline output
   ──────────────────────────────────────────── */

const PIPELINE_STATS = {
  policiesLoaded: 1537,
  policiesPrivileged: 587,
  subjectsAnalyzed: 20,
  assignments: 63,
  graphNodes: 1566,
  graphEdges: 63,
  featureVectors: 20,
  escalationPaths: 4,
  cloudTrailEvents: 2900,
  violationsDetected: 139,
  runtimeSeconds: 1.96,
};

const SEVERITY_COUNTS = {
  critical: 0,
  high: 17,
  medium: 59,
  low: 63,
};

const VIOLATION_BREAKDOWN = [
  { name: "Shadow Admin", count: 105 },
  { name: "Agent Scope Drift", count: 17 },
  { name: "Orphan Account", count: 10 },
  { name: "Stale / Dormant Account", count: 4 },
  { name: "Cross-Boundary Overreach", count: 3 },
];

type Signal = {
  id: number;
  severity: "critical" | "high" | "medium" | "low";
  confidence: number;
  subject: string;
  subjectType: string;
  department: string;
  violation: string;
  rule: string;
  evidence: Record<string, string>;
};

const TOP_SIGNALS: Signal[] = [
  {
    id: 1,
    severity: "high",
    confidence: 0.95,
    subject: "jack.brown",
    subjectType: "human",
    department: "Engineering",
    violation: "Stale / Dormant Account",
    rule: "ESC-R1",
    evidence: {
      end_result:
        "Can pass a high-privilege role to a Lambda and execute it",
      steps: "2-step escalation chain",
    },
  },
  {
    id: 2,
    severity: "high",
    confidence: 0.95,
    subject: "jack.brown",
    subjectType: "human",
    department: "Engineering",
    violation: "Cross-Boundary Overreach",
    rule: "MFA-R1-PRIV",
    evidence: {
      mfa_enabled: "false",
      privileged_permissions: "5 privileged policies attached",
    },
  },
  {
    id: 3,
    severity: "high",
    confidence: 0.95,
    subject: "svc-lambda-exec",
    subjectType: "service_account",
    department: "Platform",
    violation: "Stale / Dormant Account",
    rule: "ESC-R1",
    evidence: {
      end_result:
        "Can pass a high-privilege role to a Lambda and execute it",
      steps: "2-step escalation chain",
    },
  },
  {
    id: 4,
    severity: "high",
    confidence: 0.9,
    subject: "bob.chen",
    subjectType: "human",
    department: "DevOps",
    violation: "Agent Scope Drift",
    rule: "TRC-R1-SECFIN",
    evidence: {
      has_security_admin: "true",
      has_financial_admin: "true — crosses security/financial boundary",
    },
  },
  {
    id: 5,
    severity: "high",
    confidence: 0.9,
    subject: "agent-cost-optimizer",
    subjectType: "ai_agent",
    department: "Platform",
    violation: "Agent Scope Drift",
    rule: "TRC-R1-SECFIN",
    evidence: {
      has_security_admin: "true",
      has_financial_admin: "true — AI agent crosses security/financial boundary",
    },
  },
  {
    id: 6,
    severity: "high",
    confidence: 0.9,
    subject: "svc-deploy-prod",
    subjectType: "service_account",
    department: "DevOps",
    violation: "Shadow Admin",
    rule: "ABJ-R1-PRIV",
    evidence: {
      permission: "AdministratorAccess",
      is_privileged: "true — full admin on a deployment service account",
    },
  },
  {
    id: 7,
    severity: "medium",
    confidence: 0.8,
    subject: "bob.chen",
    subjectType: "human",
    department: "DevOps",
    violation: "Agent Scope Drift",
    rule: "TRC-R1-MULTI",
    evidence: {
      privileged_role_count: "6 privileged roles",
      categories: "financial, identity, infrastructure, security",
    },
  },
  {
    id: 8,
    severity: "medium",
    confidence: 0.8,
    subject: "eve.wilson",
    subjectType: "human",
    department: "Data Science",
    violation: "Orphan Account",
    rule: "EP-R1-HIGH",
    evidence: {
      ratio: "4.00x peer median",
      total_permissions: "4 (all privileged — SageMaker, S3, Athena, Glue)",
    },
  },
  {
    id: 9,
    severity: "medium",
    confidence: 0.7,
    subject: "carol.martinez",
    subjectType: "human",
    department: "Security",
    violation: "Cross-Boundary Overreach",
    rule: "MFA-R1-ACTIVE",
    evidence: {
      mfa_enabled: "false — security analyst without MFA",
    },
  },
  {
    id: 10,
    severity: "medium",
    confidence: 0.6,
    subject: "grace.taylor",
    subjectType: "human",
    department: "Infrastructure",
    violation: "Shadow Admin",
    rule: "ABJ-R1-PRIV",
    evidence: {
      permission: "AdministratorAccess",
      has_justification: "false — no documented justification",
    },
  },
];

const CLOUDTRAIL_STATS = {
  totalEvents: 2900,
  uniqueSubjects: 15,
  uniqueActions: 260,
  privilegedEvents: 122,
  errorEvents: 300,
  timeRange: "2023-07-10",
  source: "Invictus IR — Stratus Red Team attack simulation",
};

const DATA_SOURCES = [
  { name: "MAMIP", desc: "1,549 real AWS managed IAM policies (JSON)", status: "loaded" },
  { name: "Invictus IR", desc: "2,900 CloudTrail events — Stratus Red Team attacks", status: "loaded" },
  { name: "iann0036 IAM Dataset", desc: "Risk flags: privesc, resource exposure, credentials", status: "indexed" },
];

/* ────────────────────────────────────────────
   PASSWORD GATE
   ──────────────────────────────────────────── */

const DEMO_PASSWORD = "VEKTOR-2026-DEMO";

function PasswordGate({ onUnlock }: { onUnlock: () => void }) {
  const [pw, setPw] = useState("");
  const [error, setError] = useState(false);
  const [shake, setShake] = useState(false);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (pw.trim() === DEMO_PASSWORD) {
      onUnlock();
    } else {
      setError(true);
      setShake(true);
      setTimeout(() => setShake(false), 500);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-[#0A0F1C] px-6">
      {/* Radial glow */}
      <div className="fixed inset-0 bg-[radial-gradient(ellipse_60%_40%_at_50%_30%,rgba(59,130,246,0.08),transparent_70%)] pointer-events-none" />

      <div className={`relative w-full max-w-md ${shake ? "animate-shake" : ""}`}>
        {/* Logo */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center gap-2 mb-4">
            <Shield className="w-8 h-8 text-[#3B82F6]" />
            <span className="text-2xl font-bold tracking-tight text-white">
              VEKTOR
            </span>
          </div>
          <p className="text-[#94A3B8] text-sm">
            Live Pipeline Demo — Investor Preview
          </p>
        </div>

        {/* Form */}
        <form onSubmit={handleSubmit}>
          <div className="bg-[#151D2E] border border-[#1E293B] rounded-xl p-8">
            <div className="flex items-center gap-3 mb-6">
              <Lock className="w-5 h-5 text-[#3B82F6]" />
              <span className="text-white font-medium">Enter access code</span>
            </div>

            <input
              type="password"
              value={pw}
              onChange={(e) => {
                setPw(e.target.value);
                setError(false);
              }}
              placeholder="Access code"
              autoFocus
              className="w-full px-4 py-3 rounded-lg bg-[#0A0F1C] border border-[#1E293B] text-white placeholder:text-[#64748B] focus:outline-none focus:border-[#3B82F6] focus:ring-1 focus:ring-[#3B82F6]/30 font-mono text-sm tracking-wider transition-colors"
            />

            {error && (
              <p className="mt-2 text-sm text-[#EF4444]">
                Invalid access code. Please try again.
              </p>
            )}

            <button
              type="submit"
              className="mt-4 w-full py-3 rounded-lg bg-[#3B82F6] hover:bg-[#2563EB] text-white font-semibold text-sm transition-colors"
            >
              Access Demo
            </button>
          </div>
        </form>

        <p className="mt-6 text-center text-xs text-[#64748B]">
          This demo runs on real, open-source IAM data.
          <br />
          No customer data is used.
        </p>
      </div>

      <style jsx>{`
        @keyframes shake {
          0%, 100% { transform: translateX(0); }
          20%, 60% { transform: translateX(-8px); }
          40%, 80% { transform: translateX(8px); }
        }
        .animate-shake { animation: shake 0.4s ease-in-out; }
      `}</style>
    </div>
  );
}

/* ────────────────────────────────────────────
   SEVERITY BADGE
   ──────────────────────────────────────────── */

function SeverityBadge({ severity }: { severity: string }) {
  const colors: Record<string, string> = {
    critical: "bg-red-500/15 text-red-400 border-red-500/30",
    high: "bg-amber-500/15 text-amber-400 border-amber-500/30",
    medium: "bg-blue-500/15 text-blue-400 border-blue-500/30",
    low: "bg-slate-500/15 text-slate-400 border-slate-500/30",
  };
  return (
    <span
      className={`inline-flex px-2.5 py-0.5 text-xs font-mono font-semibold rounded border ${colors[severity] || colors.low}`}
    >
      {severity.toUpperCase()}
    </span>
  );
}

/* ────────────────────────────────────────────
   STAT CARD
   ──────────────────────────────────────────── */

function StatCard({
  label,
  value,
  sub,
  icon: Icon,
  accent = false,
}: {
  label: string;
  value: string | number;
  sub?: string;
  icon: React.ElementType;
  accent?: boolean;
}) {
  return (
    <div className="bg-[#151D2E] border border-[#1E293B] rounded-xl p-5">
      <div className="flex items-start justify-between mb-3">
        <Icon
          className={`w-5 h-5 ${accent ? "text-[#3B82F6]" : "text-[#64748B]"}`}
        />
        {sub && (
          <span className="text-xs text-[#64748B] font-mono">{sub}</span>
        )}
      </div>
      <div className="text-2xl font-bold text-white font-mono">
        {typeof value === "number" ? value.toLocaleString() : value}
      </div>
      <div className="text-xs text-[#94A3B8] mt-1">{label}</div>
    </div>
  );
}

/* ────────────────────────────────────────────
   DEMO DASHBOARD
   ──────────────────────────────────────────── */

function DemoDashboard() {
  const [selectedSignal, setSelectedSignal] = useState<Signal | null>(null);
  const [activeTab, setActiveTab] = useState<"signals" | "cloudtrail" | "data">("signals");

  return (
    <div className="min-h-screen bg-[#0A0F1C]">
      {/* Subtle background */}
      <div className="fixed inset-0 bg-[radial-gradient(ellipse_80%_50%_at_50%_-20%,rgba(59,130,246,0.06),transparent_70%)] pointer-events-none" />

      {/* Header */}
      <header className="sticky top-0 z-40 bg-[#0A0F1C]/90 backdrop-blur-xl border-b border-[#1E293B]">
        <div className="max-w-7xl mx-auto px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-4">
            <a href="/" className="flex items-center gap-2 text-[#94A3B8] hover:text-white transition-colors text-sm">
              <ArrowLeft className="w-4 h-4" />
              Back
            </a>
            <div className="w-px h-5 bg-[#1E293B]" />
            <div className="flex items-center gap-2">
              <Shield className="w-5 h-5 text-[#3B82F6]" />
              <span className="text-lg font-bold text-white tracking-tight">
                VEKTOR
              </span>
              <span className="text-xs text-[#64748B] font-mono bg-[#151D2E] px-2 py-0.5 rounded ml-1">
                LIVE DEMO
              </span>
            </div>
          </div>

          <div className="flex items-center gap-2 text-xs text-[#64748B] font-mono">
            <div className="w-2 h-2 rounded-full bg-[#10B981] animate-pulse" />
            Pipeline ran in {PIPELINE_STATS.runtimeSeconds}s
          </div>
        </div>
      </header>

      <main className="relative max-w-7xl mx-auto px-6 py-8">
        {/* ── Pipeline Summary ── */}
        <div className="mb-8">
          <h1 className="text-2xl font-bold text-white mb-1">
            Pipeline Results
          </h1>
          <p className="text-sm text-[#94A3B8]">
            Real AWS managed policies + Stratus Red Team attack simulation →
            Graph → Features → Signals
          </p>
        </div>

        {/* ── Stat Cards ── */}
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3 mb-8">
          <StatCard
            icon={Database}
            label="Policies Loaded"
            value={PIPELINE_STATS.policiesLoaded}
            sub="real AWS"
            accent
          />
          <StatCard
            icon={Network}
            label="Graph Nodes"
            value={PIPELINE_STATS.graphNodes}
          />
          <StatCard
            icon={Layers}
            label="Feature Vectors"
            value={PIPELINE_STATS.featureVectors}
            sub="~45 each"
          />
          <StatCard
            icon={Zap}
            label="Escalation Paths"
            value={PIPELINE_STATS.escalationPaths}
            accent
          />
          <StatCard
            icon={Activity}
            label="CloudTrail Events"
            value={PIPELINE_STATS.cloudTrailEvents}
            sub="attack sim"
          />
          <StatCard
            icon={AlertTriangle}
            label="Violations"
            value={PIPELINE_STATS.violationsDetected}
            accent
          />
        </div>

        {/* ── Severity Bar ── */}
        <div className="bg-[#151D2E] border border-[#1E293B] rounded-xl p-5 mb-8">
          <div className="flex items-center justify-between mb-4">
            <span className="text-sm font-semibold text-white">
              Severity Distribution
            </span>
            <span className="text-xs text-[#64748B] font-mono">
              {PIPELINE_STATS.violationsDetected} total signals
            </span>
          </div>

          {/* Bar */}
          <div className="flex h-3 rounded-full overflow-hidden mb-4">
            {SEVERITY_COUNTS.critical > 0 && (
              <div
                className="bg-red-500"
                style={{
                  width: `${(SEVERITY_COUNTS.critical / PIPELINE_STATS.violationsDetected) * 100}%`,
                }}
              />
            )}
            <div
              className="bg-amber-500"
              style={{
                width: `${(SEVERITY_COUNTS.high / PIPELINE_STATS.violationsDetected) * 100}%`,
              }}
            />
            <div
              className="bg-blue-500"
              style={{
                width: `${(SEVERITY_COUNTS.medium / PIPELINE_STATS.violationsDetected) * 100}%`,
              }}
            />
            <div
              className="bg-slate-500"
              style={{
                width: `${(SEVERITY_COUNTS.low / PIPELINE_STATS.violationsDetected) * 100}%`,
              }}
            />
          </div>

          <div className="flex gap-6 text-xs">
            {Object.entries(SEVERITY_COUNTS).map(([sev, count]) => {
              const colors: Record<string, string> = {
                critical: "text-red-400",
                high: "text-amber-400",
                medium: "text-blue-400",
                low: "text-slate-400",
              };
              const dots: Record<string, string> = {
                critical: "bg-red-500",
                high: "bg-amber-500",
                medium: "bg-blue-500",
                low: "bg-slate-500",
              };
              return (
                <div key={sev} className="flex items-center gap-1.5">
                  <div className={`w-2 h-2 rounded-full ${dots[sev]}`} />
                  <span className={colors[sev]}>
                    {sev.charAt(0).toUpperCase() + sev.slice(1)}
                  </span>
                  <span className="text-[#64748B] font-mono">{count}</span>
                </div>
              );
            })}
          </div>
        </div>

        {/* ── Violation Breakdown ── */}
        <div className="bg-[#151D2E] border border-[#1E293B] rounded-xl p-5 mb-8">
          <span className="text-sm font-semibold text-white block mb-4">
            Violation Types Detected
          </span>
          <div className="space-y-3">
            {VIOLATION_BREAKDOWN.map((v) => (
              <div key={v.name} className="flex items-center gap-3">
                <div className="flex-1">
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-sm text-[#94A3B8]">{v.name}</span>
                    <span className="text-xs text-[#64748B] font-mono">
                      {v.count}
                    </span>
                  </div>
                  <div className="h-1.5 bg-[#0A0F1C] rounded-full overflow-hidden">
                    <div
                      className="h-full bg-[#3B82F6] rounded-full transition-all duration-1000"
                      style={{
                        width: `${(v.count / PIPELINE_STATS.violationsDetected) * 100}%`,
                      }}
                    />
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* ── Tabs ── */}
        <div className="flex gap-1 mb-6 bg-[#151D2E] rounded-lg p-1 w-fit border border-[#1E293B]">
          {(
            [
              { key: "signals", label: "Signals", icon: AlertTriangle },
              { key: "cloudtrail", label: "CloudTrail", icon: Activity },
              { key: "data", label: "Data Sources", icon: Database },
            ] as const
          ).map(({ key, label, icon: Icon }) => (
            <button
              key={key}
              onClick={() => setActiveTab(key)}
              className={`flex items-center gap-2 px-4 py-2 rounded-md text-sm font-medium transition-colors ${
                activeTab === key
                  ? "bg-[#3B82F6] text-white"
                  : "text-[#94A3B8] hover:text-white"
              }`}
            >
              <Icon className="w-4 h-4" />
              {label}
            </button>
          ))}
        </div>

        {/* ── Signals Tab ── */}
        {activeTab === "signals" && (
          <div className="space-y-3">
            {TOP_SIGNALS.map((sig) => (
              <div
                key={sig.id}
                onClick={() =>
                  setSelectedSignal(selectedSignal?.id === sig.id ? null : sig)
                }
                className="bg-[#151D2E] border border-[#1E293B] rounded-xl p-5 cursor-pointer hover:border-[#3B82F6]/30 transition-colors"
              >
                <div className="flex items-start justify-between mb-3">
                  <div className="flex items-center gap-3">
                    <SeverityBadge severity={sig.severity} />
                    <span className="text-white font-semibold text-sm">
                      {sig.violation}
                    </span>
                  </div>
                  <span className="text-xs text-[#64748B] font-mono">
                    {Math.round(sig.confidence * 100)}% confidence
                  </span>
                </div>

                <div className="flex items-center gap-4 text-xs text-[#94A3B8]">
                  <span className="flex items-center gap-1">
                    {sig.subjectType === "ai_agent" ? (
                      <Bot className="w-3.5 h-3.5 text-[#2DD4BF]" />
                    ) : sig.subjectType === "service_account" ? (
                      <Terminal className="w-3.5 h-3.5 text-[#F59E0B]" />
                    ) : (
                      <Eye className="w-3.5 h-3.5" />
                    )}
                    {sig.subject}
                  </span>
                  <span className="text-[#64748B]">
                    {sig.subjectType}
                  </span>
                  <span className="text-[#64748B]">{sig.department}</span>
                  <span className="text-[#64748B] font-mono">
                    Rule: {sig.rule}
                  </span>
                </div>

                {/* Expanded evidence */}
                {selectedSignal?.id === sig.id && (
                  <div className="mt-4 pt-4 border-t border-[#1E293B]">
                    <span className="text-xs font-semibold text-[#64748B] uppercase tracking-wider block mb-2">
                      Evidence
                    </span>
                    <div className="space-y-1.5">
                      {Object.entries(sig.evidence).map(([k, v]) => (
                        <div key={k} className="flex gap-2 text-xs">
                          <span className="text-[#3B82F6] font-mono min-w-[140px]">
                            {k}
                          </span>
                          <span className="text-[#94A3B8]">{v}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            ))}
          </div>
        )}

        {/* ── CloudTrail Tab ── */}
        {activeTab === "cloudtrail" && (
          <div className="bg-[#151D2E] border border-[#1E293B] rounded-xl p-6">
            <div className="flex items-center gap-2 mb-6">
              <Activity className="w-5 h-5 text-[#3B82F6]" />
              <span className="text-white font-semibold">
                CloudTrail Activity Analysis
              </span>
            </div>
            <p className="text-xs text-[#64748B] mb-6 font-mono">
              Source: {CLOUDTRAIL_STATS.source}
            </p>

            <div className="grid grid-cols-2 sm:grid-cols-3 gap-4 mb-6">
              {[
                { label: "Total Events", value: CLOUDTRAIL_STATS.totalEvents },
                { label: "Unique Subjects", value: CLOUDTRAIL_STATS.uniqueSubjects },
                { label: "Unique Actions", value: CLOUDTRAIL_STATS.uniqueActions },
                { label: "Privileged Events", value: CLOUDTRAIL_STATS.privilegedEvents },
                { label: "Access Denied", value: CLOUDTRAIL_STATS.errorEvents },
                { label: "Date", value: CLOUDTRAIL_STATS.timeRange },
              ].map((item) => (
                <div key={item.label} className="bg-[#0A0F1C] rounded-lg p-4">
                  <div className="text-xl font-bold text-white font-mono">
                    {typeof item.value === "number"
                      ? item.value.toLocaleString()
                      : item.value}
                  </div>
                  <div className="text-xs text-[#64748B] mt-1">
                    {item.label}
                  </div>
                </div>
              ))}
            </div>

            <div className="bg-[#0A0F1C] rounded-lg p-4 font-mono text-xs text-[#94A3B8] space-y-1">
              <div className="text-[#3B82F6] mb-2">
                # Key findings from Stratus Red Team simulation:
              </div>
              <div>
                <span className="text-amber-400">122</span> privileged API
                calls detected (CreateRole, AttachPolicy, AssumeRole...)
              </div>
              <div>
                <span className="text-red-400">300</span> AccessDenied events
                — enumeration / brute force pattern
              </div>
              <div>
                <span className="text-[#10B981]">15</span> unique actor
                identities across attack timeline
              </div>
              <div>
                <span className="text-[#2DD4BF]">260</span> distinct API
                actions — broad reconnaissance footprint
              </div>
            </div>
          </div>
        )}

        {/* ── Data Sources Tab ── */}
        {activeTab === "data" && (
          <div className="space-y-4">
            {DATA_SOURCES.map((ds) => (
              <div
                key={ds.name}
                className="bg-[#151D2E] border border-[#1E293B] rounded-xl p-5 flex items-center gap-4"
              >
                <div
                  className={`w-2 h-2 rounded-full ${
                    ds.status === "loaded" ? "bg-[#10B981]" : "bg-[#3B82F6]"
                  }`}
                />
                <div className="flex-1">
                  <div className="text-sm text-white font-semibold">
                    {ds.name}
                  </div>
                  <div className="text-xs text-[#94A3B8]">{ds.desc}</div>
                </div>
                <span className="text-xs text-[#64748B] font-mono uppercase">
                  {ds.status}
                </span>
              </div>
            ))}

            <div className="bg-[#151D2E] border border-[#1E293B] rounded-xl p-6 mt-6">
              <span className="text-sm font-semibold text-white block mb-4">
                Pipeline Architecture
              </span>
              <div className="font-mono text-xs text-[#94A3B8] space-y-2">
                <div className="flex items-center gap-2">
                  <ChevronRight className="w-3 h-3 text-[#3B82F6]" />
                  <span>
                    <span className="text-white">LocalFileAdapter</span>{" "}
                    → reads MAMIP policy JSONs → GraphSnapshot
                  </span>
                </div>
                <div className="flex items-center gap-2">
                  <ChevronRight className="w-3 h-3 text-[#3B82F6]" />
                  <span>
                    <span className="text-white">IdentityGraph</span>{" "}
                    → NetworkX (1,566 nodes, 63 edges)
                  </span>
                </div>
                <div className="flex items-center gap-2">
                  <ChevronRight className="w-3 h-3 text-[#3B82F6]" />
                  <span>
                    <span className="text-white">FeatureComputer</span>{" "}
                    → ~45 features per entity (centrality, peer ratio,
                    drift...)
                  </span>
                </div>
                <div className="flex items-center gap-2">
                  <ChevronRight className="w-3 h-3 text-[#3B82F6]" />
                  <span>
                    <span className="text-white">BootstrapLabeler</span>{" "}
                    → 15 violation classes → 139 signals
                  </span>
                </div>
                <div className="flex items-center gap-2">
                  <ChevronRight className="w-3 h-3 text-[#3B82F6]" />
                  <span>
                    <span className="text-white">
                      LocalCloudTrailIngester
                    </span>{" "}
                    → 2,900 Stratus attack events → behavioral features
                  </span>
                </div>
              </div>

              <div className="mt-6 pt-4 border-t border-[#1E293B] text-xs text-[#64748B]">
                <span className="text-[#10B981] font-semibold">Zero changes</span>{" "}
                to existing backend code. The LocalFileAdapter produces the
                same GraphSnapshot the live AWS adapter would. Swap the adapter
                → same models, same signals.
              </div>
            </div>
          </div>
        )}

        {/* ── Footer ── */}
        <div className="mt-12 pt-8 border-t border-[#1E293B] flex flex-col sm:flex-row items-center justify-between gap-4 text-xs text-[#64748B]">
          <span>
            © 2026 Vektor AI — All data is from open-source, publicly
            available datasets
          </span>
          <a
            href="https://github.com/venkat15vk/vektor"
            target="_blank"
            rel="noopener noreferrer"
            className="hover:text-white transition-colors font-mono"
          >
            github.com/venkat15vk/vektor
          </a>
        </div>
      </main>
    </div>
  );
}

/* ────────────────────────────────────────────
   PAGE EXPORT
   ──────────────────────────────────────────── */

export default function DemoPage() {
  const [unlocked, setUnlocked] = useState(false);

  // Persist unlock state in sessionStorage so refresh doesn't re-prompt
  useEffect(() => {
    if (typeof window !== "undefined" && sessionStorage.getItem("vektor-demo-unlocked") === "1") {
      setUnlocked(true);
    }
  }, []);

  const handleUnlock = () => {
    setUnlocked(true);
    if (typeof window !== "undefined") {
      sessionStorage.setItem("vektor-demo-unlocked", "1");
    }
  };

  if (!unlocked) {
    return <PasswordGate onUnlock={handleUnlock} />;
  }
  return <DemoDashboard />;
}
