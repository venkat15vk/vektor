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
  KeyRound,
  BookOpen,
  Users,
  Sparkles,
  PlayCircle,
  Ban,
  CheckCircle2,
  Loader2,
  ChevronDown,
  ChevronUp,
  Fingerprint,
  CircleDot,
} from "lucide-react";

/* ────────────────────────────────────────────
   DEMO DATA — Real pipeline output (multi-system)
   ──────────────────────────────────────────── */

const PIPELINE_STATS = {
  policiesLoaded: 1537,
  policiesPrivileged: 587,
  subjectsAnalyzed: 34,
  assignments: 112,
  graphNodes: 1638,
  graphEdges: 112,
  featureVectors: 34,
  escalationPaths: 7,
  cloudTrailEvents: 2900,
  violationsDetected: 187,
  runtimeSeconds: 2.41,
  systems: 3,
};

const SEVERITY_COUNTS = {
  critical: 4,
  high: 28,
  medium: 78,
  low: 77,
};

const VIOLATION_BREAKDOWN = [
  { name: "Shadow Admin", count: 105 },
  { name: "SoD Violation (ERP)", count: 24 },
  { name: "Agent Scope Drift", count: 17 },
  { name: "Orphan Account", count: 12 },
  { name: "Excessive Privilege (IdP)", count: 11 },
  { name: "Missing MFA", count: 8 },
  { name: "Stale / Dormant Account", count: 4 },
  { name: "Cross-Boundary Overreach", count: 6 },
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
  source: "aws_iam" | "netsuite" | "okta";
  evidence: Record<string, string>;
};

const TOP_SIGNALS: Signal[] = [
  // ── NetSuite SoD Violations ──
  {
    id: 1,
    severity: "critical",
    confidence: 0.98,
    subject: "maria.gonzalez",
    subjectType: "human",
    department: "Accounts Payable",
    violation: "SoD Violation (ERP)",
    rule: "SOD-NS-R1-VENDOR-PAY",
    source: "netsuite",
    evidence: {
      sod_conflict: "Vendor Master Edit + Pay Bills — can create a fake vendor and issue payment",
      roles_held: "Vendor Manager, A/P Specialist",
      netsuite_permissions: "Vendors (Full), Pay Bills (Full), Check (Full)",
      sox_control: "ITGC-AP-03 — Vendor creation must be segregated from payment processing",
      risk: "Unauthorized vendor fraud — create fake vendor, submit invoice, approve payment",
    },
  },
  {
    id: 2,
    severity: "critical",
    confidence: 0.97,
    subject: "kevin.liu",
    subjectType: "human",
    department: "Accounting",
    violation: "SoD Violation (ERP)",
    rule: "SOD-NS-R2-JE-APPROVE",
    source: "netsuite",
    evidence: {
      sod_conflict: "Make Journal Entry + Journal Approval — can create and self-approve journal entries",
      roles_held: "Accounting Manager (custom)",
      netsuite_permissions: "Make Journal Entry (Full), Approve Journal (Full)",
      sox_control: "ITGC-GL-01 — Journal entry preparation must be segregated from approval",
      risk: "Undetected adjustments to general ledger — revenue manipulation, expense concealment",
    },
  },
  {
    id: 3,
    severity: "critical",
    confidence: 0.96,
    subject: "agent-erp-reconciler",
    subjectType: "ai_agent",
    department: "Finance Automation",
    violation: "Cross-Boundary Overreach",
    rule: "AGT-NS-R1-CROSSMOD",
    source: "netsuite",
    evidence: {
      modules_accessed: "Accounts Payable, General Ledger, Procurement",
      netsuite_permissions: "Vendor (Full), Pay Bills (Full), Make Journal Entry (Full), Purchase Order (Full)",
      sod_violations: "3 — spans vendor creation, payment, and GL posting",
      risk: "AI agent can execute complete fraud cycle: create vendor → submit PO → approve payment → post journal entry",
    },
  },
  {
    id: 4,
    severity: "high",
    confidence: 0.95,
    subject: "priya.sharma",
    subjectType: "human",
    department: "Finance",
    violation: "SoD Violation (ERP)",
    rule: "SOD-NS-R3-CREDITMEMO",
    source: "netsuite",
    evidence: {
      sod_conflict: "Credit Memo + Customer Record Edit — can create fictitious customers and issue credit memos",
      roles_held: "AR Specialist, Customer Service Rep",
      netsuite_permissions: "Credit Memo (Full), Customer (Full)",
      risk: "Revenue fraud — create unauthorized customer, issue credit memo to clear receivable",
    },
  },
  // ── Okta Misconfigurations ──
  {
    id: 5,
    severity: "critical",
    confidence: 0.99,
    subject: "admin@corp.okta.com",
    subjectType: "human",
    department: "IT",
    violation: "Excessive Privilege (IdP)",
    rule: "OKTA-R1-SUPERADMIN-MFA",
    source: "okta",
    evidence: {
      role: "Super Administrator",
      mfa_status: "SMS only — not phishing-resistant",
      recommendation: "Require FIDO2/WebAuthn for all Super Admin accounts",
      risk: "Super Admin with weak MFA — session hijack or phishing could compromise entire Okta tenant",
    },
  },
  {
    id: 6,
    severity: "high",
    confidence: 0.95,
    subject: "svc-okta-scim-sync",
    subjectType: "service_account",
    department: "IT Automation",
    violation: "Excessive Privilege (IdP)",
    rule: "OKTA-R2-SVCACCT-ADMIN",
    source: "okta",
    evidence: {
      role: "Organization Administrator",
      mfa_enabled: "false — service account, no MFA enforced",
      last_credential_rotation: "never",
      api_token_age: "347 days",
      risk: "Overprivileged service account with stale API token — identical pattern to 2023 Okta breach",
    },
  },
  {
    id: 7,
    severity: "high",
    confidence: 0.93,
    subject: "derek.thompson",
    subjectType: "human",
    department: "IT",
    violation: "Stale / Dormant Account",
    rule: "OKTA-R3-DORMANT-ADMIN",
    source: "okta",
    evidence: {
      role: "Super Administrator",
      last_login: "183 days ago",
      status: "Active — never deactivated after role change",
      risk: "Dormant Super Admin account — prime target for credential stuffing or session hijack",
    },
  },
  {
    id: 8,
    severity: "high",
    confidence: 0.92,
    subject: "okta-tenant",
    subjectType: "service_account",
    department: "IT",
    violation: "Missing MFA",
    rule: "OKTA-R4-GLOBAL-POLICY",
    source: "okta",
    evidence: {
      finding: "Global Session Policy allows 30-day session lifetime for admin console",
      superadmin_count: "8 (recommended: ≤5)",
      threat_insight: "disabled",
      risk: "Overly permissive session policy + excessive Super Admins + no ThreatInsight — high tenant takeover risk",
    },
  },
  // ── AWS IAM (existing) ──
  {
    id: 9,
    severity: "high",
    confidence: 0.95,
    subject: "jack.brown",
    subjectType: "human",
    department: "Engineering",
    violation: "Shadow Admin",
    rule: "ESC-R1",
    source: "aws_iam",
    evidence: {
      end_result: "Can pass a high-privilege role to a Lambda and execute it",
      steps: "2-step escalation chain: iam:PassRole → lambda:CreateFunction",
    },
  },
  {
    id: 10,
    severity: "high",
    confidence: 0.95,
    subject: "jack.brown",
    subjectType: "human",
    department: "Engineering",
    violation: "Missing MFA",
    rule: "MFA-R1-PRIV",
    source: "aws_iam",
    evidence: {
      mfa_enabled: "false",
      privileged_permissions: "5 privileged policies attached",
    },
  },
  {
    id: 11,
    severity: "high",
    confidence: 0.95,
    subject: "svc-lambda-exec",
    subjectType: "service_account",
    department: "Platform",
    violation: "Shadow Admin",
    rule: "ESC-R1",
    source: "aws_iam",
    evidence: {
      end_result: "Can pass a high-privilege role to a Lambda and execute it",
      steps: "2-step escalation chain",
    },
  },
  {
    id: 12,
    severity: "high",
    confidence: 0.9,
    subject: "agent-cost-optimizer",
    subjectType: "ai_agent",
    department: "Platform",
    violation: "Agent Scope Drift",
    rule: "TRC-R1-SECFIN",
    source: "aws_iam",
    evidence: {
      has_security_admin: "true",
      has_financial_admin: "true — AI agent crosses security/financial boundary",
    },
  },
  {
    id: 13,
    severity: "medium",
    confidence: 0.8,
    subject: "bob.chen",
    subjectType: "human",
    department: "DevOps",
    violation: "Agent Scope Drift",
    rule: "TRC-R1-MULTI",
    source: "aws_iam",
    evidence: {
      privileged_role_count: "6 privileged roles",
      categories: "financial, identity, infrastructure, security",
    },
  },
  {
    id: 14,
    severity: "medium",
    confidence: 0.8,
    subject: "eve.wilson",
    subjectType: "human",
    department: "Data Science",
    violation: "Orphan Account",
    rule: "EP-R1-HIGH",
    source: "aws_iam",
    evidence: {
      ratio: "4.00x peer median",
      total_permissions: "4 (all privileged — SageMaker, S3, Athena, Glue)",
    },
  },
  // ── Cross-boundary: NetSuite ↔ AWS ──
  {
    id: 15,
    severity: "high",
    confidence: 0.91,
    subject: "svc-erp-integration",
    subjectType: "service_account",
    department: "Platform",
    violation: "Cross-Boundary Overreach",
    rule: "XB-R1-IAM-ERP",
    source: "aws_iam",
    evidence: {
      aws_permissions: "AdministratorAccess (full)",
      netsuite_permissions: "Administrator role — full access to all modules",
      cross_system: "Single service account spans AWS infrastructure + NetSuite financial data",
      risk: "Compromise of this account grants both infrastructure control and financial system access",
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
  { name: "MAMIP", desc: "1,549 real AWS managed IAM policies (JSON)", status: "loaded", system: "AWS IAM" },
  { name: "Invictus IR", desc: "2,900 CloudTrail events — Stratus Red Team attacks", status: "loaded", system: "AWS IAM" },
  { name: "iann0036 IAM Dataset", desc: "Risk flags: privesc, resource exposure, credentials", status: "indexed", system: "AWS IAM" },
  { name: "NetSuite Role Export", desc: "636 permissions across 4,923 tasks — SoD conflict matrix applied", status: "loaded", system: "NetSuite" },
  { name: "NetSuite SoD Rules", desc: "4 core SoD rules: Vendor/Pay, JE/Approve, CreditMemo/Customer, Check/Vendor", status: "loaded", system: "NetSuite" },
  { name: "Okta Tenant Config", desc: "Admin roles, MFA policies, session settings, ThreatInsight status", status: "loaded", system: "Okta" },
  { name: "Okta System Log", desc: "Auth events, admin actions, privilege changes — 90-day window", status: "loaded", system: "Okta" },
];

/* ────────────────────────────────────────────
   FEATURE VECTORS (from backend/features/compute.py)
   ──────────────────────────────────────────── */

const FEATURE_CATEGORIES = {
  subject: {
    label: "Subject Features",
    desc: "~28 features per identity",
    features: [
      { name: "total_permissions", desc: "Count of all attached permissions" },
      { name: "privileged_permissions", desc: "Count of high-risk permissions" },
      { name: "unique_actions", desc: "Distinct API actions accessible" },
      { name: "unique_resources_reachable", desc: "Resources reachable via graph traversal" },
      { name: "permission_to_peer_median_ratio", desc: "Permissions vs. peer group median" },
      { name: "permission_concentration", desc: "HHI concentration index" },
      { name: "account_age_days", desc: "Days since identity creation" },
      { name: "source_system_count", desc: "Number of systems this identity exists in" },
      { name: "days_since_last_activity", desc: "Staleness indicator" },
      { name: "avg_daily_api_calls_30d", desc: "API usage intensity" },
      { name: "usage_ratio", desc: "Permissions used / permissions granted" },
      { name: "login_time_entropy", desc: "Login time variability" },
      { name: "distinct_source_ips_30d", desc: "Source IP diversity (30 days)" },
      { name: "mfa_usage_rate", desc: "Fraction of logins with MFA" },
      { name: "degree_centrality", desc: "Graph node connectivity" },
      { name: "betweenness_centrality", desc: "Graph bridging position" },
      { name: "escalation_paths_through_identity", desc: "Privilege escalation chains involving this identity" },
      { name: "peer_group_cosine_similarity", desc: "Similarity to peer group profile" },
      { name: "permissions_added_7d", desc: "New permissions (7-day window)" },
      { name: "permissions_added_30d", desc: "New permissions (30-day window)" },
      { name: "net_drift_rate", desc: "Net permission change velocity" },
      { name: "days_since_last_access_review", desc: "Days since last review cycle" },
    ],
  },
  permission: {
    label: "Permission Features",
    desc: "~10 features per permission",
    features: [
      { name: "total_actions", desc: "Actions granted by this permission" },
      { name: "high_risk_action_count", desc: "Count of sensitive/destructive actions" },
      { name: "wildcard_presence", desc: "Contains wildcard (*) grants" },
      { name: "resource_scope_breadth", desc: "Number of distinct resource types" },
      { name: "holder_count", desc: "Identities holding this permission" },
      { name: "average_usage_rate_across_holders", desc: "Mean usage rate" },
      { name: "is_privileged", desc: "Classified as privileged" },
      { name: "risk_keyword_count", desc: "IAM, Admin, Root keywords" },
      { name: "escalation_chain_participation_count", desc: "Appears in N escalation chains" },
    ],
  },
  assignment: {
    label: "Assignment Features",
    desc: "~5 features per assignment",
    features: [
      { name: "assignment_age_days", desc: "How long this assignment has existed" },
      { name: "days_since_last_used", desc: "Staleness of the assignment" },
      { name: "granted_by_type", desc: "Direct, inherited, or assumed" },
      { name: "has_business_justification", desc: "Justification recorded" },
      { name: "is_sod_pair_member", desc: "Part of a Separation of Duties conflict" },
    ],
  },
  relationship: {
    label: "Relationship Features",
    desc: "~3 cross-system features",
    features: [
      { name: "cross_system_consistency_score", desc: "Permission alignment across systems" },
      { name: "sod_pair_membership_count", desc: "Number of SoD conflicts involving this identity" },
      { name: "peer_group_deviation_score", desc: "Deviation from peer group norms" },
    ],
  },
};

/* ────────────────────────────────────────────
   RECOMMENDED POLICIES (derived from detected signals)
   ──────────────────────────────────────────── */

type PolicyStatus = "suggested" | "approved" | "training" | "active" | "rejected";

type RecommendedPolicy = {
  id: string;
  name: string;
  description: string;
  category: string;
  severity: "critical" | "high" | "medium";
  sources: ("aws_iam" | "netsuite" | "okta")[];
  triggeringSignalIds: number[];
  triggeringSummary: string;
  violationCount: number;
  featureKeys: string[]; // keys from FEATURE_CATEGORIES
  sox_control?: string;
  lifecycle: string;
};

const RECOMMENDED_POLICIES: RecommendedPolicy[] = [
  {
    id: "POL-T2-001",
    name: "Enforce JE/Approval Separation",
    description: "Users with Make Journal Entry permission must not hold Journal Approval. Detects both direct role assignment and inherited permission conflicts.",
    category: "SOX Compliance",
    severity: "critical",
    sources: ["netsuite"],
    triggeringSignalIds: [2],
    triggeringSummary: "13 users can create AND approve journal entries — GL manipulation risk",
    violationCount: 13,
    featureKeys: ["total_permissions", "privileged_permissions", "is_sod_pair_member", "sod_pair_membership_count", "permission_concentration", "has_business_justification", "peer_group_cosine_similarity"],
    sox_control: "ITGC-GL-01",
    lifecycle: "Suggested → Approved → Active → Graduated",
  },
  {
    id: "POL-T2-002",
    name: "Restrict Vendor + Payment Role Combinations",
    description: "Identities must not hold both vendor creation/edit and payment processing permissions. Prevents fictitious vendor fraud cycle.",
    category: "SOX Compliance",
    severity: "critical",
    sources: ["netsuite"],
    triggeringSignalIds: [1],
    triggeringSummary: "17 users can create vendors AND process payments — AP fraud risk",
    violationCount: 17,
    featureKeys: ["total_permissions", "privileged_permissions", "is_sod_pair_member", "sod_pair_membership_count", "unique_actions", "cross_system_consistency_score", "assignment_age_days"],
    sox_control: "ITGC-AP-03",
    lifecycle: "Suggested → Approved → Active → Graduated",
  },
  {
    id: "POL-T2-003",
    name: "Require Phishing-Resistant MFA for SuperAdmins",
    description: "All Super Administrator accounts must use FIDO2/WebAuthn. SMS and email OTP are insufficient for tenant-level admin access.",
    category: "Zero Trust",
    severity: "critical",
    sources: ["okta"],
    triggeringSignalIds: [5],
    triggeringSummary: "4 SuperAdmins using SMS/email MFA — phishing-vulnerable",
    violationCount: 4,
    featureKeys: ["mfa_usage_rate", "privileged_permissions", "degree_centrality", "source_system_count", "days_since_last_activity", "login_time_entropy", "distinct_source_ips_30d"],
    lifecycle: "Suggested → Approved → Active → Graduated",
  },
  {
    id: "POL-T2-004",
    name: "Rotate Okta API Tokens ≤ 90 Days",
    description: "Service account API tokens must be rotated within 90 days. Stale tokens are the #1 vector in IdP breaches.",
    category: "Zero Trust",
    severity: "high",
    sources: ["okta"],
    triggeringSignalIds: [6],
    triggeringSummary: "Service account svc-okta-scim-sync has a 347-day-old API token",
    violationCount: 1,
    featureKeys: ["days_since_last_activity", "assignment_age_days", "days_since_last_used", "privileged_permissions", "usage_ratio", "escalation_chain_participation_count"],
    lifecycle: "Suggested → Approved → Active → Graduated",
  },
  {
    id: "POL-T2-005",
    name: "Deactivate Dormant Admin Accounts",
    description: "Administrator accounts inactive for >90 days must be auto-deactivated. Dormant privileged accounts are prime targets for credential stuffing.",
    category: "Zero Trust",
    severity: "high",
    sources: ["okta"],
    triggeringSignalIds: [7],
    triggeringSummary: "SuperAdmin derek.thompson inactive for 183 days — still active",
    violationCount: 1,
    featureKeys: ["days_since_last_activity", "account_age_days", "avg_daily_api_calls_30d", "usage_ratio", "mfa_usage_rate", "peer_group_cosine_similarity", "days_since_last_access_review"],
    lifecycle: "Suggested → Approved → Active → Graduated",
  },
  {
    id: "POL-T2-006",
    name: "Limit Cross-Boundary Service Account Scope",
    description: "Service accounts must not span both infrastructure (AWS) and financial (NetSuite) systems with admin-level access. Compromise = full blast radius.",
    category: "Cross-Boundary",
    severity: "critical",
    sources: ["aws_iam", "netsuite"],
    triggeringSignalIds: [3, 15],
    triggeringSummary: "2 service accounts span AWS + NetSuite with admin access",
    violationCount: 2,
    featureKeys: ["source_system_count", "cross_system_consistency_score", "unique_resources_reachable", "betweenness_centrality", "escalation_paths_through_identity", "privileged_permissions", "resource_scope_breadth"],
    lifecycle: "Suggested → Approved → Active → Graduated",
  },
  {
    id: "POL-T2-007",
    name: "Cap SuperAdmin Count at 5",
    description: "Okta tenants should have ≤5 Super Administrators. Excess SuperAdmins expand the attack surface and violate least-privilege.",
    category: "Zero Trust",
    severity: "high",
    sources: ["okta"],
    triggeringSignalIds: [8],
    triggeringSummary: "Tenant has 8 SuperAdmins (recommended: ≤5) with weak session policy",
    violationCount: 3,
    featureKeys: ["holder_count", "privileged_permissions", "degree_centrality", "betweenness_centrality", "total_actions", "is_privileged"],
    lifecycle: "Suggested → Approved → Active → Graduated",
  },
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
            <img src="/vektor-logo.png" alt="Vektor" className="h-10 w-auto" />
            <span className="text-2xl font-bold tracking-tight text-white">
              vektor
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
   SOURCE BADGE
   ──────────────────────────────────────────── */

function SourceBadge({ source }: { source: string }) {
  const config: Record<string, { label: string; color: string; icon: React.ElementType }> = {
    aws_iam: { label: "AWS IAM", color: "bg-amber-500/10 text-amber-400 border-amber-500/20", icon: Shield },
    netsuite: { label: "NetSuite", color: "bg-purple-500/10 text-purple-400 border-purple-500/20", icon: BookOpen },
    okta: { label: "Okta", color: "bg-cyan-500/10 text-cyan-400 border-cyan-500/20", icon: KeyRound },
  };
  const c = config[source] || config.aws_iam;
  const Icon = c.icon;
  return (
    <span className={`inline-flex items-center gap-1 px-2 py-0.5 text-[10px] font-mono font-medium rounded border ${c.color}`}>
      <Icon className="w-3 h-3" />
      {c.label}
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
  const [activeTab, setActiveTab] = useState<"signals" | "policies" | "cloudtrail" | "data">("signals");
  const [sourceFilter, setSourceFilter] = useState<"all" | "aws_iam" | "netsuite" | "okta">("all");
  const [policyStates, setPolicyStates] = useState<Record<string, PolicyStatus>>({});
  const [expandedPolicy, setExpandedPolicy] = useState<string | null>(null);
  const [trainingPolicy, setTrainingPolicy] = useState<string | null>(null);

  const filteredSignals = sourceFilter === "all"
    ? TOP_SIGNALS
    : TOP_SIGNALS.filter((s) => s.source === sourceFilter);

  const activePolicies = RECOMMENDED_POLICIES.filter((p) => policyStates[p.id] === "active");
  const suggestedPolicies = RECOMMENDED_POLICIES.filter((p) => !policyStates[p.id] || policyStates[p.id] === "suggested");
  const rejectedPolicies = RECOMMENDED_POLICIES.filter((p) => policyStates[p.id] === "rejected");

  const handleApprove = (policyId: string) => {
    setPolicyStates((prev) => ({ ...prev, [policyId]: "training" }));
    setTrainingPolicy(policyId);
    // Simulate model training
    setTimeout(() => {
      setPolicyStates((prev) => ({ ...prev, [policyId]: "active" }));
      setTrainingPolicy(null);
    }, 2200);
  };

  const handleReject = (policyId: string) => {
    setPolicyStates((prev) => ({ ...prev, [policyId]: "rejected" }));
  };

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
              <img src="/vektor-logo.png" alt="Vektor" className="h-6 w-auto" />
              <span className="text-lg font-bold text-white tracking-tight">
                vektor
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
            AWS IAM + NetSuite ERP + Okta IdP → Unified Identity Graph → Features → ML Signals
          </p>
        </div>

        {/* ── Connected Systems ── */}
        <div className="grid grid-cols-3 gap-3 mb-6">
          {[
            { name: "AWS IAM", desc: "1,537 policies · CloudTrail events", color: "border-amber-500/30", dot: "bg-amber-400" },
            { name: "NetSuite", desc: "636 permissions · SoD conflict matrix", color: "border-purple-500/30", dot: "bg-purple-400" },
            { name: "Okta", desc: "Admin roles · MFA policies · System Log", color: "border-cyan-500/30", dot: "bg-cyan-400" },
          ].map((sys) => (
            <div key={sys.name} className={`bg-[#151D2E] border ${sys.color} rounded-xl p-4 flex items-center gap-3`}>
              <div className={`w-2.5 h-2.5 rounded-full ${sys.dot} animate-pulse`} />
              <div>
                <div className="text-sm font-semibold text-white">{sys.name}</div>
                <div className="text-[11px] text-[#64748B]">{sys.desc}</div>
              </div>
            </div>
          ))}
        </div>

        {/* ── Stat Cards ── */}
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3 mb-8">
          <StatCard
            icon={Layers}
            label="Systems Connected"
            value={PIPELINE_STATS.systems}
            sub="unified"
            accent
          />
          <StatCard
            icon={Users}
            label="Subjects Analyzed"
            value={PIPELINE_STATS.subjectsAnalyzed}
            sub="cross-system"
          />
          <StatCard
            icon={Network}
            label="Graph Nodes"
            value={PIPELINE_STATS.graphNodes}
          />
          <StatCard
            icon={Database}
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
              { key: "policies", label: "Policies", icon: Sparkles },
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
            {/* Source filter */}
            <div className="flex gap-2 mb-4">
              {(
                [
                  { key: "all", label: "All Systems" },
                  { key: "aws_iam", label: "AWS IAM" },
                  { key: "netsuite", label: "NetSuite" },
                  { key: "okta", label: "Okta" },
                ] as const
              ).map(({ key, label }) => (
                <button
                  key={key}
                  onClick={() => setSourceFilter(key)}
                  className={`px-3 py-1.5 rounded-md text-xs font-medium transition-colors ${
                    sourceFilter === key
                      ? "bg-[#3B82F6]/20 text-[#3B82F6] border border-[#3B82F6]/30"
                      : "text-[#64748B] border border-[#1E293B] hover:text-[#94A3B8]"
                  }`}
                >
                  {label}
                  <span className="ml-1 font-mono">
                    {key === "all"
                      ? TOP_SIGNALS.length
                      : TOP_SIGNALS.filter((s) => s.source === key).length}
                  </span>
                </button>
              ))}
            </div>

            {filteredSignals.map((sig) => (
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
                  <div className="flex items-center gap-3">
                    <SourceBadge source={sig.source} />
                    <span className="text-xs text-[#64748B] font-mono">
                      {Math.round(sig.confidence * 100)}%
                    </span>
                  </div>
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

        {/* ── Policies Tab ── */}
        {activeTab === "policies" && (
          <div className="space-y-6">

            {/* ── Active Policies ── */}
            {activePolicies.length > 0 && (
              <div>
                <div className="flex items-center gap-2 mb-3">
                  <div className="w-2 h-2 rounded-full bg-[#10B981] animate-pulse" />
                  <span className="text-xs font-semibold text-[#10B981] uppercase tracking-wider">Active Policies</span>
                  <span className="text-xs text-[#64748B] font-mono">({activePolicies.length})</span>
                </div>
                <div className="space-y-3">
                  {activePolicies.map((policy) => (
                    <div key={policy.id} className="bg-[#151D2E] border border-[#10B981]/30 rounded-xl overflow-hidden">
                      <div className="p-5">
                        <div className="flex items-start justify-between mb-3">
                          <div className="flex items-center gap-3">
                            <span className="inline-flex px-2.5 py-0.5 text-xs font-mono font-semibold rounded border bg-[#10B981]/15 text-[#10B981] border-[#10B981]/30">
                              ACTIVE
                            </span>
                            <span className="text-white font-semibold text-sm">{policy.name}</span>
                          </div>
                          <div className="flex items-center gap-2">
                            {policy.sources.map((s) => <SourceBadge key={s} source={s} />)}
                          </div>
                        </div>

                        <p className="text-xs text-[#94A3B8] mb-3">{policy.description}</p>

                        <div className="flex items-center gap-4 text-xs">
                          <span className="flex items-center gap-1.5 text-[#10B981] font-mono">
                            <CheckCircle2 className="w-3.5 h-3.5" />
                            {policy.violationCount} violations detected
                          </span>
                          <span className="text-[#64748B] font-mono">{policy.id}</span>
                          {policy.sox_control && (
                            <span className="text-[#3B82F6] font-mono">{policy.sox_control}</span>
                          )}
                        </div>

                        {/* Feature vector preview */}
                        <button
                          onClick={() => setExpandedPolicy(expandedPolicy === policy.id ? null : policy.id)}
                          className="mt-3 flex items-center gap-1 text-xs text-[#64748B] hover:text-[#94A3B8] transition-colors"
                        >
                          <Fingerprint className="w-3 h-3" />
                          Model features ({policy.featureKeys.length})
                          {expandedPolicy === policy.id ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
                        </button>

                        {expandedPolicy === policy.id && (
                          <div className="mt-3 pt-3 border-t border-[#1E293B]">
                            <div className="text-[10px] text-[#64748B] uppercase tracking-wider mb-2">Feature vectors used by Tier 2 model</div>
                            <div className="grid grid-cols-2 sm:grid-cols-3 gap-1.5">
                              {policy.featureKeys.map((fk) => {
                                const allFeatures = [
                                  ...FEATURE_CATEGORIES.subject.features,
                                  ...FEATURE_CATEGORIES.permission.features,
                                  ...FEATURE_CATEGORIES.assignment.features,
                                  ...FEATURE_CATEGORIES.relationship.features,
                                ];
                                const feat = allFeatures.find((f) => f.name === fk);
                                return (
                                  <div key={fk} className="bg-[#0A0F1C] rounded-md px-2.5 py-1.5 border border-[#10B981]/15">
                                    <div className="text-[11px] text-[#10B981] font-mono">{fk}</div>
                                    {feat && <div className="text-[10px] text-[#64748B] mt-0.5">{feat.desc}</div>}
                                  </div>
                                );
                              })}
                            </div>
                          </div>
                        )}
                      </div>

                      {/* Active policy bottom bar */}
                      <div className="bg-[#10B981]/5 border-t border-[#10B981]/20 px-5 py-2.5 flex items-center justify-between">
                        <span className="text-[10px] text-[#10B981]/70 font-mono">
                          Lifecycle: Suggested → Approved → <span className="text-[#10B981] font-semibold">Active</span> → Graduated
                        </span>
                        <span className="text-[10px] text-[#10B981]/70 font-mono">
                          Tier 2 ML model running
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* ── Suggested Policies ── */}
            {suggestedPolicies.length > 0 && (
              <div>
                <div className="flex items-center gap-2 mb-3">
                  <Sparkles className="w-4 h-4 text-[#3B82F6]" />
                  <span className="text-xs font-semibold text-[#94A3B8] uppercase tracking-wider">Recommended Policies</span>
                  <span className="text-xs text-[#64748B] font-mono">({suggestedPolicies.length})</span>
                </div>
                <p className="text-xs text-[#64748B] mb-4">
                  Vektor analyzed {PIPELINE_STATS.violationsDetected} signals across {PIPELINE_STATS.systems} systems and recommends these Tier 2 policies.
                  Approve to create a scoped ML model. Reject to deprioritize similar suggestions.
                </p>
                <div className="space-y-3">
                  {suggestedPolicies.map((policy) => {
                    const isTraining = trainingPolicy === policy.id;
                    return (
                      <div key={policy.id} className="bg-[#151D2E] border border-[#1E293B] rounded-xl overflow-hidden hover:border-[#3B82F6]/20 transition-colors">
                        <div className="p-5">
                          <div className="flex items-start justify-between mb-3">
                            <div className="flex items-center gap-3">
                              <SeverityBadge severity={policy.severity} />
                              <span className="text-white font-semibold text-sm">{policy.name}</span>
                            </div>
                            <div className="flex items-center gap-2">
                              {policy.sources.map((s) => <SourceBadge key={s} source={s} />)}
                            </div>
                          </div>

                          <p className="text-xs text-[#94A3B8] mb-3">{policy.description}</p>

                          {/* Triggering signal summary */}
                          <div className="bg-[#0A0F1C] rounded-lg p-3 mb-3 border border-[#1E293B]/50">
                            <div className="text-[10px] text-[#64748B] uppercase tracking-wider mb-1">Triggering signals</div>
                            <div className="text-xs text-[#94A3B8]">{policy.triggeringSummary}</div>
                            <div className="flex items-center gap-3 mt-2">
                              <span className="text-xs text-[#3B82F6] font-mono">
                                {policy.violationCount} violation{policy.violationCount !== 1 ? "s" : ""}
                              </span>
                              <span className="text-xs text-[#64748B] font-mono">{policy.category}</span>
                              {policy.sox_control && (
                                <span className="text-xs text-amber-400/70 font-mono">{policy.sox_control}</span>
                              )}
                            </div>
                          </div>

                          {/* Feature vector preview */}
                          <button
                            onClick={() => setExpandedPolicy(expandedPolicy === policy.id ? null : policy.id)}
                            className="flex items-center gap-1 text-xs text-[#64748B] hover:text-[#94A3B8] transition-colors mb-3"
                          >
                            <Fingerprint className="w-3 h-3" />
                            Preview model features ({policy.featureKeys.length})
                            {expandedPolicy === policy.id ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
                          </button>

                          {expandedPolicy === policy.id && (
                            <div className="mb-3 pt-2 pb-1">
                              <div className="text-[10px] text-[#64748B] uppercase tracking-wider mb-2">
                                Feature vectors the Tier 2 model will learn from
                              </div>
                              <div className="grid grid-cols-2 sm:grid-cols-3 gap-1.5 mb-2">
                                {policy.featureKeys.map((fk) => {
                                  const allFeatures = [
                                    ...FEATURE_CATEGORIES.subject.features,
                                    ...FEATURE_CATEGORIES.permission.features,
                                    ...FEATURE_CATEGORIES.assignment.features,
                                    ...FEATURE_CATEGORIES.relationship.features,
                                  ];
                                  const feat = allFeatures.find((f) => f.name === fk);
                                  return (
                                    <div key={fk} className="bg-[#0A0F1C] rounded-md px-2.5 py-1.5 border border-[#1E293B]">
                                      <div className="text-[11px] text-[#3B82F6] font-mono">{fk}</div>
                                      {feat && <div className="text-[10px] text-[#64748B] mt-0.5">{feat.desc}</div>}
                                    </div>
                                  );
                                })}
                              </div>
                              <div className="text-[10px] text-[#64748B] italic">
                                These {policy.featureKeys.length} features (from ~45 total) are selected based on the violation type and source system.
                              </div>
                            </div>
                          )}

                          {/* Training animation */}
                          {isTraining && (
                            <div className="bg-[#3B82F6]/5 border border-[#3B82F6]/20 rounded-lg p-3 mb-3">
                              <div className="flex items-center gap-2 mb-2">
                                <Loader2 className="w-4 h-4 text-[#3B82F6] animate-spin" />
                                <span className="text-xs text-[#3B82F6] font-semibold">Creating Tier 2 ML model...</span>
                              </div>
                              <div className="space-y-1.5 font-mono text-[11px] text-[#64748B]">
                                <div className="flex items-center gap-2">
                                  <Check className="w-3 h-3 text-[#10B981]" />
                                  <span>Feature vectors extracted ({policy.featureKeys.length} features)</span>
                                </div>
                                <div className="flex items-center gap-2">
                                  <Check className="w-3 h-3 text-[#10B981]" />
                                  <span>Policy rule compiled → model scope defined</span>
                                </div>
                                <div className="flex items-center gap-2">
                                  <Loader2 className="w-3 h-3 text-[#3B82F6] animate-spin" />
                                  <span className="text-[#3B82F6]">Training on labeled violations...</span>
                                </div>
                              </div>
                              {/* Progress bar */}
                              <div className="mt-2 h-1 bg-[#0A0F1C] rounded-full overflow-hidden">
                                <div className="h-full bg-[#3B82F6] rounded-full animate-pulse" style={{ width: "65%", transition: "width 2s ease-out" }} />
                              </div>
                            </div>
                          )}

                          {/* Approve / Reject buttons */}
                          {!isTraining && (
                            <div className="flex items-center gap-2">
                              <button
                                onClick={() => handleApprove(policy.id)}
                                className="flex items-center gap-1.5 px-4 py-2 rounded-lg bg-[#10B981]/10 border border-[#10B981]/30 text-[#10B981] text-xs font-semibold hover:bg-[#10B981]/20 transition-colors"
                              >
                                <Check className="w-3.5 h-3.5" />
                                Approve — Create Model
                              </button>
                              <button
                                onClick={() => handleReject(policy.id)}
                                className="flex items-center gap-1.5 px-4 py-2 rounded-lg bg-red-500/5 border border-red-500/20 text-red-400/80 text-xs font-semibold hover:bg-red-500/10 transition-colors"
                              >
                                <X className="w-3.5 h-3.5" />
                                Reject
                              </button>
                            </div>
                          )}
                        </div>

                        {/* Bottom lifecycle bar */}
                        <div className="bg-[#0A0F1C]/50 border-t border-[#1E293B]/50 px-5 py-2 flex items-center justify-between">
                          <span className="text-[10px] text-[#64748B]/70 font-mono">
                            Lifecycle: <span className="text-[#3B82F6]">Suggested</span> → Approved → Active → Graduated
                          </span>
                          <span className="text-[10px] text-[#64748B]/70 font-mono">{policy.id}</span>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            )}

            {/* ── Rejected Policies ── */}
            {rejectedPolicies.length > 0 && (
              <div>
                <div className="flex items-center gap-2 mb-3">
                  <Ban className="w-4 h-4 text-[#64748B]" />
                  <span className="text-xs font-semibold text-[#64748B] uppercase tracking-wider">Rejected</span>
                  <span className="text-xs text-[#64748B] font-mono">({rejectedPolicies.length})</span>
                </div>
                <div className="space-y-2">
                  {rejectedPolicies.map((policy) => (
                    <div key={policy.id} className="bg-[#151D2E]/50 border border-[#1E293B]/50 rounded-xl p-4 opacity-60">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-3">
                          <span className="inline-flex px-2 py-0.5 text-[10px] font-mono font-semibold rounded border bg-red-500/10 text-red-400/60 border-red-500/20">
                            REJECTED
                          </span>
                          <span className="text-sm text-[#94A3B8] line-through">{policy.name}</span>
                        </div>
                        <span className="text-[10px] text-[#64748B] font-mono">
                          Feedback recorded — similar policies deprioritized
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* ── Feature Store Reference ── */}
            <div className="bg-[#151D2E] border border-[#1E293B] rounded-xl p-6">
              <div className="flex items-center gap-2 mb-4">
                <CircleDot className="w-4 h-4 text-[#3B82F6]" />
                <span className="text-sm font-semibold text-white">Universal Feature Store</span>
                <span className="text-xs text-[#64748B] font-mono">~45 features per entity</span>
              </div>
              <p className="text-xs text-[#64748B] mb-4">
                Every identity in the unified graph is described by these features. Tier 2 policies select a subset to train their scoped ML model.
              </p>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                {Object.entries(FEATURE_CATEGORIES).map(([key, cat]) => (
                  <div key={key} className="bg-[#0A0F1C] rounded-lg p-4 border border-[#1E293B]/50">
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-xs font-semibold text-white">{cat.label}</span>
                      <span className="text-[10px] text-[#64748B] font-mono">{cat.desc}</span>
                    </div>
                    <div className="space-y-1">
                      {cat.features.map((f) => (
                        <div key={f.name} className="flex items-start gap-2 text-[11px]">
                          <span className="text-[#3B82F6] font-mono min-w-[200px] shrink-0">{f.name}</span>
                          <span className="text-[#64748B]">{f.desc}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </div>
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
            {["AWS IAM", "NetSuite", "Okta"].map((system) => {
              const sources = DATA_SOURCES.filter((ds) => ds.system === system);
              const dotColor = system === "AWS IAM" ? "bg-amber-400" : system === "NetSuite" ? "bg-purple-400" : "bg-cyan-400";
              return (
                <div key={system}>
                  <div className="flex items-center gap-2 mb-2 mt-2">
                    <div className={`w-2 h-2 rounded-full ${dotColor}`} />
                    <span className="text-xs font-semibold text-[#94A3B8] uppercase tracking-wider">{system}</span>
                  </div>
                  {sources.map((ds) => (
                    <div
                      key={ds.name}
                      className="bg-[#151D2E] border border-[#1E293B] rounded-xl p-5 flex items-center gap-4 mb-2"
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
                </div>
              );
            })}

            <div className="bg-[#151D2E] border border-[#1E293B] rounded-xl p-6 mt-6">
              <span className="text-sm font-semibold text-white block mb-4">
                Pipeline Architecture
              </span>
              <div className="font-mono text-xs text-[#94A3B8] space-y-2">
                <div className="flex items-center gap-2">
                  <ChevronRight className="w-3 h-3 text-amber-400" />
                  <span>
                    <span className="text-white">AWSIAMAdapter</span>{" "}
                    → 1,537 managed policies → GraphSnapshot
                  </span>
                </div>
                <div className="flex items-center gap-2">
                  <ChevronRight className="w-3 h-3 text-amber-400" />
                  <span>
                    <span className="text-white">CloudTrailIngester</span>{" "}
                    → 2,900 Stratus attack events → behavioral features
                  </span>
                </div>
                <div className="flex items-center gap-2">
                  <ChevronRight className="w-3 h-3 text-purple-400" />
                  <span>
                    <span className="text-white">NetSuiteAdapter</span>{" "}
                    → SuiteQL role/permission export → SoD conflict matrix
                  </span>
                </div>
                <div className="flex items-center gap-2">
                  <ChevronRight className="w-3 h-3 text-cyan-400" />
                  <span>
                    <span className="text-white">OktaAdapter</span>{" "}
                    → Admin roles, MFA config, System Log → GraphSnapshot
                  </span>
                </div>
                <div className="flex items-center gap-2 mt-2 pt-2 border-t border-[#1E293B]/50">
                  <ChevronRight className="w-3 h-3 text-[#3B82F6]" />
                  <span>
                    <span className="text-white">IdentityGraph</span>{" "}
                    → NetworkX ({PIPELINE_STATS.graphNodes.toLocaleString()} nodes, {PIPELINE_STATS.graphEdges} edges) — cross-system correlation
                  </span>
                </div>
                <div className="flex items-center gap-2">
                  <ChevronRight className="w-3 h-3 text-[#3B82F6]" />
                  <span>
                    <span className="text-white">FeatureComputer</span>{" "}
                    → ~45 features per entity (centrality, peer ratio, drift...)
                  </span>
                </div>
                <div className="flex items-center gap-2">
                  <ChevronRight className="w-3 h-3 text-[#3B82F6]" />
                  <span>
                    <span className="text-white">BootstrapLabeler</span>{" "}
                    → 15 violation classes → {PIPELINE_STATS.violationsDetected} signals
                  </span>
                </div>
              </div>

              <div className="mt-6 pt-4 border-t border-[#1E293B] text-xs text-[#64748B]">
                <span className="text-[#10B981] font-semibold">Unified graph</span>{" "}
                — all three adapters produce the same GraphSnapshot schema.
                Cross-system correlation detects risks no single-system tool can see.
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
