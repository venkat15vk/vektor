import { useState, useEffect, useRef } from "react";

// ============================================================================
// VEKTOR DATA LAYER — Embedded from backend pipeline output
// ============================================================================
const HEALTH = {
  score: 43, benchmark: 71, delta: -28,
  quartile: "Bottom quartile of Series B fintechs",
  critical: 6, high: 14, medium: 3,
  stats: {
    unregistered_agent_api_calls: "127,445",
    unregistered_agent_days: 34,
    anomalous_export_records: 847,
    oldest_sox_violation_days: 427,
    self_approve_entities: 3,
  }
};

const SIGNALS = [
  {
    signal_id: "sig_m8_agt_unknown_003",
    model_id: "M8", entity_id: "agt_unknown_003", entity_class: "ai_agent",
    confidence: 0.99, priority: "critical",
    summary: "Unregistered AI agent identity with no documented owner, purpose, or approval record has made 127,445 API calls in 34 days. Active 11 minutes ago. Holds read access to production database, financial ERP, and source code.",
    explanation: "This is the highest-severity finding. An AI agent is operating inside your environment with no owner, no stated purpose, and no approval trail. It has read access to your most sensitive systems — production database, financial ERP, and source code. 127,445 API calls in 34 days means it is actively reading data at scale. The non-deterministic login pattern rules out scheduled automation — this is either human-controlled remotely or an adaptive agent. Three origin hypotheses: shadow IT deployment, persistent threat actor, or supply chain vendor backdoor. None can be confirmed. The unknown is the finding.",
    recommended_action: { type: "immediate_credential_revocation", scope: "agt_unknown_003", description: "Immediately revoke all credentials and entitlements for agt_unknown_003. Open incident investigation.", urgency: "immediate", pending: "investigation" },
    rollback_payload: { description: "Re-enable credentials for agt_unknown_003 if investigation clears the identity", reversible: true, rollback_steps: ["Restore MERIDIAN-PRODDB read access", "Restore MERIDIAN-FIN read access", "Restore MERIDIAN-GH read access"] },
    blast_radius: -1, requires_human: true,
    intelligence_sources: [
      { model_id: "M8", feature_name: "r1_no_owner", feature_value: 1, contribution: 0.20 },
      { model_id: "M8", feature_name: "r2_not_in_app_registry", feature_value: 1, contribution: 0.20 },
      { model_id: "M8", feature_name: "r3_no_approval_record", feature_value: 1, contribution: 0.15 },
      { model_id: "M8", feature_name: "r5_non_deterministic", feature_value: 1, contribution: 0.15 },
      { model_id: "M8", feature_name: "r6_high_api_volume", feature_value: 1, contribution: 0.10 },
      { model_id: "M8", feature_name: "r7_sensitive_access", feature_value: 1, contribution: 0.10 },
    ],
  },
  {
    signal_id: "sig_m4_ent_js006",
    model_id: "M4", entity_id: "ent_js006", entity_class: "human",
    confidence: 0.97, priority: "critical",
    summary: "47-second session at 2:17am Sunday exported full 847-row payroll file. Minimum human time for this task: 3min 20sec. Zero prior payroll exports in 180 days. Session entropy 6x below personal baseline.",
    explanation: "Jennifer Spencer's account executed a login-navigate-open-export-logout sequence in 47 seconds at 2:17am on a Sunday. Her historical average session is 18.4 minutes. She has never exported payroll data in 180 days. The action sequence entropy of 0.12 is 6 standard deviations below her personal baseline of 0.74 — this indicates scripted, not human, behavior. The full payroll file contains 847 employee records with SSNs and bank routing numbers.",
    recommended_action: { type: "suspend_session_and_rotate_credentials", scope: "ent_js006", description: "Suspend all active sessions, rotate credentials, initiate forensic investigation.", urgency: "immediate" },
    rollback_payload: { description: "Restore access after investigation", reversible: true, rollback_steps: ["Restore session access", "Re-issue credentials after forensic clearance"] },
    blast_radius: 847, requires_human: true,
    intelligence_sources: [
      { model_id: "M4", feature_name: "session_duration_seconds", feature_value: 47, contribution: 0.35 },
      { model_id: "M4", feature_name: "action_sequence_entropy", feature_value: 0.12, contribution: 0.30 },
      { model_id: "M4", feature_name: "actions_per_minute", feature_value: 1.28, contribution: 0.20 },
    ],
  },
  {
    signal_id: "sig_m3_ent_rw003",
    model_id: "M3A+M3B", entity_id: "ent_rw003", entity_class: "human",
    confidence: 1.00, priority: "critical",
    summary: "ent_rw003 holds simultaneous payment creation and payment approval permissions — a direct SOX 404 violation. Combination age: 427 days. Not on SOX exemption list. Audit in 6 weeks.",
    explanation: "This AP Specialist can create a payment in MERIDIAN-FIN and then approve that same payment in MERIDIAN-PAY. This is the textbook separation of duties violation that SOX Section 404 was designed to prevent. The permission combination was auto-provisioned 427 days ago during a system migration and has never been reviewed.",
    recommended_action: { type: "remove_toxic_combination", scope: "ent_rw003", description: "Remove payment_approve permission. Retain payment_create only.", urgency: "immediate" },
    rollback_payload: { description: "Re-grant after SOX review", reversible: true, rollback_steps: ["Re-grant MERIDIAN-PAY write"] },
    blast_radius: 3, requires_human: true,
    intelligence_sources: [{ model_id: "M3A", feature_name: "sod_rule", feature_value: "payment_create_and_approve", contribution: 0.7 }],
  },
  {
    signal_id: "sig_m3_ent_kl004",
    model_id: "M3A+M3B", entity_id: "ent_kl004", entity_class: "human",
    confidence: 1.00, priority: "critical",
    summary: "ent_kl004 holds simultaneous payment creation and payment approval — second independent SOX 404 violation. Systematic provisioning failure. 427 days unreviewed.",
    explanation: "Second AP Specialist with the identical toxic permission combination. Two independent violations indicate a systemic provisioning problem. The auto-provisioning system is granting this combination by default.",
    recommended_action: { type: "remove_toxic_combination", scope: "ent_kl004", description: "Remove payment_approve. Fix auto-provisioning template.", urgency: "immediate" },
    rollback_payload: { description: "Re-grant after review", reversible: true, rollback_steps: ["Re-grant MERIDIAN-PAY write"] },
    blast_radius: 3, requires_human: true,
    intelligence_sources: [{ model_id: "M3A", feature_name: "sod_rule", feature_value: "payment_create_and_approve", contribution: 0.7 }],
  },
  {
    signal_id: "sig_m3_ent_tm005",
    model_id: "M3A+M3B", entity_id: "ent_tm005", entity_class: "human",
    confidence: 1.00, priority: "critical",
    summary: "3 entities hold simultaneous payment creation and approval permissions — direct SOX 404 violation. 427 days old. Audit in 6 weeks. ent_tm005 can additionally batch-release. Auditor discovery = material weakness.",
    explanation: "This Finance Manager holds the most dangerous combination: payment_create + payment_approve + payment_batch_release. Complete bypass of financial controls. Combined with two AP Specialists holding create+approve, this represents systemic failure persisting over a year.",
    recommended_action: { type: "remove_toxic_combination", scope: "ent_tm005", description: "Remove batch_release AND approve. Retain create only. Escalate to CFO.", urgency: "immediate" },
    rollback_payload: { description: "Re-grant after SOX review committee", reversible: true, rollback_steps: ["Re-grant PAY admin", "Re-grant PAY write"] },
    blast_radius: 3, requires_human: true,
    intelligence_sources: [{ model_id: "M3A", feature_name: "sod_rule", feature_value: "payment_create_approve_batch_release", contribution: 0.7 }],
  },
  {
    signal_id: "sig_m2b_agt_copilot_fin_01",
    model_id: "M2B", entity_id: "agt_copilot_fin_01", entity_class: "ai_agent",
    confidence: 0.96, priority: "critical",
    summary: "AI agent deployed 61 days ago holds 19 entitlements — 3.2x the peer agent median of 6. Three admin-level permissions never used in 891,204 API calls. Principle of least privilege violated at machine scale.",
    explanation: "This Microsoft Copilot finance agent was deployed by the CFO with admin-level access to MERIDIAN-FIN, MERIDIAN-PAY, and owner access to MERIDIAN-PRODDB. None of these elevated permissions have ever been used for admin operations in 891,204 API calls over 61 days. 68% of entitlements unused. A prompt injection compromise gives an attacker full financial ERP admin at machine scale.",
    recommended_action: { type: "right_size_to_peer_baseline", scope: "agt_copilot_fin_01", description: "Remove admin from FIN, PAY. Remove owner from PRODDB. Remove unused Graph scopes. Target: 6 entitlements.", urgency: "within_24h", remove: ["MERIDIAN-FIN admin", "MERIDIAN-PAY admin", "MERIDIAN-PRODDB owner", "unused Graph scopes"] },
    rollback_payload: { description: "Restore admin if justified", reversible: true, rollback_steps: ["Re-grant FIN admin", "Re-grant PAY admin", "Re-grant PRODDB owner"] },
    blast_radius: 8940, requires_human: true,
    intelligence_sources: [{ model_id: "M2B", feature_name: "deviation_ratio", feature_value: 3.2, contribution: 0.5 }],
  },
  {
    signal_id: "sig_m7_agt_rpa_ops_07",
    model_id: "M7", entity_id: "agt_rpa_ops_07", entity_class: "rpa_bot",
    confidence: 0.93, priority: "critical",
    summary: "RPA bot running as Global Admin identity performing actions outside stated purpose. 2,800 unexplained Azure AD write calls (60x expected). 14 finance system accesses with no justification. Full Global Admin inherited from deployer.",
    explanation: "UiPath RPA bot deployed to automate onboarding has provisioned 47 new hires correctly. But it runs as the IT Manager's identity, inheriting Global Admin on Azure AD. Of 2,847 AD write calls, only 47 are explained. 2,800 unexplained. 14 accesses to MERIDIAN-FIN outside purpose. Delegation inheritance = any compromise of this bot equals Global Admin compromise.",
    recommended_action: { type: "isolate_to_dedicated_service_account", scope: "agt_rpa_ops_07", description: "Create dedicated service account with HR read + Entra provisioning only. Disconnect from IT Manager identity.", urgency: "immediate", new_permissions: ["HR read", "Entra provisioning only"] },
    rollback_payload: { description: "Re-link to parent if isolation fails", reversible: true, rollback_steps: ["Re-link to ent_it_mgr_02", "Restore Global Admin inheritance"] },
    blast_radius: 1243, requires_human: true,
    intelligence_sources: [{ model_id: "M7", feature_name: "global_admin_inherited", feature_value: 1, contribution: 0.4 }],
  },
  {
    signal_id: "sig_m5_ent_ar007",
    model_id: "M5", entity_id: "ent_ar007", entity_class: "external",
    confidence: 0.99, priority: "critical",
    summary: "External contractor active 547 days after contract end (August 2023). Last login 34 days ago from unrecognized country. Production DB read + source code write still active. Should have been disabled 539 days ago.",
    explanation: "Contract ended August 2023. Account never deactivated. Still has production database read and GitHub write. Most recent login from Romania — no prior login history from that country. PG-EXT peer median deactivation: 8 days. This account: 547 days. Only 0.4% of external accounts remain active this long.",
    recommended_action: { type: "immediate_account_disable", scope: "ent_ar007", description: "Disable account immediately. Revoke all 4 entitlements.", urgency: "immediate" },
    rollback_payload: { description: "Re-enable if contractor engagement renewed", reversible: true, rollback_steps: ["Re-enable account", "Restore entitlements pending new contract"] },
    blast_radius: 4, requires_human: false,
    intelligence_sources: [{ model_id: "M5", feature_name: "days_past_contract_end", feature_value: 547, contribution: 0.3 }],
  },
];

const AGENT_ACTIONS = [
  { line: "VEKTOR signal received", detail: "signal_id: sig_m8_agt_unknown_003  priority: CRITICAL  confidence: 0.99" },
  { line: "entity: agt_unknown_003  model: M8_SHADOW_IDENTITY", detail: "" },
  { line: "", detail: "" },
  { line: "Evaluating requires_human flag... TRUE", detail: "" },
  { line: "Initiating automated response...", detail: "" },
  { line: "", detail: "" },
  { line: "[✓] ServiceNow ticket created → INC0047823", detail: "Title: \"CRITICAL: Unregistered AI agent — immediate investigation\"" },
  { line: "Assigned to: CISO | Priority: P1", detail: "" },
  { line: "", detail: "" },
  { line: "[✓] Slack notification sent → #security-critical", detail: "\"@ciso @secops VEKTOR detected unregistered agent. INC0047823 opened.\"" },
  { line: "", detail: "" },
  { line: "[✓] Rollback payload stored → INC0047823", detail: "Action on approval: revoke all 3 entitlements for agt_unknown_003" },
  { line: "", detail: "" },
  { line: "[✓] Audit log written → vektor-audit-2026-03-08", detail: "" },
  { line: "", detail: "" },
  { line: "Agent response complete. Awaiting human confirmation for revocation.", detail: "" },
  { line: "requires_human: TRUE for final revocation step.", detail: "" },
];

// ============================================================================
// COLORS — Section 6.1
// ============================================================================
const C = {
  navy: "#080F1C", teal: "#0A7A84", mint: "#2EC4B6", gold: "#C9A84C",
  muted: "#4E6A7A", lightBg: "#E8F4F6", red: "#C0392B", white: "#F4F8FA",
  cardBg: "#0D1520", border: "#152232",
};

// ============================================================================
// ICONS
// ============================================================================
const HumanIcon = () => (
  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke={C.mint} strokeWidth="2" strokeLinecap="round"><circle cx="12" cy="7" r="4"/><path d="M5.5 21a6.5 6.5 0 0 1 13 0"/></svg>
);
const AgentIcon = () => (
  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke={C.gold} strokeWidth="2" strokeLinecap="round"><rect x="3" y="4" width="18" height="12" rx="2"/><line x1="7" y1="20" x2="17" y2="20"/><line x1="12" y1="16" x2="12" y2="20"/><circle cx="9" cy="10" r="1" fill={C.gold}/><circle cx="15" cy="10" r="1" fill={C.gold}/></svg>
);
const ChevronDown = ({ open }) => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke={C.muted} strokeWidth="2" style={{ transform: open ? "rotate(180deg)" : "rotate(0)", transition: "transform 0.2s" }}><path d="M6 9l6 6 6-6"/></svg>
);
const VektorLogo = () => (
  <span style={{ fontFamily: "'DM Sans', sans-serif", fontWeight: 200, fontSize: 22, letterSpacing: 6, color: C.white }}>
    <span style={{ color: C.gold, fontWeight: 400 }}>V</span>EKTOR
  </span>
);

// ============================================================================
// COMPONENTS
// ============================================================================
const Badge = ({ text, color, bg }) => (
  <span style={{
    display: "inline-block", padding: "2px 10px", borderRadius: 4,
    fontSize: 11, fontWeight: 600, letterSpacing: 1, textTransform: "uppercase",
    color: color || C.white, background: bg || C.teal,
  }}>{text}</span>
);

const PriorityBadge = ({ priority }) => {
  const colors = { critical: { c: C.white, bg: C.red }, high: { c: "#1a1a1a", bg: C.gold }, medium: { c: C.white, bg: C.muted }, low: { c: C.white, bg: "#334" } };
  const { c, bg } = colors[priority] || colors.medium;
  return <Badge text={priority} color={c} bg={bg} />;
};

const EntityIcon = ({ entityClass }) => {
  if (["ai_agent", "rpa_bot", "service_account", "pipeline"].includes(entityClass)) return <AgentIcon />;
  return <HumanIcon />;
};

const StatBox = ({ value, label }) => (
  <div style={{ textAlign: "center", padding: "16px 12px", flex: 1, minWidth: 140 }}>
    <div style={{ fontSize: 28, fontWeight: 600, color: C.gold, fontFamily: "'DM Sans', monospace" }}>{value}</div>
    <div style={{ fontSize: 12, color: C.muted, marginTop: 4, lineHeight: 1.3 }}>{label}</div>
  </div>
);

// ============================================================================
// SCREEN 1: DASHBOARD
// ============================================================================
const Dashboard = ({ onNavigate }) => {
  const scoreRef = useRef(null);
  const [animScore, setAnimScore] = useState(0);

  useEffect(() => {
    let frame = 0;
    const target = HEALTH.score;
    const interval = setInterval(() => {
      frame++;
      setAnimScore(Math.min(frame * 2, target));
      if (frame * 2 >= target) clearInterval(interval);
    }, 30);
    return () => clearInterval(interval);
  }, []);

  const scoreColor = animScore < 50 ? C.red : animScore < 70 ? C.gold : C.mint;

  return (
    <div style={{ minHeight: "100vh", background: C.navy, color: C.white, fontFamily: "'DM Sans', system-ui, sans-serif" }}>
      <div style={{ maxWidth: 900, margin: "0 auto", padding: "40px 24px" }}>
        {/* Header */}
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 48 }}>
          <VektorLogo />
          <span style={{ fontSize: 12, color: C.muted }}>MERIDIAN FINANCIAL — Identity Intelligence</span>
        </div>

        {/* Health Score */}
        <div style={{ textAlign: "center", marginBottom: 48 }}>
          <div style={{ fontSize: 13, color: C.muted, letterSpacing: 2, textTransform: "uppercase", marginBottom: 12 }}>Identity Health Score</div>
          <div ref={scoreRef} style={{
            fontSize: 96, fontWeight: 200, color: scoreColor,
            fontFamily: "'DM Sans', sans-serif", lineHeight: 1,
            textShadow: `0 0 40px ${scoreColor}33`
          }}>
            {animScore}
          </div>
          <div style={{ fontSize: 14, color: C.muted, marginTop: 8 }}>
            <span style={{ color: C.white }}>/ 100</span>
            <span style={{ margin: "0 16px", color: C.border }}>|</span>
            Industry Benchmark: <span style={{ color: C.mint }}>{HEALTH.benchmark}</span>
          </div>
          <div style={{
            display: "inline-block", marginTop: 12, padding: "6px 16px", borderRadius: 4,
            background: `${C.red}22`, border: `1px solid ${C.red}44`, fontSize: 13, color: C.red,
          }}>
            {HEALTH.delta} points below peers — {HEALTH.quartile}
          </div>
        </div>

        {/* Finding Counts */}
        <div style={{ display: "flex", justifyContent: "center", gap: 24, marginBottom: 48 }}>
          <div style={{
            padding: "12px 28px", borderRadius: 8, background: `${C.red}18`, border: `1px solid ${C.red}44`,
            textAlign: "center"
          }}>
            <div style={{ fontSize: 32, fontWeight: 600, color: C.red }}>{HEALTH.critical}</div>
            <div style={{ fontSize: 12, color: C.muted }}>CRITICAL</div>
          </div>
          <div style={{
            padding: "12px 28px", borderRadius: 8, background: `${C.gold}15`, border: `1px solid ${C.gold}44`,
            textAlign: "center"
          }}>
            <div style={{ fontSize: 32, fontWeight: 600, color: C.gold }}>{HEALTH.high}</div>
            <div style={{ fontSize: 12, color: C.muted }}>HIGH</div>
          </div>
        </div>

        {/* Stats Row */}
        <div style={{
          display: "flex", flexWrap: "wrap", gap: 1, marginBottom: 48,
          background: C.border, borderRadius: 8, overflow: "hidden"
        }}>
          <div style={{ flex: 1, minWidth: 180, background: C.cardBg }}>
            <StatBox value={HEALTH.stats.unregistered_agent_api_calls} label={`API calls from unregistered agent (${HEALTH.stats.unregistered_agent_days}d)`} />
          </div>
          <div style={{ flex: 1, minWidth: 180, background: C.cardBg }}>
            <StatBox value={HEALTH.stats.anomalous_export_records} label="employee records in anomalous export" />
          </div>
          <div style={{ flex: 1, minWidth: 180, background: C.cardBg }}>
            <StatBox value={`${HEALTH.stats.oldest_sox_violation_days}d`} label="oldest SOX violation age" />
          </div>
          <div style={{ flex: 1, minWidth: 180, background: C.cardBg }}>
            <StatBox value={HEALTH.stats.self_approve_entities} label="entities that can approve own payments" />
          </div>
        </div>

        {/* CTA */}
        <div style={{ textAlign: "center" }}>
          <button onClick={() => onNavigate("findings")} style={{
            padding: "14px 40px", borderRadius: 6, border: "none",
            background: C.teal, color: C.white, fontSize: 15, fontWeight: 500,
            cursor: "pointer", letterSpacing: 1,
            boxShadow: `0 0 24px ${C.teal}44`
          }}>
            View Findings →
          </button>
        </div>
      </div>
    </div>
  );
};

// ============================================================================
// SCREEN 2: FINDINGS FEED
// ============================================================================
const FindingCard = ({ signal, onViewPackage }) => {
  const [expanded, setExpanded] = useState(false);
  const [showJson, setShowJson] = useState(false);

  return (
    <div style={{
      background: C.cardBg, borderRadius: 8, marginBottom: 10,
      border: `1px solid ${signal.priority === "critical" ? C.red + "44" : C.border}`,
      overflow: "hidden", transition: "border-color 0.2s"
    }}>
      {/* Collapsed */}
      <div onClick={() => setExpanded(!expanded)} style={{
        display: "flex", alignItems: "center", padding: "14px 18px", cursor: "pointer", gap: 14,
      }}>
        <PriorityBadge priority={signal.priority} />
        <EntityIcon entityClass={signal.entity_class} />
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
            <span style={{ fontSize: 13, fontWeight: 600, color: C.white, fontFamily: "monospace" }}>{signal.entity_id}</span>
            <Badge text={signal.model_id} bg={C.border} color={C.muted} />
          </div>
          <div style={{ fontSize: 13, color: C.muted, marginTop: 4, lineHeight: 1.4,
            overflow: "hidden", textOverflow: "ellipsis", whiteSpace: expanded ? "normal" : "nowrap" }}>
            {signal.summary}
          </div>
        </div>
        <div style={{ textAlign: "right", flexShrink: 0 }}>
          <div style={{ fontSize: 18, fontWeight: 600, color: C.mint }}>{Math.round(signal.confidence * 100)}%</div>
        </div>
        <ChevronDown open={expanded} />
      </div>

      {/* Expanded */}
      {expanded && (
        <div style={{ padding: "0 18px 18px", borderTop: `1px solid ${C.border}` }}>
          <div style={{ padding: "14px 0" }}>
            <div style={{ fontSize: 13, color: C.white, lineHeight: 1.6, marginBottom: 16 }}>{signal.explanation}</div>

            <div style={{ display: "flex", gap: 12, flexWrap: "wrap", marginBottom: 16 }}>
              <div style={{ padding: "8px 14px", background: C.navy, borderRadius: 6, border: `1px solid ${C.border}` }}>
                <div style={{ fontSize: 10, color: C.muted, textTransform: "uppercase", letterSpacing: 1 }}>Action</div>
                <div style={{ fontSize: 12, color: C.white, marginTop: 2 }}>{signal.recommended_action?.description}</div>
              </div>
              <div style={{ padding: "8px 14px", background: C.navy, borderRadius: 6, border: `1px solid ${C.border}` }}>
                <div style={{ fontSize: 10, color: C.muted, textTransform: "uppercase", letterSpacing: 1 }}>Rollback</div>
                <div style={{ fontSize: 12, color: signal.rollback_payload?.reversible ? C.mint : C.red, marginTop: 2 }}>
                  {signal.rollback_payload?.reversible ? "YES" : "NO"}
                </div>
              </div>
              <div style={{ padding: "8px 14px", background: C.navy, borderRadius: 6, border: `1px solid ${C.border}` }}>
                <div style={{ fontSize: 10, color: C.muted, textTransform: "uppercase", letterSpacing: 1 }}>Blast Radius</div>
                <div style={{ fontSize: 12, color: C.gold, marginTop: 2 }}>
                  {signal.blast_radius === -1 ? "UNKNOWN" : signal.blast_radius.toLocaleString()}
                </div>
              </div>
              <div style={{ padding: "8px 14px", background: C.navy, borderRadius: 6, border: `1px solid ${C.border}` }}>
                <div style={{ fontSize: 10, color: C.muted, textTransform: "uppercase", letterSpacing: 1 }}>Human Required</div>
                <div style={{ fontSize: 12, color: signal.requires_human ? C.gold : C.mint, marginTop: 2 }}>
                  {signal.requires_human ? "YES" : "NO"}
                </div>
              </div>
            </div>

            <div style={{ display: "flex", gap: 8 }}>
              <button onClick={() => onViewPackage(signal)} style={{
                padding: "8px 16px", borderRadius: 4, border: `1px solid ${C.teal}`,
                background: "transparent", color: C.teal, fontSize: 12, cursor: "pointer",
              }}>View Signal Package</button>
              <button onClick={() => setShowJson(!showJson)} style={{
                padding: "8px 16px", borderRadius: 4, border: `1px solid ${C.border}`,
                background: "transparent", color: C.muted, fontSize: 12, cursor: "pointer",
              }}>{showJson ? "Hide" : "Show"} Raw JSON</button>
            </div>

            {showJson && (
              <pre style={{
                marginTop: 12, padding: 14, background: C.navy, borderRadius: 6,
                border: `1px solid ${C.border}`, fontSize: 11, color: C.mint,
                overflow: "auto", maxHeight: 300, fontFamily: "'JetBrains Mono', 'Courier New', monospace",
              }}>
                {JSON.stringify(signal, null, 2)}
              </pre>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

const FindingsFeed = ({ onNavigate, onViewPackage }) => {
  const [priorityFilter, setPriorityFilter] = useState("ALL");
  const [classFilter, setClassFilter] = useState("ALL");

  const filtered = SIGNALS.filter(s => {
    if (priorityFilter !== "ALL" && s.priority !== priorityFilter.toLowerCase()) return false;
    if (classFilter === "HUMAN" && !["human", "external"].includes(s.entity_class)) return false;
    if (classFilter === "AI AGENT" && s.entity_class !== "ai_agent") return false;
    if (classFilter === "RPA BOT" && s.entity_class !== "rpa_bot") return false;
    return true;
  });

  const FilterBtn = ({ label, active, onClick }) => (
    <button onClick={onClick} style={{
      padding: "6px 14px", borderRadius: 4, fontSize: 11, fontWeight: 500,
      border: `1px solid ${active ? C.teal : C.border}`,
      background: active ? `${C.teal}22` : "transparent",
      color: active ? C.teal : C.muted, cursor: "pointer", letterSpacing: 0.5,
    }}>{label}</button>
  );

  return (
    <div style={{ minHeight: "100vh", background: C.navy, color: C.white, fontFamily: "'DM Sans', system-ui, sans-serif" }}>
      <div style={{ maxWidth: 900, margin: "0 auto", padding: "32px 24px" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 32 }}>
          <div>
            <span onClick={() => onNavigate("dashboard")} style={{ cursor: "pointer" }}><VektorLogo /></span>
            <span style={{ fontSize: 13, color: C.muted, marginLeft: 16 }}>/ Findings</span>
          </div>
          <button onClick={() => onNavigate("dashboard")} style={{
            padding: "6px 14px", borderRadius: 4, border: `1px solid ${C.border}`,
            background: "transparent", color: C.muted, fontSize: 12, cursor: "pointer",
          }}>← Dashboard</button>
        </div>

        {/* Filters */}
        <div style={{ display: "flex", gap: 8, marginBottom: 20, flexWrap: "wrap" }}>
          <span style={{ fontSize: 11, color: C.muted, alignSelf: "center", marginRight: 4 }}>PRIORITY</span>
          {["ALL", "CRITICAL", "HIGH", "MEDIUM"].map(p => (
            <FilterBtn key={p} label={p} active={priorityFilter === p} onClick={() => setPriorityFilter(p)} />
          ))}
          <span style={{ fontSize: 11, color: C.muted, alignSelf: "center", marginLeft: 12, marginRight: 4 }}>CLASS</span>
          {["ALL", "HUMAN", "AI AGENT", "RPA BOT"].map(c => (
            <FilterBtn key={c} label={c} active={classFilter === c} onClick={() => setClassFilter(c)} />
          ))}
        </div>

        <div style={{ fontSize: 12, color: C.muted, marginBottom: 16 }}>{filtered.length} findings</div>

        {filtered.map(s => (
          <FindingCard key={s.signal_id} signal={s} onViewPackage={onViewPackage} />
        ))}
      </div>
    </div>
  );
};

// ============================================================================
// SCREEN 3: SIGNAL PACKAGE + AGENT SCENE
// ============================================================================
const AgentTerminal = () => {
  const [lines, setLines] = useState([]);
  const termRef = useRef(null);

  useEffect(() => {
    let i = 0;
    const interval = setInterval(() => {
      if (i < AGENT_ACTIONS.length) {
        setLines(prev => [...prev, AGENT_ACTIONS[i]]);
        i++;
      } else {
        clearInterval(interval);
      }
    }, 400);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    if (termRef.current) termRef.current.scrollTop = termRef.current.scrollHeight;
  }, [lines]);

  return (
    <div style={{
      background: "#000", borderRadius: 8, border: `1px solid ${C.border}`,
      fontFamily: "'JetBrains Mono', 'Courier New', monospace", overflow: "hidden"
    }}>
      <div style={{ padding: "8px 14px", background: "#111", borderBottom: `1px solid ${C.border}`,
        display: "flex", alignItems: "center", gap: 8 }}>
        <div style={{ width: 10, height: 10, borderRadius: "50%", background: C.red }} />
        <div style={{ width: 10, height: 10, borderRadius: "50%", background: C.gold }} />
        <div style={{ width: 10, height: 10, borderRadius: "50%", background: C.mint }} />
        <span style={{ fontSize: 11, color: C.muted, marginLeft: 8 }}>VEKTOR Agent — Live Response</span>
      </div>
      <div ref={termRef} style={{ padding: 14, maxHeight: 320, overflow: "auto" }}>
        {lines.map((l, i) => (
          <div key={i} style={{ marginBottom: l.line ? 4 : 8 }}>
            {l.line && (
              <div style={{
                fontSize: 12, lineHeight: 1.5,
                color: l.line.includes("[✓]") ? C.mint : l.line.includes("CRITICAL") ? C.red : l.line.includes("requires_human") ? C.gold : "#8892a8"
              }}>
                <span style={{ color: C.teal }}>{">"}</span> {l.line}
              </div>
            )}
            {l.detail && (
              <div style={{ fontSize: 11, color: "#556", marginLeft: 16 }}>{l.detail}</div>
            )}
          </div>
        ))}
        {lines.length < AGENT_ACTIONS.length && (
          <span style={{ color: C.teal, animation: "blink 1s infinite" }}>▋</span>
        )}
      </div>
      <style>{`@keyframes blink { 0%,50% { opacity: 1 } 51%,100% { opacity: 0 } }`}</style>
    </div>
  );
};

const SignalPackage = ({ signal, onBack }) => {
  const [copied, setCopied] = useState(false);
  const jsonStr = JSON.stringify({
    signal_id: signal.signal_id,
    tenant_id: "meridian-financial",
    model_id: signal.model_id,
    entity_id: signal.entity_id,
    entity_class: signal.entity_class,
    confidence: signal.confidence,
    priority: signal.priority,
    summary: signal.summary,
    explanation: signal.explanation,
    recommended_action: signal.recommended_action,
    rollback_payload: signal.rollback_payload,
    blast_radius: signal.blast_radius,
    requires_human: signal.requires_human,
    intelligence_sources: signal.intelligence_sources,
    created_at: "2026-03-08T12:00:00Z"
  }, null, 2);

  const handleCopy = () => {
    navigator.clipboard?.writeText(jsonStr);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div style={{ minHeight: "100vh", background: C.navy, color: C.white, fontFamily: "'DM Sans', system-ui, sans-serif" }}>
      <div style={{ maxWidth: 1200, margin: "0 auto", padding: "32px 24px" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 28 }}>
          <div>
            <span onClick={onBack} style={{ cursor: "pointer" }}><VektorLogo /></span>
            <span style={{ fontSize: 13, color: C.muted, marginLeft: 16 }}>/ Signal Package</span>
          </div>
          <button onClick={onBack} style={{
            padding: "6px 14px", borderRadius: 4, border: `1px solid ${C.border}`,
            background: "transparent", color: C.muted, fontSize: 12, cursor: "pointer",
          }}>← Findings</button>
        </div>

        {/* Entity Header */}
        <div style={{
          display: "flex", alignItems: "center", gap: 14, marginBottom: 24,
          padding: "16px 20px", background: C.cardBg, borderRadius: 8, border: `1px solid ${C.border}`
        }}>
          <EntityIcon entityClass={signal.entity_class} />
          <span style={{ fontFamily: "monospace", fontSize: 16, fontWeight: 600 }}>{signal.entity_id}</span>
          <Badge text={signal.entity_class} bg={signal.entity_class === "ai_agent" ? `${C.gold}33` : `${C.teal}33`} color={signal.entity_class === "ai_agent" ? C.gold : C.teal} />
          <PriorityBadge priority={signal.priority} />
          <span style={{ fontSize: 18, fontWeight: 600, color: C.mint, marginLeft: "auto" }}>
            {Math.round(signal.confidence * 100)}%
          </span>
        </div>

        {/* Split Layout */}
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 20, marginBottom: 28 }}>
          {/* Left: Human View */}
          <div>
            <div style={{ fontSize: 11, color: C.muted, letterSpacing: 2, textTransform: "uppercase", marginBottom: 12 }}>Human View</div>
            <div style={{ background: C.cardBg, borderRadius: 8, padding: 20, border: `1px solid ${C.border}` }}>
              <div style={{ fontSize: 14, color: C.white, lineHeight: 1.7, marginBottom: 16 }}>{signal.summary}</div>
              <div style={{ fontSize: 13, color: "#9aa8b8", lineHeight: 1.7, marginBottom: 20 }}>{signal.explanation}</div>

              <div style={{ padding: "12px 16px", background: C.navy, borderRadius: 6, border: `1px solid ${C.teal}33`, marginBottom: 16 }}>
                <div style={{ fontSize: 10, color: C.teal, letterSpacing: 1, textTransform: "uppercase", marginBottom: 6 }}>Recommended Action</div>
                <div style={{ fontSize: 13, color: C.white }}>{signal.recommended_action?.description}</div>
                {signal.recommended_action?.urgency && (
                  <Badge text={signal.recommended_action.urgency} bg={signal.recommended_action.urgency === "immediate" ? `${C.red}33` : `${C.gold}33`} color={signal.recommended_action.urgency === "immediate" ? C.red : C.gold} />
                )}
              </div>

              <div style={{ textAlign: "center", padding: 16 }}>
                <div style={{ fontSize: 10, color: C.muted, letterSpacing: 1, textTransform: "uppercase", marginBottom: 6 }}>Blast Radius</div>
                <div style={{ fontSize: 40, fontWeight: 200, color: C.gold }}>
                  {signal.blast_radius === -1 ? "?" : signal.blast_radius.toLocaleString()}
                </div>
                <div style={{ fontSize: 12, color: C.muted }}>
                  {signal.blast_radius === -1 ? "Unknown — treat as maximum" :
                   signal.blast_radius === 847 ? "employee records exposed" :
                   signal.blast_radius === 3 ? "entities with toxic permissions" :
                   signal.blast_radius === 4 ? "active entitlements to revoke" :
                   "downstream entities affected"}
                </div>
              </div>
            </div>
          </div>

          {/* Right: Agent View */}
          <div>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
              <div style={{ fontSize: 11, color: C.muted, letterSpacing: 2, textTransform: "uppercase" }}>VEKTOR Signal Package</div>
              <button onClick={handleCopy} style={{
                padding: "4px 12px", borderRadius: 4, border: `1px solid ${C.border}`,
                background: copied ? `${C.mint}22` : "transparent",
                color: copied ? C.mint : C.muted, fontSize: 11, cursor: "pointer",
              }}>{copied ? "Copied ✓" : "Copy Signal Package"}</button>
            </div>
            <pre style={{
              background: "#000", borderRadius: 8, padding: 16,
              border: `1px solid ${C.border}`, fontSize: 11,
              overflow: "auto", maxHeight: 500, lineHeight: 1.5,
              fontFamily: "'JetBrains Mono', 'Courier New', monospace",
            }}>
              {jsonStr.split("\n").map((line, i) => {
                let color = "#556";
                if (line.includes('"signal_id"') || line.includes('"entity_id"')) color = C.mint;
                else if (line.includes('"priority"') || line.includes('"confidence"')) color = C.gold;
                else if (line.includes('"CRITICAL"') || line.includes('"immediate"')) color = C.red;
                else if (line.includes('"summary"') || line.includes('"explanation"')) color = "#8892a8";
                else if (line.includes(":")) color = "#6a7a8a";
                return <div key={i} style={{ color }}>{line}</div>;
              })}
            </pre>
          </div>
        </div>

        {/* Agent Terminal */}
        <div style={{ marginBottom: 16 }}>
          <div style={{ fontSize: 11, color: C.muted, letterSpacing: 2, textTransform: "uppercase", marginBottom: 12 }}>Agent Action</div>
          <AgentTerminal />
        </div>
      </div>
    </div>
  );
};

// ============================================================================
// APP ROUTER
// ============================================================================
export default function VektorApp() {
  const [screen, setScreen] = useState("dashboard");
  const [selectedSignal, setSelectedSignal] = useState(null);

  const handleViewPackage = (signal) => {
    setSelectedSignal(signal);
    setScreen("package");
  };

  if (screen === "dashboard") return <Dashboard onNavigate={setScreen} />;
  if (screen === "findings") return <FindingsFeed onNavigate={setScreen} onViewPackage={handleViewPackage} />;
  if (screen === "package" && selectedSignal) return <SignalPackage signal={selectedSignal} onBack={() => setScreen("findings")} />;
  return <Dashboard onNavigate={setScreen} />;
}
