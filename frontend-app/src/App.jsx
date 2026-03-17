import { useState, useEffect, useRef } from "react";

// ============================================================================
// VEKTOR API LAYER — Live API with embedded fallback
// ============================================================================
const API_BASE = "https://zooming-perfection-production.up.railway.app";

// Fallback data used if API is unreachable
const FALLBACK_HEALTH = {
  score: 43, benchmark: 71, delta: -28,
  quartile: "Bottom quartile of Series B fintechs",
  critical: 6, high: 14, medium: 3,
  stats: {
    unregistered_agent_api_calls: 127445,
    unregistered_agent_days: 34,
    anomalous_export_records: 847,
    oldest_sox_violation_days: 427,
    self_approve_entities: 3,
  }
};

const FALLBACK_SIGNALS = [
  {
    signal_id: "sig_m8_agt_unknown_003",
    model_id: "M8", entity_id: "agt_unknown_003", entity_class: "ai_agent",
    confidence: 0.99, priority: "critical",
    summary: "Unregistered AI agent identity with no documented owner, purpose, or approval record has made 127,445 API calls in 34 days. Active 11 minutes ago.",
    explanation: "This is the highest-severity finding. An AI agent is operating inside your environment with no owner, no stated purpose, and no approval trail.",
    recommended_action: { type: "immediate_credential_revocation", scope: "agt_unknown_003", description: "Immediately revoke all credentials and entitlements for agt_unknown_003.", urgency: "immediate" },
    rollback_payload: { description: "Re-enable credentials if investigation clears", reversible: true, rollback_steps: ["Restore MERIDIAN-PRODDB read", "Restore MERIDIAN-FIN read", "Restore MERIDIAN-GH read"] },
    blast_radius: -1, requires_human: true,
    intelligence_sources: [{ model_id: "M8", feature_name: "shadow_score", feature_value: 0.99, contribution: 1.0 }],
  },
];

const AGENT_ACTIONS = [
  { line: "VEKTOR signal received", detail: "signal_id: sig_m8_agt_unknown_003  priority: CRITICAL  confidence: 0.99" },
  { line: "entity: agt_unknown_003  model: M8_SHADOW_IDENTITY", detail: "" },
  { line: "", detail: "" },
  { line: "Evaluating requires_human flag... TRUE", detail: "" },
  { line: "Initiating automated response...", detail: "" },
  { line: "", detail: "" },
  { line: "[✓] ServiceNow ticket created → INC0047823", detail: 'Title: "CRITICAL: Unregistered AI agent — immediate investigation"' },
  { line: "Assigned to: CISO | Priority: P1", detail: "" },
  { line: "", detail: "" },
  { line: "[✓] Slack notification sent → #security-critical", detail: '"@ciso @secops VEKTOR detected unregistered agent. INC0047823 opened."' },
  { line: "", detail: "" },
  { line: "[✓] Rollback payload stored → INC0047823", detail: "Action on approval: revoke all 3 entitlements for agt_unknown_003" },
  { line: "", detail: "" },
  { line: "[✓] Audit log written → vektor-audit-2026-03-08", detail: "" },
  { line: "", detail: "" },
  { line: "Agent response complete. Awaiting human confirmation for revocation.", detail: "" },
  { line: "requires_human: TRUE for final revocation step.", detail: "" },
];

// ============================================================================
// API FETCH HELPERS
// ============================================================================
async function fetchHealth() {
  try {
    const res = await fetch(`${API_BASE}/health-score`, { signal: AbortSignal.timeout(5000) });
    if (!res.ok) throw new Error(res.status);
    const data = await res.json();
    // Normalize: format api_calls as string with commas for display
    if (data.stats && typeof data.stats.unregistered_agent_api_calls === "number") {
      data.stats.unregistered_agent_api_calls = data.stats.unregistered_agent_api_calls.toLocaleString();
    }
    return { data, live: true };
  } catch (e) {
    console.warn("VEKTOR API unreachable, using fallback data:", e.message);
    const fb = { ...FALLBACK_HEALTH, stats: { ...FALLBACK_HEALTH.stats, unregistered_agent_api_calls: FALLBACK_HEALTH.stats.unregistered_agent_api_calls.toLocaleString() } };
    return { data: fb, live: false };
  }
}

async function fetchSignals() {
  try {
    const res = await fetch(`${API_BASE}/signals?limit=50`, { signal: AbortSignal.timeout(5000) });
    if (!res.ok) throw new Error(res.status);
    const data = await res.json();
    // Normalize requires_human from 1/0 to true/false
    const signals = (data.signals || []).map(s => ({
      ...s,
      requires_human: s.requires_human === 1 || s.requires_human === true,
      // Parse JSON strings if needed
      recommended_action: typeof s.recommended_action === "string" ? JSON.parse(s.recommended_action) : s.recommended_action,
      rollback_payload: typeof s.rollback_payload === "string" ? JSON.parse(s.rollback_payload) : s.rollback_payload,
      intelligence_sources: typeof s.intelligence_sources === "string" ? JSON.parse(s.intelligence_sources) : s.intelligence_sources,
    }));
    // Sort: critical first, then by confidence desc
    const priorityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
    signals.sort((a, b) => {
      const pd = (priorityOrder[a.priority] || 9) - (priorityOrder[b.priority] || 9);
      if (pd !== 0) return pd;
      return b.confidence - a.confidence;
    });
    // Deduplicate by entity_id — keep highest priority/confidence per entity
    const seen = new Set();
    const deduped = [];
    for (const s of signals) {
      if (!seen.has(s.entity_id)) {
        seen.add(s.entity_id);
        deduped.push(s);
      }
    }
    return { data: deduped, live: true };
  } catch (e) {
    console.warn("VEKTOR API unreachable, using fallback signals:", e.message);
    return { data: FALLBACK_SIGNALS, live: false };
  }
}

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

const LiveBadge = ({ live }) => (
  <span style={{
    display: "inline-flex", alignItems: "center", gap: 6,
    padding: "3px 10px", borderRadius: 4, fontSize: 10, fontWeight: 500,
    letterSpacing: 1, textTransform: "uppercase",
    background: live ? `${C.mint}18` : `${C.gold}18`,
    color: live ? C.mint : C.gold,
    border: `1px solid ${live ? C.mint + "44" : C.gold + "44"}`,
  }}>
    <span style={{ width: 6, height: 6, borderRadius: "50%", background: live ? C.mint : C.gold, display: "inline-block" }} />
    {live ? "LIVE API" : "CACHED DATA"}
  </span>
);

const Loader = () => (
  <div style={{ minHeight: "100vh", background: C.navy, display: "flex", alignItems: "center", justifyContent: "center" }}>
    <div style={{ textAlign: "center" }}>
      <VektorLogo />
      <div style={{ marginTop: 24, color: C.muted, fontSize: 13 }}>Loading signals...</div>
    </div>
  </div>
);

// ============================================================================
// SCREEN 1: DASHBOARD
// ============================================================================
const Dashboard = ({ health, isLive, onNavigate }) => {
  const [animScore, setAnimScore] = useState(0);

  useEffect(() => {
    let frame = 0;
    const target = health.score;
    const interval = setInterval(() => {
      frame++;
      setAnimScore(Math.min(frame * 2, target));
      if (frame * 2 >= target) clearInterval(interval);
    }, 30);
    return () => clearInterval(interval);
  }, [health.score]);

  const scoreColor = animScore < 50 ? C.red : animScore < 70 ? C.gold : C.mint;

  return (
    <div style={{ minHeight: "100vh", background: C.navy, color: C.white, fontFamily: "'DM Sans', system-ui, sans-serif" }}>
      <div style={{ maxWidth: 900, margin: "0 auto", padding: "40px 24px" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 48 }}>
          <VektorLogo />
          <div style={{ display: "flex", alignItems: "center", gap: 16 }}>
            <LiveBadge live={isLive} />
            <span style={{ fontSize: 12, color: C.muted }}>MERIDIAN FINANCIAL</span>
          </div>
        </div>

        <div style={{ textAlign: "center", marginBottom: 48 }}>
          <div style={{ fontSize: 13, color: C.muted, letterSpacing: 2, textTransform: "uppercase", marginBottom: 12 }}>Identity Health Score</div>
          <div style={{
            fontSize: 96, fontWeight: 200, color: scoreColor,
            fontFamily: "'DM Sans', sans-serif", lineHeight: 1,
            textShadow: `0 0 40px ${scoreColor}33`
          }}>
            {animScore}
          </div>
          <div style={{ fontSize: 14, color: C.muted, marginTop: 8 }}>
            <span style={{ color: C.white }}>/ 100</span>
            <span style={{ margin: "0 16px", color: C.border }}>|</span>
            Industry Benchmark: <span style={{ color: C.mint }}>{health.benchmark}</span>
          </div>
          <div style={{
            display: "inline-block", marginTop: 12, padding: "6px 16px", borderRadius: 4,
            background: `${C.red}22`, border: `1px solid ${C.red}44`, fontSize: 13, color: C.red,
          }}>
            {health.delta} points below peers — {health.quartile}
          </div>
        </div>

        <div style={{ display: "flex", justifyContent: "center", gap: 24, marginBottom: 48 }}>
          <div style={{
            padding: "12px 28px", borderRadius: 8, background: `${C.red}18`, border: `1px solid ${C.red}44`,
            textAlign: "center"
          }}>
            <div style={{ fontSize: 32, fontWeight: 600, color: C.red }}>{health.critical}</div>
            <div style={{ fontSize: 12, color: C.muted }}>CRITICAL</div>
          </div>
          <div style={{
            padding: "12px 28px", borderRadius: 8, background: `${C.gold}15`, border: `1px solid ${C.gold}44`,
            textAlign: "center"
          }}>
            <div style={{ fontSize: 32, fontWeight: 600, color: C.gold }}>{health.high}</div>
            <div style={{ fontSize: 12, color: C.muted }}>HIGH</div>
          </div>
        </div>

        <div style={{
          display: "flex", flexWrap: "wrap", gap: 1, marginBottom: 48,
          background: C.border, borderRadius: 8, overflow: "hidden"
        }}>
          <div style={{ flex: 1, minWidth: 180, background: C.cardBg }}>
            <StatBox value={health.stats.unregistered_agent_api_calls} label={`API calls from unregistered agent (${health.stats.unregistered_agent_days}d)`} />
          </div>
          <div style={{ flex: 1, minWidth: 180, background: C.cardBg }}>
            <StatBox value={health.stats.anomalous_export_records} label="employee records in anomalous export" />
          </div>
          <div style={{ flex: 1, minWidth: 180, background: C.cardBg }}>
            <StatBox value={`${health.stats.oldest_sox_violation_days}d`} label="oldest SOX violation age" />
          </div>
          <div style={{ flex: 1, minWidth: 180, background: C.cardBg }}>
            <StatBox value={health.stats.self_approve_entities} label="entities that can approve own payments" />
          </div>
        </div>

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
                  {signal.blast_radius === -1 ? "UNKNOWN" : (typeof signal.blast_radius === "number" ? signal.blast_radius.toLocaleString() : signal.blast_radius)}
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

const FindingsFeed = ({ signals, isLive, onNavigate, onViewPackage }) => {
  const [priorityFilter, setPriorityFilter] = useState("ALL");
  const [classFilter, setClassFilter] = useState("ALL");

  const filtered = signals.filter(s => {
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
          <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
            <LiveBadge live={isLive} />
            <button onClick={() => onNavigate("dashboard")} style={{
              padding: "6px 14px", borderRadius: 4, border: `1px solid ${C.border}`,
              background: "transparent", color: C.muted, fontSize: 12, cursor: "pointer",
            }}>← Dashboard</button>
          </div>
        </div>

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
        {lines.filter(Boolean).map((l, i) => (
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
    tenant_id: signal.tenant_id || "meridian-financial",
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
    created_at: signal.created_at || new Date().toISOString()
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

        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 20, marginBottom: 28 }}>
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
                  {signal.blast_radius === -1 ? "?" : (typeof signal.blast_radius === "number" ? signal.blast_radius.toLocaleString() : signal.blast_radius)}
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
  const [health, setHealth] = useState(null);
  const [signals, setSignals] = useState(null);
  const [isLive, setIsLive] = useState(false);

  useEffect(() => {
    let mounted = true;
    async function load() {
      const [h, s] = await Promise.all([fetchHealth(), fetchSignals()]);
      if (mounted) {
        setHealth(h.data);
        setSignals(s.data);
        setIsLive(h.live && s.live);
      }
    }
    load();
    return () => { mounted = false; };
  }, []);

  const handleViewPackage = (signal) => {
    setSelectedSignal(signal);
    setScreen("package");
  };

  if (!health || !signals) return <Loader />;
  if (screen === "dashboard") return <Dashboard health={health} isLive={isLive} onNavigate={setScreen} />;
  if (screen === "findings") return <FindingsFeed signals={signals} isLive={isLive} onNavigate={setScreen} onViewPackage={handleViewPackage} />;
  if (screen === "package" && selectedSignal) return <SignalPackage signal={selectedSignal} onBack={() => setScreen("findings")} />;
  return <Dashboard health={health} isLive={isLive} onNavigate={setScreen} />;
}
