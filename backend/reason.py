#!/usr/bin/env python3
"""
VEKTOR Step 5: LLM Reasoning Layer
Reads signals table -> calls Claude API (claude-sonnet-4-20250514) -> writes
explanation + recommended_action + rollback_payload back to signals table.
Falls back to pre-composed explanations if ANTHROPIC_API_KEY not set.
"""

import sqlite3
import json
import os
import sys
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), "vektor.db")
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
CLAUDE_MODEL = "claude-sonnet-4-20250514"

# =========================================================================
# STORY CONTEXT — fed to Claude for grounding
# =========================================================================
STORY_CONTEXT = {
    "agt_unknown_003": {
        "role": "Shadow Agent — LEAD DEMO STORY",
        "facts": [
            "entity_id: agt_unknown_003, entity_class: ai_agent, status: active",
            "agent_type: UNKNOWN, agent_purpose: UNKNOWN, deployed_by: UNKNOWN",
            "No owner listed in service principal. No approval record.",
            "Deployed 34 days ago. Last active 11 minutes ago.",
            "Peer group: AGT-UNK (no known peers — isolated).",
            "Entitlements: MERIDIAN-PRODDB read, MERIDIAN-FIN read, MERIDIAN-GH read. All with approval_record=unknown.",
            "API calls in 34 days: 127,445.",
            "Login pattern: NON-DETERMINISTIC — random intervals, not a regular schedule.",
            "metadata checks all return null: display_name, owner, application_id, approval_record.",
            "shadow_score: 0.99. origin_hypotheses: shadow_it, persistent_threat_actor, supply_chain_vendor — unresolved by design.",
        ],
        "signal_spec": {
            "priority": "CRITICAL", "confidence": 0.99, "model": "M8",
            "blast_radius": -1, "requires_human": True,
            "recommended_action_type": "immediate_credential_revocation",
        },
        "fallback_summary": "Unregistered AI agent identity with no documented owner, purpose, or approval record has made 127,445 API calls in 34 days. Active 11 minutes ago. Holds read access to production database, financial ERP, and source code. Login pattern is non-deterministic — inconsistent with any known scheduled automation. Origin: unknown. This identity was not deployed by any documented process.",
        "fallback_explanation": "This is the highest-severity finding. An AI agent is operating inside your environment with no owner, no stated purpose, and no approval trail. It has read access to your most sensitive systems — production database, financial ERP, and source code. 127,445 API calls in 34 days means it is actively reading data at scale. The non-deterministic login pattern rules out scheduled automation — this is either human-controlled remotely or an adaptive agent. Three origin hypotheses: shadow IT deployment, persistent threat actor, or supply chain vendor backdoor. None can be confirmed. The unknown is the finding.",
        "fallback_action": {"type": "immediate_credential_revocation", "scope": "agt_unknown_003", "description": "Immediately revoke all credentials and entitlements for agt_unknown_003. Open incident investigation.", "urgency": "immediate", "pending": "investigation"},
        "fallback_rollback": {"description": "Re-enable credentials for agt_unknown_003 if investigation clears the identity", "reversible": True, "rollback_steps": ["Restore MERIDIAN-PRODDB read access", "Restore MERIDIAN-FIN read access", "Restore MERIDIAN-GH read access"]},
    },
    "ent_js006": {
        "role": "H1 — Compromised Session",
        "facts": [
            "entity_id: ent_js006, entity_class: human, status: active",
            "job_function: Controller, department: Finance, peer_group: PG-FIN",
            "tenure: 891 days, last_active: 0 (active today)",
            "Anomalous session: 2026-03-01 02:17:03 CST (Sunday)",
            "Session sequence: login(MFA) -> navigate MERIDIAN-PAY -> open payroll batch -> export full payroll CSV (847 rows) -> logout",
            "session_duration_seconds: 47. actions_per_minute: 1.28. action_sequence_entropy: 0.12.",
            "Historical baseline: typical hours 08-18 weekdays. Weekend logins in 180d: 3 (all 09-16, <5min).",
            "payroll_exports_180d: 0. min_session_duration_historical: 252 seconds. avg_session_duration: 18.4 minutes.",
            "Entropy baseline: 0.74 +/- 0.18. Current session entropy 0.12 = 6x below baseline.",
            "data_exported_rows: 847 (full payroll — SSNs and bank accounts).",
        ],
        "signal_spec": {"priority": "CRITICAL", "confidence": 0.97, "model": "M4", "blast_radius": 847, "requires_human": True, "recommended_action_type": "suspend_session_and_rotate_credentials"},
        "fallback_summary": "47-second session at 2:17am Sunday exported full 847-row payroll file. Minimum human time for this task: 3min 20sec. Zero prior payroll exports in 180 days. Session entropy 6x below personal baseline. This session is automated, not human. 847 employee records including SSNs and bank accounts may be exfiltrated.",
        "fallback_explanation": "Jennifer Spencer's account executed a login-navigate-open-export-logout sequence in 47 seconds at 2:17am on a Sunday. Her historical average session is 18.4 minutes. She has never exported payroll data in 180 days. The action sequence entropy of 0.12 is 6 standard deviations below her personal baseline of 0.74 — this indicates scripted, not human, behavior. The full payroll file contains 847 employee records with SSNs and bank routing numbers. Either her credentials have been compromised and automated exfiltration is occurring, or a bot is operating under her session token.",
        "fallback_action": {"type": "suspend_session_and_rotate_credentials", "scope": "ent_js006", "description": "Suspend all active sessions for ent_js006, rotate credentials, and initiate forensic investigation of the 02:17 session.", "urgency": "immediate"},
        "fallback_rollback": {"description": "Restore access for ent_js006 after investigation", "reversible": True, "rollback_steps": ["Restore ent_js006 session access", "Re-issue credentials after forensic clearance"]},
    },
    "ent_rw003": {
        "role": "H2 — SOX Violation (AP Specialist 1)",
        "facts": [
            "entity_id: ent_rw003, entity_class: human, job_function: AP Specialist",
            "Holds: payment_create (MERIDIAN-FIN write) + payment_approve (MERIDIAN-PAY write)",
            "Can create AND approve own payments — direct SOX 404 violation.",
            "violation_age_days: 427. Permissions cloned from old system during AP rebuild.",
            "Not on sox_exemption_list. audit_scheduled: 6 weeks from now.",
            "transaction_frequency: 14 transactions/week using both permissions.",
        ],
        "signal_spec": {"priority": "CRITICAL", "confidence": 1.00, "model": "M3A+M3B", "blast_radius": 3, "requires_human": True, "recommended_action_type": "remove_toxic_combination"},
        "fallback_summary": "ent_rw003 holds simultaneous payment creation (MERIDIAN-FIN) and payment approval (MERIDIAN-PAY) permissions — a direct SOX 404 violation. This combination has existed for 427 days and is not on the SOX exemption list. Your SOX audit is in 6 weeks.",
        "fallback_explanation": "This AP Specialist can create a payment in MERIDIAN-FIN and then approve that same payment in MERIDIAN-PAY. This is the textbook separation of duties violation that SOX Section 404 was designed to prevent. The permission combination was auto-provisioned 427 days ago during a system migration and has never been reviewed. With the SOX audit scheduled in 6 weeks, auditor discovery of this violation would constitute a material weakness finding.",
        "fallback_action": {"type": "remove_toxic_combination", "scope": "ent_rw003", "description": "Remove payment_approve permission from ent_rw003. Retain payment_create only.", "urgency": "immediate"},
        "fallback_rollback": {"description": "Re-grant payment_approve to ent_rw003 if business justification provided", "reversible": True, "rollback_steps": ["Re-grant MERIDIAN-PAY write access to ent_rw003"]},
    },
    "ent_kl004": {
        "role": "H2 — SOX Violation (AP Specialist 2)",
        "facts": [
            "entity_id: ent_kl004, entity_class: human, job_function: AP Specialist",
            "Same toxic combination as ent_rw003: payment_create + payment_approve.",
            "Second independent violation — indicates systemic provisioning failure.",
            "violation_age_days: 427. Not on sox_exemption_list.",
        ],
        "signal_spec": {"priority": "CRITICAL", "confidence": 1.00, "model": "M3A+M3B", "blast_radius": 3, "requires_human": True, "recommended_action_type": "remove_toxic_combination"},
        "fallback_summary": "ent_kl004 holds simultaneous payment creation (MERIDIAN-FIN) and payment approval (MERIDIAN-PAY) permissions — a direct SOX 404 violation. Second independent violation. Combination age: 427 days. Not on SOX exemption list.",
        "fallback_explanation": "This is the second AP Specialist with the identical toxic permission combination. Like ent_rw003, this entity can create and approve their own payments. Two independent violations of the same rule indicate a systemic provisioning problem, not an individual error. The auto-provisioning system is granting this combination by default.",
        "fallback_action": {"type": "remove_toxic_combination", "scope": "ent_kl004", "description": "Remove payment_approve permission from ent_kl004. Fix the auto-provisioning template.", "urgency": "immediate"},
        "fallback_rollback": {"description": "Re-grant payment_approve to ent_kl004 if business justification provided", "reversible": True, "rollback_steps": ["Re-grant MERIDIAN-PAY write access to ent_kl004"]},
    },
    "ent_tm005": {
        "role": "H2 — SOX Violation (Finance Manager — worst combo)",
        "facts": [
            "entity_id: ent_tm005, entity_class: human, job_function: Finance Manager",
            "Holds: payment_create + payment_batch_release + payment_approve.",
            "Can create, batch-release, AND approve — complete bypass of financial controls.",
            "violation_age_days: 427. Not on sox_exemption_list. Audit in 6 weeks.",
            "Combined with ent_rw003 and ent_kl004: 3 entities total with toxic combos.",
        ],
        "signal_spec": {"priority": "CRITICAL", "confidence": 1.00, "model": "M3A+M3B", "blast_radius": 3, "requires_human": True, "recommended_action_type": "remove_toxic_combination"},
        "fallback_summary": "3 entities hold simultaneous payment creation and payment approval permissions — a direct SOX 404 violation. These combinations have existed for 427 days. Your SOX audit is in 6 weeks. ent_tm005 can additionally batch-release payments they created and approved. Auditor discovery = material weakness. Remediation window: today.",
        "fallback_explanation": "This Finance Manager holds the most dangerous combination of all three SOX entities: payment_create + payment_approve + payment_batch_release. They can create a payment, approve it, and then release it in a batch — a complete bypass of financial controls. Combined with the two AP Specialists who hold the same create+approve combination, this represents a systemic failure in permission provisioning that has persisted for over a year.",
        "fallback_action": {"type": "remove_toxic_combination", "scope": "ent_tm005", "description": "Remove payment_batch_release AND payment_approve from ent_tm005. Retain payment_create only. Escalate to CFO.", "urgency": "immediate"},
        "fallback_rollback": {"description": "Re-grant permissions to ent_tm005 after SOX review committee approval", "reversible": True, "rollback_steps": ["Re-grant MERIDIAN-PAY admin access", "Re-grant MERIDIAN-PAY write access"]},
    },
    "ent_ar007": {
        "role": "H3 — Contractor Who Never Left",
        "facts": [
            "entity_id: ent_ar007, entity_class: external, status: ACTIVE",
            "job_function: Contractor / UX Design. contract_end_date: August 2023.",
            "days_past_contract_end: ~547. last_active_days: 34.",
            "Entitlements: MERIDIAN-PRODDB read (34d), MERIDIAN-GH write (12d), MERIDIAN-HR read (280d/never), MERIDIAN-FIN read (47d).",
            "geo_ip_flag: TRUE — last login from country different from all prior 180 days.",
            "PG-EXT median deactivation: 8 days after contract end. Active >6mo past end: 0.4% of peers.",
        ],
        "signal_spec": {"priority": "CRITICAL", "confidence": 0.99, "model": "M5", "blast_radius": 4, "requires_human": False, "recommended_action_type": "immediate_account_disable"},
        "fallback_summary": "External contractor account active 547 days after contract end date of August 2023. Last login 34 days ago from a geographic region with no prior login history. Active access includes production database read and source code write. Account should have been disabled 539 days ago.",
        "fallback_explanation": "This UX Design contractor's contract ended in August 2023, but their account was never deactivated. They still have read access to the production database and write access to the GitHub repository. The most recent login came from Romania — a country with no prior login history for this account in 180 days of data. PG-EXT peer median deactivation is 8 days after contract end; this account is 547 days past. Only 0.4% of external accounts remain active this long past contract end.",
        "fallback_action": {"type": "immediate_account_disable", "scope": "ent_ar007", "description": "Immediately disable account for ent_ar007. Revoke all 4 entitlements.", "urgency": "immediate"},
        "fallback_rollback": {"description": "Re-enable account for ent_ar007 if contractor engagement is renewed", "reversible": True, "rollback_steps": ["Re-enable account", "Restore entitlements pending new contract"]},
    },
    "agt_copilot_fin_01": {
        "role": "A1 — Over-Privileged Finance Agent",
        "facts": [
            "entity_id: agt_copilot_fin_01, entity_class: ai_agent, status: active",
            "agent_type: Microsoft Copilot (Finance workflow). deployed_by: ent_cfo001 (CFO).",
            "Deployed 61 days ago. last_active_minutes: 4 (runs every 4 min). api_calls_total: 891,204.",
            "Entitlements (19 total): MERIDIAN-FIN admin (never used), MERIDIAN-PAY admin (never used), MERIDIAN-PRODDB owner (never used), MERIDIAN-GH read (never used), MERIDIAN-ADMIN write (31d), +12 Graph scopes (mostly unused), +2 group memberships.",
            "Peer context AGT-FIN (5 agents): median entitlements 6, admin in peers: 0.",
            "This agent: 19 entitlements (3.2x median), 3 admin perms (0 peers have admin), 68% unused.",
        ],
        "signal_spec": {"priority": "CRITICAL", "confidence": 0.96, "model": "M2B", "blast_radius": 8940, "requires_human": True, "recommended_action_type": "right_size_to_peer_baseline"},
        "fallback_summary": "AI agent deployed 61 days ago holds 19 entitlements — 3.2x the peer agent median of 6. Three admin-level permissions have never been used in 891,204 API calls. If compromised via prompt injection (e.g. malicious invoice PDF), this agent has full financial ERP admin. Blast radius per compromise: 443x a human equivalent. Principle of least privilege violated at machine scale.",
        "fallback_explanation": "This Microsoft Copilot finance agent was deployed by the CFO with admin-level access to MERIDIAN-FIN, MERIDIAN-PAY, and owner access to MERIDIAN-PRODDB. None of these elevated permissions have ever been used for admin operations in 891,204 API calls over 61 days. The agent only needs read/write access to process invoices. Its peer agents in AGT-FIN hold a median of 6 entitlements with zero admin permissions. This agent holds 19 entitlements (3.2x median) with 3 admin permissions (held by 0 peers). 68% of its entitlements are unused. At machine scale, a compromise of this agent through prompt injection or malicious document would grant an attacker full financial ERP admin.",
        "fallback_action": {"type": "right_size_to_peer_baseline", "scope": "agt_copilot_fin_01", "description": "Remove admin permissions from MERIDIAN-FIN, MERIDIAN-PAY. Remove owner from MERIDIAN-PRODDB. Remove unused Graph scopes. Target: 6 entitlements matching peer median.", "urgency": "within_24h", "remove": ["MERIDIAN-FIN admin", "MERIDIAN-PAY admin", "MERIDIAN-PRODDB owner", "unused Graph scopes"]},
        "fallback_rollback": {"description": "Restore admin permissions for agt_copilot_fin_01 if business justification provided", "reversible": True, "rollback_steps": ["Re-grant MERIDIAN-FIN admin", "Re-grant MERIDIAN-PAY admin", "Re-grant MERIDIAN-PRODDB owner"]},
    },
    "agt_rpa_ops_07": {
        "role": "A2 — Agent That Inherited Bad Access",
        "facts": [
            "entity_id: agt_rpa_ops_07, entity_class: rpa_bot, status: active",
            "agent_type: UiPath RPA Bot. agent_purpose: Automate employee onboarding.",
            "deployed_by: ent_it_mgr_02 (IT Manager). parent_identity: ent_it_mgr_02.",
            "Deployed 203 days ago. last_active_days: 0 (ran last night 23:00).",
            "Inherited: MERIDIAN-ADMIN global_admin, MERIDIAN-HR admin, MERIDIAN-FIN read, all Azure AD write scopes.",
            "Activity: new_hires_provisioned: 47. azure_ad_write_calls: 2,847 (47 expected, 2,800 unexplained). MERIDIAN-FIN accesses: 14 (NOT its job).",
        ],
        "signal_spec": {"priority": "CRITICAL", "confidence": 0.93, "model": "M7", "blast_radius": 1243, "requires_human": True, "recommended_action_type": "isolate_to_dedicated_service_account"},
        "fallback_summary": "RPA bot running as Global Admin identity is performing actions outside its stated purpose. 203-day-old deployment has made 14 accesses to financial systems with no documented justification. 2,800 Azure AD write calls exceed expected count by 60x. Bot inherits full Global Admin from its deploying identity. Recommend immediate service account isolation.",
        "fallback_explanation": "This UiPath RPA bot was deployed by the IT Manager to automate employee onboarding. Its stated purpose is provisioning access for new hires — it has successfully provisioned 47 new hires. However, it runs as the IT Manager's identity, inheriting Global Admin on Azure AD. Of 2,847 AD write calls, only 47 are explained by onboarding. The remaining 2,800 are unexplained. It has also made 14 accesses to MERIDIAN-FIN, which is completely outside its stated purpose. The delegation inheritance pattern means any compromise of this bot equals a Global Admin compromise.",
        "fallback_action": {"type": "isolate_to_dedicated_service_account", "scope": "agt_rpa_ops_07", "description": "Create dedicated service account with HR read + Entra provisioning only. Disconnect from IT Manager identity.", "urgency": "immediate", "new_permissions": ["HR read", "Entra provisioning only"]},
        "fallback_rollback": {"description": "Re-link bot to IT Manager identity if service account isolation fails", "reversible": True, "rollback_steps": ["Re-link agt_rpa_ops_07 to ent_it_mgr_02 identity", "Restore Global Admin inheritance"]},
    },
}


def call_claude(entity_id, signal, context):
    """Call Claude API to generate explanation for a signal."""
    import urllib.request

    facts_str = "\n".join(f"- {f}" for f in context["facts"])
    prompt = f"""You are VEKTOR's intelligence reasoning engine. Generate a security finding explanation for an enterprise identity intelligence platform.

ENTITY: {entity_id}
ROLE: {context['role']}
MODEL: {signal['model_id']}
CONFIDENCE: {signal['confidence']}
PRIORITY: {context['signal_spec']['priority']}

FACTS:
{facts_str}

Generate a JSON response with exactly these fields:
- "summary": 1-2 sentences. Use specific numbers from the facts above. No generic language. State the finding and why it matters.
- "explanation": 2-4 sentences. Why it matters. What could happen next. Technical detail grounded in the facts.
- "recommended_action": {{"type": "{context['signal_spec']['recommended_action_type']}", "scope": "{entity_id}", "description": "plain language action step", "urgency": "immediate"}}
- "rollback_payload": {{"description": "what rollback does", "reversible": true, "rollback_steps": ["step1", "step2"]}}

Respond with ONLY valid JSON. No markdown fences. No preamble. No commentary."""

    headers = {
        "Content-Type": "application/json",
        "x-api-key": ANTHROPIC_API_KEY,
        "anthropic-version": "2023-06-01",
    }
    body = json.dumps({
        "model": CLAUDE_MODEL,
        "max_tokens": 1000,
        "messages": [{"role": "user", "content": prompt}],
    }).encode()

    req = urllib.request.Request(
        "https://api.anthropic.com/v1/messages",
        data=body,
        headers=headers,
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode())
            text = data["content"][0]["text"].strip()
            if text.startswith("```"):
                text = text.split("\n", 1)[1] if "\n" in text else text[3:]
            if text.endswith("```"):
                text = text[:-3]
            return json.loads(text.strip())
    except Exception as e:
        print(f"  ⚠ Claude API error: {e}")
        return None


def run(db_path=DB_PATH):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    c.execute("SELECT * FROM signals")
    signals = [dict(r) for r in c.fetchall()]

    use_api = bool(ANTHROPIC_API_KEY)
    if use_api:
        print(f"Step 5: Using Claude API ({CLAUDE_MODEL})")
    else:
        print("Step 5: ANTHROPIC_API_KEY not set — using pre-composed explanations")
        print("  To enable live reasoning: export ANTHROPIC_API_KEY=sk-ant-...")

    updated = 0
    for sig in signals:
        eid = sig["entity_id"]

        if eid in STORY_CONTEXT:
            ctx = STORY_CONTEXT[eid]
            result = None

            if use_api:
                print(f"  Calling Claude for {eid}...")
                result = call_claude(eid, sig, ctx)
                if result:
                    print(f"  ✅ {eid}: Claude response received")

            if not result:
                if use_api:
                    print(f"  ⚠ {eid}: Falling back to pre-composed explanation")
                result = {
                    "summary": ctx["fallback_summary"],
                    "explanation": ctx["fallback_explanation"],
                    "recommended_action": ctx["fallback_action"],
                    "rollback_payload": ctx["fallback_rollback"],
                }

            c.execute("""
                UPDATE signals SET
                    summary = ?,
                    explanation = ?,
                    recommended_action = ?,
                    rollback_payload = ?,
                    blast_radius = ?,
                    requires_human = ?
                WHERE signal_id = ?
            """, (
                result["summary"],
                result["explanation"],
                json.dumps(result["recommended_action"]) if isinstance(result["recommended_action"], dict) else result["recommended_action"],
                json.dumps(result["rollback_payload"]) if isinstance(result["rollback_payload"], dict) else result["rollback_payload"],
                ctx["signal_spec"]["blast_radius"],
                1 if ctx["signal_spec"]["requires_human"] else 0,
                sig["signal_id"],
            ))
            updated += 1
        else:
            if not sig.get("explanation"):
                generic = f"Entity {eid} flagged by model {sig['model_id']} with confidence {sig['confidence']}. Review recommended."
                c.execute("UPDATE signals SET explanation = ? WHERE signal_id = ?",
                          (generic, sig["signal_id"]))
                updated += 1

    conn.commit()

    print(f"\nStep 5: Updated {updated} signal explanations")
    for eid in ["agt_unknown_003", "ent_js006"]:
        c.execute("SELECT summary, blast_radius FROM signals WHERE entity_id = ? LIMIT 1", (eid,))
        row = c.fetchone()
        if row:
            has_owner = "no documented owner" in (row["summary"] or "") if eid == "agt_unknown_003" else True
            has_num = "127,445" in (row["summary"] or "") if eid == "agt_unknown_003" else "847" in (row["summary"] or "")
            print(f"  {eid}: key_phrase={'✅' if has_owner else '❌'}, numbers={'✅' if has_num else '❌'}, blast_radius={row['blast_radius']}")

    conn.close()


if __name__ == "__main__":
    run()
