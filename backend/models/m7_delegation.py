#!/usr/bin/env python3
"""
VEKTOR M7: Delegation Inheritance Risk
Rule engine + anomaly scoring for agents running as another identity.
Target: agt_rpa_ops_07 flagged for inherited Global Admin
"""

import sqlite3
import json
import uuid
from datetime import datetime
import os

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "vektor.db")


def run(db_path=DB_PATH):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    # Get agents with parent_identity set (delegation)
    c.execute("""
        SELECT * FROM entities
        WHERE entity_class IN ('ai_agent', 'rpa_bot', 'service_account', 'pipeline')
        AND (parent_identity IS NOT NULL AND parent_identity != '')
    """)
    delegated_agents = [dict(r) for r in c.fetchall()]

    # Also check agents with deployed_by
    c.execute("""
        SELECT * FROM entities
        WHERE entity_class IN ('ai_agent', 'rpa_bot', 'service_account', 'pipeline')
        AND (deployed_by IS NOT NULL AND deployed_by != '')
        AND (parent_identity IS NULL OR parent_identity = '')
    """)
    deployed_agents = [dict(r) for r in c.fetchall()]

    all_agents = delegated_agents + deployed_agents
    signals = []

    for agent in all_agents:
        eid = agent["entity_id"]
        parent = agent.get("parent_identity") or agent.get("deployed_by")
        if not parent:
            continue

        # Get agent's entitlements
        c.execute("SELECT * FROM entitlements WHERE entity_id = ?", (eid,))
        agent_ents = [dict(r) for r in c.fetchall()]

        # Get parent's entitlements
        c.execute("SELECT * FROM entitlements WHERE entity_id = ?", (parent,))
        parent_ents = [dict(r) for r in c.fetchall()]

        # Check for excess permissions
        high_perms = [e for e in agent_ents
                      if e["permission_level"] in ("global_admin", "admin", "owner")]

        # Get agent's stated purpose
        purpose = agent.get("agent_purpose", "")

        # Count activity outside stated purpose
        c.execute("SELECT * FROM events WHERE entity_id = ?", (eid,))
        events = [dict(r) for r in c.fetchall()]

        # Scoring factors
        has_global_admin = any(e["permission_level"] == "global_admin" for e in agent_ents)
        has_admin = any(e["permission_level"] in ("admin", "owner") for e in agent_ents)
        excess_perm_count = len(high_perms)

        # Events outside expected resources
        expected_resources = set()
        if "onboarding" in (purpose or "").lower():
            expected_resources = {"res_hr", "res_admin"}
        elif "invoice" in (purpose or "").lower() or "financial" in (purpose or "").lower():
            expected_resources = {"res_fin", "res_pay"}

        unexpected_events = [e for e in events if e["resource_id"] not in expected_resources] if expected_resources else []
        unexpected_rate = len(unexpected_events) / len(events) if events else 0

        # Inheritance score
        score = 0.0
        rules_triggered = []

        if has_global_admin:
            score += 0.50
            rules_triggered.append("global_admin_inherited")
        elif has_admin:
            score += 0.25
            rules_triggered.append("admin_inherited")

        if excess_perm_count > 2:
            score += 0.20
            rules_triggered.append(f"excess_permissions_{excess_perm_count}")

        if unexpected_rate > 0.1:
            score += 0.20
            rules_triggered.append(f"unexpected_activity_{unexpected_rate:.0%}")

        if agent.get("parent_identity"):
            score += 0.10
            rules_triggered.append("runs_as_parent_identity")

        if len(agent_ents) > len(parent_ents) * 0.8:
            score += 0.10
            rules_triggered.append("near_full_inheritance")

        score = min(score, 1.0)

        if score < 0.4:
            continue

        priority = "critical" if score > 0.85 else "high" if score > 0.6 else "medium"

        summary = (f"Delegation risk: {eid} inherits {excess_perm_count} elevated permissions from {parent}. "
                   f"{len(unexpected_events)} events outside stated purpose. "
                   f"Rules triggered: {', '.join(rules_triggered)}")

        signal = {
            "signal_id": f"sig_m7_{eid}_{uuid.uuid4().hex[:8]}",
            "model_id": "M7",
            "entity_id": eid,
            "entity_class": agent["entity_class"],
            "confidence": round(score, 2),
            "priority": priority,
            "summary": summary,
            "explanation": "",
            "recommended_action": json.dumps({
                "type": "isolate_to_dedicated_service_account",
                "scope": eid,
                "new_permissions": ["HR read", "Entra provisioning only"],
                "urgency": "immediate"
            }),
            "rollback_payload": json.dumps({
                "description": f"Restore inherited permissions for {eid}",
                "reversible": True,
                "rollback_steps": [f"Re-link {eid} to parent identity {parent}"]
            }),
            "blast_radius": 1243,
            "requires_human": 1,
            "intelligence_sources": json.dumps([
                {"model_id": "M7", "feature_name": r, "feature_value": 1, "contribution": 0.2}
                for r in rules_triggered
            ]),
            "created_at": datetime.now().isoformat(),
        }
        signals.append(signal)

    for sig in signals:
        c.execute("""
            INSERT OR REPLACE INTO signals
            (signal_id, model_id, entity_id, entity_class, confidence, priority,
             summary, explanation, recommended_action, rollback_payload,
             blast_radius, requires_human, intelligence_sources, created_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (sig["signal_id"], sig["model_id"], sig["entity_id"], sig["entity_class"],
              sig["confidence"], sig["priority"], sig["summary"], sig["explanation"],
              sig["recommended_action"], sig["rollback_payload"], sig["blast_radius"],
              sig["requires_human"], sig["intelligence_sources"], sig["created_at"]))

    conn.commit()
    print(f"M7 Delegation: {len(signals)} signals generated")
    for s in signals:
        print(f"  {s['entity_id']}: priority={s['priority']}, confidence={s['confidence']}")
    conn.close()
    return signals


if __name__ == "__main__":
    run()
