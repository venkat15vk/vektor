#!/usr/bin/env python3
"""
VEKTOR Step 8: Agent Scene
Watches for CRITICAL signals → logs mock ServiceNow ticket,
Slack notification, rollback storage, and audit log.
~40 lines of core logic.
"""

import sqlite3
import json
import uuid
import time
from datetime import datetime
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "vektor.db")


def run_agent(db_path=DB_PATH, target_entity="agt_unknown_003"):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    # Find the highest-priority signal for the target entity
    c.execute("""
        SELECT * FROM signals
        WHERE entity_id = ? AND priority = 'critical'
        ORDER BY confidence DESC LIMIT 1
    """, (target_entity,))
    signal = c.fetchone()

    if not signal:
        print(f"No critical signal found for {target_entity}")
        conn.close()
        return []

    sig = dict(signal)
    signal_id = sig["signal_id"]
    inc_number = f"INC{random_inc()}"
    now = datetime.now().isoformat()

    # Mock actions sequence
    actions = [
        {
            "signal_id": signal_id,
            "action_type": "signal_received",
            "description": json.dumps({
                "line": f"VEKTOR signal received",
                "detail": f"signal_id: {signal_id}  priority: CRITICAL  confidence: {sig['confidence']}"
            }),
            "created_at": now,
        },
        {
            "signal_id": signal_id,
            "action_type": "entity_identified",
            "description": json.dumps({
                "line": f"entity: {target_entity}  model: {sig['model_id']}_SHADOW_IDENTITY",
                "detail": ""
            }),
            "created_at": now,
        },
        {
            "signal_id": signal_id,
            "action_type": "requires_human_check",
            "description": json.dumps({
                "line": "Evaluating requires_human flag... TRUE",
                "detail": "Final revocation requires human approval"
            }),
            "created_at": now,
        },
        {
            "signal_id": signal_id,
            "action_type": "servicenow_ticket",
            "description": json.dumps({
                "line": f"[✓] ServiceNow ticket created → {inc_number}",
                "detail": f"Title: \"CRITICAL: Unregistered AI agent — immediate investigation\"",
                "extra": f"Assigned to: CISO | Priority: P1"
            }),
            "created_at": now,
        },
        {
            "signal_id": signal_id,
            "action_type": "slack_notification",
            "description": json.dumps({
                "line": "[✓] Slack notification sent → #security-critical",
                "detail": f"\"@ciso @secops VEKTOR detected unregistered agent. {inc_number} opened.\""
            }),
            "created_at": now,
        },
        {
            "signal_id": signal_id,
            "action_type": "rollback_stored",
            "description": json.dumps({
                "line": f"[✓] Rollback payload stored → {inc_number}",
                "detail": f"Action on approval: revoke all 3 entitlements for {target_entity}"
            }),
            "created_at": now,
        },
        {
            "signal_id": signal_id,
            "action_type": "audit_log",
            "description": json.dumps({
                "line": f"[✓] Audit log written → vektor-audit-{datetime.now().strftime('%Y-%m-%d')}",
                "detail": ""
            }),
            "created_at": now,
        },
        {
            "signal_id": signal_id,
            "action_type": "complete",
            "description": json.dumps({
                "line": "Agent response complete. Awaiting human confirmation for revocation.",
                "detail": "requires_human: TRUE for final revocation step."
            }),
            "created_at": now,
        },
    ]

    # Write to mock_actions table
    for action in actions:
        c.execute("""
            INSERT INTO mock_actions (signal_id, action_type, description, created_at)
            VALUES (?, ?, ?, ?)
        """, (action["signal_id"], action["action_type"], action["description"], action["created_at"]))

    conn.commit()
    conn.close()

    print(f"Agent: {len(actions)} mock actions created for {target_entity}")
    for a in actions:
        desc = json.loads(a["description"])
        print(f"  > {desc['line']}")

    return actions


def random_inc():
    import random
    return f"00{random.randint(40000, 99999)}"


if __name__ == "__main__":
    run_agent()
