#!/usr/bin/env python3
"""
VEKTOR M3: Separation of Duties
M3A: Rule engine — detects payment_create + payment_approve combos
M3B: Severity scorer — ranks by age, transaction freq, exemption status
"""

import sqlite3
import json
import uuid
from datetime import datetime
import os

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "vektor.db")

# SoD matrix: toxic permission combinations
SOD_RULES = [
    {
        "name": "payment_create_and_approve",
        "description": "Entity can create AND approve payments — direct SOX 404 violation",
        "conditions": [
            {"resource_id": "res_fin", "min_permission": "write"},   # payment_create
            {"resource_id": "res_pay", "min_permission": "write"},   # payment_approve
        ]
    },
    {
        "name": "payment_create_approve_and_batch_release",
        "description": "Entity can create, approve, AND batch-release payments",
        "conditions": [
            {"resource_id": "res_fin", "min_permission": "admin"},   # payment_create (admin)
            {"resource_id": "res_pay", "min_permission": "admin"},   # payment_approve (admin)
            {"resource_id": "res_pay", "min_permission": "write"},   # batch_release
        ]
    }
]

PERMISSION_HIERARCHY = {"global_admin": 5, "admin": 4, "owner": 3, "write": 2, "read": 1, "none": 0}
SOX_EXEMPTION_LIST = []  # None of the story entities are exempted


def run(db_path=DB_PATH):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    # Get all human entities in Finance
    c.execute("SELECT * FROM entities WHERE department = 'Finance' AND entity_class = 'human'")
    finance_humans = c.fetchall()

    signals = []

    for entity in finance_humans:
        eid = entity["entity_id"]

        # Get entitlements
        c.execute("SELECT * FROM entitlements WHERE entity_id = ?", (eid,))
        ents = c.fetchall()

        # Check each SoD rule
        for rule in SOD_RULES:
            conditions_met = True
            for cond in rule["conditions"]:
                has_perm = False
                for ent in ents:
                    if (ent["resource_id"] == cond["resource_id"] and
                        PERMISSION_HIERARCHY.get(ent["permission_level"], 0) >=
                        PERMISSION_HIERARCHY.get(cond["min_permission"], 0)):
                        has_perm = True
                        break
                if not has_perm:
                    conditions_met = False
                    break

            if conditions_met and eid not in SOX_EXEMPTION_LIST:
                # M3B severity scoring
                max_age = max((e["entitlement_age_days"] or 0) for e in ents)

                # Count events (transaction frequency)
                c.execute("SELECT COUNT(*) as cnt FROM events WHERE entity_id = ?", (eid,))
                tx_count = c.fetchone()["cnt"]

                severity = min(1.0, 0.5 + (max_age / 1000) + (tx_count / 200) * 0.1)
                confidence = 1.00  # Deterministic rule — always 1.0

                summary_parts = []
                if "batch_release" in rule["name"]:
                    summary_parts.append(f"{eid} holds payment_create + payment_approve + payment_batch_release permissions")
                else:
                    summary_parts.append(f"{eid} holds payment_create + payment_approve permissions")
                summary_parts.append(f"Violation age: {max_age} days. Not on SOX exemption list.")

                signal = {
                    "signal_id": f"sig_m3_{eid}_{uuid.uuid4().hex[:8]}",
                    "model_id": "M3A+M3B",
                    "entity_id": eid,
                    "entity_class": entity["entity_class"],
                    "confidence": confidence,
                    "priority": "critical",
                    "summary": " ".join(summary_parts),
                    "explanation": "",
                    "recommended_action": json.dumps({
                        "type": "remove_toxic_combination",
                        "scope": eid,
                        "description": f"Remove one side of the {rule['name']} combination",
                        "urgency": "immediate"
                    }),
                    "rollback_payload": json.dumps({
                        "description": f"Restore permission combination for {eid}",
                        "reversible": True,
                        "rollback_steps": ["Re-grant removed permission after SOX review"]
                    }),
                    "blast_radius": 3,
                    "requires_human": 1,
                    "intelligence_sources": json.dumps([
                        {"model_id": "M3A", "feature_name": "sod_rule", "feature_value": rule["name"], "contribution": 0.7},
                        {"model_id": "M3B", "feature_name": "violation_age_days", "feature_value": max_age, "contribution": 0.2},
                        {"model_id": "M3B", "feature_name": "transaction_frequency", "feature_value": tx_count, "contribution": 0.1},
                    ]),
                    "created_at": datetime.now().isoformat(),
                }
                signals.append(signal)

    # Write signals
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
    print(f"M3 SoD: {len(signals)} signals generated")
    for s in signals:
        print(f"  {s['entity_id']}: {s['priority']}, confidence={s['confidence']}")
    conn.close()
    return signals


if __name__ == "__main__":
    run()
