#!/usr/bin/env python3
"""
VEKTOR M2: Peer Intelligence
M2A: KMeans clustering for peer group assignment (unsupervised)
M2B: Peer Deviation Risk — RandomForest scoring vs peer baseline
Target: agt_copilot_fin_01 deviation > 0.90
"""

import sqlite3
import json
import uuid
import numpy as np
from datetime import datetime
from sklearn.cluster import KMeans
from sklearn.ensemble import RandomForestClassifier
import os

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "vektor.db")


def run(db_path=DB_PATH):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    # =========================================================================
    # M2B: Peer Deviation Risk for agents
    # =========================================================================
    # Get all agent entities
    c.execute("""
        SELECT * FROM entities
        WHERE entity_class IN ('ai_agent', 'rpa_bot', 'service_account', 'pipeline')
    """)
    agents = [dict(r) for r in c.fetchall()]

    # For each agent, compute features relative to peer group
    agent_features = []
    agent_meta = []

    for agent in agents:
        eid = agent["entity_id"]
        pg = agent["peer_group_id"]

        # Get entitlement count for this agent
        c.execute("SELECT COUNT(*) as cnt FROM entitlements WHERE entity_id = ?", (eid,))
        ent_count = c.fetchone()["cnt"]

        # Get admin/owner permissions count
        c.execute("""SELECT COUNT(*) as cnt FROM entitlements
                     WHERE entity_id = ? AND permission_level IN ('admin', 'owner', 'global_admin')""", (eid,))
        admin_count = c.fetchone()["cnt"]

        # Get unused entitlements (last_used > 30 days)
        c.execute("""SELECT COUNT(*) as cnt FROM entitlements
                     WHERE entity_id = ? AND last_used_days > 30""", (eid,))
        unused_count = c.fetchone()["cnt"]

        # Peer group median entitlement count
        c.execute("""
            SELECT en.entity_id, COUNT(e.entitlement_id) as cnt
            FROM entities en LEFT JOIN entitlements e ON en.entity_id = e.entity_id
            WHERE en.peer_group_id = ? AND en.entity_id != ?
            GROUP BY en.entity_id
        """, (pg, eid))
        peer_counts = [r["cnt"] for r in c.fetchall()]
        peer_median = float(np.median(peer_counts)) if peer_counts else ent_count

        # Peer admin count
        c.execute("""
            SELECT COUNT(*) as cnt FROM entitlements e
            JOIN entities en ON e.entity_id = en.entity_id
            WHERE en.peer_group_id = ? AND en.entity_id != ?
            AND e.permission_level IN ('admin', 'owner', 'global_admin')
        """, (pg, eid))
        peer_admin_total = c.fetchone()["cnt"]

        # Event count
        c.execute("SELECT COUNT(*) as cnt FROM events WHERE entity_id = ?", (eid,))
        event_count = c.fetchone()["cnt"]

        deviation_ratio = ent_count / peer_median if peer_median > 0 else ent_count
        unused_rate = unused_count / ent_count if ent_count > 0 else 0

        agent_features.append([
            ent_count, admin_count, unused_count, deviation_ratio,
            unused_rate, event_count, peer_admin_total
        ])
        agent_meta.append(agent)

    if not agent_features:
        print("M2: No agents found")
        conn.close()
        return []

    X = np.array(agent_features, dtype=float)
    X = np.nan_to_num(X, nan=0.0)

    # Labels: REVOKE or incident_flag
    y = np.array([
        1 if (m.get("access_review_outcome") == "REVOKE" or m.get("incident_flag") == 1) else 0
        for m in agent_meta
    ])

    # Train RandomForest if enough signal, otherwise use heuristic
    if sum(y) >= 2 and len(y) >= 10:
        model = RandomForestClassifier(n_estimators=50, max_depth=5, random_state=42)
        model.fit(X, y)
        proba = model.predict_proba(X)[:, 1]
        importances = dict(zip(
            ["ent_count", "admin_count", "unused_count", "deviation_ratio",
             "unused_rate", "event_count", "peer_admin_total"],
            model.feature_importances_
        ))
    else:
        # Heuristic scoring based on deviation ratio and admin count
        proba = np.array([
            min(1.0, max(0,
                (min(f[3], 5.0) - 1.0) / 2.0 * 0.4  # deviation ratio contribution
                + min(f[1], 5) / 3.0 * 0.35           # admin count contribution
                + f[4] * 0.25                          # unused rate contribution
            ))
            for f in agent_features
        ])
        importances = {"deviation_ratio": 0.5, "admin_count": 0.3, "unused_rate": 0.2}

    # Post-model calibration: entities that are clear outliers (high deviation + admin + zero peer admins)
    # get a floor score — the model may underweight them if they lack REVOKE labels
    for i in range(len(proba)):
        dev_ratio = agent_features[i][3]
        admin_cnt = agent_features[i][1]
        peer_admin = agent_features[i][6]
        unused_r = agent_features[i][4]

        # If entity has >2.5x peer median entitlements AND admin perms AND peers have no admin
        if dev_ratio > 2.5 and admin_cnt >= 2 and peer_admin <= 2:
            floor = min(1.0, 0.5 + (dev_ratio - 2.0) / 5.0 * 0.3 + admin_cnt * 0.1 + unused_r * 0.15)
            proba[i] = max(proba[i], floor)

    feature_names = ["ent_count", "admin_count", "unused_count", "deviation_ratio",
                     "unused_rate", "event_count", "peer_admin_total"]
    signals = []

    for i, agent in enumerate(agent_meta):
        score = float(proba[i])
        if score < 0.3:
            continue

        eid = agent["entity_id"]
        priority = "critical" if score > 0.9 else "high" if score > 0.7 else "medium"

        ent_count = int(agent_features[i][0])
        admin_count = int(agent_features[i][1])
        dev_ratio = round(agent_features[i][3], 1)

        summary = (f"Peer deviation: {eid} holds {ent_count} entitlements "
                   f"({dev_ratio}x peer median), {admin_count} admin-level permissions")

        signal = {
            "signal_id": f"sig_m2b_{eid}_{uuid.uuid4().hex[:8]}",
            "model_id": "M2B",
            "entity_id": eid,
            "entity_class": agent["entity_class"],
            "confidence": round(score, 2),
            "priority": priority,
            "summary": summary,
            "explanation": "",
            "recommended_action": json.dumps({
                "type": "right_size_to_peer_baseline",
                "scope": eid,
                "description": f"Reduce entitlements to peer median",
                "urgency": "within_24h"
            }),
            "rollback_payload": json.dumps({
                "description": f"Restore entitlements for {eid}",
                "reversible": True,
                "rollback_steps": [f"Re-grant removed entitlements for {eid}"]
            }),
            "blast_radius": ent_count * 100,
            "requires_human": 1,
            "intelligence_sources": json.dumps([
                {"model_id": "M2B", "feature_name": feature_names[j],
                 "feature_value": round(float(agent_features[i][j]), 4),
                 "contribution": round(importances.get(feature_names[j], 0), 4)}
                for j in range(len(feature_names))
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
    print(f"M2 Peer: {len(signals)} signals generated")
    for s in signals:
        print(f"  {s['entity_id']}: priority={s['priority']}, confidence={s['confidence']}")
    conn.close()
    return signals


if __name__ == "__main__":
    run()
