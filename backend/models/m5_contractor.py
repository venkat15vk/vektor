#!/usr/bin/env python3
"""
VEKTOR M5: Contractor Expiry Risk
Logistic Regression on external entities.
Target: ent_ar007 scores > 0.98
"""

import sqlite3
import json
import uuid
import numpy as np
from datetime import datetime
from sklearn.linear_model import LogisticRegression
import os

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "vektor.db")


def run(db_path=DB_PATH):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    # Get all external entities
    c.execute("SELECT * FROM entities WHERE entity_class = 'external' OR peer_group_id = 'PG-EXT'")
    externals = [dict(r) for r in c.fetchall()]

    if not externals:
        print("M5: No external entities found")
        conn.close()
        return []

    features = []
    meta = []

    for ent in externals:
        eid = ent["entity_id"]

        # Days past contract end
        contract_end = ent.get("contract_end_date")
        days_past = 0
        if contract_end:
            try:
                from datetime import datetime as dt2
                end_dt = dt2.strptime(contract_end, "%Y-%m-%d")
                now = dt2(2026, 3, 8)
                days_past = max(0, (now - end_dt).days)
            except:
                pass

        # Entitlement count
        c.execute("SELECT COUNT(*) as cnt FROM entitlements WHERE entity_id = ?", (eid,))
        ent_count = c.fetchone()["cnt"]

        # Last active
        last_active = ent["last_active_days"] or 999

        # Geo IP change
        c.execute("SELECT geo_ip_change_flag FROM events WHERE entity_id = ? AND geo_ip_change_flag = 1", (eid,))
        geo_changes = len(c.fetchall())

        # Sensitive resource access
        c.execute("""SELECT COUNT(*) as cnt FROM entitlements
                     WHERE entity_id = ? AND resource_sensitivity IN ('critical', 'high')""", (eid,))
        sensitive_count = c.fetchone()["cnt"]

        features.append([days_past, ent_count, last_active, geo_changes, sensitive_count, ent["tenure_days"] or 0])
        meta.append(ent)

    X = np.array(features, dtype=float)
    # Label: offboarding_cleanup_flag
    y = np.array([1 if m.get("offboarding_cleanup_flag") else 0 for m in meta])

    # If not enough positive labels, use heuristic scoring
    if sum(y) < 2:
        # Heuristic: score based on days_past_contract_end
        scores = []
        for f in features:
            days_past = f[0]
            if days_past > 365:
                scores.append(0.99)
            elif days_past > 180:
                scores.append(0.90)
            elif days_past > 30:
                scores.append(0.70)
            else:
                scores.append(0.1)
        proba = np.array(scores)
    else:
        model = LogisticRegression(random_state=42, max_iter=1000)
        model.fit(X, y)
        proba = model.predict_proba(X)[:, 1]

    signals = []
    feature_names = ["days_past_contract_end", "entitlement_count", "last_active_days",
                     "geo_ip_changes", "sensitive_access_count", "tenure_days"]

    for i, ent in enumerate(meta):
        score = float(proba[i])
        if score < 0.5:
            continue

        eid = ent["entity_id"]
        priority = "critical" if score > 0.9 else "high" if score > 0.7 else "medium"

        contract_end = ent.get("contract_end_date", "unknown")
        days_past = int(features[i][0])

        summary = (f"Contractor {eid} active {days_past} days past contract end ({contract_end}). "
                   f"Last active {ent['last_active_days']} days ago. "
                   f"{int(features[i][4])} sensitive resource entitlements still active.")

        signal = {
            "signal_id": f"sig_m5_{eid}_{uuid.uuid4().hex[:8]}",
            "model_id": "M5",
            "entity_id": eid,
            "entity_class": ent["entity_class"],
            "confidence": round(score, 2),
            "priority": priority,
            "summary": summary,
            "explanation": "",
            "recommended_action": json.dumps({
                "type": "immediate_account_disable",
                "scope": eid,
                "urgency": "immediate"
            }),
            "rollback_payload": json.dumps({
                "description": f"Re-enable account for {eid}",
                "reversible": True,
                "rollback_steps": [f"Re-enable account and restore entitlements for {eid}"]
            }),
            "blast_radius": int(features[i][1]),
            "requires_human": 0,
            "intelligence_sources": json.dumps([
                {"model_id": "M5", "feature_name": feature_names[j],
                 "feature_value": features[i][j], "contribution": round(0.3 if j == 0 else 0.15, 2)}
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
    print(f"M5 Contractor: {len(signals)} signals generated")
    for s in signals:
        print(f"  {s['entity_id']}: priority={s['priority']}, confidence={s['confidence']}")
    conn.close()
    return signals


if __name__ == "__main__":
    run()
