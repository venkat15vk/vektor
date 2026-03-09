#!/usr/bin/env python3
"""
VEKTOR M6: Access Velocity (New Hire Risk)
GradientBoosting on entities with tenure < 90 days.
Labels: access_review_outcome = REVOKE on short-tenure entities
"""

import sqlite3
import json
import uuid
import numpy as np
from datetime import datetime
from sklearn.ensemble import GradientBoostingClassifier
import os

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "vektor.db")


def run(db_path=DB_PATH):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    # Focus on entities with relatively short tenure
    c.execute("SELECT * FROM entities WHERE tenure_days < 180")
    short_tenure = [dict(r) for r in c.fetchall()]

    if not short_tenure:
        print("M6: No short-tenure entities")
        conn.close()
        return []

    features = []
    meta = []

    for ent in short_tenure:
        eid = ent["entity_id"]
        tenure = ent["tenure_days"] or 1

        c.execute("SELECT COUNT(*) as cnt FROM entitlements WHERE entity_id = ?", (eid,))
        ent_count = c.fetchone()["cnt"]

        c.execute("""SELECT COUNT(*) as cnt FROM entitlements
                     WHERE entity_id = ? AND permission_level IN ('admin', 'owner', 'global_admin')""", (eid,))
        admin_count = c.fetchone()["cnt"]

        c.execute("SELECT COUNT(*) as cnt FROM events WHERE entity_id = ?", (eid,))
        event_count = c.fetchone()["cnt"]

        # Velocity = entitlements per day
        velocity = ent_count / tenure if tenure > 0 else 0

        features.append([tenure, ent_count, admin_count, event_count, velocity])
        meta.append(ent)

    X = np.array(features, dtype=float)
    X = np.nan_to_num(X, nan=0.0)
    y = np.array([1 if m.get("access_review_outcome") == "REVOKE" else 0 for m in meta])

    feature_names = ["tenure_days", "ent_count", "admin_count", "event_count", "velocity"]

    if sum(y) >= 1 and len(y) >= 5:
        model = GradientBoostingClassifier(n_estimators=50, max_depth=3, random_state=42)
        model.fit(X, y)
        proba = model.predict_proba(X)[:, 1]
    else:
        proba = np.array([min(1.0, f[4] * 2 + f[2] * 0.3) for f in features])

    signals = []
    for i, ent in enumerate(meta):
        score = float(proba[i])
        if score < 0.5:
            continue

        eid = ent["entity_id"]
        priority = "high" if score > 0.7 else "medium"

        summary = (f"Access velocity risk: {eid} accumulated {int(features[i][1])} entitlements "
                   f"in {int(features[i][0])} days (velocity: {features[i][4]:.2f}/day)")

        signal = {
            "signal_id": f"sig_m6_{eid}_{uuid.uuid4().hex[:8]}",
            "model_id": "M6",
            "entity_id": eid,
            "entity_class": ent["entity_class"],
            "confidence": round(score, 2),
            "priority": priority,
            "summary": summary,
            "explanation": "",
            "recommended_action": json.dumps({
                "type": "review_access_grants",
                "scope": eid,
                "urgency": "within_7d"
            }),
            "rollback_payload": json.dumps({
                "description": f"No rollback needed — review only",
                "reversible": True,
                "rollback_steps": []
            }),
            "blast_radius": 1,
            "requires_human": 1,
            "intelligence_sources": json.dumps([
                {"model_id": "M6", "feature_name": feature_names[j],
                 "feature_value": round(float(features[i][j]), 4), "contribution": 0.2}
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
    print(f"M6 Velocity: {len(signals)} signals generated")
    for s in signals:
        print(f"  {s['entity_id']}: priority={s['priority']}, confidence={s['confidence']}")
    conn.close()
    return signals


if __name__ == "__main__":
    run()
