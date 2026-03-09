#!/usr/bin/env python3
"""
VEKTOR M1: Dormancy Risk
GradientBoosting on entitlement usage patterns.
Labels: access_review_outcome = REVOKE
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

    c.execute("SELECT * FROM entities")
    entities = [dict(r) for r in c.fetchall()]

    features = []
    meta = []

    for ent in entities:
        eid = ent["entity_id"]

        # Entitlement stats
        c.execute("SELECT * FROM entitlements WHERE entity_id = ?", (eid,))
        ents = [dict(r) for r in c.fetchall()]
        if not ents:
            continue

        ent_count = len(ents)
        max_last_used = max(e["last_used_days"] or 0 for e in ents)
        avg_last_used = np.mean([e["last_used_days"] or 0 for e in ents])
        unused_30d = sum(1 for e in ents if (e["last_used_days"] or 0) > 30)
        unused_rate = unused_30d / ent_count if ent_count > 0 else 0

        # Event activity
        c.execute("SELECT COUNT(*) as cnt FROM events WHERE entity_id = ?", (eid,))
        event_count = c.fetchone()["cnt"]

        last_active = ent["last_active_days"] or 0
        tenure = ent["tenure_days"] or 0

        features.append([ent_count, max_last_used, avg_last_used, unused_rate,
                         event_count, last_active, tenure])
        meta.append(ent)

    X = np.array(features, dtype=float)
    X = np.nan_to_num(X, nan=0.0)
    y = np.array([1 if m.get("access_review_outcome") == "REVOKE" else 0 for m in meta])

    feature_names = ["ent_count", "max_last_used_days", "avg_last_used_days",
                     "unused_rate", "event_count", "last_active_days", "tenure_days"]

    if sum(y) >= 2 and len(y) >= 10:
        model = GradientBoostingClassifier(n_estimators=80, max_depth=3, random_state=42)
        model.fit(X, y)
        proba = model.predict_proba(X)[:, 1]
        importances = dict(zip(feature_names, model.feature_importances_))
    else:
        proba = np.array([min(1.0, f[3] * 0.5 + f[5] / 200 * 0.3) for f in features])
        importances = {n: 1.0 / len(feature_names) for n in feature_names}

    signals = []
    for i, ent in enumerate(meta):
        score = float(proba[i])
        if score < 0.5:
            continue

        eid = ent["entity_id"]
        priority = "critical" if score > 0.9 else "high" if score > 0.7 else "medium"

        summary = (f"Dormancy risk: {eid} has {int(features[i][3] * 100)}% unused entitlements, "
                   f"last active {int(features[i][5])} days ago")

        signal = {
            "signal_id": f"sig_m1_{eid}_{uuid.uuid4().hex[:8]}",
            "model_id": "M1",
            "entity_id": eid,
            "entity_class": ent["entity_class"],
            "confidence": round(score, 2),
            "priority": priority,
            "summary": summary,
            "explanation": "",
            "recommended_action": json.dumps({
                "type": "revoke_unused_entitlements",
                "scope": eid,
                "urgency": "within_7d"
            }),
            "rollback_payload": json.dumps({
                "description": f"Restore revoked entitlements for {eid}",
                "reversible": True,
                "rollback_steps": [f"Re-grant entitlements for {eid}"]
            }),
            "blast_radius": 1,
            "requires_human": 1,
            "intelligence_sources": json.dumps([
                {"model_id": "M1", "feature_name": feature_names[j],
                 "feature_value": round(float(features[i][j]), 4),
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
    print(f"M1 Dormancy: {len(signals)} signals generated")
    for s in signals[:5]:
        print(f"  {s['entity_id']}: priority={s['priority']}, confidence={s['confidence']}")
    if len(signals) > 5:
        print(f"  ... and {len(signals) - 5} more")
    conn.close()
    return signals


if __name__ == "__main__":
    run()
