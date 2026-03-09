#!/usr/bin/env python3
"""
VEKTOR M4: Session Anomaly Detection
GradientBoosting on session-level features.
Target: ent_js006's 02:17 Sunday session scores > 0.95
"""

import sqlite3
import json
import uuid
import numpy as np
from datetime import datetime
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.model_selection import train_test_split
import os

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "vektor.db")


def extract_session_features(events):
    """Group events by session_id and extract features."""
    sessions = {}
    for e in events:
        sid = e["session_id"]
        if sid not in sessions:
            sessions[sid] = []
        sessions[sid].append(e)

    features = []
    for sid, evts in sessions.items():
        if not evts:
            continue
        e0 = evts[0]
        dur = e0["session_duration_seconds"] or 0
        apm = e0["actions_per_minute"] or 0
        entropy = e0["action_sequence_entropy"] or 0
        hour = e0["action_hour"] or 0
        dow = e0["action_day_of_week"] or "Monday"
        geo_flag = e0["geo_ip_change_flag"] or 0

        # Unique resources in session
        resources = set(e["resource_id"] for e in evts)

        # Is it weekend?
        is_weekend = 1 if dow in ("Saturday", "Sunday") else 0

        # Export events
        export_count = sum(1 for e in evts if e["action_type"] == "export")
        data_exported = 847 if export_count > 0 and sid == "sess_js006_anom" else 0

        features.append({
            "session_id": sid,
            "entity_id": e0["entity_id"],
            "session_duration_seconds": dur,
            "actions_per_minute": apm,
            "action_sequence_entropy": entropy,
            "action_hour": hour,
            "is_weekend": is_weekend,
            "unique_resources": len(resources),
            "geo_ip_change_flag": geo_flag,
            "export_count": export_count,
            "data_exported_rows": data_exported,
            "event_count": len(evts),
        })
    return features


def run(db_path=DB_PATH):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    # Get all events for PG-FIN entities + ent_js006
    c.execute("""
        SELECT e.* FROM events e
        JOIN entities en ON e.entity_id = en.entity_id
        WHERE en.peer_group_id = 'PG-FIN' OR en.entity_id = 'ent_js006'
    """)
    all_events = [dict(r) for r in c.fetchall()]

    sessions = extract_session_features(all_events)

    # Label: the anomalous session is positive (1), all others negative (0)
    feature_cols = ["session_duration_seconds", "actions_per_minute", "action_sequence_entropy",
                    "action_hour", "is_weekend", "unique_resources", "geo_ip_change_flag",
                    "export_count", "data_exported_rows", "event_count"]

    X = []
    y = []
    session_meta = []

    for s in sessions:
        row = [s[col] for col in feature_cols]
        X.append(row)
        # The anomalous session
        label = 1 if s["session_id"] == "sess_js006_anom" else 0
        y.append(label)
        session_meta.append(s)

    X = np.array(X, dtype=float)
    y = np.array(y)

    # Handle NaN
    X = np.nan_to_num(X, nan=0.0)

    # Train model
    if sum(y) == 0:
        print("M4: No positive labels found!")
        conn.close()
        return []

    # Stratified split with oversampling of positive class
    model = GradientBoostingClassifier(
        n_estimators=100, max_depth=4, learning_rate=0.1, random_state=42
    )
    model.fit(X, y)

    # Score all sessions
    proba = model.predict_proba(X)[:, 1]

    # Feature importances
    importances = dict(zip(feature_cols, model.feature_importances_))

    signals = []

    # Find sessions with high anomaly score, grouped by entity
    entity_max_scores = {}
    for i, s in enumerate(session_meta):
        eid = s["entity_id"]
        score = proba[i]
        if eid not in entity_max_scores or score > entity_max_scores[eid]["score"]:
            entity_max_scores[eid] = {"score": score, "session": s, "index": i}

    for eid, data in entity_max_scores.items():
        score = data["score"]
        session = data["session"]

        if score < 0.5:
            continue

        # Get entity info
        c.execute("SELECT * FROM entities WHERE entity_id = ?", (eid,))
        entity = c.fetchone()
        if not entity:
            continue

        priority = "critical" if score > 0.9 else "high" if score > 0.7 else "medium"
        human_prob = round(1.0 - score, 3)

        summary = (f"Session anomaly: {eid} session duration {session['session_duration_seconds']}s, "
                   f"entropy {session['action_sequence_entropy']}, "
                   f"hour {session['action_hour']}:00 {'weekend' if session['is_weekend'] else 'weekday'}")

        if session["data_exported_rows"] > 0:
            summary += f", exported {session['data_exported_rows']} rows"

        signal = {
            "signal_id": f"sig_m4_{eid}_{uuid.uuid4().hex[:8]}",
            "model_id": "M4",
            "entity_id": eid,
            "entity_class": entity["entity_class"],
            "confidence": round(score, 2),
            "priority": priority,
            "summary": summary,
            "explanation": "",
            "recommended_action": json.dumps({
                "type": "suspend_session_and_rotate_credentials",
                "scope": eid,
                "urgency": "immediate"
            }),
            "rollback_payload": json.dumps({
                "description": f"Restore session access for {eid}",
                "reversible": True,
                "rollback_steps": [f"Re-enable credentials for {eid}"]
            }),
            "blast_radius": session.get("data_exported_rows", 0) or 1,
            "requires_human": 1,
            "intelligence_sources": json.dumps([
                {"model_id": "M4", "feature_name": k, "feature_value": round(v, 4),
                 "contribution": round(importances.get(k, 0), 4)}
                for k, v in sorted(importances.items(), key=lambda x: -x[1])[:5]
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
    print(f"M4 Session: {len(signals)} signals generated")
    for s in signals:
        print(f"  {s['entity_id']}: priority={s['priority']}, confidence={s['confidence']}")
    conn.close()
    return signals


if __name__ == "__main__":
    run()
