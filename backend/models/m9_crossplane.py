#!/usr/bin/env python3
"""
VEKTOR M9: Cross-Plane Amplifier
Signal fusion: combines M2B (peer deviation) + M7 (delegation) signals
for human-agent pairs. Identifies amplification risk.
"""

import sqlite3
import json
import uuid
import math
from datetime import datetime
import os

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "vektor.db")


def run(db_path=DB_PATH):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    # Find all (human, agent) pairs via deployed_by or parent_identity
    c.execute("""
        SELECT a.entity_id as agent_id, a.entity_class as agent_class,
               a.deployed_by, a.parent_identity
        FROM entities a
        WHERE a.entity_class IN ('ai_agent', 'rpa_bot', 'service_account', 'pipeline')
        AND (a.deployed_by IS NOT NULL AND a.deployed_by != '')
    """)
    pairs = [dict(r) for r in c.fetchall()]

    signals = []

    for pair in pairs:
        agent_id = pair["agent_id"]
        human_id = pair.get("parent_identity") or pair.get("deployed_by")
        if not human_id:
            continue

        # Get agent signals (M2B, M7, M8)
        c.execute("""
            SELECT * FROM signals
            WHERE entity_id = ? AND model_id IN ('M2B', 'M7', 'M8')
        """, (agent_id,))
        agent_signals = [dict(r) for r in c.fetchall()]

        # Get human signals (M1, M2B, M4, M5, M6)
        c.execute("""
            SELECT * FROM signals
            WHERE entity_id = ? AND model_id IN ('M1', 'M2B', 'M4', 'M5', 'M6')
        """, (human_id,))
        human_signals = [dict(r) for r in c.fetchall()]

        agent_risk = max([s["confidence"] for s in agent_signals], default=0.0)
        human_risk = max([s["confidence"] for s in human_signals], default=0.3)

        # Estimate API call multiplier from event count
        c.execute("SELECT COUNT(*) as cnt FROM events WHERE entity_id = ?", (agent_id,))
        agent_events = c.fetchone()["cnt"]
        # Scale: events in our sample represent fraction of actual calls
        estimated_api = agent_events * 850
        api_call_multiplier = estimated_api / 500 if estimated_api > 0 else 1

        # M9 formula from spec:
        # amplification_score = human_risk × (1 + log(api_call_multiplier)) × agent_risk
        if api_call_multiplier > 0:
            amplification = human_risk * (1 + math.log(api_call_multiplier)) * agent_risk
        else:
            amplification = 0

        if amplification <= 0.7:
            continue

        confidence = round(min(amplification / 3.0, 0.99), 2)  # Normalize to 0-1
        priority = "critical" if amplification > 1.5 else "high"

        summary = (f"Cross-plane amplification: {agent_id} deployed by {human_id}. "
                   f"Agent risk {agent_risk:.2f} × human risk {human_risk:.2f} × "
                   f"{int(api_call_multiplier)}x API volume = amplification {amplification:.2f}. "
                   f"Compromise produces {int(api_call_multiplier)}x human-equivalent blast radius.")

        signal = {
            "signal_id": f"sig_m9_{agent_id}_{uuid.uuid4().hex[:8]}",
            "model_id": "M9",
            "entity_id": agent_id,
            "entity_class": pair["agent_class"],
            "confidence": confidence,
            "priority": priority,
            "summary": summary,
            "explanation": "",
            "recommended_action": json.dumps({
                "type": "cross_plane_review",
                "scope": f"{human_id},{agent_id}",
                "description": f"Review delegation chain from {human_id} to {agent_id}",
                "urgency": "immediate"
            }),
            "rollback_payload": json.dumps({
                "description": f"No rollback — requires investigation",
                "reversible": False,
                "rollback_steps": []
            }),
            "blast_radius": int(api_call_multiplier),
            "requires_human": 1,
            "intelligence_sources": json.dumps([
                {"model_id": "M9", "feature_name": "human_risk_score", "feature_value": round(human_risk, 4), "contribution": 0.3},
                {"model_id": "M9", "feature_name": "agent_risk_score", "feature_value": round(agent_risk, 4), "contribution": 0.4},
                {"model_id": "M9", "feature_name": "api_call_multiplier", "feature_value": round(api_call_multiplier, 2), "contribution": 0.3},
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
    print(f"M9 Cross-Plane: {len(signals)} signals generated")
    for s in signals:
        print(f"  {s['entity_id']}: priority={s['priority']}, confidence={s['confidence']}, amplification")
    conn.close()
    return signals


if __name__ == "__main__":
    run()
