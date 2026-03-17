#!/usr/bin/env python3
"""
VEKTOR M11: Peer Deviation on Cloud IAM Roles
Identifies roles with far more permissions than their peers.
"""

import sqlite3
import json
import os
import uuid
import statistics
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "vektor.db")


def run(db_path=DB_PATH):
    print("M11: Cloud IAM Peer Deviation Analysis")
    
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    
    # Get entitlement counts per entity, grouped by cloud
    c.execute("""
        SELECT e.entity_id, e.job_function, e.department, e.agent_type,
               COUNT(ent.entitlement_id) as ent_count,
               SUM(CASE WHEN ent.permission_level = 'admin' THEN 1 ELSE 0 END) as admin_count,
               SUM(CASE WHEN ent.permission_level = 'write' THEN 1 ELSE 0 END) as write_count,
               SUM(CASE WHEN ent.resource_sensitivity = 'critical' THEN 1 ELSE 0 END) as critical_resource_count
        FROM entities e
        JOIN entitlements ent ON e.entity_id = ent.entity_id
        WHERE e.department IN ('AWS', 'Azure', 'GCP')
        GROUP BY e.entity_id
    """)
    
    entities = [dict(r) for r in c.fetchall()]
    print(f"  Analyzing {len(entities)} cloud IAM entities...")
    
    # Group by cloud for peer comparison
    by_cloud = {}
    for e in entities:
        cloud = e["department"]
        if cloud not in by_cloud:
            by_cloud[cloud] = []
        by_cloud[cloud].append(e)
    
    signals = []
    
    for cloud, peers in by_cloud.items():
        if len(peers) < 3:
            continue
        
        ent_counts = [p["ent_count"] for p in peers]
        admin_counts = [p["admin_count"] for p in peers]
        
        median_ent = statistics.median(ent_counts)
        mean_ent = statistics.mean(ent_counts)
        stdev_ent = statistics.stdev(ent_counts) if len(ent_counts) > 1 else 1
        median_admin = statistics.median(admin_counts)
        
        p75 = sorted(ent_counts)[int(len(ent_counts) * 0.75)]
        p95 = sorted(ent_counts)[int(len(ent_counts) * 0.95)]
        
        for entity in peers:
            ent_count = entity["ent_count"]
            admin_count = entity["admin_count"]
            
            # Calculate deviation
            if median_ent > 0:
                deviation_ratio = ent_count / median_ent
            else:
                deviation_ratio = ent_count
            
            z_score = (ent_count - mean_ent) / stdev_ent if stdev_ent > 0 else 0
            
            # Flag if significantly above peers
            if deviation_ratio < 2.0 and z_score < 2.0:
                continue
            
            # Determine priority based on deviation severity
            if deviation_ratio >= 5.0 or (admin_count > 0 and deviation_ratio >= 3.0):
                priority = "critical"
                confidence = min(0.99, 0.85 + (deviation_ratio / 50))
            elif deviation_ratio >= 3.0 or admin_count > median_admin * 2:
                priority = "high"
                confidence = min(0.95, 0.80 + (deviation_ratio / 50))
            else:
                priority = "medium"
                confidence = min(0.90, 0.70 + (deviation_ratio / 50))
            
            signal = {
                "signal_id": f"sig_m11_{entity['entity_id']}_{uuid.uuid4().hex[:6]}",
                "tenant_id": "cloud-iam-analysis",
                "model_id": "M11",
                "entity_id": entity["entity_id"],
                "entity_class": "iam_role",
                "confidence": round(confidence, 2),
                "priority": priority,
                "summary": f"{entity['job_function']} ({cloud}) holds {ent_count} entitlements — {deviation_ratio:.1f}x the peer median of {median_ent:.0f}. {admin_count} admin-level permissions. {entity['critical_resource_count']} on critical resources.",
                "explanation": f"This {cloud} role has significantly more permissions than its peers. Peer group: {len(peers)} {cloud} roles. Median entitlements: {median_ent:.0f}. This role: {ent_count} ({deviation_ratio:.1f}x). Admin permissions: {admin_count} (peer median: {median_admin:.0f}). Z-score: {z_score:.1f}. Roles with excessive permissions increase blast radius if compromised.",
                "recommended_action": json.dumps({
                    "type": "right_size_to_peer_baseline",
                    "scope": entity["entity_id"],
                    "description": f"Reduce entitlements from {ent_count} toward peer median of {median_ent:.0f}. Review {admin_count} admin permissions.",
                    "urgency": "immediate" if priority == "critical" else "within_7d"
                }),
                "rollback_payload": json.dumps({
                    "description": "Restore removed permissions if business justification provided",
                    "reversible": True,
                    "rollback_steps": [f"Re-grant removed entitlements for {entity['entity_id']}"]
                }),
                "blast_radius": ent_count,
                "requires_human": 1,
                "intelligence_sources": json.dumps([
                    {"model_id": "M11", "feature_name": "deviation_ratio", "feature_value": round(deviation_ratio, 2), "contribution": 0.4},
                    {"model_id": "M11", "feature_name": "admin_count", "feature_value": admin_count, "contribution": 0.3},
                    {"model_id": "M11", "feature_name": "z_score", "feature_value": round(z_score, 2), "contribution": 0.2},
                    {"model_id": "M11", "feature_name": "critical_resources", "feature_value": entity["critical_resource_count"], "contribution": 0.1}
                ]),
                "created_at": datetime.utcnow().isoformat()
            }
            signals.append(signal)
    
    # Write signals
    for sig in signals:
        c.execute("""INSERT OR REPLACE INTO signals VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                  (sig["signal_id"], sig["tenant_id"], sig["model_id"], sig["entity_id"],
                   sig["entity_class"], sig["confidence"], sig["priority"], sig["summary"],
                   sig["explanation"], sig["recommended_action"], sig["rollback_payload"],
                   sig["blast_radius"], sig["requires_human"], sig["intelligence_sources"],
                   sig["created_at"]))
    
    conn.commit()
    conn.close()
    
    critical = sum(1 for s in signals if s["priority"] == "critical")
    high = sum(1 for s in signals if s["priority"] == "high")
    medium = sum(1 for s in signals if s["priority"] == "medium")
    print(f"  M11 Results: {len(signals)} over-provisioned roles ({critical} critical, {high} high, {medium} medium)")
    
    # Print top 5
    top = sorted(signals, key=lambda s: s["confidence"], reverse=True)[:5]
    for s in top:
        print(f"    → {s['entity_id']}: {s['summary'][:100]}...")
    
    return signals


if __name__ == "__main__":
    run()
