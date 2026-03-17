#!/usr/bin/env python3
"""
VEKTOR M10: Separation of Duties on Cloud IAM
Detects toxic permission combinations in AWS, Azure, and GCP policies.
"""

import sqlite3
import json
import os
import uuid
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "vektor.db")

# Toxic combinations — if an entity holds BOTH sides, it's a violation
TOXIC_COMBOS = [
    # AWS
    {"name": "create_and_delete_same_resource", "cloud": "AWS",
     "left": ["write"], "right": ["write"],
     "left_pattern": "create", "right_pattern": "delete",
     "severity": "critical",
     "description": "Can create and delete the same resource type — data destruction risk"},
    {"name": "iam_passrole_with_service_write", "cloud": "AWS",
     "left": ["admin"], "right": ["write"],
     "left_pattern": "iam", "right_pattern": None,
     "severity": "critical",
     "description": "IAM admin + service write = can escalate to any service role"},
    {"name": "iam_full_with_data_access", "cloud": "AWS",
     "left": ["admin"], "right": ["read", "write"],
     "left_pattern": "iam", "right_pattern": "s3",
     "severity": "critical",
     "description": "IAM admin + S3 access = can grant themselves access to any bucket"},
    
    # Azure
    {"name": "authorization_write_with_resource_write", "cloud": "Azure",
     "left": ["admin"], "right": ["write"],
     "left_pattern": "authorization", "right_pattern": None,
     "severity": "critical",
     "description": "Can modify role assignments AND write to resources — self-escalation"},
    {"name": "keyvault_admin_with_compute", "cloud": "Azure",
     "left": ["admin", "write"], "right": ["write"],
     "left_pattern": "keyvault", "right_pattern": "compute",
     "severity": "high",
     "description": "Key Vault write + Compute write = extract secrets and deploy"},
    
    # GCP
    {"name": "iam_role_admin_with_service_account", "cloud": "GCP",
     "left": ["admin"], "right": ["admin", "write"],
     "left_pattern": "iam", "right_pattern": "iam",
     "severity": "critical",
     "description": "Can create roles AND manage service accounts — full privilege escalation"},
    {"name": "storage_admin_with_iam", "cloud": "GCP",
     "left": ["admin", "write"], "right": ["admin"],
     "left_pattern": "storage", "right_pattern": "iam",
     "severity": "critical",
     "description": "Storage admin + IAM admin = exfiltrate data and cover tracks"},
]


def run(db_path=DB_PATH):
    print("M10: Cloud IAM Separation of Duties Analysis")
    
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    
    # Get all cloud IAM entities and their entitlements
    c.execute("""
        SELECT e.entity_id, e.job_function, e.department, e.agent_type,
               ent.permission_level, ent.resource_id, r.resource_name, ent.resource_sensitivity
        FROM entities e
        JOIN entitlements ent ON e.entity_id = ent.entity_id
        JOIN resources r ON ent.resource_id = r.resource_id
        WHERE e.department IN ('AWS', 'Azure', 'GCP')
    """)
    
    # Group entitlements by entity
    entity_entitlements = {}
    for row in c.fetchall():
        eid = row["entity_id"]
        if eid not in entity_entitlements:
            entity_entitlements[eid] = {
                "job_function": row["job_function"],
                "department": row["department"],
                "agent_type": row["agent_type"],
                "entitlements": []
            }
        entity_entitlements[eid]["entitlements"].append({
            "permission_level": row["permission_level"],
            "resource_id": row["resource_id"],
            "resource_name": row["resource_name"],
            "sensitivity": row["resource_sensitivity"]
        })
    
    print(f"  Analyzing {len(entity_entitlements)} cloud IAM entities...")
    
    signals = []
    
    for eid, data in entity_entitlements.items():
        cloud = data["department"]
        ents = data["entitlements"]
        
        for combo in TOXIC_COMBOS:
            if combo["cloud"] != cloud:
                continue
            
            # Check if entity has both sides of the toxic combination
            left_match = [e for e in ents 
                         if e["permission_level"] in combo["left"]
                         and (combo["left_pattern"] is None or 
                              combo["left_pattern"] in e["resource_name"].lower())]
            
            right_match = [e for e in ents
                          if e["permission_level"] in combo["right"]
                          and (combo["right_pattern"] is None or
                               combo["right_pattern"] in e["resource_name"].lower())]
            
            if left_match and right_match:
                # Found a toxic combination
                confidence = 1.0 if combo["severity"] == "critical" else 0.95
                
                left_resources = list(set(e["resource_name"] for e in left_match))[:3]
                right_resources = list(set(e["resource_name"] for e in right_match))[:3]
                
                signal = {
                    "signal_id": f"sig_m10_{eid}_{combo['name']}_{uuid.uuid4().hex[:6]}",
                    "tenant_id": "cloud-iam-analysis",
                    "model_id": "M10",
                    "entity_id": eid,
                    "entity_class": "iam_role",
                    "confidence": confidence,
                    "priority": combo["severity"],
                    "summary": f"{data['job_function']} ({cloud}) holds toxic permission combination: {combo['name']}. {combo['description']}.",
                    "explanation": f"This {cloud} role holds permissions on both sides of a separation of duties boundary. Left side: {', '.join(left_resources)}. Right side: {', '.join(right_resources)}. {combo['description']}. Total entitlements: {len(ents)}.",
                    "recommended_action": json.dumps({
                        "type": "remove_toxic_combination",
                        "scope": eid,
                        "description": f"Split {combo['name']} into separate roles. Remove one side of the toxic combination.",
                        "urgency": "immediate" if combo["severity"] == "critical" else "within_7d"
                    }),
                    "rollback_payload": json.dumps({
                        "description": f"Re-grant removed permissions if business justification provided",
                        "reversible": True,
                        "rollback_steps": [f"Re-grant {combo['left_pattern']} permissions", f"Re-grant {combo['right_pattern']} permissions"]
                    }),
                    "blast_radius": len(ents),
                    "requires_human": 1,
                    "intelligence_sources": json.dumps([
                        {"model_id": "M10", "feature_name": "toxic_combo", "feature_value": combo["name"], "contribution": 0.7},
                        {"model_id": "M10", "feature_name": "total_entitlements", "feature_value": len(ents), "contribution": 0.3}
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
    print(f"  M10 Results: {len(signals)} SoD violations ({critical} critical, {high} high)")
    
    return signals


if __name__ == "__main__":
    run()
