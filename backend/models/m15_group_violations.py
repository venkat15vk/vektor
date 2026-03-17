#!/usr/bin/env python3
"""
VEKTOR M15: Group & Role Policy Violation Detection
Analyzes cloud IAM data for group-related policy violations:
- Roles that can create/manage groups AND access resources those groups protect
- Roles with unscoped group management (can modify any group)
- Roles combining group membership control with privilege escalation
- Ownerless/unscoped group management patterns
- Group-to-resource permission chains
"""

import sqlite3
import json
import os
import uuid
from datetime import datetime
from collections import defaultdict

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "vektor.db")

# Group-related toxic patterns
GROUP_VIOLATIONS = [
    # Azure group violations
    {
        "name": "group_management_with_authorization",
        "cloud": "Azure",
        "description": "Can manage group membership AND modify role assignments — can add themselves to any group then grant that group elevated access",
        "required_patterns": [
            {"resource_contains": "group", "level": ["admin", "write"]},
            {"resource_contains": "authorization", "level": ["admin", "write"]}
        ],
        "severity": "critical",
        "violation_type": "group_privilege_escalation"
    },
    {
        "name": "group_management_with_keyvault",
        "cloud": "Azure",
        "description": "Can manage group membership AND access Key Vault — can add themselves to a group with secret access then read all secrets",
        "required_patterns": [
            {"resource_contains": "group", "level": ["admin", "write"]},
            {"resource_contains": "keyvault", "level": ["admin", "write", "read"]}
        ],
        "severity": "critical",
        "violation_type": "group_secret_access"
    },
    {
        "name": "group_management_with_storage",
        "cloud": "Azure",
        "description": "Can manage group membership AND write to storage — can add themselves to a data-access group then exfiltrate data",
        "required_patterns": [
            {"resource_contains": "group", "level": ["admin", "write"]},
            {"resource_contains": "storage", "level": ["admin", "write"]}
        ],
        "severity": "high",
        "violation_type": "group_data_exfiltration"
    },
    {
        "name": "group_management_with_compute",
        "cloud": "Azure",
        "description": "Can manage group membership AND manage compute resources — can leverage group access to deploy and execute code",
        "required_patterns": [
            {"resource_contains": "group", "level": ["admin", "write"]},
            {"resource_contains": "compute", "level": ["admin", "write"]}
        ],
        "severity": "high",
        "violation_type": "group_compute_escalation"
    },
    {
        "name": "unscoped_group_creation_with_directory",
        "cloud": "Azure",
        "description": "Can create groups AND has directory-level permissions — can create shadow groups with broad access that bypass governance",
        "required_patterns": [
            {"resource_contains": "group", "level": ["admin", "write"]},
            {"resource_contains": "directory", "level": ["admin", "write", "read"]}
        ],
        "severity": "high",
        "violation_type": "shadow_group_creation"
    },

    # AWS group violations
    {
        "name": "iam_group_with_policy_attach",
        "cloud": "AWS",
        "description": "Can manage IAM groups AND attach policies — can create a group, add users, and grant the group any permission",
        "required_patterns": [
            {"resource_contains": "iam", "level": ["admin"]},
            {"resource_contains": "iam", "level": ["write"]}
        ],
        "severity": "critical",
        "violation_type": "group_policy_escalation"
    },

    # GCP group violations
    {
        "name": "iam_group_with_role_binding",
        "cloud": "GCP",
        "description": "Can manage group membership AND create role bindings — can add members to groups and bind those groups to any role",
        "required_patterns": [
            {"resource_contains": "iam", "level": ["admin"]},
            {"resource_contains": "resourcemanager", "level": ["admin", "write"]}
        ],
        "severity": "critical",
        "violation_type": "group_binding_escalation"
    },
]


def analyze_group_permission_sprawl(conn):
    """Find roles with excessive group-related permissions compared to peers."""
    c = conn.cursor()
    
    signals = []
    
    # Get all Azure entities and count their group-related vs total entitlements
    c.execute("""
        SELECT e.entity_id, e.job_function, e.department,
               COUNT(ent.entitlement_id) as total_ents,
               SUM(CASE WHEN r.resource_name LIKE '%roup%' OR r.resource_name LIKE '%irectory%' 
                   OR r.resource_name LIKE '%Microsoft.Authorization%' THEN 1 ELSE 0 END) as group_related_ents,
               SUM(CASE WHEN ent.permission_level IN ('admin', 'write') 
                   AND (r.resource_name LIKE '%roup%' OR r.resource_name LIKE '%irectory%')
                   THEN 1 ELSE 0 END) as group_write_ents
        FROM entities e
        JOIN entitlements ent ON e.entity_id = ent.entity_id
        JOIN resources r ON ent.resource_id = r.resource_id
        WHERE e.department IN ('Azure', 'AWS', 'GCP')
        GROUP BY e.entity_id
        HAVING group_write_ents > 0
    """)
    
    entities = [dict(r) for r in c.fetchall()]
    
    if not entities:
        return signals
    
    # Calculate peer statistics for group permissions
    group_write_counts = [e["group_write_ents"] for e in entities]
    import statistics
    if len(group_write_counts) < 2:
        return signals
    
    median_group = statistics.median(group_write_counts)
    mean_group = statistics.mean(group_write_counts)
    stdev_group = statistics.stdev(group_write_counts) if len(group_write_counts) > 1 else 1
    
    for entity in entities:
        group_count = entity["group_write_ents"]
        total = entity["total_ents"]
        
        if median_group > 0:
            deviation = group_count / median_group
        else:
            deviation = group_count
        
        # Flag entities with disproportionate group management permissions
        if deviation < 3.0:
            continue
        
        group_pct = (entity["group_related_ents"] / total * 100) if total > 0 else 0
        
        if deviation >= 5.0:
            priority = "critical"
            confidence = 0.96
        elif deviation >= 3.0:
            priority = "high"
            confidence = 0.90
        else:
            continue
        
        signal = {
            "signal_id": f"sig_m15_sprawl_{entity['entity_id']}_{uuid.uuid4().hex[:6]}",
            "tenant_id": "cloud-iam-analysis",
            "model_id": "M15",
            "entity_id": entity["entity_id"],
            "entity_class": "iam_role",
            "confidence": confidence,
            "priority": priority,
            "summary": f"{entity['job_function']} ({entity['department']}) holds {group_count} group management write permissions — {deviation:.1f}x the peer median of {median_group:.0f}. {group_pct:.0f}% of its {total} total entitlements relate to group/directory management. Disproportionate group control enables shadow group creation and membership manipulation.",
            "explanation": f"This {entity['department']} role has significantly more group/directory write permissions than its peers. It can manage group membership, potentially adding itself or service accounts to privileged groups. Combined with its other {total - group_count} non-group entitlements, a compromise of this role could leverage group membership to access resources indirectly. Peer median for group write permissions: {median_group:.0f}. This role: {group_count} ({deviation:.1f}x).",
            "recommended_action": json.dumps({
                "type": "scope_group_permissions",
                "scope": entity["entity_id"],
                "description": f"Reduce group management permissions from {group_count} to peer median of {median_group:.0f}. Scope group write access to specific groups, not tenant-wide.",
                "urgency": "immediate" if priority == "critical" else "within_7d"
            }),
            "rollback_payload": json.dumps({
                "description": "Restore group management permissions if scoped access is insufficient",
                "reversible": True,
                "rollback_steps": [f"Re-grant {group_count} group management permissions"]
            }),
            "blast_radius": total,
            "requires_human": 1,
            "intelligence_sources": json.dumps([
                {"model_id": "M15", "feature_name": "group_write_count", "feature_value": group_count, "contribution": 0.4},
                {"model_id": "M15", "feature_name": "deviation_from_peers", "feature_value": round(deviation, 2), "contribution": 0.3},
                {"model_id": "M15", "feature_name": "group_permission_pct", "feature_value": round(group_pct, 1), "contribution": 0.2},
                {"model_id": "M15", "feature_name": "total_entitlements", "feature_value": total, "contribution": 0.1}
            ]),
            "created_at": datetime.utcnow().isoformat()
        }
        signals.append(signal)
    
    return signals


def analyze_group_toxic_combos(conn):
    """Find roles with toxic group-related permission combinations."""
    c = conn.cursor()
    
    # Get all cloud entities with their entitlements
    c.execute("""
        SELECT e.entity_id, e.job_function, e.department,
               ent.permission_level, r.resource_name
        FROM entities e
        JOIN entitlements ent ON e.entity_id = ent.entity_id
        JOIN resources r ON ent.resource_id = r.resource_id
        WHERE e.department IN ('AWS', 'Azure', 'GCP')
    """)
    
    entity_data = defaultdict(lambda: {"job_function": "", "department": "", "entitlements": []})
    for row in c.fetchall():
        eid = row["entity_id"]
        entity_data[eid]["job_function"] = row["job_function"]
        entity_data[eid]["department"] = row["department"]
        entity_data[eid]["entitlements"].append({
            "permission_level": row["permission_level"],
            "resource_name": row["resource_name"].lower()
        })
    
    signals = []
    
    for eid, data in entity_data.items():
        cloud = data["department"]
        ents = data["entitlements"]
        
        for violation in GROUP_VIOLATIONS:
            if violation["cloud"] != cloud:
                continue
            
            # Check all required patterns
            all_matched = True
            matched_details = []
            
            for pattern in violation["required_patterns"]:
                search_term = pattern["resource_contains"].lower()
                required_levels = pattern["level"]
                
                matches = [e for e in ents 
                          if search_term in e["resource_name"] 
                          and e["permission_level"] in required_levels]
                
                if not matches:
                    all_matched = False
                    break
                matched_details.append(f"{search_term}:{matches[0]['permission_level']}")
            
            if all_matched:
                confidence = 0.98 if violation["severity"] == "critical" else 0.93
                
                signal = {
                    "signal_id": f"sig_m15_{eid}_{violation['name']}_{uuid.uuid4().hex[:6]}",
                    "tenant_id": "cloud-iam-analysis",
                    "model_id": "M15",
                    "entity_id": eid,
                    "entity_class": "iam_role",
                    "confidence": confidence,
                    "priority": violation["severity"],
                    "summary": f"{data['job_function']} ({cloud}): {violation['description']}. Violation type: {violation['violation_type']}. Matched permissions: {', '.join(matched_details)}.",
                    "explanation": f"This {cloud} role combines group management capabilities with access to protected resources, creating an indirect privilege escalation path through group membership manipulation. {violation['description']}. An attacker compromising this role could modify group membership to gain access to resources the groups protect, bypassing direct permission checks.",
                    "recommended_action": json.dumps({
                        "type": "split_group_and_resource_permissions",
                        "scope": eid,
                        "description": f"Separate group management permissions from resource access permissions into distinct roles. Violation: {violation['violation_type']}.",
                        "urgency": "immediate" if violation["severity"] == "critical" else "within_7d"
                    }),
                    "rollback_payload": json.dumps({
                        "description": "Re-combine group and resource permissions if split causes operational issues",
                        "reversible": True,
                        "rollback_steps": ["Re-grant group management permissions to this role"]
                    }),
                    "blast_radius": len(ents),
                    "requires_human": 1,
                    "intelligence_sources": json.dumps([
                        {"model_id": "M15", "feature_name": "violation_type", "feature_value": violation["violation_type"], "contribution": 0.5},
                        {"model_id": "M15", "feature_name": "toxic_combo", "feature_value": violation["name"], "contribution": 0.3},
                        {"model_id": "M15", "feature_name": "total_entitlements", "feature_value": len(ents), "contribution": 0.2}
                    ]),
                    "created_at": datetime.utcnow().isoformat()
                }
                signals.append(signal)
    
    return signals


def run(db_path=DB_PATH):
    print("M15: Group & Role Policy Violation Detection")
    
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    
    # Run both analyses
    sprawl_signals = analyze_group_permission_sprawl(conn)
    print(f"  Group permission sprawl: {len(sprawl_signals)} findings")
    
    toxic_signals = analyze_group_toxic_combos(conn)
    print(f"  Group toxic combinations: {len(toxic_signals)} findings")
    
    all_signals = sprawl_signals + toxic_signals
    
    # Write all signals
    for sig in all_signals:
        c.execute("""INSERT OR REPLACE INTO signals VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                  (sig["signal_id"], sig["tenant_id"], sig["model_id"], sig["entity_id"],
                   sig["entity_class"], sig["confidence"], sig["priority"], sig["summary"],
                   sig["explanation"], sig["recommended_action"], sig["rollback_payload"],
                   sig["blast_radius"], sig["requires_human"], sig["intelligence_sources"],
                   sig["created_at"]))
    
    conn.commit()
    
    critical = sum(1 for s in all_signals if s["priority"] == "critical")
    high = sum(1 for s in all_signals if s["priority"] == "high")
    
    print(f"\n  M15 RESULTS: {len(all_signals)} group policy violations ({critical} critical, {high} high)")
    print(f"    Sprawl (disproportionate group control): {len(sprawl_signals)}")
    print(f"    Toxic combos (group + resource access):  {len(toxic_signals)}")
    
    # Top findings
    top = sorted(all_signals, key=lambda s: ({"critical": 0, "high": 1}.get(s["priority"], 9), -s["confidence"]))[:5]
    print(f"\n  TOP 5 GROUP VIOLATIONS:")
    for s in top:
        print(f"    [{s['priority'].upper()}] {s['entity_id']}")
        print(f"    {s['summary'][:150]}...")
        print()
    
    conn.close()
    return all_signals


if __name__ == "__main__":
    run()
