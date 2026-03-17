#!/usr/bin/env python3
"""
VEKTOR M14: Privilege Escalation Path Detection
Finds multi-step chains where combining individually low-risk permissions
creates high-risk privilege escalation paths.
"""

import sqlite3
import json
import os
import uuid
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "vektor.db")

# Known privilege escalation chains
# Each chain: if an entity has ALL permissions in "requires", it can escalate
ESCALATION_CHAINS = [
    # AWS
    {
        "name": "aws_create_assume_role",
        "cloud": "AWS",
        "description": "Can create a new IAM role, attach admin policy, and assume it — full account takeover",
        "requires_patterns": ["iam"],  # entity must have admin on IAM
        "requires_levels": ["admin"],
        "severity": "critical",
        "blast_radius_label": "full AWS account",
        "individual_risk": "medium",
        "combined_risk": "account takeover"
    },
    {
        "name": "aws_lambda_escalation",
        "cloud": "AWS",
        "description": "Can create Lambda function with elevated role and invoke it — code execution as any role",
        "requires_patterns": ["lambda", "iam"],
        "requires_levels": ["write", "admin"],
        "severity": "critical",
        "blast_radius_label": "all Lambda-accessible resources",
        "individual_risk": "medium",
        "combined_risk": "arbitrary code execution with escalated privileges"
    },
    {
        "name": "aws_ec2_ssm_escalation",
        "cloud": "AWS",
        "description": "Can launch EC2 instance with instance profile and access via SSM — bypass network controls",
        "requires_patterns": ["ec2", "iam"],
        "requires_levels": ["write", "read"],
        "severity": "high",
        "blast_radius_label": "all EC2-accessible VPC resources",
        "individual_risk": "low",
        "combined_risk": "network boundary bypass"
    },
    
    # Azure
    {
        "name": "azure_self_escalation",
        "cloud": "Azure",
        "description": "Can modify own role assignments — self-escalation to Owner",
        "requires_patterns": ["authorization"],
        "requires_levels": ["admin"],
        "severity": "critical",
        "blast_radius_label": "entire Azure subscription",
        "individual_risk": "high",
        "combined_risk": "self-escalation to subscription Owner"
    },
    {
        "name": "azure_keyvault_compute_chain",
        "cloud": "Azure",
        "description": "Can read secrets from Key Vault and deploy to Compute — extract credentials and use them",
        "requires_patterns": ["keyvault", "compute"],
        "requires_levels": ["read", "write"],
        "severity": "high",
        "blast_radius_label": "all secrets + compute resources",
        "individual_risk": "medium",
        "combined_risk": "credential extraction and lateral movement"
    },
    {
        "name": "azure_managed_identity_abuse",
        "cloud": "Azure",
        "description": "Can create managed identities and assign roles — create backdoor service principals",
        "requires_patterns": ["managedidentity", "authorization"],
        "requires_levels": ["write", "admin"],
        "severity": "critical",
        "blast_radius_label": "entire Azure AD tenant",
        "individual_risk": "medium",
        "combined_risk": "persistent backdoor via managed identity"
    },
    
    # GCP
    {
        "name": "gcp_service_account_key_escalation",
        "cloud": "GCP",
        "description": "Can create service account keys and impersonate — persistent access as any service account",
        "requires_patterns": ["iam"],
        "requires_levels": ["admin"],
        "severity": "critical",
        "blast_radius_label": "all GCP project resources",
        "individual_risk": "medium",
        "combined_risk": "persistent credential-based access"
    },
    {
        "name": "gcp_cloudfunctions_escalation",
        "cloud": "GCP",
        "description": "Can deploy Cloud Functions with elevated service account — code execution with escalated privileges",
        "requires_patterns": ["cloudfunctions", "iam"],
        "requires_levels": ["write", "read"],
        "severity": "high",
        "blast_radius_label": "all resources accessible to target service account",
        "individual_risk": "low",
        "combined_risk": "serverless code execution with privilege escalation"
    },
]


def run(db_path=DB_PATH):
    print("M14: Privilege Escalation Path Detection")
    
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    
    # Get all cloud entities with their entitlements
    c.execute("""
        SELECT e.entity_id, e.job_function, e.department,
               ent.permission_level, ent.resource_id, r.resource_name
        FROM entities e
        JOIN entitlements ent ON e.entity_id = ent.entity_id
        JOIN resources r ON ent.resource_id = r.resource_id
        WHERE e.department IN ('AWS', 'Azure', 'GCP')
    """)
    
    entity_data = {}
    for row in c.fetchall():
        eid = row["entity_id"]
        if eid not in entity_data:
            entity_data[eid] = {
                "job_function": row["job_function"],
                "department": row["department"],
                "entitlements": []
            }
        entity_data[eid]["entitlements"].append({
            "permission_level": row["permission_level"],
            "resource_name": row["resource_name"].lower()
        })
    
    print(f"  Checking {len(entity_data)} entities against {len(ESCALATION_CHAINS)} escalation chains...")
    
    signals = []
    
    for eid, data in entity_data.items():
        cloud = data["department"]
        ents = data["entitlements"]
        
        for chain in ESCALATION_CHAINS:
            if chain["cloud"] != cloud:
                continue
            
            # Check if entity has all required permission patterns
            all_matched = True
            matched_resources = []
            
            for i, pattern in enumerate(chain["requires_patterns"]):
                level_needed = chain["requires_levels"][i] if i < len(chain["requires_levels"]) else "read"
                
                # Check if any entitlement matches this pattern + level
                level_hierarchy = {"admin": 4, "owner": 4, "write": 3, "read": 2, "none": 1}
                needed_rank = level_hierarchy.get(level_needed, 2)
                
                match = [e for e in ents 
                        if pattern in e["resource_name"].lower()
                        and level_hierarchy.get(e["permission_level"], 0) >= needed_rank]
                
                if not match:
                    all_matched = False
                    break
                matched_resources.extend([m["resource_name"] for m in match[:2]])
            
            if all_matched:
                confidence = 0.99 if chain["severity"] == "critical" else 0.94
                
                signal = {
                    "signal_id": f"sig_m14_{eid}_{chain['name']}_{uuid.uuid4().hex[:6]}",
                    "tenant_id": "cloud-iam-analysis",
                    "model_id": "M14",
                    "entity_id": eid,
                    "entity_class": "iam_role",
                    "confidence": confidence,
                    "priority": chain["severity"],
                    "summary": f"Privilege escalation path detected in {data['job_function']} ({cloud}): {chain['description']}. Individual permission risk: {chain['individual_risk']}. Combined risk: {chain['combined_risk']}.",
                    "explanation": f"This {cloud} role holds a combination of permissions that individually appear {chain['individual_risk']}-risk but together enable {chain['combined_risk']}. Chain: {chain['name']}. Matched resources: {', '.join(list(set(matched_resources))[:5])}. Blast radius: {chain['blast_radius_label']}. No single-permission scanner catches this — it requires analyzing the combination.",
                    "recommended_action": json.dumps({
                        "type": "break_escalation_chain",
                        "scope": eid,
                        "description": f"Remove one link in the escalation chain. Recommended: separate {chain['requires_patterns'][0]} and {chain['requires_patterns'][-1]} into different roles.",
                        "urgency": "immediate" if chain["severity"] == "critical" else "within_7d"
                    }),
                    "rollback_payload": json.dumps({
                        "description": "Restore separated permissions if escalation path is intentional",
                        "reversible": True,
                        "rollback_steps": [f"Re-combine {p} permissions" for p in chain["requires_patterns"]]
                    }),
                    "blast_radius": -1,  # Unknown — treat as maximum
                    "requires_human": 1,
                    "intelligence_sources": json.dumps([
                        {"model_id": "M14", "feature_name": "escalation_chain", "feature_value": chain["name"], "contribution": 0.6},
                        {"model_id": "M14", "feature_name": "individual_risk", "feature_value": chain["individual_risk"], "contribution": 0.1},
                        {"model_id": "M14", "feature_name": "combined_risk", "feature_value": chain["combined_risk"], "contribution": 0.3}
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
    print(f"  M14 Results: {len(signals)} escalation paths ({critical} critical, {high} high)")
    
    # Print top findings
    top = sorted(signals, key=lambda s: s["confidence"], reverse=True)[:5]
    for s in top:
        print(f"    → {s['entity_id']}: {s['summary'][:120]}...")
    
    return signals


if __name__ == "__main__":
    run()
