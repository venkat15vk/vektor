#!/usr/bin/env python3
"""
VEKTOR Cloud IAM Adapter
Reads AWS, Azure, and GCP IAM policy datasets and normalizes them
into VEKTOR's canonical schema (entities, entitlements, resources, signals tables).

Data source: github.com/iann0036/iam-dataset (already cloned to data/cloud-iam/)
"""

import sqlite3
import json
import os
import hashlib
from datetime import datetime

BASE = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE, "..", "data", "cloud-iam")
DB_PATH = os.path.join(BASE, "..", "vektor.db")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def load_aws(conn):
    """Load AWS IAM services, privileges, and managed policies."""
    c = conn.cursor()
    
    # Load IAM definition (services + privileges)
    with open(os.path.join(DATA_DIR, "aws", "iam_definition.json")) as f:
        services = json.load(f)
    
    # Load managed policies
    with open(os.path.join(DATA_DIR, "aws", "managed_policies.json")) as f:
        mp_data = json.load(f)
    policies = mp_data.get("policies", []) if isinstance(mp_data, dict) else mp_data
    
    print(f"  AWS: {len(services)} services, {len(policies)} managed policies")
    
    # Create resources for AWS services
    for svc in services:
        prefix = svc.get("prefix", "unknown")
        svc_name = svc.get("service_name", prefix)
        resource_id = f"aws-svc-{prefix}"
        
        # Determine sensitivity based on service type
        sensitive_prefixes = ["iam", "sts", "organizations", "kms", "secretsmanager", 
                           "s3", "rds", "dynamodb", "ec2", "lambda", "cloudtrail"]
        sensitivity = "critical" if prefix in sensitive_prefixes else "high" if prefix.startswith(("s3", "ec2", "rds")) else "medium"
        
        c.execute("INSERT OR REPLACE INTO resources VALUES (?,?,?,?,?)",
                  (resource_id, svc_name, "cloud_iam", sensitivity, None))
    
    # Create entities for managed policies and map their privileges as entitlements
    ent_count = 0
    entitlement_count = 0
    
    for policy in policies:
        if not isinstance(policy, dict):
            continue
        
        policy_name = policy.get("name", policy.get("arn", "unknown")) or "unknown"
        policy_arn = policy.get("arn", "") or ""
        
        # Skip AWS service-linked role policies (too noisy)
        if "service-role" in policy_arn.lower() and not policy.get("credentials_exposure"):
            continue
            
        entity_id = f"aws-policy-{hashlib.md5(policy_name.encode()).hexdigest()[:8]}"
        
        # Determine entity properties
        is_admin = policy.get("permissions_management_actions", 0) if isinstance(policy.get("permissions_management_actions"), int) else 0
        is_deprecated = policy.get("deprecated", False)
        access_levels = policy.get("access_levels", [])
        has_data_access = policy.get("data_access", False)
        has_cred_exposure = policy.get("credentials_exposure", False)
        
        c.execute("INSERT OR REPLACE INTO entities VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                  (entity_id, "iam_policy", "active" if not is_deprecated else "disabled",
                   0, policy_name, "AWS", "AWS-POLICIES",
                   0, None, None, None,
                   f"AWS Managed Policy: {policy_name}", "aws_iam_policy",
                   "NOT_REVIEWED", 0, 0))
        ent_count += 1
        
        # Create entitlements for each access level
        for level in access_levels:
            perm_level = "admin" if level == "Permissions management" else \
                        "write" if level == "Write" else \
                        "read" if level in ("Read", "List") else \
                        "read" if level == "Tagging" else "read"
            
            ent_id = f"ent-aws-{entity_id}-{level.lower().replace(' ','_')}"
            c.execute("INSERT OR REPLACE INTO entitlements VALUES (?,?,?,?,?,?,?,?,?)",
                      (ent_id, entity_id, f"aws-svc-iam", perm_level,
                       0, 0, "auto_provisioned", "approved",
                       "critical" if level == "Permissions management" else "high"))
            entitlement_count += 1
    
    # Also create entities for each AWS service privilege pattern (for SoD analysis)
    for svc in services:
        prefix = svc.get("prefix", "unknown")
        svc_name = svc.get("service_name", prefix)
        resource_id = f"aws-svc-{prefix}"
        
        for priv in svc.get("privileges", []):
            priv_name = priv.get("privilege", "unknown")
            access_level = priv.get("access_level", "Read")
            
            # Store as entitlement linked to a synthetic "service-user" entity
            svc_entity_id = f"aws-svc-entity-{prefix}"
            
            # Ensure the service entity exists
            c.execute("INSERT OR IGNORE INTO entities VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                      (svc_entity_id, "service_account", "active",
                       0, f"AWS {svc_name}", "AWS", "AWS-SERVICES",
                       0, None, None, None,
                       f"AWS Service: {svc_name}", "aws_service",
                       "NOT_REVIEWED", 0, 0))
    
    print(f"  AWS: loaded {ent_count} policy entities, {entitlement_count} entitlements")
    return ent_count, entitlement_count


def load_azure(conn):
    """Load Azure built-in roles and their permitted actions."""
    c = conn.cursor()
    
    with open(os.path.join(DATA_DIR, "azure", "built-in-roles.json")) as f:
        data = json.load(f)
    
    roles = data.get("roles", []) if isinstance(data, dict) else data
    print(f"  Azure: {len(roles)} built-in roles")
    
    ent_count = 0
    entitlement_count = 0
    
    # Sensitive Azure resource providers
    sensitive_providers = ["Microsoft.Authorization", "Microsoft.KeyVault", 
                          "Microsoft.Storage", "Microsoft.Sql", "Microsoft.Compute",
                          "Microsoft.Network", "Microsoft.ManagedIdentity"]
    
    for role in roles:
        if not isinstance(role, dict):
            continue
            
        role_name = role.get("name", "unknown")
        description = role.get("description", "")
        has_external = role.get("hasExternal", False)
        has_unknown = role.get("hasUnknown", False)
        permitted = role.get("permittedActions", [])
        
        entity_id = f"azure-role-{hashlib.md5(role_name.encode()).hexdigest()[:8]}"
        
        # Count permission types
        write_count = sum(1 for p in permitted if "/write" in p.get("name", "").lower() or "/delete" in p.get("name", "").lower())
        read_count = sum(1 for p in permitted if "/read" in p.get("name", "").lower())
        admin_actions = [p for p in permitted if "Microsoft.Authorization" in p.get("name", "") or "roleAssignments" in p.get("name", "")]
        
        # Determine highest permission level
        if admin_actions:
            max_level = "admin"
        elif write_count > 0:
            max_level = "write"
        else:
            max_level = "read"
        
        c.execute("INSERT OR REPLACE INTO entities VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                  (entity_id, "iam_role", "active",
                   0, role_name, "Azure", "AZURE-ROLES",
                   0, None, None, None,
                   f"Azure Role: {description[:100]}" if description else f"Azure Role: {role_name}",
                   "azure_builtin_role",
                   "NOT_REVIEWED", 0, 0))
        ent_count += 1
        
        # Create resource for Azure
        c.execute("INSERT OR IGNORE INTO resources VALUES (?,?,?,?,?)",
                  ("azure-iam", "Azure IAM", "cloud_iam", "critical", None))
        
        # Create entitlements per permitted action
        for action in permitted:
            action_name = action.get("name", "unknown")
            
            # Determine permission level
            if "Microsoft.Authorization" in action_name or "roleAssignments" in action_name:
                perm = "admin"
                sens = "critical"
            elif "/write" in action_name or "/delete" in action_name or "/action" in action_name:
                perm = "write"
                sens = "high"
            else:
                perm = "read"
                sens = "medium"
            
            ent_id = f"ent-azure-{hashlib.md5((entity_id + action_name).encode()).hexdigest()[:10]}"
            
            # Determine resource
            provider = action_name.split("/")[0] if "/" in action_name else "Microsoft.Unknown"
            resource_id = f"azure-{hashlib.md5(provider.encode()).hexdigest()[:6]}"
            c.execute("INSERT OR IGNORE INTO resources VALUES (?,?,?,?,?)",
                      (resource_id, provider, "cloud_iam",
                       "critical" if provider in sensitive_providers else "high", None))
            
            c.execute("INSERT OR REPLACE INTO entitlements VALUES (?,?,?,?,?,?,?,?,?)",
                      (ent_id, entity_id, resource_id, perm,
                       0, 0, "auto_provisioned", "approved", sens))
            entitlement_count += 1
    
    print(f"  Azure: loaded {ent_count} role entities, {entitlement_count} entitlements")
    return ent_count, entitlement_count


def load_gcp(conn):
    """Load GCP predefined roles and their permissions."""
    c = conn.cursor()
    
    # role_permissions.json maps permission -> list of roles
    # We need to invert this to get role -> list of permissions
    with open(os.path.join(DATA_DIR, "gcp", "role_permissions.json")) as f:
        perm_to_roles = json.load(f)
    
    print(f"  GCP: {len(perm_to_roles)} unique permissions")
    
    # Invert: build role -> permissions map
    role_perms = {}
    role_names = {}
    for perm, roles_list in perm_to_roles.items():
        for role_info in roles_list:
            role_id = role_info.get("id", "unknown")
            role_name = role_info.get("name", role_id)
            if role_id not in role_perms:
                role_perms[role_id] = []
                role_names[role_id] = role_name
            role_perms[role_id].append(perm)
    
    print(f"  GCP: {len(role_perms)} unique roles")
    
    # Sensitive GCP permission prefixes
    sensitive_prefixes = ["iam.", "resourcemanager.", "storage.", "bigquery.",
                         "compute.", "cloudsql.", "secretmanager.", "cloudkms."]
    
    ent_count = 0
    entitlement_count = 0
    
    for role_id, permissions in role_perms.items():
        role_name = role_names.get(role_id, role_id)
        entity_id = f"gcp-role-{hashlib.md5(role_id.encode()).hexdigest()[:8]}"
        
        # Count sensitive permissions
        iam_perms = [p for p in permissions if p.startswith("iam.")]
        write_perms = [p for p in permissions if ".create" in p or ".delete" in p or ".update" in p or ".set" in p]
        admin_perms = [p for p in permissions if "iam.roles" in p or "iam.serviceAccount" in p or "resourcemanager" in p]
        
        if admin_perms:
            max_level = "admin"
        elif write_perms:
            max_level = "write"
        else:
            max_level = "read"
        
        c.execute("INSERT OR REPLACE INTO entities VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                  (entity_id, "iam_role", "active",
                   0, role_name, "GCP", "GCP-ROLES",
                   0, None, None, None,
                   f"GCP Role: {role_name} ({len(permissions)} permissions)",
                   "gcp_predefined_role",
                   "NOT_REVIEWED", 0, 0))
        ent_count += 1
        
        # Create resource for GCP
        c.execute("INSERT OR IGNORE INTO resources VALUES (?,?,?,?,?)",
                  ("gcp-iam", "GCP IAM", "cloud_iam", "critical", None))
        
        # Create entitlements per permission (group by service prefix to avoid explosion)
        service_groups = {}
        for perm in permissions:
            svc = perm.split(".")[0] if "." in perm else "unknown"
            if svc not in service_groups:
                service_groups[svc] = {"read": 0, "write": 0, "admin": 0, "perms": []}
            
            if ".create" in perm or ".delete" in perm or ".update" in perm or ".set" in perm:
                service_groups[svc]["write"] += 1
            elif "iam.roles" in perm or "iam.serviceAccount" in perm:
                service_groups[svc]["admin"] += 1
            else:
                service_groups[svc]["read"] += 1
            service_groups[svc]["perms"].append(perm)
        
        for svc, counts in service_groups.items():
            # Highest level for this service group
            if counts["admin"] > 0:
                perm_level = "admin"
            elif counts["write"] > 0:
                perm_level = "write"
            else:
                perm_level = "read"
            
            is_sensitive = any(svc.startswith(sp.rstrip(".")) for sp in sensitive_prefixes)
            
            resource_id = f"gcp-{hashlib.md5(svc.encode()).hexdigest()[:6]}"
            c.execute("INSERT OR IGNORE INTO resources VALUES (?,?,?,?,?)",
                      (resource_id, f"GCP {svc}", "cloud_iam",
                       "critical" if is_sensitive else "high", None))
            
            ent_id = f"ent-gcp-{hashlib.md5((entity_id + svc).encode()).hexdigest()[:10]}"
            c.execute("INSERT OR REPLACE INTO entitlements VALUES (?,?,?,?,?,?,?,?,?)",
                      (ent_id, entity_id, resource_id, perm_level,
                       0, 0, "auto_provisioned", "approved",
                       "critical" if is_sensitive else "high"))
            entitlement_count += 1
    
    print(f"  GCP: loaded {ent_count} role entities, {entitlement_count} entitlements")
    return ent_count, entitlement_count


def run():
    print("=" * 60)
    print("VEKTOR Cloud IAM Adapter")
    print("=" * 60)
    
    conn = get_db()
    
    aws_ent, aws_entl = load_aws(conn)
    azure_ent, azure_entl = load_azure(conn)
    gcp_ent, gcp_entl = load_gcp(conn)
    
    conn.commit()
    
    total_entities = aws_ent + azure_ent + gcp_ent
    total_entitlements = aws_entl + azure_entl + gcp_entl
    
    print(f"\n{'=' * 60}")
    print(f"TOTALS:")
    print(f"  Entities loaded:     {total_entities}")
    print(f"  Entitlements loaded: {total_entitlements}")
    print(f"  Clouds:              AWS + Azure + GCP")
    print(f"{'=' * 60}")
    
    conn.close()


if __name__ == "__main__":
    run()
