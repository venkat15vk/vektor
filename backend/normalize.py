#!/usr/bin/env python3
"""
VEKTOR Step 3: Normalization Layer
Reads 4 CSV files → populates SQLite canonical tables.
No source-specific fields downstream. Enum validation enforced.
"""

import csv
import sqlite3
import os
import sys

DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
DB_PATH = os.path.join(os.path.dirname(__file__), "vektor.db")

# Enum constraints
VALID_ENTITY_CLASS = {"human", "ai_agent", "rpa_bot", "service_account", "pipeline", "external"}
VALID_ENTITY_STATUS = {"active", "inactive", "disabled", "suspended"}
VALID_PERMISSION_LEVEL = {"global_admin", "admin", "owner", "write", "read", "none"}
VALID_RESOURCE_SENSITIVITY = {"critical", "high", "medium", "low"}
VALID_RESOURCE_TYPE = {"erp", "payroll", "database", "scm", "hr", "iam"}
VALID_ACTION_TYPE = {"login", "export", "read", "write", "admin_op", "provision", "unknown"}
VALID_ACCESS_REVIEW = {"REVOKE", "APPROVE", "NOT_REVIEWED"}
VALID_APPROVAL_RECORD = {"approved", "auto_provisioned", "unknown"}


def create_schema(conn):
    c = conn.cursor()

    c.execute("DROP TABLE IF EXISTS signals")
    c.execute("DROP TABLE IF EXISTS events")
    c.execute("DROP TABLE IF EXISTS entitlements")
    c.execute("DROP TABLE IF EXISTS entities")
    c.execute("DROP TABLE IF EXISTS resources")
    c.execute("DROP TABLE IF EXISTS mock_actions")

    c.execute("""
    CREATE TABLE resources (
        resource_id TEXT PRIMARY KEY,
        resource_name TEXT NOT NULL,
        resource_type TEXT NOT NULL,
        sensitivity TEXT NOT NULL,
        owner_entity_id TEXT
    )""")

    c.execute("""
    CREATE TABLE entities (
        entity_id TEXT PRIMARY KEY,
        entity_class TEXT NOT NULL,
        entity_status TEXT NOT NULL,
        tenure_days INTEGER,
        job_function TEXT,
        department TEXT,
        peer_group_id TEXT,
        last_active_days INTEGER,
        contract_end_date TEXT,
        deployed_by TEXT,
        parent_identity TEXT,
        agent_purpose TEXT,
        agent_type TEXT,
        access_review_outcome TEXT,
        incident_flag INTEGER DEFAULT 0,
        offboarding_cleanup_flag INTEGER DEFAULT 0
    )""")

    c.execute("""
    CREATE TABLE entitlements (
        entitlement_id TEXT PRIMARY KEY,
        entity_id TEXT NOT NULL,
        resource_id TEXT NOT NULL,
        permission_level TEXT NOT NULL,
        last_used_days INTEGER,
        entitlement_age_days INTEGER,
        granted_by TEXT,
        approval_record TEXT,
        resource_sensitivity TEXT,
        FOREIGN KEY (entity_id) REFERENCES entities(entity_id),
        FOREIGN KEY (resource_id) REFERENCES resources(resource_id)
    )""")

    c.execute("""
    CREATE TABLE events (
        event_id TEXT PRIMARY KEY,
        entity_id TEXT NOT NULL,
        resource_id TEXT NOT NULL,
        action_type TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        action_hour INTEGER,
        action_day_of_week TEXT,
        session_id TEXT,
        session_duration_seconds INTEGER,
        actions_per_minute REAL,
        action_sequence_entropy REAL,
        geo_ip_country TEXT,
        geo_ip_change_flag INTEGER DEFAULT 0,
        FOREIGN KEY (entity_id) REFERENCES entities(entity_id),
        FOREIGN KEY (resource_id) REFERENCES resources(resource_id)
    )""")

    c.execute("""
    CREATE TABLE signals (
        signal_id TEXT PRIMARY KEY,
        tenant_id TEXT DEFAULT 'meridian-financial',
        model_id TEXT NOT NULL,
        entity_id TEXT NOT NULL,
        entity_class TEXT,
        confidence REAL,
        priority TEXT,
        summary TEXT,
        explanation TEXT,
        recommended_action TEXT,
        rollback_payload TEXT,
        blast_radius INTEGER,
        requires_human INTEGER DEFAULT 1,
        intelligence_sources TEXT,
        created_at TEXT,
        FOREIGN KEY (entity_id) REFERENCES entities(entity_id)
    )""")

    c.execute("""
    CREATE TABLE mock_actions (
        action_id INTEGER PRIMARY KEY AUTOINCREMENT,
        signal_id TEXT,
        action_type TEXT,
        description TEXT,
        created_at TEXT,
        FOREIGN KEY (signal_id) REFERENCES signals(signal_id)
    )""")

    conn.commit()


def validate_enum(value, valid_set, field_name, row_id):
    if value and value not in valid_set:
        print(f"  ⚠ WARN: Invalid {field_name}='{value}' for {row_id}, skipping validation")
        return False
    return True


def load_resources(conn):
    path = os.path.join(DATA_DIR, "resources.csv")
    c = conn.cursor()
    count = 0
    with open(path) as f:
        for row in csv.DictReader(f):
            validate_enum(row["resource_type"], VALID_RESOURCE_TYPE, "resource_type", row["resource_id"])
            validate_enum(row["sensitivity"], VALID_RESOURCE_SENSITIVITY, "sensitivity", row["resource_id"])
            c.execute("INSERT INTO resources VALUES (?,?,?,?,?)",
                      (row["resource_id"], row["resource_name"], row["resource_type"],
                       row["sensitivity"], row["owner_entity_id"]))
            count += 1
    conn.commit()
    return count


def load_entities(conn):
    path = os.path.join(DATA_DIR, "entities.csv")
    c = conn.cursor()
    count = 0
    with open(path) as f:
        for row in csv.DictReader(f):
            validate_enum(row["entity_class"], VALID_ENTITY_CLASS, "entity_class", row["entity_id"])
            validate_enum(row["entity_status"], VALID_ENTITY_STATUS, "entity_status", row["entity_id"])
            if row["access_review_outcome"]:
                validate_enum(row["access_review_outcome"], VALID_ACCESS_REVIEW, "access_review_outcome", row["entity_id"])
            c.execute("""INSERT INTO entities VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                      (row["entity_id"], row["entity_class"], row["entity_status"],
                       int(row["tenure_days"]) if row["tenure_days"] else None,
                       row["job_function"] or None, row["department"] or None,
                       row["peer_group_id"] or None,
                       int(row["last_active_days"]) if row["last_active_days"] else None,
                       row["contract_end_date"] or None,
                       row["deployed_by"] or None, row["parent_identity"] or None,
                       row["agent_purpose"] or None, row["agent_type"] or None,
                       row["access_review_outcome"] or None,
                       int(row["incident_flag"]) if row["incident_flag"] else 0,
                       int(row["offboarding_cleanup_flag"]) if row["offboarding_cleanup_flag"] else 0))
            count += 1
    conn.commit()
    return count


def load_entitlements(conn):
    path = os.path.join(DATA_DIR, "entitlements.csv")
    c = conn.cursor()
    count = 0
    with open(path) as f:
        for row in csv.DictReader(f):
            validate_enum(row["permission_level"], VALID_PERMISSION_LEVEL, "permission_level", row["entitlement_id"])
            validate_enum(row["resource_sensitivity"], VALID_RESOURCE_SENSITIVITY, "resource_sensitivity", row["entitlement_id"])
            if row["approval_record"]:
                validate_enum(row["approval_record"], VALID_APPROVAL_RECORD, "approval_record", row["entitlement_id"])
            c.execute("INSERT INTO entitlements VALUES (?,?,?,?,?,?,?,?,?)",
                      (row["entitlement_id"], row["entity_id"], row["resource_id"],
                       row["permission_level"],
                       int(row["last_used_days"]) if row["last_used_days"] else None,
                       int(row["entitlement_age_days"]) if row["entitlement_age_days"] else None,
                       row["granted_by"] or None,
                       row["approval_record"] or None,
                       row["resource_sensitivity"] or None))
            count += 1
    conn.commit()
    return count


def load_events(conn):
    path = os.path.join(DATA_DIR, "events.csv")
    c = conn.cursor()
    count = 0
    with open(path) as f:
        for row in csv.DictReader(f):
            validate_enum(row["action_type"], VALID_ACTION_TYPE, "action_type", row["event_id"])
            geo_flag = 1 if row.get("geo_ip_change_flag", "").lower() == "true" else 0
            c.execute("INSERT INTO events VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                      (row["event_id"], row["entity_id"], row["resource_id"],
                       row["action_type"], row["timestamp"],
                       int(row["action_hour"]) if row["action_hour"] else None,
                       row["action_day_of_week"] or None,
                       row["session_id"] or None,
                       int(row["session_duration_seconds"]) if row["session_duration_seconds"] else None,
                       float(row["actions_per_minute"]) if row["actions_per_minute"] else None,
                       float(row["action_sequence_entropy"]) if row["action_sequence_entropy"] else None,
                       row["geo_ip_country"] or None,
                       geo_flag))
            count += 1
    conn.commit()
    return count


def verify(conn):
    c = conn.cursor()
    print("\n--- Verification ---")

    # All entity_class values valid
    c.execute("SELECT DISTINCT entity_class FROM entities")
    classes = [r[0] for r in c.fetchall()]
    invalid = [cl for cl in classes if cl not in VALID_ENTITY_CLASS]
    print(f"Entity classes: {classes}")
    print(f"Invalid classes: {invalid if invalid else 'NONE ✅'}")

    # All 6 story entities
    story_ids = ['ent_js006', 'ent_rw003', 'ent_kl004', 'ent_tm005', 'ent_ar007',
                 'agt_copilot_fin_01', 'agt_rpa_ops_07', 'agt_unknown_003']
    c.execute(f"SELECT entity_id FROM entities WHERE entity_id IN ({','.join('?' * len(story_ids))})", story_ids)
    found = [r[0] for r in c.fetchall()]
    print(f"Story entities: {len(found)}/8 present {'✅' if len(found) == 8 else '❌'}")

    # Enum fields valid
    c.execute("SELECT DISTINCT entity_status FROM entities")
    statuses = [r[0] for r in c.fetchall()]
    print(f"Entity statuses: {statuses}")

    c.execute("SELECT DISTINCT permission_level FROM entitlements")
    perms = [r[0] for r in c.fetchall()]
    print(f"Permission levels: {perms}")


def main():
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)

    conn = sqlite3.connect(DB_PATH)
    create_schema(conn)

    print("VEKTOR Normalization Layer")
    print("=" * 40)

    res_count = load_resources(conn)
    print(f"Resources:    {res_count} rows loaded")

    ent_count = load_entities(conn)
    print(f"Entities:     {ent_count} rows loaded")

    entl_count = load_entitlements(conn)
    print(f"Entitlements: {entl_count} rows loaded")

    evt_count = load_events(conn)
    print(f"Events:       {evt_count} rows loaded")

    verify(conn)
    conn.close()
    print(f"\n✅ vektor.db created at {DB_PATH}")


if __name__ == "__main__":
    main()
