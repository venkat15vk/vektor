#!/usr/bin/env python3
"""
VEKTOR Step 2: Synthetic Data Generation
Generates 4 CSV files for Meridian Financial with all 6 identity stories.
"""

import csv
import random
import uuid
import os
from datetime import datetime, timedelta

random.seed(42)

OUT_DIR = os.path.join(os.path.dirname(__file__), "data")
os.makedirs(OUT_DIR, exist_ok=True)

# =============================================================================
# CONSTANTS
# =============================================================================
RESOURCES = [
    {"resource_id": "res_fin",    "resource_name": "MERIDIAN-FIN",    "resource_type": "erp",      "sensitivity": "critical", "owner_entity_id": "ent_cfo001"},
    {"resource_id": "res_pay",    "resource_name": "MERIDIAN-PAY",    "resource_type": "payroll",  "sensitivity": "critical", "owner_entity_id": "ent_cfo001"},
    {"resource_id": "res_proddb", "resource_name": "MERIDIAN-PRODDB", "resource_type": "database", "sensitivity": "critical", "owner_entity_id": "ent_eng001"},
    {"resource_id": "res_gh",     "resource_name": "MERIDIAN-GH",     "resource_type": "scm",      "sensitivity": "high",     "owner_entity_id": "ent_eng001"},
    {"resource_id": "res_hr",     "resource_name": "MERIDIAN-HR",     "resource_type": "hr",       "sensitivity": "high",     "owner_entity_id": "ent_hr001"},
    {"resource_id": "res_admin",  "resource_name": "MERIDIAN-ADMIN",  "resource_type": "iam",      "sensitivity": "critical", "owner_entity_id": "ent_it001"},
]

RES_MAP = {r["resource_name"]: r["resource_id"] for r in RESOURCES}
RES_SENS = {r["resource_id"]: r["sensitivity"] for r in RESOURCES}

PEER_GROUPS = ["PG-FIN", "PG-ENG", "PG-OPS", "PG-EXT", "AGT-FIN", "AGT-ENG", "AGT-UNK"]
DEPARTMENTS = ["Finance", "Engineering", "Operations", "External", "Unknown"]
PERMISSION_LEVELS = ["global_admin", "admin", "owner", "write", "read", "none"]

FIRST_NAMES = ["James","Maria","David","Sarah","Michael","Jennifer","Robert","Linda","William","Elizabeth",
               "Richard","Barbara","Joseph","Susan","Thomas","Jessica","Charles","Karen","Daniel","Nancy",
               "Matthew","Lisa","Anthony","Betty","Mark","Dorothy","Donald","Sandra","Steven","Ashley",
               "Andrew","Kimberly","Joshua","Donna","Kenneth","Emily","Kevin","Carol","Brian","Michelle",
               "George","Amanda","Timothy","Melissa","Ronald","Deborah","Edward","Stephanie","Jason","Rebecca",
               "Jeffrey","Sharon","Ryan","Laura","Jacob","Cynthia","Gary","Kathleen","Nicholas","Amy",
               "Eric","Angela","Jonathan","Shirley","Stephen","Anna","Larry","Brenda","Justin","Pamela",
               "Scott","Emma","Brandon","Nicole","Benjamin","Helen","Samuel","Samantha","Raymond","Katherine",
               "Gregory","Christine","Frank","Debra","Alexander","Rachel","Patrick","Carolyn","Jack","Janet"]
LAST_NAMES = ["Smith","Johnson","Williams","Brown","Jones","Garcia","Miller","Davis","Rodriguez","Martinez",
              "Hernandez","Lopez","Gonzalez","Wilson","Anderson","Thomas","Taylor","Moore","Jackson","Martin",
              "Lee","Perez","Thompson","White","Harris","Sanchez","Clark","Ramirez","Lewis","Robinson",
              "Walker","Young","Allen","King","Wright","Scott","Torres","Nguyen","Hill","Flores",
              "Green","Adams","Nelson","Baker","Hall","Rivera","Campbell","Mitchell","Carter","Roberts"]

JOB_FUNCTIONS_FIN = ["Finance Analyst", "AP Specialist", "AR Specialist", "Treasury Analyst", "Financial Controller", "Accountant", "Payroll Specialist", "Tax Analyst", "Audit Analyst"]
JOB_FUNCTIONS_ENG = ["Software Engineer", "DevOps Engineer", "QA Engineer", "Data Engineer", "ML Engineer", "Frontend Developer", "Backend Developer", "Security Engineer", "Platform Engineer", "SRE"]
JOB_FUNCTIONS_OPS = ["HR Specialist", "IT Administrator", "Operations Manager", "Facilities Coordinator", "Compliance Analyst", "Project Manager", "Office Manager", "People Operations"]
JOB_FUNCTIONS_EXT = ["Contractor / UX Design", "Contractor / Data Migration", "Contractor / Security Audit", "Contractor / Cloud Architecture", "Contractor / DevOps"]

AGENT_TYPES = ["Microsoft Copilot", "UiPath RPA", "LangChain Agent", "Custom Python Agent", "ServiceNow Bot"]
AGENT_PURPOSES_FIN = ["AP invoice processing", "Financial reporting automation", "Budget reconciliation", "Expense categorization", "Revenue recognition"]
AGENT_PURPOSES_ENG = ["CI/CD pipeline runner", "Code review automation", "Dependency scanner", "Test automation", "Infrastructure provisioning", "Log analysis", "Alert triage", "Deploy automation"]

NOW = datetime(2026, 3, 8, 12, 0, 0)
DAY_180_AGO = NOW - timedelta(days=180)

# =============================================================================
# HELPER FUNCTIONS
# =============================================================================
ent_counter = {"h": 0, "a": 0}

def gen_ent_id(prefix="ent"):
    ent_counter["h"] += 1
    return f"{prefix}_{str(ent_counter['h']).zfill(5)}"

def gen_agent_id(prefix="agt"):
    ent_counter["a"] += 1
    return f"{prefix}_{str(ent_counter['a']).zfill(5)}"

def rand_date_range(start, end):
    delta = (end - start).days
    if delta <= 0:
        return start
    return start + timedelta(days=random.randint(0, delta))

def uid():
    return str(uuid.uuid4())[:12]

# =============================================================================
# STORY ENTITIES (Section 2)
# =============================================================================
story_entities = []
story_entitlements = []
story_events = []

# --- H1: ent_js006 — Compromised Session ---
story_entities.append({
    "entity_id": "ent_js006",
    "entity_class": "human",
    "entity_status": "active",
    "tenure_days": 891,
    "job_function": "Controller",
    "department": "Finance",
    "peer_group_id": "PG-FIN",
    "last_active_days": 0,
    "contract_end_date": "",
    "deployed_by": "",
    "parent_identity": "",
    "agent_purpose": "",
    "agent_type": "",
    "access_review_outcome": "APPROVE",
    "incident_flag": 1,
    "offboarding_cleanup_flag": 0,
})

# H1 entitlements
h1_entitlements = [
    ("res_fin",  "write", 0, 891, "ent_hr001", "approved", "critical"),
    ("res_pay",  "read",  0, 891, "ent_hr001", "approved", "critical"),
    ("res_hr",   "read",  5, 400, "ent_hr001", "approved", "high"),
    ("res_proddb","read", 14, 300, "ent_hr001", "approved", "critical"),
]
for i, (res, perm, lu, age, gb, ar, sens) in enumerate(h1_entitlements):
    story_entitlements.append({
        "entitlement_id": f"entl_js006_{i+1}",
        "entity_id": "ent_js006",
        "resource_id": res,
        "permission_level": perm,
        "last_used_days": lu,
        "entitlement_age_days": age,
        "granted_by": gb,
        "approval_record": ar,
        "resource_sensitivity": sens,
    })

# H1 events — 180 days of history PLUS the anomalous session
# Normal sessions: ~50 sessions over 180 days, weekday 08-18, avg 18.4min
# 3 weekend logins (09-16, <5min each)
h1_session_count = 50
for s in range(h1_session_count):
    days_back = random.randint(1, 180)
    dt_base = NOW - timedelta(days=days_back)
    hour = random.randint(8, 17)
    minute = random.randint(0, 59)
    dt_base = dt_base.replace(hour=hour, minute=minute, second=random.randint(0, 59))
    # Force weekday
    while dt_base.weekday() >= 5:
        dt_base -= timedelta(days=1)
    dur = max(252, int(random.gauss(18.4 * 60, 5 * 60)))  # avg 18.4 min, min 252s
    entropy = round(random.gauss(0.74, 0.18), 2)
    entropy = max(0.3, min(1.0, entropy))
    apm = round(random.uniform(0.2, 0.5), 2)
    sess_id = f"sess_js006_{s:03d}"
    actions = random.choice(["login", "read", "write"])
    story_events.append({
        "event_id": f"evt_js006_{s:04d}",
        "entity_id": "ent_js006",
        "resource_id": random.choice(["res_fin", "res_pay", "res_hr"]),
        "action_type": actions,
        "timestamp": dt_base.strftime("%Y-%m-%dT%H:%M:%S"),
        "action_hour": dt_base.hour,
        "action_day_of_week": dt_base.strftime("%A"),
        "session_id": sess_id,
        "session_duration_seconds": dur,
        "actions_per_minute": apm,
        "action_sequence_entropy": entropy,
        "geo_ip_country": "US",
        "geo_ip_change_flag": "false",
    })

# 3 weekend logins (09-16, <5min)
for w in range(3):
    days_back = random.choice([30, 60, 120])
    dt_base = NOW - timedelta(days=days_back)
    while dt_base.weekday() < 5:
        dt_base += timedelta(days=1)
    hour = random.randint(9, 15)
    dt_base = dt_base.replace(hour=hour, minute=random.randint(0, 59), second=random.randint(0, 59))
    dur = random.randint(60, 290)
    sess_id = f"sess_js006_wk{w}"
    story_events.append({
        "event_id": f"evt_js006_wk{w:02d}",
        "entity_id": "ent_js006",
        "resource_id": "res_fin",
        "action_type": "read",
        "timestamp": dt_base.strftime("%Y-%m-%dT%H:%M:%S"),
        "action_hour": dt_base.hour,
        "action_day_of_week": dt_base.strftime("%A"),
        "session_id": sess_id,
        "session_duration_seconds": dur,
        "actions_per_minute": round(random.uniform(0.2, 0.4), 2),
        "action_sequence_entropy": round(random.gauss(0.74, 0.15), 2),
        "geo_ip_country": "US",
        "geo_ip_change_flag": "false",
    })

# THE ANOMALOUS SESSION — 5 events, Sunday 02:17, 47 seconds
anomalous_ts = datetime(2026, 3, 1, 2, 17, 3)  # Sunday
anomalous_session_events = [
    ("evt_js006_anom_01", "res_admin", "login",    "2026-03-01T02:17:03"),
    ("evt_js006_anom_02", "res_pay",   "read",     "2026-03-01T02:17:11"),
    ("evt_js006_anom_03", "res_pay",   "read",     "2026-03-01T02:17:18"),
    ("evt_js006_anom_04", "res_pay",   "export",   "2026-03-01T02:17:33"),
    ("evt_js006_anom_05", "res_admin", "login",    "2026-03-01T02:17:50"),
]
for eid, res, act, ts in anomalous_session_events:
    story_events.append({
        "event_id": eid,
        "entity_id": "ent_js006",
        "resource_id": res,
        "action_type": act,
        "timestamp": ts,
        "action_hour": 2,
        "action_day_of_week": "Sunday",
        "session_id": "sess_js006_anom",
        "session_duration_seconds": 47,
        "actions_per_minute": 1.28,
        "action_sequence_entropy": 0.12,
        "geo_ip_country": "US",
        "geo_ip_change_flag": "false",
    })


# --- H2: SOX Violation — ent_rw003, ent_kl004, ent_tm005 ---
sox_entities = [
    {
        "entity_id": "ent_rw003",
        "entity_class": "human",
        "entity_status": "active",
        "tenure_days": 612,
        "job_function": "AP Specialist",
        "department": "Finance",
        "peer_group_id": "PG-FIN",
        "last_active_days": 1,
        "contract_end_date": "",
        "deployed_by": "",
        "parent_identity": "",
        "agent_purpose": "",
        "agent_type": "",
        "access_review_outcome": "NOT_REVIEWED",
        "incident_flag": 0,
        "offboarding_cleanup_flag": 0,
    },
    {
        "entity_id": "ent_kl004",
        "entity_class": "human",
        "entity_status": "active",
        "tenure_days": 580,
        "job_function": "AP Specialist",
        "department": "Finance",
        "peer_group_id": "PG-FIN",
        "last_active_days": 0,
        "contract_end_date": "",
        "deployed_by": "",
        "parent_identity": "",
        "agent_purpose": "",
        "agent_type": "",
        "access_review_outcome": "NOT_REVIEWED",
        "incident_flag": 0,
        "offboarding_cleanup_flag": 0,
    },
    {
        "entity_id": "ent_tm005",
        "entity_class": "human",
        "entity_status": "active",
        "tenure_days": 730,
        "job_function": "Finance Manager",
        "department": "Finance",
        "peer_group_id": "PG-FIN",
        "last_active_days": 0,
        "contract_end_date": "",
        "deployed_by": "",
        "parent_identity": "",
        "agent_purpose": "",
        "agent_type": "",
        "access_review_outcome": "NOT_REVIEWED",
        "incident_flag": 0,
        "offboarding_cleanup_flag": 0,
    },
]
story_entities.extend(sox_entities)

# SOX entitlements — permission combos per Section 2
# ent_rw003: payment_create (FIN) + payment_approve (PAY)
story_entitlements.extend([
    {"entitlement_id": "entl_rw003_1", "entity_id": "ent_rw003", "resource_id": "res_fin", "permission_level": "write",
     "last_used_days": 1, "entitlement_age_days": 427, "granted_by": "ent_it001", "approval_record": "auto_provisioned",
     "resource_sensitivity": "critical"},
    {"entitlement_id": "entl_rw003_2", "entity_id": "ent_rw003", "resource_id": "res_pay", "permission_level": "write",
     "last_used_days": 1, "entitlement_age_days": 427, "granted_by": "ent_it001", "approval_record": "auto_provisioned",
     "resource_sensitivity": "critical"},
    {"entitlement_id": "entl_rw003_3", "entity_id": "ent_rw003", "resource_id": "res_hr", "permission_level": "read",
     "last_used_days": 10, "entitlement_age_days": 427, "granted_by": "ent_it001", "approval_record": "approved",
     "resource_sensitivity": "high"},
])

# ent_kl004: same combo as rw003
story_entitlements.extend([
    {"entitlement_id": "entl_kl004_1", "entity_id": "ent_kl004", "resource_id": "res_fin", "permission_level": "write",
     "last_used_days": 0, "entitlement_age_days": 427, "granted_by": "ent_it001", "approval_record": "auto_provisioned",
     "resource_sensitivity": "critical"},
    {"entitlement_id": "entl_kl004_2", "entity_id": "ent_kl004", "resource_id": "res_pay", "permission_level": "write",
     "last_used_days": 0, "entitlement_age_days": 427, "granted_by": "ent_it001", "approval_record": "auto_provisioned",
     "resource_sensitivity": "critical"},
    {"entitlement_id": "entl_kl004_3", "entity_id": "ent_kl004", "resource_id": "res_hr", "permission_level": "read",
     "last_used_days": 7, "entitlement_age_days": 427, "granted_by": "ent_it001", "approval_record": "approved",
     "resource_sensitivity": "high"},
])

# ent_tm005: payment_create + payment_batch_release + payment_approve
story_entitlements.extend([
    {"entitlement_id": "entl_tm005_1", "entity_id": "ent_tm005", "resource_id": "res_fin", "permission_level": "admin",
     "last_used_days": 0, "entitlement_age_days": 427, "granted_by": "ent_it001", "approval_record": "auto_provisioned",
     "resource_sensitivity": "critical"},
    {"entitlement_id": "entl_tm005_2", "entity_id": "ent_tm005", "resource_id": "res_pay", "permission_level": "admin",
     "last_used_days": 0, "entitlement_age_days": 427, "granted_by": "ent_it001", "approval_record": "auto_provisioned",
     "resource_sensitivity": "critical"},
    {"entitlement_id": "entl_tm005_3", "entity_id": "ent_tm005", "resource_id": "res_pay", "permission_level": "write",
     "last_used_days": 2, "entitlement_age_days": 427, "granted_by": "ent_it001", "approval_record": "auto_provisioned",
     "resource_sensitivity": "critical"},
    {"entitlement_id": "entl_tm005_4", "entity_id": "ent_tm005", "resource_id": "res_hr", "permission_level": "read",
     "last_used_days": 5, "entitlement_age_days": 500, "granted_by": "ent_it001", "approval_record": "approved",
     "resource_sensitivity": "high"},
])

# SOX entities events — normal activity
for ent_id in ["ent_rw003", "ent_kl004", "ent_tm005"]:
    for e in range(30):
        days_back = random.randint(1, 180)
        dt = NOW - timedelta(days=days_back)
        dt = dt.replace(hour=random.randint(8, 17), minute=random.randint(0, 59), second=random.randint(0, 59))
        while dt.weekday() >= 5:
            dt -= timedelta(days=1)
        story_events.append({
            "event_id": f"evt_{ent_id}_{e:04d}",
            "entity_id": ent_id,
            "resource_id": random.choice(["res_fin", "res_pay"]),
            "action_type": random.choice(["read", "write"]),
            "timestamp": dt.strftime("%Y-%m-%dT%H:%M:%S"),
            "action_hour": dt.hour,
            "action_day_of_week": dt.strftime("%A"),
            "session_id": f"sess_{ent_id}_{e:03d}",
            "session_duration_seconds": random.randint(300, 3600),
            "actions_per_minute": round(random.uniform(0.2, 0.6), 2),
            "action_sequence_entropy": round(random.gauss(0.7, 0.15), 2),
            "geo_ip_country": "US",
            "geo_ip_change_flag": "false",
        })


# --- H3: ent_ar007 — Contractor Who Never Left ---
story_entities.append({
    "entity_id": "ent_ar007",
    "entity_class": "external",
    "entity_status": "active",
    "tenure_days": 547,
    "job_function": "Contractor / UX Design",
    "department": "External",
    "peer_group_id": "PG-EXT",
    "last_active_days": 34,
    "contract_end_date": "2023-08-15",
    "deployed_by": "",
    "parent_identity": "",
    "agent_purpose": "",
    "agent_type": "",
    "access_review_outcome": "NOT_REVIEWED",
    "incident_flag": 0,
    "offboarding_cleanup_flag": 1,
})

story_entitlements.extend([
    {"entitlement_id": "entl_ar007_1", "entity_id": "ent_ar007", "resource_id": "res_proddb", "permission_level": "read",
     "last_used_days": 34, "entitlement_age_days": 547, "granted_by": "ent_eng001", "approval_record": "approved",
     "resource_sensitivity": "critical"},
    {"entitlement_id": "entl_ar007_2", "entity_id": "ent_ar007", "resource_id": "res_gh", "permission_level": "write",
     "last_used_days": 12, "entitlement_age_days": 547, "granted_by": "ent_eng001", "approval_record": "approved",
     "resource_sensitivity": "high"},
    {"entitlement_id": "entl_ar007_3", "entity_id": "ent_ar007", "resource_id": "res_hr", "permission_level": "read",
     "last_used_days": 280, "entitlement_age_days": 547, "granted_by": "ent_hr001", "approval_record": "approved",
     "resource_sensitivity": "high"},
    {"entitlement_id": "entl_ar007_4", "entity_id": "ent_ar007", "resource_id": "res_fin", "permission_level": "read",
     "last_used_days": 47, "entitlement_age_days": 400, "granted_by": "ent_hr001", "approval_record": "approved",
     "resource_sensitivity": "critical"},
])

# H3 events — sparse, with geo_ip_change
for e in range(10):
    days_back = random.randint(12, 120)
    dt = NOW - timedelta(days=days_back)
    dt = dt.replace(hour=random.randint(6, 22), minute=random.randint(0, 59), second=random.randint(0, 59))
    geo = "RO" if e == 0 else "US"  # most recent login from different country
    story_events.append({
        "event_id": f"evt_ar007_{e:04d}",
        "entity_id": "ent_ar007",
        "resource_id": random.choice(["res_proddb", "res_gh", "res_fin"]),
        "action_type": random.choice(["login", "read", "write"]),
        "timestamp": dt.strftime("%Y-%m-%dT%H:%M:%S"),
        "action_hour": dt.hour,
        "action_day_of_week": dt.strftime("%A"),
        "session_id": f"sess_ar007_{e:03d}",
        "session_duration_seconds": random.randint(120, 1800),
        "actions_per_minute": round(random.uniform(0.2, 0.5), 2),
        "action_sequence_entropy": round(random.gauss(0.6, 0.2), 2),
        "geo_ip_country": geo,
        "geo_ip_change_flag": "true" if geo != "US" else "false",
    })


# --- A1: agt_copilot_fin_01 — Over-Privileged Finance Agent ---
story_entities.append({
    "entity_id": "agt_copilot_fin_01",
    "entity_class": "ai_agent",
    "entity_status": "active",
    "tenure_days": 61,
    "job_function": "AP Automation",
    "department": "Finance",
    "peer_group_id": "AGT-FIN",
    "last_active_days": 0,
    "contract_end_date": "",
    "deployed_by": "ent_cfo001",
    "parent_identity": "",
    "agent_purpose": "Automate AP invoice processing and financial reporting",
    "agent_type": "Microsoft Copilot",
    "access_review_outcome": "NOT_REVIEWED",
    "incident_flag": 0,
    "offboarding_cleanup_flag": 0,
})

# A1 entitlements: 19 total
a1_base = [
    ("res_fin",    "admin",  3, 61),
    ("res_pay",    "admin",  8, 61),
    ("res_proddb", "owner",  61, 61),
    ("res_gh",     "read",   61, 61),
    ("res_admin",  "write",  31, 61),
]
for i, (res, perm, lu, age) in enumerate(a1_base):
    story_entitlements.append({
        "entitlement_id": f"entl_agt_fin01_{i+1}",
        "entity_id": "agt_copilot_fin_01",
        "resource_id": res,
        "permission_level": perm,
        "last_used_days": lu,
        "entitlement_age_days": age,
        "granted_by": "ent_cfo001",
        "approval_record": "approved",
        "resource_sensitivity": RES_SENS[res],
    })

# +12 graph scopes (mostly unused) + 2 group memberships = 14 more
for i in range(14):
    lu = 61 if i < 10 else random.randint(5, 30)  # mostly unused
    story_entitlements.append({
        "entitlement_id": f"entl_agt_fin01_graph_{i+1}",
        "entity_id": "agt_copilot_fin_01",
        "resource_id": "res_admin",
        "permission_level": "read",
        "last_used_days": lu,
        "entitlement_age_days": 61,
        "granted_by": "ent_cfo001",
        "approval_record": "approved",
        "resource_sensitivity": "critical",
    })

# A1 events — high volume: ~891,204 API calls in 61 days, runs every 4 min
# We'll generate representative samples (not all 891k)
for e in range(200):
    days_back = random.randint(0, 61)
    dt = NOW - timedelta(days=days_back)
    dt = dt.replace(hour=random.randint(0, 23), minute=random.randint(0, 59), second=random.randint(0, 59))
    story_events.append({
        "event_id": f"evt_agt_fin01_{e:04d}",
        "entity_id": "agt_copilot_fin_01",
        "resource_id": random.choice(["res_fin", "res_pay"]),
        "action_type": random.choice(["read", "write", "admin_op"]),
        "timestamp": dt.strftime("%Y-%m-%dT%H:%M:%S"),
        "action_hour": dt.hour,
        "action_day_of_week": dt.strftime("%A"),
        "session_id": f"sess_agt_fin01_{e:04d}",
        "session_duration_seconds": random.randint(1, 10),
        "actions_per_minute": round(random.uniform(10, 30), 2),
        "action_sequence_entropy": round(random.uniform(0.05, 0.15), 2),
        "geo_ip_country": "US",
        "geo_ip_change_flag": "false",
    })


# --- A2: agt_rpa_ops_07 — Agent That Inherited Bad Access ---
story_entities.append({
    "entity_id": "agt_rpa_ops_07",
    "entity_class": "rpa_bot",
    "entity_status": "active",
    "tenure_days": 203,
    "job_function": "Onboarding Bot",
    "department": "Operations",
    "peer_group_id": "AGT-ENG",
    "last_active_days": 0,
    "contract_end_date": "",
    "deployed_by": "ent_it_mgr_02",
    "parent_identity": "ent_it_mgr_02",
    "agent_purpose": "Automate employee onboarding - provision access for new hires",
    "agent_type": "UiPath RPA",
    "access_review_outcome": "NOT_REVIEWED",
    "incident_flag": 0,
    "offboarding_cleanup_flag": 0,
})

# A2 entitlements — inherited from ent_it_mgr_02
story_entitlements.extend([
    {"entitlement_id": "entl_agt_rpa07_1", "entity_id": "agt_rpa_ops_07", "resource_id": "res_admin",
     "permission_level": "global_admin", "last_used_days": 0, "entitlement_age_days": 203,
     "granted_by": "ent_it_mgr_02", "approval_record": "auto_provisioned", "resource_sensitivity": "critical"},
    {"entitlement_id": "entl_agt_rpa07_2", "entity_id": "agt_rpa_ops_07", "resource_id": "res_hr",
     "permission_level": "admin", "last_used_days": 0, "entitlement_age_days": 203,
     "granted_by": "ent_it_mgr_02", "approval_record": "auto_provisioned", "resource_sensitivity": "high"},
    {"entitlement_id": "entl_agt_rpa07_3", "entity_id": "agt_rpa_ops_07", "resource_id": "res_fin",
     "permission_level": "read", "last_used_days": 5, "entitlement_age_days": 203,
     "granted_by": "ent_it_mgr_02", "approval_record": "auto_provisioned", "resource_sensitivity": "critical"},
    {"entitlement_id": "entl_agt_rpa07_4", "entity_id": "agt_rpa_ops_07", "resource_id": "res_admin",
     "permission_level": "write", "last_used_days": 0, "entitlement_age_days": 203,
     "granted_by": "ent_it_mgr_02", "approval_record": "auto_provisioned", "resource_sensitivity": "critical"},
])

# A2 events — nightly runs + suspicious finance accesses
for e in range(60):
    days_back = random.randint(0, 203)
    dt = NOW - timedelta(days=days_back)
    dt = dt.replace(hour=23, minute=random.randint(0, 30), second=random.randint(0, 59))
    act = "provision" if e < 47 else random.choice(["write", "admin_op", "read"])
    res = "res_hr" if e < 47 else random.choice(["res_admin", "res_fin"])
    story_events.append({
        "event_id": f"evt_agt_rpa07_{e:04d}",
        "entity_id": "agt_rpa_ops_07",
        "resource_id": res,
        "action_type": act,
        "timestamp": dt.strftime("%Y-%m-%dT%H:%M:%S"),
        "action_hour": 23,
        "action_day_of_week": dt.strftime("%A"),
        "session_id": f"sess_agt_rpa07_{e:04d}",
        "session_duration_seconds": random.randint(30, 300),
        "actions_per_minute": round(random.uniform(5, 20), 2),
        "action_sequence_entropy": round(random.uniform(0.05, 0.2), 2),
        "geo_ip_country": "US",
        "geo_ip_change_flag": "false",
    })


# --- A3: agt_unknown_003 — Shadow Agent (LEAD DEMO STORY) ---
story_entities.append({
    "entity_id": "agt_unknown_003",
    "entity_class": "ai_agent",
    "entity_status": "active",
    "tenure_days": 34,
    "job_function": "UNKNOWN",
    "department": "Unknown",
    "peer_group_id": "AGT-UNK",
    "last_active_days": 0,
    "contract_end_date": "",
    "deployed_by": "",
    "parent_identity": "",
    "agent_purpose": "",
    "agent_type": "",
    "access_review_outcome": "NOT_REVIEWED",
    "incident_flag": 1,
    "offboarding_cleanup_flag": 0,
})

# A3 entitlements — no approval records
story_entitlements.extend([
    {"entitlement_id": "entl_agt_unk003_1", "entity_id": "agt_unknown_003", "resource_id": "res_proddb",
     "permission_level": "read", "last_used_days": 0, "entitlement_age_days": 34,
     "granted_by": "", "approval_record": "unknown", "resource_sensitivity": "critical"},
    {"entitlement_id": "entl_agt_unk003_2", "entity_id": "agt_unknown_003", "resource_id": "res_fin",
     "permission_level": "read", "last_used_days": 0, "entitlement_age_days": 34,
     "granted_by": "", "approval_record": "unknown", "resource_sensitivity": "critical"},
    {"entitlement_id": "entl_agt_unk003_3", "entity_id": "agt_unknown_003", "resource_id": "res_gh",
     "permission_level": "read", "last_used_days": 0, "entitlement_age_days": 34,
     "granted_by": "", "approval_record": "unknown", "resource_sensitivity": "high"},
])

# A3 events — non-deterministic schedule, 127,445 API calls in 34 days (sample 150)
for e in range(150):
    days_back = random.randint(0, 34)
    dt = NOW - timedelta(days=days_back)
    dt = dt.replace(hour=random.randint(0, 23), minute=random.randint(0, 59), second=random.randint(0, 59))
    story_events.append({
        "event_id": f"evt_agt_unk003_{e:04d}",
        "entity_id": "agt_unknown_003",
        "resource_id": random.choice(["res_proddb", "res_fin", "res_gh"]),
        "action_type": random.choice(["read", "unknown"]),
        "timestamp": dt.strftime("%Y-%m-%dT%H:%M:%S"),
        "action_hour": dt.hour,
        "action_day_of_week": dt.strftime("%A"),
        "session_id": f"sess_agt_unk003_{e:04d}",
        "session_duration_seconds": random.randint(1, 60),
        "actions_per_minute": round(random.uniform(15, 50), 2),
        "action_sequence_entropy": round(random.uniform(0.6, 0.95), 2),
        "geo_ip_country": random.choice(["US", "DE", "SG", "IE"]),
        "geo_ip_change_flag": "true" if random.random() > 0.5 else "false",
    })


# =============================================================================
# SUPPORTING NAMED ENTITIES (resource owners, deployers referenced above)
# =============================================================================
support_entities = [
    {"entity_id": "ent_cfo001",    "entity_class": "human", "entity_status": "active", "tenure_days": 1200, "job_function": "CFO",
     "department": "Finance", "peer_group_id": "PG-FIN", "last_active_days": 0},
    {"entity_id": "ent_eng001",    "entity_class": "human", "entity_status": "active", "tenure_days": 950, "job_function": "VP Engineering",
     "department": "Engineering", "peer_group_id": "PG-ENG", "last_active_days": 0},
    {"entity_id": "ent_hr001",     "entity_class": "human", "entity_status": "active", "tenure_days": 800, "job_function": "HR Director",
     "department": "Operations", "peer_group_id": "PG-OPS", "last_active_days": 1},
    {"entity_id": "ent_it001",     "entity_class": "human", "entity_status": "active", "tenure_days": 700, "job_function": "IT Administrator",
     "department": "Operations", "peer_group_id": "PG-OPS", "last_active_days": 0},
    {"entity_id": "ent_it_mgr_02", "entity_class": "human", "entity_status": "active", "tenure_days": 650, "job_function": "IT Manager",
     "department": "Operations", "peer_group_id": "PG-OPS", "last_active_days": 0},
]
for se in support_entities:
    se.update({
        "contract_end_date": "", "deployed_by": "", "parent_identity": "",
        "agent_purpose": "", "agent_type": "",
        "access_review_outcome": "APPROVE", "incident_flag": 0, "offboarding_cleanup_flag": 0,
    })

# =============================================================================
# BACKGROUND POPULATION (Section 6.3)
# =============================================================================
bg_entities = []
bg_entitlements = []
bg_events = []

all_bg_entity_ids = []

# Helper to build a background entity
def make_bg_human(eid, pg, dept, jf, status="active", tenure_range=(90, 1200),
                  la_range=(0, 30), aro="APPROVE", inc=0, obc=0, ced=""):
    tenure = random.randint(*tenure_range)
    return {
        "entity_id": eid, "entity_class": "human", "entity_status": status,
        "tenure_days": tenure, "job_function": jf, "department": dept,
        "peer_group_id": pg, "last_active_days": random.randint(*la_range),
        "contract_end_date": ced, "deployed_by": "", "parent_identity": "",
        "agent_purpose": "", "agent_type": "",
        "access_review_outcome": aro, "incident_flag": inc, "offboarding_cleanup_flag": obc,
    }

def make_bg_agent(eid, ecls, pg, dept, jf, atype, apurp, dby, status="active",
                  tenure_range=(30, 365), la_range=(0, 5), aro="APPROVE", inc=0, obc=0):
    tenure = random.randint(*tenure_range)
    return {
        "entity_id": eid, "entity_class": ecls, "entity_status": status,
        "tenure_days": tenure, "job_function": jf, "department": dept,
        "peer_group_id": pg, "last_active_days": random.randint(*la_range),
        "contract_end_date": "", "deployed_by": dby, "parent_identity": "",
        "agent_purpose": apurp, "agent_type": atype,
        "access_review_outcome": aro, "incident_flag": inc, "offboarding_cleanup_flag": obc,
    }

def make_entitlements_for(eid, count_range=(3, 8), perm_max="write"):
    ents = []
    count = random.randint(*count_range)
    perms = ["read", "write"] if perm_max == "write" else ["read"]
    for i in range(count):
        res = random.choice(RESOURCES)
        ents.append({
            "entitlement_id": f"entl_{eid}_{i+1}",
            "entity_id": eid,
            "resource_id": res["resource_id"],
            "permission_level": random.choice(perms),
            "last_used_days": random.randint(0, 60),
            "entitlement_age_days": random.randint(30, 800),
            "granted_by": random.choice(["ent_it001", "ent_hr001", "ent_eng001"]),
            "approval_record": "approved",
            "resource_sensitivity": res["sensitivity"],
        })
    return ents

def make_events_for(eid, count_range=(20, 60)):
    evts = []
    count = random.randint(*count_range)
    for e in range(count):
        days_back = random.randint(0, 180)
        dt = NOW - timedelta(days=days_back)
        dt = dt.replace(hour=random.randint(7, 19), minute=random.randint(0, 59), second=random.randint(0, 59))
        evts.append({
            "event_id": f"evt_{eid}_{e:04d}",
            "entity_id": eid,
            "resource_id": random.choice([r["resource_id"] for r in RESOURCES]),
            "action_type": random.choice(["login", "read", "write"]),
            "timestamp": dt.strftime("%Y-%m-%dT%H:%M:%S"),
            "action_hour": dt.hour,
            "action_day_of_week": dt.strftime("%A"),
            "session_id": f"sess_{eid}_{e:04d}",
            "session_duration_seconds": random.randint(120, 3600),
            "actions_per_minute": round(random.uniform(0.1, 0.6), 2),
            "action_sequence_entropy": round(random.gauss(0.7, 0.15), 2),
            "geo_ip_country": "US",
            "geo_ip_change_flag": "false",
        })
    return evts

# Track how many of each we've generated
bg_idx = 0

# --- 80 Clean human employees ---
# Distribute across PG-FIN (remaining to get ~31 total), PG-ENG (~58), PG-OPS (~24)
# Story entities already in PG-FIN: ent_js006, ent_rw003, ent_kl004, ent_tm005 = 4
# Support in PG-FIN: ent_cfo001 = 1. Total story+support PG-FIN = 5
# Need ~26 more PG-FIN from clean + overprov + dormant
# PG-ENG support: ent_eng001 = 1. Need ~57 more
# PG-OPS support: ent_hr001, ent_it001, ent_it_mgr_02 = 3. Need ~21 more
# PG-EXT: ent_ar007 = 1. Need ~18 more

fin_clean = 18
eng_clean = 35
ops_clean = 14
ext_clean = 6

for i in range(fin_clean):
    eid = f"ent_bg_{bg_idx:03d}"
    bg_idx += 1
    jf = random.choice(JOB_FUNCTIONS_FIN)
    bg_entities.append(make_bg_human(eid, "PG-FIN", "Finance", jf))
    bg_entitlements.extend(make_entitlements_for(eid, (3, 6), "read"))
    bg_events.extend(make_events_for(eid, (25, 45)))

for i in range(eng_clean):
    eid = f"ent_bg_{bg_idx:03d}"
    bg_idx += 1
    jf = random.choice(JOB_FUNCTIONS_ENG)
    bg_entities.append(make_bg_human(eid, "PG-ENG", "Engineering", jf))
    bg_entitlements.extend(make_entitlements_for(eid, (3, 7), "write"))
    bg_events.extend(make_events_for(eid, (30, 55)))

for i in range(ops_clean):
    eid = f"ent_bg_{bg_idx:03d}"
    bg_idx += 1
    jf = random.choice(JOB_FUNCTIONS_OPS)
    bg_entities.append(make_bg_human(eid, "PG-OPS", "Operations", jf))
    bg_entitlements.extend(make_entitlements_for(eid, (2, 5), "read"))
    bg_events.extend(make_events_for(eid, (20, 40)))

for i in range(ext_clean):
    eid = f"ent_bg_{bg_idx:03d}"
    bg_idx += 1
    jf = random.choice(JOB_FUNCTIONS_EXT)
    end_date = (NOW - timedelta(days=random.randint(-30, 60))).strftime("%Y-%m-%d")  # some still active
    bg_entities.append(make_bg_human(eid, "PG-EXT", "External", jf, ced=end_date))
    bg_entitlements.extend(make_entitlements_for(eid, (2, 4), "read"))
    bg_events.extend(make_events_for(eid, (10, 25)))

# --- 30 Mildly over-provisioned humans ---
for i in range(30):
    eid = f"ent_bg_{bg_idx:03d}"
    bg_idx += 1
    pg = random.choice(["PG-FIN", "PG-ENG", "PG-OPS"])
    dept = {"PG-FIN": "Finance", "PG-ENG": "Engineering", "PG-OPS": "Operations"}[pg]
    jfs = {"PG-FIN": JOB_FUNCTIONS_FIN, "PG-ENG": JOB_FUNCTIONS_ENG, "PG-OPS": JOB_FUNCTIONS_OPS}[pg]
    jf = random.choice(jfs)
    bg_entities.append(make_bg_human(eid, pg, dept, jf, aro="APPROVE"))
    # More entitlements, some unused
    ents = make_entitlements_for(eid, (6, 12), "write")
    # Make some have high last_used_days (unused)
    for e in ents:
        if random.random() > 0.5:
            e["last_used_days"] = random.randint(60, 180)
    bg_entitlements.extend(ents)
    bg_events.extend(make_events_for(eid, (20, 40)))

# --- 14 Dormant-entitlement humans (non-story) ---
for i in range(14):
    eid = f"ent_bg_{bg_idx:03d}"
    bg_idx += 1
    pg = random.choice(["PG-FIN", "PG-ENG", "PG-OPS"])
    dept = {"PG-FIN": "Finance", "PG-ENG": "Engineering", "PG-OPS": "Operations"}[pg]
    jfs = {"PG-FIN": JOB_FUNCTIONS_FIN, "PG-ENG": JOB_FUNCTIONS_ENG, "PG-OPS": JOB_FUNCTIONS_OPS}[pg]
    jf = random.choice(jfs)
    bg_entities.append(make_bg_human(eid, pg, dept, jf, la_range=(30, 120), aro="REVOKE"))
    ents = make_entitlements_for(eid, (3, 8), "write")
    for e in ents:
        e["last_used_days"] = random.randint(60, 180)
    bg_entitlements.extend(ents)
    bg_events.extend(make_events_for(eid, (5, 15)))

# --- 12 Clean registered agents ---
for i in range(12):
    eid = f"agt_bg_{bg_idx:03d}"
    bg_idx += 1
    if i < 5:
        pg, dept = "AGT-FIN", "Finance"
        jf = random.choice(["AP Automation", "Financial Reporting", "Budget Bot", "Expense Categorizer", "Revenue Bot"])
        apurp = random.choice(AGENT_PURPOSES_FIN)
    else:
        pg, dept = "AGT-ENG", "Engineering"
        jf = random.choice(["CI/CD Bot", "Code Scanner", "Dependency Bot", "Test Runner", "Deploy Bot", "Log Analyzer", "Alert Bot"])
        apurp = random.choice(AGENT_PURPOSES_ENG)
    atype = random.choice(AGENT_TYPES)
    dby = random.choice(["ent_cfo001", "ent_eng001", "ent_it001"])
    # Ensure good mix: first 6 are ai_agent, next 3 service_account, last 3 pipeline
    if i < 6:
        ecls = "ai_agent"
    elif i < 9:
        ecls = "service_account"
    else:
        ecls = "pipeline"
    bg_entities.append(make_bg_agent(eid, ecls, pg, dept, jf, atype, apurp, dby))
    ents = make_entitlements_for(eid, (3, 6), "read")
    for e in ents:
        e["approval_record"] = "approved"
    bg_entitlements.extend(ents)
    bg_events.extend(make_events_for(eid, (30, 80)))

# --- 8 Mildly over-privileged agents ---
for i in range(8):
    eid = f"agt_bg_{bg_idx:03d}"
    bg_idx += 1
    if i < 4:
        pg, dept = "AGT-FIN", "Finance"
        jf = random.choice(["AP Automation", "Financial Reporting"])
        apurp = random.choice(AGENT_PURPOSES_FIN)
    else:
        pg, dept = "AGT-ENG", "Engineering"
        jf = random.choice(["CI/CD Bot", "Deploy Bot"])
        apurp = random.choice(AGENT_PURPOSES_ENG)
    atype = random.choice(AGENT_TYPES)
    dby = random.choice(["ent_cfo001", "ent_eng001", "ent_it001"])
    bg_entities.append(make_bg_agent(eid, "ai_agent" if i < 4 else "rpa_bot", pg, dept, jf, atype, apurp, dby,
                                     aro="REVOKE"))
    ents = make_entitlements_for(eid, (8, 14), "write")
    for e in ents:
        if random.random() > 0.4:
            e["last_used_days"] = random.randint(30, 120)
    bg_entitlements.extend(ents)
    bg_events.extend(make_events_for(eid, (40, 100)))


# =============================================================================
# ASSEMBLE ALL DATA
# =============================================================================
all_entities = story_entities + support_entities + bg_entities

# Verify count — need exactly 150
current_count = len(all_entities)
print(f"Entity count before padding: {current_count}")

# Pad to 150 if needed
while len(all_entities) < 150:
    eid = f"ent_bg_{bg_idx:03d}"
    bg_idx += 1
    pg = random.choice(["PG-ENG", "PG-OPS"])
    dept = {"PG-ENG": "Engineering", "PG-OPS": "Operations"}[pg]
    jfs = {"PG-ENG": JOB_FUNCTIONS_ENG, "PG-OPS": JOB_FUNCTIONS_OPS}[pg]
    jf = random.choice(jfs)
    ent = make_bg_human(eid, pg, dept, jf)
    all_entities.append(ent)
    bg_entitlements.extend(make_entitlements_for(eid, (3, 5), "read"))
    bg_events.extend(make_events_for(eid, (15, 30)))

# Trim to exactly 150 if over
if len(all_entities) > 150:
    all_entities = all_entities[:150]

all_entitlements = story_entitlements + bg_entitlements
all_events = story_events + bg_events

print(f"Final entity count: {len(all_entities)}")
print(f"Entitlement count: {len(all_entitlements)}")
print(f"Event count: {len(all_events)}")
print(f"Resource count: {len(RESOURCES)}")

# =============================================================================
# WRITE CSV FILES
# =============================================================================

# --- entities.csv ---
entity_fields = [
    "entity_id", "entity_class", "entity_status", "tenure_days", "job_function",
    "department", "peer_group_id", "last_active_days", "contract_end_date",
    "deployed_by", "parent_identity", "agent_purpose", "agent_type",
    "access_review_outcome", "incident_flag", "offboarding_cleanup_flag"
]

with open(os.path.join(OUT_DIR, "entities.csv"), "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=entity_fields)
    writer.writeheader()
    for ent in all_entities:
        writer.writerow(ent)

# --- entitlements.csv ---
entitlement_fields = [
    "entitlement_id", "entity_id", "resource_id", "permission_level",
    "last_used_days", "entitlement_age_days", "granted_by", "approval_record",
    "resource_sensitivity"
]

with open(os.path.join(OUT_DIR, "entitlements.csv"), "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=entitlement_fields)
    writer.writeheader()
    for ent in all_entitlements:
        writer.writerow(ent)

# --- events.csv ---
event_fields = [
    "event_id", "entity_id", "resource_id", "action_type", "timestamp",
    "action_hour", "action_day_of_week", "session_id", "session_duration_seconds",
    "actions_per_minute", "action_sequence_entropy", "geo_ip_country",
    "geo_ip_change_flag"
]

with open(os.path.join(OUT_DIR, "events.csv"), "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=event_fields)
    writer.writeheader()
    for evt in all_events:
        writer.writerow(evt)

# --- resources.csv ---
resource_fields = ["resource_id", "resource_name", "resource_type", "sensitivity", "owner_entity_id"]

with open(os.path.join(OUT_DIR, "resources.csv"), "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=resource_fields)
    writer.writeheader()
    for res in RESOURCES:
        writer.writerow(res)

print("\n✅ All 4 CSV files generated in backend/data/")
