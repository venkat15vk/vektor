#!/usr/bin/env python3
"""
VEKTOR Cloud IAM Analysis Runner
Runs the adapter + all cloud IAM models and prints summary.
"""

import os
import sys
import sqlite3

BASE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE)
sys.path.insert(0, os.path.join(BASE, "adapters"))
sys.path.insert(0, os.path.join(BASE, "models"))

DB_PATH = os.path.join(BASE, "vektor.db")


def run_all():
    print("=" * 70)
    print("VEKTOR Cloud IAM Analysis — Running on Real Public Data")
    print("=" * 70)
    print()
    
    # Step 1: Run adapter
    print("STEP 1: Ingesting AWS + Azure + GCP IAM data...")
    print("-" * 50)
    from adapters.cloud_iam_adapter import run as run_adapter
    run_adapter()
    print()
    
    # Step 2: Run models
    print("STEP 2: Running cloud IAM models...")
    print("-" * 50)
    
    from models.m10_sod_cloud import run as run_m10
    m10_signals = run_m10()
    print()
    
    from models.m11_peer_cloud import run as run_m11
    m11_signals = run_m11()
    print()
    
    from models.m14_escalation_path import run as run_m14
    m14_signals = run_m14()
    print()
    
    # Summary
    all_signals = m10_signals + m11_signals + m14_signals
    critical = sum(1 for s in all_signals if s["priority"] == "critical")
    high = sum(1 for s in all_signals if s["priority"] == "high")
    medium = sum(1 for s in all_signals if s["priority"] == "medium")
    
    print("=" * 70)
    print("RESULTS SUMMARY")
    print("=" * 70)
    print(f"  Total signals generated:  {len(all_signals)}")
    print(f"    CRITICAL:               {critical}")
    print(f"    HIGH:                   {high}")
    print(f"    MEDIUM:                 {medium}")
    print()
    print(f"  By model:")
    print(f"    M10 (SoD violations):        {len(m10_signals)}")
    print(f"    M11 (Peer deviation):        {len(m11_signals)}")
    print(f"    M14 (Escalation paths):      {len(m14_signals)}")
    print()
    
    # Top 10 most dangerous findings
    print("TOP 10 MOST DANGEROUS FINDINGS:")
    print("-" * 50)
    top = sorted(all_signals, key=lambda s: (
        {"critical": 0, "high": 1, "medium": 2}.get(s["priority"], 9),
        -s["confidence"]
    ))[:10]
    
    for i, s in enumerate(top, 1):
        print(f"  {i}. [{s['priority'].upper()}] {s['model_id']} | conf: {s['confidence']}")
        print(f"     {s['summary'][:120]}")
        print()
    
    # Verify in DB
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM signals WHERE model_id IN ('M10','M11','M14')")
    db_count = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM entities WHERE department IN ('AWS','Azure','GCP')")
    ent_count = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM entitlements WHERE entitlement_id LIKE 'ent-aws%' OR entitlement_id LIKE 'ent-azure%' OR entitlement_id LIKE 'ent-gcp%'")
    entl_count = c.fetchone()[0]
    conn.close()
    
    print("=" * 70)
    print("DATABASE VERIFICATION:")
    print(f"  Cloud IAM entities in DB:      {ent_count}")
    print(f"  Cloud IAM entitlements in DB:  {entl_count}")
    print(f"  Cloud IAM signals in DB:       {db_count}")
    print("=" * 70)
    print()
    print("These findings are from REAL AWS, Azure, and GCP IAM policy data.")
    print("Not synthetic. Not self-reported. Public dataset, reproducible results.")


if __name__ == "__main__":
    run_all()
