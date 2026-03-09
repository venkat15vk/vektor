#!/usr/bin/env python3
"""
VEKTOR: Run all ML models in correct order.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

from models import m8_shadow, m3_sod, m4_session, m5_contractor, m2_peer, m7_delegation, m1_dormancy, m6_velocity, m9_crossplane

DB_PATH = os.path.join(os.path.dirname(__file__), "vektor.db")

def run_all():
    print("=" * 60)
    print("VEKTOR ML Pipeline — Running all models")
    print("=" * 60)

    print("\n[1/9] M8 Shadow Identity Detector")
    m8_shadow.run(DB_PATH)

    print("\n[2/9] M3 SoD Violation Detector")
    m3_sod.run(DB_PATH)

    print("\n[3/9] M4 Session Anomaly")
    m4_session.run(DB_PATH)

    print("\n[4/9] M5 Contractor Expiry Risk")
    m5_contractor.run(DB_PATH)

    print("\n[5/9] M2 Peer Deviation")
    m2_peer.run(DB_PATH)

    print("\n[6/9] M7 Delegation Inheritance")
    m7_delegation.run(DB_PATH)

    print("\n[7/9] M1 Dormancy Risk")
    m1_dormancy.run(DB_PATH)

    print("\n[8/9] M6 Access Velocity")
    m6_velocity.run(DB_PATH)

    print("\n[9/9] M9 Cross-Plane Amplifier")
    m9_crossplane.run(DB_PATH)

    print("\n" + "=" * 60)
    print("All models complete. Verifying signals...")
    print("=" * 60)

    import sqlite3
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # Verification
    story_ids = ['ent_js006', 'ent_rw003', 'ent_kl004', 'ent_tm005', 'ent_ar007',
                 'agt_copilot_fin_01', 'agt_rpa_ops_07', 'agt_unknown_003']

    print("\nStory entity signals:")
    for sid in story_ids:
        c.execute("SELECT signal_id, model_id, priority, confidence FROM signals WHERE entity_id = ?", (sid,))
        rows = c.fetchall()
        if rows:
            for r in rows:
                print(f"  ✅ {sid}: {r[1]} priority={r[2]} confidence={r[3]}")
        else:
            print(f"  ❌ {sid}: NO SIGNAL")

    c.execute("SELECT COUNT(*) FROM signals WHERE priority = 'critical'")
    critical_count = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM signals WHERE priority = 'high'")
    high_count = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM signals")
    total_count = c.fetchone()[0]

    print(f"\nTotal signals: {total_count}")
    print(f"Critical: {critical_count}")
    print(f"High: {high_count}")

    conn.close()


if __name__ == "__main__":
    run_all()
