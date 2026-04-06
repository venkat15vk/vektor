#!/usr/bin/env python3
"""
Vektor AI — End-to-End Demo Runner

Runs the complete Vektor pipeline on real, open-source IAM data:

  1. Load real AWS managed policies (MAMIP) → GraphSnapshot
  2. Ingest into unified identity graph
  3. Compute ~45 features per entity
  4. Run bootstrap labeler → silver labels
  5. Load CloudTrail activity logs (if available)
  6. Output scored signals with explanations

Usage:
    python demo/run.py                     # full pipeline
    python demo/run.py --no-cloudtrail     # skip CloudTrail (faster)
    python demo/run.py --max-ct-files 50   # limit CloudTrail files loaded
    python demo/run.py --verbose           # show debug output

Prerequisites:
    python demo/download_data.py    # download datasets first
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import structlog

structlog.configure(
    processors=[
        structlog.stdlib.add_log_level,
        structlog.dev.ConsoleRenderer(colors=True),
    ],
    wrapper_class=structlog.stdlib.BoundLogger,
    logger_factory=structlog.PrintLoggerFactory(),
)

logger = structlog.get_logger(__name__)

# Vektor modules (existing code — no modifications)
from backend.graph.store import IdentityGraph
from backend.features.compute import FeatureComputer
from backend.features.store import FeatureStore
from backend.models.bootstrap import BootstrapLabeler

# Demo-specific modules (new code)
from demo.local_adapter import LocalFileAdapter
from demo.local_cloudtrail_ingester import load_cloudtrail_directory

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
DEMO_DIR = Path(__file__).parent
POLICIES_DIR = DEMO_DIR / "data" / "aws_policies"
CLOUDTRAIL_DIR = DEMO_DIR / "data" / "cloudtrail"
ATTACKS_DIR = DEMO_DIR / "data" / "attack_events"


# ---------------------------------------------------------------------------
# Violation class names (from bootstrap labeler)
# ---------------------------------------------------------------------------
VIOLATION_NAMES = {
    1: "Overprivileged Access",
    2: "Stale / Dormant Account",
    3: "Orphan Account",
    4: "Segregation of Duties Violation",
    5: "Excessive Admin Privileges",
    6: "Missing MFA on Privileged Account",
    7: "Break-Glass Misuse",
    8: "Cross-Boundary Overreach",
    9: "Service Account Overprivilege",
    10: "Credential Exposure Risk",
    11: "Permission Creep / Drift",
    12: "Shadow Admin",
    13: "Agent Scope Drift",
    14: "Agent Over-Provisioning",
    15: "Agent Cross-Boundary Risk",
}

SEVERITY_COLORS = {
    "critical": "\033[91m",  # red
    "high": "\033[93m",      # yellow
    "medium": "\033[94m",    # blue
    "low": "\033[90m",       # gray
}
RESET = "\033[0m"
BOLD = "\033[1m"
GREEN = "\033[92m"
CYAN = "\033[96m"


def severity_from_confidence(confidence: float, violation_class: int) -> str:
    """Map confidence + violation class to severity."""
    # Privileged-access violations are always higher severity
    critical_classes = {5, 6, 9, 10, 12}
    if violation_class in critical_classes and confidence >= 0.8:
        return "critical"
    if confidence >= 0.85:
        return "high"
    if confidence >= 0.6:
        return "medium"
    return "low"


async def run_pipeline(
    skip_cloudtrail: bool = False,
    max_ct_files: int | None = None,
    max_ct_events: int | None = None,
    verbose: bool = False,
) -> None:
    """Run the complete Vektor AI pipeline."""

    print(f"""
{BOLD}╔══════════════════════════════════════════════════════════════╗
║              VEKTOR AI — Pipeline Demo Runner                ║
║     Real AWS IAM Policies → Graph → Features → Signals       ║
╚══════════════════════════════════════════════════════════════╝{RESET}
""")

    total_start = time.time()

    # ================================================================
    # STEP 1: Load real IAM policies via LocalFileAdapter
    # ================================================================
    print(f"{BOLD}━━━ Step 1: Load Real AWS Managed Policies ━━━{RESET}")

    if not POLICIES_DIR.exists() or not list(POLICIES_DIR.glob("*.json")):
        print("  ❌ No policy files found. Run 'python demo/download_data.py --policies' first.")
        return

    adapter = LocalFileAdapter(policies_dir=POLICIES_DIR)
    await adapter.connect()

    t0 = time.time()
    snapshot = await adapter.extract()
    t1 = time.time()

    print(f"  ✅ Extracted in {t1-t0:.2f}s")
    print(f"     Subjects:         {len(snapshot.subjects):>6}")
    print(f"     Permissions:      {len(snapshot.permissions):>6}  (real AWS managed policies)")
    print(f"     Resources:        {len(snapshot.resources):>6}")
    print(f"     Assignments:      {len(snapshot.assignments):>6}")
    print(f"     Escalation Paths: {len(snapshot.escalation_paths):>6}")

    # Show some policy examples
    privileged = [p for p in snapshot.permissions if p.is_privileged]
    print(f"\n     Privileged policies: {len(privileged)} / {len(snapshot.permissions)}")
    if privileged[:3]:
        for p in privileged[:3]:
            print(f"       • {p.name} ({len(p.actions)} actions, {len(p.risk_keywords)} risk flags)")

    # ================================================================
    # STEP 2: Ingest into Identity Graph
    # ================================================================
    print(f"\n{BOLD}━━━ Step 2: Build Unified Identity Graph ━━━{RESET}")

    t0 = time.time()
    graph = IdentityGraph()
    graph.ingest(snapshot)
    t1 = time.time()

    graph_stats = graph.get_graph_stats()
    print(f"  ✅ Graph built in {t1-t0:.2f}s")
    print(f"     Nodes: {graph_stats['total_nodes']:>6}  |  Edges: {graph_stats['total_edges']:>6}")
    print(f"     Sources: {', '.join(graph_stats['sources'])}")

    # Cross-system subjects (would show more with multiple adapters)
    cross = graph.find_cross_system_subjects()
    if cross:
        print(f"     Cross-system identities: {len(cross)}")

    # Escalation paths
    print(f"     Escalation paths detected: {graph_stats['escalation_paths']}")

    # ================================================================
    # STEP 3: Compute Features
    # ================================================================
    print(f"\n{BOLD}━━━ Step 3: Compute Universal Features (~45 per entity) ━━━{RESET}")

    t0 = time.time()
    computer = FeatureComputer(graph)
    features = computer.compute_all()
    t1 = time.time()

    print(f"  ✅ Features computed in {t1-t0:.2f}s")
    print(f"     Feature vectors: {len(features)}")

    # Show feature highlights for a couple of subjects
    if features and verbose:
        for sid, fv in list(features.items())[:3]:
            subj = graph.get_subject(sid)
            if subj:
                sf = fv.subject
                print(f"\n     📊 {subj.display_name} ({subj.type.value})")
                print(f"        Permissions: {sf.total_permissions} (privileged: {sf.privileged_permissions})")
                print(f"        Unique actions: {sf.unique_actions}")
                print(f"        Peer ratio: {sf.permission_to_peer_median_ratio:.2f}x median")
                print(f"        MFA: {'enabled' if subj.mfa_enabled else 'DISABLED'}")

    # Store features
    feature_store = FeatureStore()
    feature_store.store(features)

    # ================================================================
    # STEP 4: Run Bootstrap Labeler
    # ================================================================
    print(f"\n{BOLD}━━━ Step 4: Run Bootstrap Labeler (15 Violation Classes) ━━━{RESET}")

    t0 = time.time()
    labeler = BootstrapLabeler(graph, feature_store)
    labels = labeler.label_all()
    t1 = time.time()

    # Count violations vs clean labels
    total_labels = sum(len(v) for v in labels.values())
    violation_labels = sum(
        1 for v_list in labels.values()
        for lbl in v_list
        if lbl.label == 1
    )

    print(f"  ✅ Labeling done in {t1-t0:.2f}s")
    print(f"     Total labels generated: {total_labels}")
    print(f"     Violations detected:    {violation_labels}")

    # ================================================================
    # STEP 5: Load CloudTrail Activity (if available)
    # ================================================================
    ct_events = []
    ct_stats = {}

    if not skip_cloudtrail:
        print(f"\n{BOLD}━━━ Step 5: Load CloudTrail Activity Logs ━━━{RESET}")

        ct_dirs = []
        if CLOUDTRAIL_DIR.exists() and any(CLOUDTRAIL_DIR.rglob("*.json*")):
            ct_dirs.append(("flaws.cloud", CLOUDTRAIL_DIR))
        if ATTACKS_DIR.exists() and any(ATTACKS_DIR.rglob("*.json*")):
            ct_dirs.append(("Invictus attacks", ATTACKS_DIR))

        if ct_dirs:
            for label, ct_dir in ct_dirs:
                t0 = time.time()
                events, stats = load_cloudtrail_directory(
                    ct_dir,
                    max_files=max_ct_files,
                    max_events=max_ct_events,
                )
                t1 = time.time()
                ct_events.extend(events)
                ct_stats[label] = stats
                print(f"  ✅ {label}: {stats['total_events']:,} events in {t1-t0:.2f}s")
                print(f"     Unique subjects: {stats['unique_subjects']}")
                print(f"     Unique actions:  {stats['unique_actions']}")
                print(f"     Privileged:      {stats['privileged_events']}")
                print(f"     Errors/denied:   {stats['error_events']}")
                if stats.get('time_range_start'):
                    print(f"     Time range:      {stats['time_range_start'][:10]} → {stats['time_range_end'][:10]}")
        else:
            print("  ⚠  No CloudTrail data found. Run 'python demo/download_data.py' to download.")
    else:
        print(f"\n{BOLD}━━━ Step 5: CloudTrail (skipped) ━━━{RESET}")

    # ================================================================
    # STEP 6: Output Signals
    # ================================================================
    print(f"\n{BOLD}━━━ Step 6: Vektor Signals ━━━{RESET}")

    # Collect and rank all violation signals
    signals: list[dict] = []

    for subject_id, label_list in labels.items():
        subj = graph.get_subject(subject_id)
        if not subj:
            continue

        for lbl in label_list:
            if lbl.label != 1:  # only violations
                continue

            severity = severity_from_confidence(lbl.confidence, lbl.violation_class)
            violation_name = VIOLATION_NAMES.get(lbl.violation_class, f"Class {lbl.violation_class}")

            signals.append({
                "subject": subj.display_name,
                "subject_type": subj.type.value,
                "department": subj.department or "N/A",
                "violation": violation_name,
                "violation_class": lbl.violation_class,
                "confidence": lbl.confidence,
                "severity": severity,
                "rule": lbl.rule_id,
                "evidence": lbl.evidence,
                "sources": lbl.source_systems,
                "mfa": subj.mfa_enabled,
            })

    # Sort by severity then confidence
    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    signals.sort(key=lambda s: (severity_rank.get(s["severity"], 9), -s["confidence"]))

    if not signals:
        print("  ℹ  No violations detected. Pipeline ran clean.")
    else:
        print(f"\n  Found {BOLD}{len(signals)} signals{RESET} across {len(set(s['subject'] for s in signals))} subjects:\n")

        # Print each signal
        for i, sig in enumerate(signals, 1):
            color = SEVERITY_COLORS.get(sig["severity"], "")
            sev = sig["severity"].upper()

            print(f"  {BOLD}Signal #{i}{RESET}  {color}[{sev}]{RESET}  confidence={sig['confidence']:.0%}")
            print(f"    Subject:   {sig['subject']} ({sig['subject_type']}, {sig['department']})")
            print(f"    Violation: {sig['violation']}")
            print(f"    Rule:      {sig['rule']}")

            # Show key evidence
            evidence = sig.get("evidence", {})
            if evidence:
                for k, v in list(evidence.items())[:4]:
                    if isinstance(v, list):
                        v_str = ", ".join(str(x) for x in v[:5])
                        if len(v) > 5:
                            v_str += f" ... (+{len(v)-5} more)"
                    elif isinstance(v, float):
                        v_str = f"{v:.2f}"
                    else:
                        v_str = str(v)[:120]
                    print(f"    Evidence:  {k} = {v_str}")

            print()

    # ================================================================
    # Summary
    # ================================================================
    total_time = time.time() - total_start

    print(f"""
{BOLD}╔══════════════════════════════════════════════════════════════╗
║                      Pipeline Summary                        ║
╠══════════════════════════════════════════════════════════════╣{RESET}
  Policies loaded:       {len(snapshot.permissions):>8}  (real AWS managed policies)
  Subjects analyzed:     {len(snapshot.subjects):>8}
  Assignments:           {len(snapshot.assignments):>8}
  Graph nodes:           {graph_stats['total_nodes']:>8}
  Graph edges:           {graph_stats['total_edges']:>8}
  Feature vectors:       {len(features):>8}
  Escalation paths:      {len(snapshot.escalation_paths):>8}
  CloudTrail events:     {len(ct_events):>8}
  Violations detected:   {len(signals):>8}
  Total runtime:         {total_time:>7.2f}s
{BOLD}╚══════════════════════════════════════════════════════════════╝{RESET}
""")

    # Severity breakdown
    sev_counts = {}
    for s in signals:
        sev_counts[s["severity"]] = sev_counts.get(s["severity"], 0) + 1
    if sev_counts:
        print(f"  Severity breakdown:")
        for sev in ["critical", "high", "medium", "low"]:
            if sev in sev_counts:
                color = SEVERITY_COLORS.get(sev, "")
                print(f"    {color}{sev.upper():>8}{RESET}: {sev_counts[sev]}")

    # Violation class breakdown
    class_counts: dict[str, int] = {}
    for s in signals:
        vname = s["violation"]
        class_counts[vname] = class_counts.get(vname, 0) + 1
    if class_counts:
        print(f"\n  Violation type breakdown:")
        for vname, count in sorted(class_counts.items(), key=lambda x: -x[1]):
            print(f"    {count:>3}x  {vname}")

    print()


def main():
    parser = argparse.ArgumentParser(description="Vektor AI — End-to-End Demo")
    parser.add_argument("--no-cloudtrail", action="store_true",
                        help="Skip loading CloudTrail logs (faster)")
    parser.add_argument("--max-ct-files", type=int, default=None,
                        help="Max CloudTrail files to load")
    parser.add_argument("--max-ct-events", type=int, default=50000,
                        help="Max CloudTrail events to load (default: 50000)")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Show detailed feature output")
    args = parser.parse_args()

    asyncio.run(run_pipeline(
        skip_cloudtrail=args.no_cloudtrail,
        max_ct_files=args.max_ct_files,
        max_ct_events=args.max_ct_events,
        verbose=args.verbose,
    ))


if __name__ == "__main__":
    main()
