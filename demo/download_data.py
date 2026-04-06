#!/usr/bin/env python3
"""
Vektor AI — Demo Data Downloader

Downloads real, open-source IAM and CloudTrail datasets for local testing.
All datasets are publicly available under permissive licenses.

Sources:
  1. MAMIP (zoph-io) — 1,465+ real AWS managed IAM policies as JSON
  2. flaws.cloud — 1.9M anonymized CloudTrail events from a real AWS environment
  3. Invictus IR — CloudTrail events from Stratus Red Team attack simulation

Usage:
    python demo/download_data.py            # download all
    python demo/download_data.py --policies # just policies
    python demo/download_data.py --cloudtrail # just cloudtrail
    python demo/download_data.py --attacks  # just attack events
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

DEMO_DIR = Path(__file__).parent
DATA_DIR = DEMO_DIR / "data"
POLICIES_DIR = DATA_DIR / "aws_policies"
CLOUDTRAIL_DIR = DATA_DIR / "cloudtrail"
ATTACKS_DIR = DATA_DIR / "attack_events"


def run_cmd(cmd: list[str], cwd: str | None = None) -> subprocess.CompletedProcess:
    """Run a shell command and return result."""
    return subprocess.run(cmd, capture_output=True, text=True, cwd=cwd)


def download_mamip_policies() -> None:
    """
    Download AWS managed IAM policies from MAMIP (zoph-io/MAMIP).
    These are the actual JSON policy documents for all 1,465+ AWS managed policies.
    """
    print("\n" + "=" * 60)
    print("📦 Downloading MAMIP — AWS Managed IAM Policies")
    print("=" * 60)

    if list(POLICIES_DIR.glob("*.json")) and len(list(POLICIES_DIR.glob("*.json"))) > 100:
        print(f"  ✅ Already have {len(list(POLICIES_DIR.glob('*.json')))} policies, skipping.")
        return

    POLICIES_DIR.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory() as tmpdir:
        print("  ⬇  Cloning MAMIP repo (sparse checkout — policies/ only)...")
        # Use sparse checkout to only get the policies folder
        result = run_cmd(["git", "clone", "--depth", "1", "--filter=blob:none",
                          "--sparse", "https://github.com/zoph-io/MAMIP.git", tmpdir])
        if result.returncode != 0:
            print(f"  ❌ Clone failed: {result.stderr}")
            return

        run_cmd(["git", "sparse-checkout", "set", "policies"], cwd=tmpdir)

        policies_src = Path(tmpdir) / "policies"
        if not policies_src.exists():
            print("  ❌ No policies/ directory found in MAMIP repo")
            return

        count = 0
        for f in policies_src.glob("*.json"):
            shutil.copy2(f, POLICIES_DIR / f.name)
            count += 1

        print(f"  ✅ Downloaded {count} AWS managed IAM policies")


def download_flaws_cloudtrail() -> None:
    """
    Download the flaws.cloud CloudTrail dataset.
    1.9M anonymized events from a real AWS environment (2017-2020).
    """
    print("\n" + "=" * 60)
    print("📦 Downloading flaws.cloud — CloudTrail Logs")
    print("=" * 60)

    # Check if we already have data
    existing = list(CLOUDTRAIL_DIR.rglob("*.json")) + list(CLOUDTRAIL_DIR.rglob("*.json.gz"))
    if len(existing) > 10:
        print(f"  ✅ Already have {len(existing)} CloudTrail files, skipping.")
        return

    CLOUDTRAIL_DIR.mkdir(parents=True, exist_ok=True)
    tar_url = "http://summitroute.com/downloads/flaws_cloudtrail_logs.tar"

    with tempfile.TemporaryDirectory() as tmpdir:
        tar_path = Path(tmpdir) / "flaws_cloudtrail_logs.tar"
        print(f"  ⬇  Downloading CloudTrail tar (~240MB)...")
        print(f"     URL: {tar_url}")

        # Use curl (more reliable for large files)
        result = run_cmd(["curl", "-L", "-o", str(tar_path), "--max-time", "600",
                          "--connect-timeout", "30", tar_url])
        if result.returncode != 0:
            print(f"  ❌ Download failed: {result.stderr}")
            print("  ℹ  This is a large file. You can download manually:")
            print(f"     curl -L -o demo/data/cloudtrail/flaws.tar {tar_url}")
            return

        if not tar_path.exists() or tar_path.stat().st_size < 1_000_000:
            print("  ❌ Download incomplete or file too small")
            return

        print("  📂 Extracting CloudTrail logs...")
        try:
            with tarfile.open(tar_path, "r") as tar:
                tar.extractall(path=CLOUDTRAIL_DIR, filter="data")
        except Exception as e:
            print(f"  ❌ Extraction failed: {e}")
            return

        # Count resulting files
        json_files = list(CLOUDTRAIL_DIR.rglob("*.json.gz")) + list(CLOUDTRAIL_DIR.rglob("*.json"))
        print(f"  ✅ Extracted {len(json_files)} CloudTrail log files")


def download_invictus_attacks() -> None:
    """
    Download the Invictus IR attack dataset.
    CloudTrail events from Stratus Red Team attack simulation.
    """
    print("\n" + "=" * 60)
    print("📦 Downloading Invictus IR — Attack Simulation CloudTrail")
    print("=" * 60)

    existing = list(ATTACKS_DIR.rglob("*.json")) + list(ATTACKS_DIR.rglob("*.json.gz"))
    if len(existing) > 5:
        print(f"  ✅ Already have {len(existing)} attack event files, skipping.")
        return

    ATTACKS_DIR.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory() as tmpdir:
        print("  ⬇  Cloning Invictus IR attack dataset...")
        result = run_cmd(["git", "clone", "--depth", "1",
                          "https://github.com/invictus-ir/aws_dataset.git", tmpdir])
        if result.returncode != 0:
            print(f"  ❌ Clone failed: {result.stderr}")
            return

        # Copy CloudTrail directory contents
        ct_src = Path(tmpdir) / "CloudTrail"
        if not ct_src.exists():
            print("  ❌ No CloudTrail/ directory found in invictus dataset")
            return

        count = 0
        for f in ct_src.rglob("*"):
            if f.is_file():
                dest = ATTACKS_DIR / f.relative_to(ct_src)
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(f, dest)
                count += 1

        print(f"  ✅ Downloaded {count} attack simulation files")


def show_summary() -> None:
    """Show what we have."""
    print("\n" + "=" * 60)
    print("📊 Demo Data Summary")
    print("=" * 60)

    policies = list(POLICIES_DIR.glob("*.json")) if POLICIES_DIR.exists() else []
    ct_files = (list(CLOUDTRAIL_DIR.rglob("*.json")) +
                list(CLOUDTRAIL_DIR.rglob("*.json.gz"))) if CLOUDTRAIL_DIR.exists() else []
    attack_files = (list(ATTACKS_DIR.rglob("*.json")) +
                    list(ATTACKS_DIR.rglob("*.json.gz"))) if ATTACKS_DIR.exists() else []

    print(f"  AWS Managed Policies:   {len(policies):>6} files  → {POLICIES_DIR}")
    print(f"  CloudTrail Logs:        {len(ct_files):>6} files  → {CLOUDTRAIL_DIR}")
    print(f"  Attack Events:          {len(attack_files):>6} files  → {ATTACKS_DIR}")

    total_size = 0
    for d in [POLICIES_DIR, CLOUDTRAIL_DIR, ATTACKS_DIR]:
        if d.exists():
            for f in d.rglob("*"):
                if f.is_file():
                    total_size += f.stat().st_size
    print(f"\n  Total size: {total_size / (1024*1024):.1f} MB")


def main() -> None:
    parser = argparse.ArgumentParser(description="Download demo datasets for Vektor AI")
    parser.add_argument("--policies", action="store_true", help="Download MAMIP policies only")
    parser.add_argument("--cloudtrail", action="store_true", help="Download flaws.cloud CloudTrail only")
    parser.add_argument("--attacks", action="store_true", help="Download Invictus attack data only")
    args = parser.parse_args()

    # If no specific flag, download all
    download_all = not (args.policies or args.cloudtrail or args.attacks)

    print("🚀 Vektor AI — Demo Data Downloader")
    print("   Downloading real, open-source IAM datasets for local testing")

    if download_all or args.policies:
        download_mamip_policies()

    if download_all or args.cloudtrail:
        download_flaws_cloudtrail()

    if download_all or args.attacks:
        download_invictus_attacks()

    show_summary()
    print("\n✅ Done! Run 'python demo/run.py' to test the pipeline.\n")


if __name__ == "__main__":
    main()
