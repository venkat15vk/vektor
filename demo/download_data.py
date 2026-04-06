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
    # Check JSON data files
    for f in ["data_netsuite_sod.json", "data_okta_detections.json"]:
        p = DEMO_DIR / f
        if p.exists():
            total_size += p.stat().st_size
            print(f"  ✓ {f} ({p.stat().st_size / 1024:.0f} KB)")
    print(f"\n  Total size: {total_size / (1024*1024):.1f} MB")


def download_netsuite_sod() -> None:
    """Download NetSuite SoD dataset from coltonwaynelawson repo."""
    output_file = DEMO_DIR / "data_netsuite_sod.json"
    if output_file.exists():
        print("  ✓ NetSuite SoD data already exists, skipping")
        return

    print("\n📥 Downloading NetSuite SoD dataset...")
    print("   Source: coltonwaynelawson/netsuite-segregation-of-duties-analysis")

    with tempfile.TemporaryDirectory() as tmpdir:
        try:
            subprocess.run(
                ["git", "clone", "--depth=1",
                 "https://github.com/coltonwaynelawson/netsuite-segregation-of-duties-analysis.git",
                 tmpdir],
                check=True, capture_output=True, text=True,
            )
            # Parse the notebook to extract SoD data
            nb_path = Path(tmpdir) / "sod.ipynb"
            if nb_path.exists():
                _parse_netsuite_notebook(nb_path, output_file)
                print(f"  ✓ Saved parsed SoD data to {output_file}")
            else:
                print("  ✗ Notebook not found in repo")
        except subprocess.CalledProcessError as e:
            print(f"  ✗ Failed to clone repo: {e}")
            # Create a fallback with embedded data
            _create_fallback_netsuite_data(output_file)


def _parse_netsuite_notebook(nb_path: Path, output_path: Path) -> None:
    """Parse the Jupyter notebook to extract employee-role-permission SoD data."""
    import re

    with open(nb_path) as f:
        nb = json.load(f)

    artifacts = {"None", "View", "Edit", "Full", "Create"}

    def parse_table(cell_outputs):
        entries = []
        for out in cell_outputs:
            text = ""
            if out.get("data") and out["data"].get("text/plain"):
                text = "".join(out["data"]["text/plain"])
            for line in text.split("\n"):
                m = re.match(r"\s*\d+\s+(.+?)\s{2,}(.+?)(?:\s{2,}|$)", line.strip())
                if m:
                    name, role = m.group(1).strip(), m.group(2).strip()
                    if name and role and name not in artifacts and name != "Name":
                        entries.append({"name": name, "role": role})
        return entries

    rule_cells = [
        (8, "JE_create_approve", "Make Journal Entry + Journal Approval",
         "Can create and self-approve journal entries — GL manipulation risk"),
        (10, "invoice_payment", "Invoice + Customer Deposit/Payment",
         "Can create invoices and receive deposits — revenue fraud risk"),
        (12, "vendor_pay", "Vendors + Pay Bills",
         "Can create fake vendors and issue unauthorized payments"),
        (14, "creditmemo_payment", "Credit Memo + Customer Deposit/Payment",
         "Can issue credit memos and process payments — unauthorized refund risk"),
        (16, "customer_refund", "Customers + Customer Refund",
         "Can create fictitious customers and issue refunds"),
        (18, "customer_creditmemo", "Customers + Credit Memo",
         "Can create fictitious customers and issue credit memos"),
    ]

    sod_rules = {}
    all_employees = set()
    all_roles = set()

    for cell_idx, rule_id, rule_name, risk in rule_cells:
        if cell_idx < len(nb["cells"]):
            entries = parse_table(nb["cells"][cell_idx].get("outputs", []))
            users = list(set(e["name"] for e in entries if e["name"] not in artifacts))
            for e in entries:
                if e["name"] not in artifacts:
                    all_employees.add(e["name"])
                    all_roles.add(e["role"])
            sod_rules[rule_id] = {
                "rule_name": rule_name,
                "risk": risk,
                "violating_users": users,
                "user_count": len(users),
                "user_roles": [e for e in entries if e["name"] not in artifacts],
            }

    output = {
        "source": "coltonwaynelawson/netsuite-segregation-of-duties-analysis",
        "description": "NetSuite SoD violations from obfuscated real-world data",
        "total_violating_employees": len(all_employees),
        "employees": sorted(all_employees),
        "roles": sorted(all_roles),
        "sod_rules": sod_rules,
    }

    with open(output_path, "w") as f:
        json.dump(output, f, indent=2)


def _create_fallback_netsuite_data(output_path: Path) -> None:
    """Create a minimal fallback if git clone fails."""
    print("  → Creating fallback NetSuite SoD data (embedded)")
    # Minimal representative dataset
    output = {
        "source": "embedded-fallback",
        "description": "Minimal NetSuite SoD data (git clone unavailable)",
        "total_violating_employees": 5,
        "employees": ["Amber Gray", "Charles Young", "Andrea Villarreal", "Crystal Jones", "Sean Collins"],
        "roles": [
            "Company Accounting - Controller",
            "Company Accounting - Maintenance and Invoicing",
            "Entity Accounting - AP & Cash App",
            "Custom EFT Role",
            "Entity Director of Shared Services",
        ],
        "sod_rules": {
            "JE_create_approve": {
                "rule_name": "Make Journal Entry + Journal Approval",
                "risk": "Can create and self-approve journal entries",
                "violating_users": ["Amber Gray", "Charles Young", "Crystal Jones"],
                "user_count": 3,
                "user_roles": [
                    {"name": "Amber Gray", "role": "Company Accounting - Controller"},
                    {"name": "Charles Young", "role": "Entity Director of Shared Services"},
                ],
            },
            "vendor_pay": {
                "rule_name": "Vendors + Pay Bills",
                "risk": "Can create fake vendors and issue unauthorized payments",
                "violating_users": ["Andrea Villarreal", "Charles Young", "Sean Collins"],
                "user_count": 3,
                "user_roles": [
                    {"name": "Andrea Villarreal", "role": "Entity Accounting - AP & Cash App"},
                    {"name": "Charles Young", "role": "Custom EFT Role"},
                ],
            },
        },
    }
    with open(output_path, "w") as f:
        json.dump(output, f, indent=2)


def download_okta_detections() -> None:
    """Download official Okta detection rules from okta/customer-detections."""
    output_file = DEMO_DIR / "data_okta_detections.json"
    if output_file.exists():
        print("  ✓ Okta detection rules already exist, skipping")
        return

    print("\n📥 Downloading Okta detection rules...")
    print("   Source: okta/customer-detections (official)")

    with tempfile.TemporaryDirectory() as tmpdir:
        try:
            subprocess.run(
                ["git", "clone", "--depth=1",
                 "https://github.com/okta/customer-detections.git",
                 tmpdir],
                check=True, capture_output=True, text=True,
            )
            _parse_okta_detections(Path(tmpdir) / "detections", output_file)
            print(f"  ✓ Saved parsed detection rules to {output_file}")
        except subprocess.CalledProcessError as e:
            print(f"  ✗ Failed to clone repo: {e}")
            _create_fallback_okta_data(output_file)


def _parse_okta_detections(detections_dir: Path, output_path: Path) -> None:
    """Parse YAML detection rules into structured JSON."""
    try:
        import yaml
    except ImportError:
        print("  → Installing PyYAML...")
        subprocess.run([sys.executable, "-m", "pip", "install", "pyyaml",
                        "--break-system-packages", "-q"], check=True)
        import yaml

    detections = []
    for fname in sorted(os.listdir(detections_dir)):
        if not fname.endswith(".yml"):
            continue
        with open(detections_dir / fname) as f:
            try:
                rule = yaml.safe_load(f)
            except Exception:
                continue

        oie_query = None
        det = rule.get("detection", {})
        if det.get("okta_systemlog", {}).get("OIE"):
            oie_query = det["okta_systemlog"]["OIE"].strip()

        detections.append({
            "id": rule.get("id", ""),
            "title": rule.get("title", ""),
            "description": rule.get("description", "").strip(),
            "threat_tactic": rule.get("threat", {}).get("Tactic", []),
            "threat_technique": rule.get("threat", {}).get("Technique", []),
            "prevention": rule.get("prevention", []),
            "oie_query": oie_query,
            "false_positives": rule.get("false_positives", []),
            "filename": fname,
        })

    with open(output_path, "w") as f:
        json.dump({
            "source": "okta/customer-detections",
            "description": "Official Okta detection rules for identity threats",
            "total_rules": len(detections),
            "rules": detections,
        }, f, indent=2)


def _create_fallback_okta_data(output_path: Path) -> None:
    """Create minimal fallback if git clone fails."""
    print("  → Creating fallback Okta detection rules (embedded)")
    with open(output_path, "w") as f:
        json.dump({
            "source": "embedded-fallback",
            "description": "Minimal Okta detection rules",
            "total_rules": 5,
            "rules": [
                {"id": "1", "title": "Admin Console Login with Weak MFA", "threat_tactic": ["Initial Access"]},
                {"id": "2", "title": "New Super Admin Created", "threat_tactic": ["Persistence"]},
                {"id": "3", "title": "New API Token Created", "threat_tactic": ["Persistence"]},
                {"id": "4", "title": "Password Spray Detected", "threat_tactic": ["Credential Access"]},
                {"id": "5", "title": "MFA Policy Downgrade", "threat_tactic": ["Defense Evasion"]},
            ],
        }, f, indent=2)


def main() -> None:
    parser = argparse.ArgumentParser(description="Download demo datasets for Vektor AI")
    parser.add_argument("--policies", action="store_true", help="Download MAMIP policies only")
    parser.add_argument("--cloudtrail", action="store_true", help="Download flaws.cloud CloudTrail only")
    parser.add_argument("--attacks", action="store_true", help="Download Invictus attack data only")
    parser.add_argument("--netsuite", action="store_true", help="Download NetSuite SoD data only")
    parser.add_argument("--okta", action="store_true", help="Download Okta detection rules only")
    args = parser.parse_args()

    # If no specific flag, download all
    download_all = not (args.policies or args.cloudtrail or args.attacks or args.netsuite or args.okta)

    print("🚀 Vektor AI — Demo Data Downloader")
    print("   Downloading real, open-source IAM datasets for local testing")

    if download_all or args.policies:
        download_mamip_policies()

    if download_all or args.cloudtrail:
        download_flaws_cloudtrail()

    if download_all or args.attacks:
        download_invictus_attacks()

    if download_all or args.netsuite:
        download_netsuite_sod()

    if download_all or args.okta:
        download_okta_detections()

    show_summary()
    print("\n✅ Done! Run 'python demo/run.py' to test the pipeline.\n")


if __name__ == "__main__":
    main()
