"""
Vektor AI — Local NetSuite Adapter

Reads real-world NetSuite SoD (Segregation of Duties) violation data from the
coltonwaynelawson/netsuite-segregation-of-duties-analysis dataset. This dataset
contains obfuscated but structurally real employee-role-permission mappings
extracted from a production NetSuite instance.

Data source:
  - demo/data_netsuite_sod.json (parsed from the Jupyter notebook output)
  - 29 employees with SoD violations across 6 rule types
  - 37 real NetSuite roles (e.g., "Company Accounting - Controller",
    "Entity Accounting - AP & Cash App")
  - 6 SoD conflict rules covering the canonical NetSuite audit checks:
      1. Make Journal Entry + Journal Approval
      2. Invoice + Customer Deposit/Payment
      3. Vendors + Pay Bills
      4. Credit Memo + Customer Deposit/Payment
      5. Customers + Customer Refund
      6. Customers + Credit Memo

The adapter produces the same GraphSnapshot as the live NetSuiteAdapter would.
"""

from __future__ import annotations

import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import structlog

from backend.adapters.base import BaseAdapter
from backend.adapters.models import (
    Assignment,
    EscalationPath,
    EscalationStep,
    GraphSnapshot,
    Permission,
    PermissionType,
    Resource,
    Sensitivity,
    Subject,
    SubjectStatus,
    SubjectType,
    utcnow,
    vektor_id,
)

logger = structlog.get_logger(__name__)

SOURCE = "netsuite"

# ---------------------------------------------------------------------------
# NetSuite SoD conflict rules — the 6 canonical checks
# ---------------------------------------------------------------------------
SOD_RULES: list[dict[str, Any]] = [
    {
        "id": "SOD-NS-R1-JE-APPROVE",
        "name": "Journal Entry Create + Approve",
        "permission_a": "Make Journal Entry",
        "permission_b": "Journal Approval",
        "risk": "Can create and self-approve journal entries — GL manipulation risk",
        "sox_control": "ITGC-GL-01",
        "severity": "critical",
        "confidence": 0.97,
    },
    {
        "id": "SOD-NS-R2-VENDOR-PAY",
        "name": "Vendor Create + Pay Bills",
        "permission_a": "Vendors",
        "permission_b": "Pay Bills",
        "risk": "Can create fake vendors and issue unauthorized payments",
        "sox_control": "ITGC-AP-03",
        "severity": "critical",
        "confidence": 0.98,
    },
    {
        "id": "SOD-NS-R3-CREDITMEMO-PAY",
        "name": "Credit Memo + Customer Payment",
        "permission_a": "Credit Memo",
        "permission_b": "Customer Payment",
        "risk": "Can issue credit memos and process payments — unauthorized refund risk",
        "sox_control": "ITGC-AR-02",
        "severity": "high",
        "confidence": 0.93,
    },
    {
        "id": "SOD-NS-R4-CUSTOMER-CREDITMEMO",
        "name": "Customer Create + Credit Memo",
        "permission_a": "Customers",
        "permission_b": "Credit Memo",
        "risk": "Can create fictitious customers and issue credit memos",
        "sox_control": "ITGC-AR-01",
        "severity": "high",
        "confidence": 0.92,
    },
    {
        "id": "SOD-NS-R5-CUSTOMER-REFUND",
        "name": "Customer Create + Customer Refund",
        "permission_a": "Customers",
        "permission_b": "Customer Refund",
        "risk": "Can create fictitious customers and issue refunds",
        "sox_control": "ITGC-AR-03",
        "severity": "high",
        "confidence": 0.91,
    },
    {
        "id": "SOD-NS-R6-INVOICE-DEPOSIT",
        "name": "Invoice + Customer Deposit",
        "permission_a": "Invoice",
        "permission_b": "Customer Deposit",
        "risk": "Can create invoices and receive deposits — revenue fraud risk",
        "sox_control": "ITGC-REV-01",
        "severity": "medium",
        "confidence": 0.85,
    },
]

# Map SoD JSON rule keys to our rule definitions
SOD_KEY_MAP = {
    "JE_create_approve": "SOD-NS-R1-JE-APPROVE",
    "vendor_pay": "SOD-NS-R2-VENDOR-PAY",
    "creditmemo_payment": "SOD-NS-R3-CREDITMEMO-PAY",
    "customer_creditmemo": "SOD-NS-R4-CUSTOMER-CREDITMEMO",
    "customer_refund": "SOD-NS-R5-CUSTOMER-REFUND",
    "invoice_payment": "SOD-NS-R6-INVOICE-DEPOSIT",
}

# Departments assigned to employees based on role name patterns
DEPT_MAP = {
    "Controller": "Accounting",
    "Revenue": "Revenue Accounting",
    "AP": "Accounts Payable",
    "Cash App": "Accounts Payable",
    "Credit": "Credit & Collections",
    "Shared Services": "Shared Services",
    "Fixed Assets": "Fixed Assets",
    "Human Resources": "Human Resources",
    "Production": "Operations",
    "Buyer": "Procurement",
    "Inventory": "Inventory",
    "EFT": "Treasury",
    "VP": "Executive",
    "Director": "Management",
    "Celigo": "Integrations",
    "Messenger": "IT",
}


def _infer_department(roles: list[str]) -> str:
    """Infer department from NetSuite role names."""
    for role in roles:
        for pattern, dept in DEPT_MAP.items():
            if pattern.lower() in role.lower():
                return dept
    return "Finance"


class LocalNetSuiteAdapter(BaseAdapter):
    """
    Reads real NetSuite SoD violation data from local JSON.

    Drop-in replacement for the live NetSuiteAdapter — produces the same
    GraphSnapshot the SuiteQL + TBA adapter would. When Venkat points this
    at a real NetSuite sandbox, he swaps which adapter is instantiated —
    graph, features, and models stay identical.
    """

    source_name = SOURCE

    def __init__(self, data_path: str | Path | None = None):
        self._data_path = Path(data_path) if data_path else (
            Path(__file__).parent / "data_netsuite_sod.json"
        )
        self._data: dict[str, Any] | None = None

    async def connect(self, credentials: dict | None = None) -> None:
        """Load the local SoD data file."""
        if not self._data_path.exists():
            raise FileNotFoundError(
                f"NetSuite SoD data not found at {self._data_path}. "
                "Run the download script first."
            )
        with open(self._data_path) as f:
            self._data = json.load(f)
        logger.info(
            "netsuite.local.connected",
            employees=self._data["total_violating_employees"],
            roles=len(self._data["roles"]),
        )

    async def test_connection(self) -> bool:
        return self._data_path.exists()

    async def extract(self) -> GraphSnapshot:
        """
        Build a complete GraphSnapshot from the NetSuite SoD dataset.

        1. Creates Subject objects for each employee
        2. Creates Permission objects for each NetSuite role
        3. Creates Assignment objects linking employees to roles
        4. Detects SoD escalation paths based on conflicting permissions
        """
        if self._data is None:
            await self.connect()

        assert self._data is not None
        now = utcnow()
        random.seed(42)  # Reproducible

        subjects: list[Subject] = []
        permissions: list[Permission] = []
        resources: list[Resource] = []
        assignments: list[Assignment] = []
        escalation_paths: list[EscalationPath] = []

        # --- NetSuite Modules as Resources ---
        module_names = [
            "General Ledger", "Accounts Payable", "Accounts Receivable",
            "Procurement", "Inventory", "Fixed Assets", "Payroll",
            "Revenue Recognition", "Treasury", "Human Resources",
        ]
        resource_map: dict[str, Resource] = {}
        for mod in module_names:
            r = Resource(
                id=vektor_id(SOURCE, f"module:{mod}"),
                source=SOURCE,
                type="netsuite_module",
                name=mod,
                sensitivity=(
                    Sensitivity.CRITICAL if mod in ("General Ledger", "Treasury", "Payroll")
                    else Sensitivity.HIGH if mod in ("Accounts Payable", "Accounts Receivable", "Revenue Recognition")
                    else Sensitivity.MEDIUM
                ),
            )
            resource_map[mod] = r
            resources.append(r)

        # --- Build role → permission objects ---
        role_permission_map: dict[str, Permission] = {}
        for role_name in self._data["roles"]:
            # Determine which NetSuite permissions this role grants
            actions = []
            is_privileged = False
            risk_keywords = []

            # Map role names to likely permission sets
            rn_lower = role_name.lower()
            if "controller" in rn_lower or "director" in rn_lower or "vp" in rn_lower:
                actions = ["Make Journal Entry", "Journal Approval", "Vendors", "Pay Bills", "Credit Memo"]
                is_privileged = True
                risk_keywords = ["financial_admin", "journal_approval"]
            elif "ap" in rn_lower or "cash app" in rn_lower:
                actions = ["Vendors", "Pay Bills", "Check", "Vendor Bill"]
                risk_keywords = ["accounts_payable"]
            elif "maintenance and invoicing" in rn_lower or "maint" in rn_lower:
                actions = ["Invoice", "Credit Memo", "Customers", "Customer Payment"]
                risk_keywords = ["invoicing", "credit_memo"]
            elif "revenue" in rn_lower:
                actions = ["Invoice", "Credit Memo", "Customers", "Revenue Recognition"]
                risk_keywords = ["revenue"]
            elif "credit" in rn_lower and "collections" in rn_lower:
                actions = ["Credit Memo", "Customers", "Customer Refund", "Customer Payment"]
                risk_keywords = ["credit_collections"]
            elif "shared services" in rn_lower:
                actions = ["Vendors", "Customer Refund", "Credit Memo", "Customers"]
                risk_keywords = ["shared_services"]
            elif "eft" in rn_lower:
                actions = ["Pay Bills", "Check", "Vendor Payment"]
                risk_keywords = ["electronic_funds_transfer"]
            elif "buyer" in rn_lower or "procurement" in rn_lower:
                actions = ["Purchase Order", "Vendors"]
                risk_keywords = ["procurement"]
            elif "fixed assets" in rn_lower:
                actions = ["Make Journal Entry", "Fixed Assets"]
                risk_keywords = ["fixed_assets"]
            elif "human resources" in rn_lower:
                actions = ["Employee Record", "Payroll"]
                risk_keywords = ["hr"]
            else:
                actions = ["View"]

            perm = Permission(
                id=vektor_id(SOURCE, f"role:{role_name}"),
                source=SOURCE,
                name=role_name,
                type=PermissionType.ROLE,
                actions=actions,
                is_privileged=is_privileged,
                risk_keywords=risk_keywords,
                attributes={"center_type": "Classic Center"},
            )
            role_permission_map[role_name] = perm
            permissions.append(perm)

        # --- Build employee → subject objects + assignments ---
        employee_roles: dict[str, list[str]] = {}
        for rule_data in self._data["sod_rules"].values():
            for entry in rule_data["user_roles"]:
                name = entry["name"]
                role = entry["role"]
                if name not in employee_roles:
                    employee_roles[name] = []
                if role not in employee_roles[name]:
                    employee_roles[name].append(role)

        for emp_name in self._data["employees"]:
            roles = employee_roles.get(emp_name, [])
            dept = _infer_department(roles)

            subj = Subject(
                id=vektor_id(SOURCE, f"employee:{emp_name}"),
                external_id=emp_name.lower().replace(" ", ".").replace(".", "."),
                source=SOURCE,
                type=SubjectType.HUMAN,
                display_name=emp_name,
                email=f"{emp_name.lower().replace(' ', '.')}@company.com",
                department=dept,
                status=SubjectStatus.ACTIVE,
                mfa_enabled=random.choice([True, True, True, True, True, False]),  # 83% MFA
                last_seen=now - timedelta(days=random.randint(0, 14)),  # all recently active
                created_at=now - timedelta(days=random.randint(180, 1200)),
                attributes={"netsuite_roles": roles},
            )
            subjects.append(subj)

            # Create assignments
            for role_name in roles:
                perm = role_permission_map.get(role_name)
                if perm:
                    assignments.append(Assignment(
                        subject_id=subj.id,
                        permission_id=perm.id,
                        source=SOURCE,
                        granted_at=now - timedelta(days=random.randint(30, 600)),
                        is_active=True,
                    ))

        # --- Detect SoD escalation paths ---
        for sod_json_key, sod_rule_id in SOD_KEY_MAP.items():
            rule_def = next(r for r in SOD_RULES if r["id"] == sod_rule_id)
            rule_data = self._data["sod_rules"].get(sod_json_key, {})
            
            for emp_name in rule_data.get("violating_users", []):
                subj_id = vektor_id(SOURCE, f"employee:{emp_name}")
                # Only create if we have the subject
                if any(s.id == subj_id for s in subjects):
                    roles_held = [
                        e["role"] for e in rule_data.get("user_roles", [])
                        if e["name"] == emp_name
                    ]
                    escalation_paths.append(EscalationPath(
                        subject_id=subj_id,
                        steps=[
                            EscalationStep(
                                action=rule_def["permission_a"],
                                resource="NetSuite ERP",
                                description=f"Has '{rule_def['permission_a']}' via role(s): {', '.join(roles_held[:2])}",
                            ),
                            EscalationStep(
                                action=rule_def["permission_b"],
                                resource="NetSuite ERP",
                                description=f"Also has '{rule_def['permission_b']}' — SoD conflict",
                            ),
                        ],
                        end_result=rule_def["risk"],
                        confidence=rule_def["confidence"],
                        source=SOURCE,
                    ))

        snapshot = GraphSnapshot(
            source=SOURCE,
            subjects=subjects,
            permissions=permissions,
            resources=resources,
            assignments=assignments,
            escalation_paths=escalation_paths,
        )

        logger.info(
            "netsuite.local.extracted",
            subjects=len(subjects),
            permissions=len(permissions),
            assignments=len(assignments),
            escalation_paths=len(escalation_paths),
        )

        return snapshot
