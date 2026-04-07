"""
Vektor AI — Local Trading / Financial Services Adapter

Reads synthetic trading firm data and produces a GraphSnapshot with realistic
SEC/FINRA violations. Models a broker-dealer with front-office, middle-office,
back-office, research, and compliance desks with information barriers.

Data sources:
  - demo/data_trading_finserv.json — synthetic trading firm modeled on:
    • SEC EDGAR Form 3/4/5 — insider filing structure (entity-resource graph)
    • FINRA Regulatory Oversight Reports (2024-2026) — examination findings
    • FINRA Rules 2241, 3110, 5270, 5280 — Chinese walls, supervision, trading ahead
    • SEC Rule 10b-5, Regulation FD, Regulation SHO — insider trading, MNPI
    • Morgan Stanley Block Trade Enforcement ($249M, 2025) — cross-boundary access

The adapter produces realistic findings including:
  - Chinese wall breaches (research ↔ trading)
  - Block trade front-running (Morgan Stanley pattern)
  - MNPI access and disclosure
  - Compliance officer personal trading violations
  - Cross-desk unauthorized access
  - Terminated trader with active credentials
  - AI pre-trade agent MNPI scope drift
  - AI research agent Chinese wall breach
  - Operations SoD (amend + approve + settle)
  - Missing MFA on trading accounts

All violation categories are mapped to specific SEC rules and FINRA regulations
and informed by real enforcement actions and examination findings.
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

SOURCE = "trading"

# ---------------------------------------------------------------------------
# SEC/FINRA violation rules
# ---------------------------------------------------------------------------
FINSERV_RULES: list[dict[str, Any]] = [
    {
        "id": "FINRA-R1-CHINESE-WALL",
        "name": "Chinese Wall Breach",
        "description": "Information barrier violation — research/trading separation breached",
        "regulation": "FINRA Rule 2241 — Research Analyst Conflicts",
        "severity": "critical",
        "violation_class": 15,  # Cross-Boundary Bypass
    },
    {
        "id": "SEC-R2-FRONT-RUNNING",
        "name": "Block Trade Front-Running",
        "description": "Trading ahead of pending block order using MNPI",
        "regulation": "SEC Rule 10b-5 / FINRA Rule 5270",
        "severity": "critical",
        "violation_class": 15,  # Cross-Boundary Bypass
    },
    {
        "id": "SEC-R3-MNPI",
        "name": "MNPI Access / Disclosure",
        "description": "Unauthorized access to or disclosure of material non-public information",
        "regulation": "SEC Rule 10b-5 / Regulation FD",
        "severity": "critical",
        "violation_class": 15,  # Cross-Boundary Bypass
    },
    {
        "id": "FINRA-R4-COMP-TRADING",
        "name": "Compliance Personal Trading",
        "description": "Compliance personnel trading restricted securities without pre-clearance",
        "regulation": "FINRA Rule 3110 / Rule 3210",
        "severity": "critical",
        "violation_class": 1,  # SoD Violation
    },
    {
        "id": "FINRA-R5-CROSS-DESK",
        "name": "Cross-Desk Unauthorized Access",
        "description": "Unauthorized cross-desk position visibility enabling information arbitrage",
        "regulation": "FINRA Rule 3110 — Supervision",
        "severity": "high",
        "violation_class": 13,  # Toxic Role Combination
    },
    {
        "id": "FINRA-R6-DORMANT",
        "name": "Dormant / Terminated Access",
        "description": "Terminated personnel retaining active trading or surveillance credentials",
        "regulation": "FINRA Rule 4511 / Rule 3110",
        "severity": "critical",
        "violation_class": 4,  # Stale / Dormant Account
    },
    {
        "id": "SEC-R7-AGENT-SCOPE",
        "name": "AI Agent MNPI Scope Drift",
        "description": "AI trading agent accessing data beyond scope — crosses information barriers",
        "regulation": "SEC Rule 10b-5 (agent analogue) / FINRA Rule 5270",
        "severity": "critical",
        "violation_class": 10,  # Service Account Misuse (AI agent)
    },
    {
        "id": "FINRA-R8-AGENT-WALL",
        "name": "AI Agent Chinese Wall Breach",
        "description": "AI research agent accessing proprietary trading data — biases research",
        "regulation": "FINRA Rule 2241 (agent analogue)",
        "severity": "high",
        "violation_class": 10,  # Service Account Misuse (AI agent)
    },
    {
        "id": "FINRA-R9-OPS-SOD",
        "name": "Operations SoD Violation",
        "description": "Toxic permission combination — can amend, approve, and settle without independent check",
        "regulation": "FINRA Rule 3110 / SOX ITGC",
        "severity": "high",
        "violation_class": 1,  # SoD Violation
    },
    {
        "id": "SEC-R10-MISSING-MFA",
        "name": "Trading Account Without MFA",
        "description": "Trading account without multi-factor authentication",
        "regulation": "SEC Regulation S-P / FINRA cybersecurity guidance",
        "severity": "high",
        "violation_class": 8,  # Missing MFA
    },
]

# Map violation type strings from data file to rule IDs
VIOLATION_TYPE_MAP = {
    "chinese_wall_breach": "FINRA-R1-CHINESE-WALL",
    "block_trade_front_running": "SEC-R2-FRONT-RUNNING",
    "mnpi_access": "SEC-R3-MNPI",
    "compliance_trading_violation": "FINRA-R4-COMP-TRADING",
    "cross_desk_access": "FINRA-R5-CROSS-DESK",
    "dormant_terminated": "FINRA-R6-DORMANT",
    "ai_agent_scope_drift": "SEC-R7-AGENT-SCOPE",
    "ai_chinese_wall_breach": "FINRA-R8-AGENT-WALL",
    "excessive_trading_access": "FINRA-R9-OPS-SOD",
    "missing_mfa_trading": "SEC-R10-MISSING-MFA",
}


class LocalTradingAdapter(BaseAdapter):
    """
    Reads synthetic trading firm data from local JSON.

    Drop-in replacement for a live Bloomberg/FIX/OMS adapter — produces the
    same GraphSnapshot a real trading system adapter would. When connected
    to a real broker-dealer, swap which adapter is instantiated — graph,
    features, and models stay identical.
    """

    source_name = SOURCE

    def __init__(self, data_path: str | Path | None = None):
        self._data_path = Path(data_path) if data_path else (
            Path(__file__).parent / "data_trading_finserv.json"
        )
        self._data: dict[str, Any] | None = None

    async def connect(self, credentials: dict | None = None) -> None:
        """Load the local trading firm data file."""
        if not self._data_path.exists():
            raise FileNotFoundError(
                f"Trading firm data not found at {self._data_path}. "
                "Ensure data_trading_finserv.json is present in demo/."
            )
        with open(self._data_path) as f:
            self._data = json.load(f)
        firm = self._data["firm"]["name"]
        n_personnel = len(self._data["personnel"])
        n_terminated = len(self._data["terminated_personnel"])
        n_agents = len(self._data["ai_agents"])
        logger.info(
            "trading.local.connected",
            firm=firm,
            personnel=n_personnel,
            terminated=n_terminated,
            ai_agents=n_agents,
        )

    async def test_connection(self) -> bool:
        return self._data_path.exists()

    async def extract(self) -> GraphSnapshot:
        """
        Build a complete GraphSnapshot from the trading firm data.

        1. Creates Resource objects for desks, systems, and information barriers
        2. Creates Permission objects from trading RBAC roles
        3. Creates Subject objects for traders, sales, research, compliance,
           operations, IT, terminated personnel, and AI agents
        4. Creates Assignment objects linking subjects to roles
        5. Detects SEC/FINRA violations as EscalationPaths
        """
        if self._data is None:
            await self.connect()

        assert self._data is not None
        now = utcnow()
        random.seed(43)  # Reproducible, different seed from healthcare

        subjects: list[Subject] = []
        permissions: list[Permission] = []
        resources: list[Resource] = []
        assignments: list[Assignment] = []
        escalation_paths: list[EscalationPath] = []

        # --- Trading Resources: Desks, Systems, Barriers ---
        resource_map: dict[str, Resource] = {}

        # Trading desks
        for desk in self._data["firm"]["desks"]:
            is_restricted = desk.get("is_restricted", False)
            sensitivity = (
                Sensitivity.CRITICAL if is_restricted
                else Sensitivity.HIGH if desk["division"] == "front-office"
                else Sensitivity.MEDIUM
            )
            r = Resource(
                id=vektor_id(SOURCE, f"desk:{desk['id']}"),
                source=SOURCE,
                type="trading_desk",
                name=desk["name"],
                sensitivity=sensitivity,
                attributes={
                    "division": desk["division"],
                    "asset_class": desk["asset_class"],
                    "is_restricted": is_restricted,
                    "restriction_note": desk.get("restriction_note", ""),
                },
            )
            resource_map[desk["id"]] = r
            resources.append(r)

        # Information barriers as resources (they are governance controls)
        for barrier in self._data["firm"]["information_barriers"]:
            r = Resource(
                id=vektor_id(SOURCE, f"barrier:{barrier['id']}"),
                source=SOURCE,
                type="information_barrier",
                name=barrier["name"],
                sensitivity=Sensitivity.CRITICAL,
                attributes={
                    "side_a": barrier["side_a"],
                    "side_b": barrier["side_b"],
                    "regulation": barrier["regulation"],
                    "description": barrier["description"],
                },
            )
            resource_map[barrier["id"]] = r
            resources.append(r)

        # Trading systems as resources
        trading_systems = [
            ("Order Management System", "trading_system", Sensitivity.CRITICAL),
            ("Block Order Book", "trading_system", Sensitivity.CRITICAL),
            ("Market Data Feed", "market_data", Sensitivity.MEDIUM),
            ("Research Portal", "research_system", Sensitivity.HIGH),
            ("Trade Blotter", "surveillance_system", Sensitivity.CRITICAL),
            ("Communications Surveillance", "surveillance_system", Sensitivity.CRITICAL),
            ("Restricted List", "compliance_system", Sensitivity.CRITICAL),
            ("P&L / Risk System", "risk_system", Sensitivity.HIGH),
            ("Settlement System", "operations_system", Sensitivity.HIGH),
            ("Audit Trail", "compliance_system", Sensitivity.CRITICAL),
            ("Client Flow Data", "trading_system", Sensitivity.CRITICAL),
        ]
        for sys_name, sys_type, sensitivity in trading_systems:
            r = Resource(
                id=vektor_id(SOURCE, f"system:{sys_name}"),
                source=SOURCE,
                type=sys_type,
                name=sys_name,
                sensitivity=sensitivity,
            )
            resource_map[sys_name] = r
            resources.append(r)

        # --- Build trading RBAC role → Permission objects ---
        role_permission_map: dict[str, Permission] = {}
        for role_def in self._data["finserv_rbac_roles"]:
            role_name = role_def["role"]
            risk_keywords = _risk_keywords_for_role(role_def)
            perm = Permission(
                id=vektor_id(SOURCE, f"role:{role_name}"),
                source=SOURCE,
                name=role_name,
                type=PermissionType.ROLE,
                actions=role_def["actions"],
                is_privileged=role_def.get("is_privileged", False),
                risk_keywords=risk_keywords,
                attributes={
                    "scope": role_def.get("scope", ""),
                    "desk_access": role_def.get("desk_access", []),
                    "chinese_wall": role_def.get("chinese_wall", False),
                    "mnpi_access": role_def.get("mnpi_access", False),
                    "restricted_trading": role_def.get("restricted_trading", False),
                    "is_agent": role_def.get("is_agent", False),
                },
            )
            role_permission_map[role_name] = perm
            permissions.append(perm)

        # --- Build Subject objects ---
        subject_map: dict[str, Subject] = {}

        # Active personnel
        for person in self._data["personnel"]:
            subj = _build_subject(person, now)
            subject_map[person["id"]] = subj
            subjects.append(subj)

            role_name = person["role"]
            perm = role_permission_map.get(role_name)
            if perm:
                assignments.append(Assignment(
                    subject_id=subj.id,
                    permission_id=perm.id,
                    source=SOURCE,
                    granted_at=now - timedelta(days=random.randint(60, 1200)),
                    is_active=True,
                ))

        # Terminated personnel (dormant violations)
        for person in self._data["terminated_personnel"]:
            subj = _build_subject(person, now)
            subject_map[person["id"]] = subj
            subjects.append(subj)

            role_name = person["role"]
            perm = role_permission_map.get(role_name)
            if perm:
                assignments.append(Assignment(
                    subject_id=subj.id,
                    permission_id=perm.id,
                    source=SOURCE,
                    granted_at=now - timedelta(days=random.randint(200, 800)),
                    is_active=True,  # Still active despite termination
                ))

        # AI Agents
        for agent in self._data["ai_agents"]:
            subj = _build_subject(agent, now)
            subject_map[agent["id"]] = subj
            subjects.append(subj)

            role_name = agent["role"]
            perm = role_permission_map.get(role_name)
            if perm:
                assignments.append(Assignment(
                    subject_id=subj.id,
                    permission_id=perm.id,
                    source=SOURCE,
                    granted_at=now - timedelta(days=random.randint(30, 180)),
                    is_active=True,
                ))

        # --- Cross-desk access injection for TRAD-006 (Natasha Volkov) ---
        # She gets extra assignments to equities and FI desks
        volkov_subj = subject_map.get("TRAD-006")
        if volkov_subj:
            for extra_role in ("Trader — Equities", "Trader — Fixed Income"):
                extra_perm = role_permission_map.get(extra_role)
                if extra_perm:
                    assignments.append(Assignment(
                        subject_id=volkov_subj.id,
                        permission_id=extra_perm.id,
                        source=SOURCE,
                        granted_at=now - timedelta(days=random.randint(10, 60)),
                        is_active=True,
                    ))

        # --- Detect SEC/FINRA violations → EscalationPaths ---
        for violation in self._data["injected_violations"]:
            v_type = violation["type"]
            rule_id = VIOLATION_TYPE_MAP.get(v_type)
            if not rule_id:
                continue

            rule_def = next(
                (r for r in FINSERV_RULES if r["id"] == rule_id), None
            )
            if not rule_def:
                continue

            subj_data_id = violation["subject_id"]
            subj = subject_map.get(subj_data_id)
            if not subj:
                continue

            steps = _build_escalation_steps(violation, rule_def)

            escalation_paths.append(EscalationPath(
                subject_id=subj.id,
                steps=steps,
                end_result=violation["description"],
                confidence=violation["confidence"],
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
            "trading.local.extracted",
            firm=self._data["firm"]["name"],
            subjects=len(subjects),
            permissions=len(permissions),
            resources=len(resources),
            assignments=len(assignments),
            escalation_paths=len(escalation_paths),
            desks=len(self._data["firm"]["desks"]),
            information_barriers=len(self._data["firm"]["information_barriers"]),
        )

        return snapshot


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def _build_subject(record: dict[str, Any], now: datetime) -> Subject:
    """Build a Subject from a personnel/terminated/agent record."""
    entity_type = record.get("type", "human")
    if entity_type == "ai_agent":
        subject_type = SubjectType.AI_AGENT
    elif entity_type == "service_account":
        subject_type = SubjectType.SERVICE_ACCOUNT
    else:
        subject_type = SubjectType.HUMAN

    status_str = record.get("status", "active")
    status = SubjectStatus.ACTIVE if status_str == "active" else SubjectStatus.INACTIVE

    last_login_days = record.get("last_login_days_ago", 0)

    # Determine department from desk
    desk = record.get("desk", "")
    desk_dept_map = {
        "DESK-EQ": "Equities Trading",
        "DESK-FI": "Fixed Income Trading",
        "DESK-BLOCK": "Block Trading",
        "DESK-DERIV": "Derivatives",
        "DESK-SALES": "Institutional Sales",
        "DESK-RES": "Equity Research",
        "DESK-RISK": "Risk Management",
        "DESK-COMP": "Compliance",
        "DESK-OPS": "Operations",
        "DESK-IT": "Technology",
    }
    department = desk_dept_map.get(desk, "Trading")

    attributes: dict[str, Any] = {
        "desk": desk,
        "role_title": record.get("role", ""),
    }
    if record.get("series_licenses"):
        attributes["series_licenses"] = record["series_licenses"]
    if record.get("years_experience"):
        attributes["years_experience"] = record["years_experience"]
    if record.get("coverage"):
        attributes["coverage"] = record["coverage"]
    if record.get("mnpi_access"):
        attributes["mnpi_access"] = True
    if record.get("termination_date"):
        attributes["termination_date"] = record["termination_date"]
    if record.get("notes"):
        attributes["notes"] = record["notes"]
    if record.get("violation_injected"):
        attributes["violation_type"] = record["violation_injected"]

    return Subject(
        id=vektor_id(SOURCE, f"entity:{record['id']}"),
        external_id=record["id"],
        source=SOURCE,
        type=subject_type,
        display_name=record["name"],
        email=(
            f"{record['name'].lower().replace(' ', '.').replace(',', '')}@apexcapital.com"
            if subject_type == SubjectType.HUMAN
            else f"{record['id'].lower()}@agents.apexcapital.com"
        ),
        department=department,
        status=status,
        mfa_enabled=record.get("mfa"),
        last_seen=now - timedelta(days=last_login_days) if last_login_days else now,
        created_at=now - timedelta(days=random.randint(90, 2000)),
        attributes=attributes,
    )


def _risk_keywords_for_role(role_def: dict[str, Any]) -> list[str]:
    """Generate risk keywords for a trading RBAC role."""
    keywords = []
    rn = role_def["role"].lower()

    if "execute" in str(role_def.get("actions", [])):
        keywords.append("order_execution")
    if role_def.get("mnpi_access"):
        keywords.append("mnpi_access")
    if role_def.get("chinese_wall"):
        keywords.append("chinese_wall_restricted")
    if role_def.get("restricted_trading"):
        keywords.append("restricted_trading")
    if role_def.get("is_agent"):
        keywords.append("ai_agent")
    if role_def.get("is_privileged"):
        keywords.append("privileged_access")
    if "admin" in rn:
        keywords.append("admin_access")
    if "compliance" in rn:
        keywords.append("compliance_access")
    if "research" in rn:
        keywords.append("research_silo")
    if "block" in rn:
        keywords.append("block_trading")
    if "risk" in rn:
        keywords.append("risk_management")
    if "settlement" in rn or "operations" in rn:
        keywords.append("operations")

    return keywords


def _build_escalation_steps(
    violation: dict[str, Any],
    rule_def: dict[str, Any],
) -> list[EscalationStep]:
    """Build escalation steps from a violation record."""
    v_type = violation["type"]
    evidence = violation.get("evidence", {})

    if v_type == "chinese_wall_breach":
        return [
            EscalationStep(
                action="Chinese Wall Breach",
                resource=evidence.get("restricted_resource", "Research System"),
                description=f"Barrier crossed: {evidence.get('information_barrier', 'N/A')}. {evidence.get('access_type', '')}",
            ),
            EscalationStep(
                action="Trading After Access",
                resource="Order Management System",
                description=f"Timing: {evidence.get('timing', 'N/A')}. {evidence.get('trading_activity_post_access', '')}",
            ),
        ]

    elif v_type == "block_trade_front_running":
        return [
            EscalationStep(
                action="Block Order Book Access",
                resource="Block Order Book",
                description=f"Barrier: {evidence.get('information_barrier', 'N/A')}. {evidence.get('access_type', '')}",
            ),
            EscalationStep(
                action="Front-Running Trade Execution",
                resource="Order Management System",
                description=f"Timing: {evidence.get('timing', 'N/A')}",
            ),
            EscalationStep(
                action="Profit from MNPI",
                resource="Trading P&L",
                description=f"Estimated profit: {evidence.get('profit_estimate', 'N/A')}. {evidence.get('morgan_stanley_parallel', '')}",
            ),
        ]

    elif v_type == "mnpi_access":
        return [
            EscalationStep(
                action="MNPI Access",
                resource=evidence.get("restricted_resource", "Block Order Book"),
                description=f"Barrier: {evidence.get('information_barrier', 'N/A')}. {evidence.get('access_type', '')}",
            ),
            EscalationStep(
                action="MNPI Disclosure to Client",
                resource="Communications",
                description=f"Flagged communication: {evidence.get('communication_flagged', 'N/A')}. Clients notified: {evidence.get('clients_notified', 0)}",
            ),
        ]

    elif v_type == "compliance_trading_violation":
        return [
            EscalationStep(
                action="Compliance Officer Trading",
                resource="Restricted List / Personal Trading",
                description=f"Manages restricted list AND executed personal trades. Securities: {', '.join(evidence.get('restricted_securities_traded', []))}",
            ),
            EscalationStep(
                action="SoD Violation — Compliance + Trading",
                resource="Personal Brokerage Account",
                description=f"Personal trades in 30d: {evidence.get('personal_trades_30d', 0)} (peer avg: {evidence.get('peer_personal_trades_avg', 0)}). Account: {evidence.get('trading_account', 'N/A')}",
            ),
        ]

    elif v_type == "cross_desk_access":
        additional = evidence.get("additional_access", [])
        return [
            EscalationStep(
                action="Cross-Desk Position Access",
                resource="Multiple Trading Desks",
                description=f"Primary desk: {evidence.get('primary_desk', 'N/A')}. Additional access: {', '.join(additional)}",
            ),
            EscalationStep(
                action="Information Arbitrage Risk",
                resource="P&L / Risk System",
                description=f"Risk: {evidence.get('risk', 'N/A')}. Justification: {'on file' if evidence.get('justification_on_file') else 'NONE'}",
            ),
        ]

    elif v_type == "dormant_terminated":
        return [
            EscalationStep(
                action="Dormant Credential Active",
                resource="Trading Systems",
                description=f"Terminated {evidence.get('termination_date', 'unknown')} — {evidence.get('days_since_termination', 'N/A')} days ago. Last activity: {evidence.get('last_activity', 'N/A')}",
            ),
            EscalationStep(
                action="Active Trading Permissions",
                resource="Order Management System",
                description=f"Active permissions: {', '.join(evidence.get('active_permissions', []))}. MFA: {'enabled' if evidence.get('mfa_enabled') else 'DISABLED'}. {evidence.get('risk', '')}",
            ),
        ]

    elif v_type == "ai_agent_scope_drift":
        return [
            EscalationStep(
                action="AI Agent Cross-Barrier Access",
                resource="Block Order Book / Client Flow",
                description=f"Assigned desk: {evidence.get('assigned_desk', 'N/A')}. Unauthorized access: {', '.join(evidence.get('unauthorized_access', []))}",
            ),
            EscalationStep(
                action="Information Barrier Crossed by AI",
                resource=evidence.get("information_barrier_crossed", "Information Barrier"),
                description=f"Expected scope: {evidence.get('expected_scope', 'N/A')}. Orders suggested after access: {evidence.get('orders_suggested_after_access', 0)}",
            ),
            EscalationStep(
                action="Automated Front-Running Risk",
                resource="Order Management System",
                description=evidence.get("risk", "AI agent with MNPI access — automated front-running risk"),
            ),
        ]

    elif v_type == "ai_chinese_wall_breach":
        return [
            EscalationStep(
                action="AI Agent Chinese Wall Breach",
                resource="Trading Desk Positions / P&L",
                description=f"Assigned desk: {evidence.get('assigned_desk', 'N/A')}. Unauthorized access: {', '.join(evidence.get('unauthorized_access', []))}",
            ),
            EscalationStep(
                action="Research Bias Risk",
                resource="Research Portal",
                description=f"Barrier crossed: {evidence.get('information_barrier_crossed', 'N/A')}. Reports drafted after access: {evidence.get('research_reports_drafted_after_access', 0)}. {evidence.get('risk', '')}",
            ),
        ]

    elif v_type == "excessive_trading_access":
        return [
            EscalationStep(
                action="Toxic Permission Combination",
                resource="Settlement System",
                description=f"Permissions: {', '.join(evidence.get('toxic_combination', []))}",
            ),
            EscalationStep(
                action="SoD Violation — Amend + Approve + Settle",
                resource="Operations Systems",
                description=f"Amendments in 30d: {evidence.get('amendments_30d', 0)} (peer avg: {evidence.get('peer_amendments_avg', 0)}). Exceptions approved: {evidence.get('exceptions_approved_30d', 0)}. {evidence.get('risk', '')}",
            ),
        ]

    elif v_type == "missing_mfa_trading":
        return [
            EscalationStep(
                action="Trading Access Without MFA",
                resource="Trading Systems",
                description=f"Role: {evidence.get('role', 'N/A')}. Access: {evidence.get('access_level', 'N/A')}. MFA: DISABLED. Status: {evidence.get('account_status', 'N/A')}",
            ),
        ]

    # Fallback
    return [
        EscalationStep(
            action=rule_def["name"],
            resource="Trading Systems",
            description=violation["description"],
        ),
    ]
