"""
Vektor AI — Local Healthcare Adapter

Reads synthetic FHIR-inspired healthcare tenant data and produces a GraphSnapshot
with realistic HIPAA violations. Models a multi-facility health system with
providers, nurses, staff, contractors, and AI clinical agents.

Data sources:
  - demo/data_healthcare_fhir.json — synthetic healthcare tenant modeled on:
    • Synthea (by MITRE) — synthetic patient/encounter generation in FHIR R4
    • Azure Health Data Services FHIR RBAC — documented role definitions
    • OpenMRS — open source EHR with documented RBAC model
    • HHS OCR Breach Portal — 7,400+ HIPAA breach records informing taxonomy

The adapter produces realistic findings including:
  - Unauthorized record access (billing clerk accessing psychiatric notes)
  - Peer deviation (nurse accessing 10x more records than peers)
  - Break-glass abuse (IT admin using emergency access without justification)
  - Dormant contractors with active PHI credentials
  - AI scribe agent scope drift across departments
  - Cross-system PHI aggregation (AI coder agent across EHR + billing + pharmacy)
  - Missing MFA on PHI-accessing accounts
  - Excessive bulk data exports
  - Celebrity/VIP record snooping

All violation categories are mapped to specific HIPAA Security/Privacy Rule
sections and informed by real HHS OCR enforcement actions.
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

SOURCE = "healthcare"

# ---------------------------------------------------------------------------
# HIPAA violation rules — mapped to HIPAA Security/Privacy Rule sections
# ---------------------------------------------------------------------------
HIPAA_RULES: list[dict[str, Any]] = [
    {
        "id": "HIPAA-R1-UNAUTH-ACCESS",
        "name": "Unauthorized PHI Access",
        "description": "Access to PHI without treatment, payment, or operations justification",
        "hipaa_section": "§164.502(a) — Minimum Necessary",
        "severity": "critical",
        "violation_class": 15,  # Cross-Boundary Bypass
    },
    {
        "id": "HIPAA-R2-PEER-DEVIATION",
        "name": "Anomalous Access Volume",
        "description": "Record access volume significantly exceeding peer norms",
        "hipaa_section": "§164.312(b) — Audit Controls",
        "severity": "high",
        "violation_class": 6,  # Permission Creep (maps to excessive access)
    },
    {
        "id": "HIPAA-R3-BREAKGLASS-ABUSE",
        "name": "Break-Glass Abuse",
        "description": "Emergency access override without genuine emergency or justification",
        "hipaa_section": "§164.312(a)(1) — Access Control",
        "severity": "critical",
        "violation_class": 14,  # Break-Glass Abuse
    },
    {
        "id": "HIPAA-R4-DORMANT-CONTRACTOR",
        "name": "Dormant Contractor / Vendor Access",
        "description": "Terminated contractor or vendor retaining active PHI access",
        "hipaa_section": "§164.308(a)(3)(ii)(A) — Workforce Clearance",
        "severity": "high",
        "violation_class": 4,  # Stale / Dormant Account
    },
    {
        "id": "HIPAA-R5-AGENT-SCOPE-DRIFT",
        "name": "AI Agent Scope Drift",
        "description": "AI agent accessing PHI beyond its designated operational scope",
        "hipaa_section": "§164.502(b) — Minimum Necessary",
        "severity": "critical",
        "violation_class": 10,  # Service Account Misuse (AI agent)
    },
    {
        "id": "HIPAA-R6-CROSS-SYSTEM",
        "name": "Cross-System PHI Aggregation",
        "description": "Entity accessing PHI across clinical, billing, and pharmacy systems",
        "hipaa_section": "§164.502(b) — Minimum Necessary",
        "severity": "high",
        "violation_class": 9,  # Cross-System Inconsistency
    },
    {
        "id": "HIPAA-R7-MISSING-MFA",
        "name": "PHI Access Without MFA",
        "description": "Account with PHI access lacks multi-factor authentication",
        "hipaa_section": "§164.312(d) — Person or Entity Authentication",
        "severity": "medium",
        "violation_class": 8,  # Missing MFA
    },
    {
        "id": "HIPAA-R8-EXCESSIVE-EXPORT",
        "name": "Excessive Data Export",
        "description": "Bulk PHI export volume exceeding peer norms — exfiltration risk",
        "hipaa_section": "§164.312(b) — Audit Controls",
        "severity": "high",
        "violation_class": 11,  # Unauthorized Config Change (maps to data exfil)
    },
    {
        "id": "HIPAA-R9-CELEBRITY-SNOOP",
        "name": "VIP Record Snooping",
        "description": "Accessing records of VIP/celebrity patients without clinical need",
        "hipaa_section": "§164.502(a) — Minimum Necessary",
        "severity": "high",
        "violation_class": 15,  # Cross-Boundary Bypass
    },
]

# Map violation type strings from data file to HIPAA rule IDs
VIOLATION_TYPE_MAP = {
    "unauthorized_record_access": "HIPAA-R1-UNAUTH-ACCESS",
    "peer_deviation": "HIPAA-R2-PEER-DEVIATION",
    "break_glass_abuse": "HIPAA-R3-BREAKGLASS-ABUSE",
    "dormant_contractor": "HIPAA-R4-DORMANT-CONTRACTOR",
    "ai_agent_scope_drift": "HIPAA-R5-AGENT-SCOPE-DRIFT",
    "cross_system_aggregation": "HIPAA-R6-CROSS-SYSTEM",
    "missing_mfa": "HIPAA-R7-MISSING-MFA",
    "excessive_export": "HIPAA-R8-EXCESSIVE-EXPORT",
    "celebrity_snooping": "HIPAA-R9-CELEBRITY-SNOOP",
}


class LocalHealthcareAdapter(BaseAdapter):
    """
    Reads synthetic healthcare tenant data from local JSON.

    Drop-in replacement for a live FHIR/EHR adapter — produces the same
    GraphSnapshot a real Epic/Cerner/OpenMRS adapter would. When connected
    to a real health system, swap which adapter is instantiated — graph,
    features, and models stay identical.
    """

    source_name = SOURCE

    def __init__(self, data_path: str | Path | None = None):
        self._data_path = Path(data_path) if data_path else (
            Path(__file__).parent / "data_healthcare_fhir.json"
        )
        self._data: dict[str, Any] | None = None

    async def connect(self, credentials: dict | None = None) -> None:
        """Load the local healthcare data file."""
        if not self._data_path.exists():
            raise FileNotFoundError(
                f"Healthcare FHIR data not found at {self._data_path}. "
                "Ensure data_healthcare_fhir.json is present in demo/."
            )
        with open(self._data_path) as f:
            self._data = json.load(f)
        org_name = self._data["organization"]["name"]
        n_providers = len(self._data["providers"])
        n_contractors = len(self._data["contractors"])
        n_agents = len(self._data["ai_agents"])
        logger.info(
            "healthcare.local.connected",
            organization=org_name,
            providers=n_providers,
            contractors=n_contractors,
            ai_agents=n_agents,
        )

    async def test_connection(self) -> bool:
        return self._data_path.exists()

    async def extract(self) -> GraphSnapshot:
        """
        Build a complete GraphSnapshot from the healthcare tenant data.

        1. Creates Resource objects for facilities, departments, and data systems
        2. Creates Permission objects from FHIR RBAC roles
        3. Creates Subject objects for providers, nurses, staff, contractors, AI agents
        4. Creates Assignment objects linking subjects to roles
        5. Detects HIPAA violations as EscalationPaths
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

        # --- Healthcare Resources: Facilities, Departments, Data Systems ---
        resource_map: dict[str, Resource] = {}

        # Facilities
        for fac in self._data["organization"]["facilities"]:
            r = Resource(
                id=vektor_id(SOURCE, f"facility:{fac['id']}"),
                source=SOURCE,
                type="healthcare_facility",
                name=fac["name"],
                sensitivity=Sensitivity.HIGH,
                attributes={
                    "facility_type": fac["type"],
                    "departments": fac["departments"],
                },
            )
            resource_map[fac["id"]] = r
            resources.append(r)

            # Department-level resources
            for dept in fac["departments"]:
                dept_key = f"{fac['id']}:{dept}"
                sensitivity = Sensitivity.CRITICAL if dept in (
                    "Psychiatry", "Substance Abuse", "Adolescent Psych"
                ) else Sensitivity.HIGH if dept in (
                    "Oncology", "ICU", "Surgery", "Emergency"
                ) else Sensitivity.MEDIUM
                dr = Resource(
                    id=vektor_id(SOURCE, f"dept:{dept_key}"),
                    source=SOURCE,
                    type="healthcare_department",
                    name=f"{dept} — {fac['name']}",
                    sensitivity=sensitivity,
                    attributes={
                        "facility_id": fac["id"],
                        "department": dept,
                        "has_42cfr_data": dept in (
                            "Psychiatry", "Substance Abuse", "Adolescent Psych"
                        ),
                    },
                )
                resource_map[dept_key] = dr
                resources.append(dr)

        # Data systems as resources
        data_systems = [
            ("EHR Clinical Notes", "clinical_system", Sensitivity.CRITICAL),
            ("FHIR Server", "clinical_system", Sensitivity.CRITICAL),
            ("Pharmacy Dispensing", "pharmacy_system", Sensitivity.HIGH),
            ("Billing System", "billing_system", Sensitivity.HIGH),
            ("Lab Results", "clinical_system", Sensitivity.HIGH),
            ("Radiology PACS", "clinical_system", Sensitivity.HIGH),
            ("Patient Portal", "patient_facing", Sensitivity.MEDIUM),
            ("Research Data Warehouse", "research_system", Sensitivity.HIGH),
            ("Audit Log System", "security_system", Sensitivity.CRITICAL),
        ]
        for sys_name, sys_type, sensitivity in data_systems:
            r = Resource(
                id=vektor_id(SOURCE, f"system:{sys_name}"),
                source=SOURCE,
                type=sys_type,
                name=sys_name,
                sensitivity=sensitivity,
            )
            resource_map[sys_name] = r
            resources.append(r)

        # --- Build FHIR RBAC role → Permission objects ---
        role_permission_map: dict[str, Permission] = {}
        for role_def in self._data["fhir_rbac_roles"]:
            role_name = role_def["role"]
            perm = Permission(
                id=vektor_id(SOURCE, f"role:{role_name}"),
                source=SOURCE,
                name=role_name,
                type=PermissionType.ROLE,
                actions=role_def["actions"],
                is_privileged=role_def["is_privileged"],
                risk_keywords=_risk_keywords_for_role(role_name),
                attributes={
                    "scope": role_def["scope"],
                    "description": role_def["description"],
                },
            )
            role_permission_map[role_name] = perm
            permissions.append(perm)

        # --- Build Subject objects from providers, contractors, AI agents ---
        subject_map: dict[str, Subject] = {}

        # Providers (physicians, nurses, pharmacists, billing, HIM, IT, research)
        for prov in self._data["providers"]:
            subj = _build_subject(prov, now)
            subject_map[prov["id"]] = subj
            subjects.append(subj)

            # Assignment: link provider to their FHIR RBAC role
            role_name = prov["role"]
            perm = role_permission_map.get(role_name)
            if perm:
                assignments.append(Assignment(
                    subject_id=subj.id,
                    permission_id=perm.id,
                    source=SOURCE,
                    granted_at=now - timedelta(days=random.randint(60, 800)),
                    is_active=True,
                ))

            # Also assign Break-Glass permission to physicians and IT admins
            if prov["role"] in ("Attending Physician", "IT System Admin"):
                bg_perm = role_permission_map.get("Break-Glass Emergency")
                if bg_perm:
                    assignments.append(Assignment(
                        subject_id=subj.id,
                        permission_id=bg_perm.id,
                        source=SOURCE,
                        granted_at=now - timedelta(days=random.randint(60, 800)),
                        is_active=True,
                    ))

        # Contractors (dormant violations injected)
        for cont in self._data["contractors"]:
            subj = _build_subject(cont, now)
            subject_map[cont["id"]] = subj
            subjects.append(subj)

            role_name = cont["role"]
            perm = role_permission_map.get(role_name)
            if perm:
                assignments.append(Assignment(
                    subject_id=subj.id,
                    permission_id=perm.id,
                    source=SOURCE,
                    granted_at=now - timedelta(days=random.randint(200, 600)),
                    is_active=True,  # Still active despite contract end
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

            # AI Coder also gets additional cross-system assignments
            if agent["id"] == "AI-CODER-001":
                for extra_role in ("Billing Clerk", "Clinical Staff"):
                    extra_perm = role_permission_map.get(extra_role)
                    if extra_perm:
                        assignments.append(Assignment(
                            subject_id=subj.id,
                            permission_id=extra_perm.id,
                            source=SOURCE,
                            granted_at=now - timedelta(days=random.randint(30, 90)),
                            is_active=True,
                        ))

        # --- Detect HIPAA violations → EscalationPaths ---
        for violation in self._data["injected_violations"]:
            v_type = violation["type"]
            rule_id = VIOLATION_TYPE_MAP.get(v_type)
            if not rule_id:
                continue

            rule_def = next(
                (r for r in HIPAA_RULES if r["id"] == rule_id), None
            )
            if not rule_def:
                continue

            subj_data_id = violation["subject_id"]
            subj = subject_map.get(subj_data_id)
            if not subj:
                continue

            # Build evidence steps based on violation type
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
            "healthcare.local.extracted",
            organization=self._data["organization"]["name"],
            subjects=len(subjects),
            permissions=len(permissions),
            resources=len(resources),
            assignments=len(assignments),
            escalation_paths=len(escalation_paths),
            facilities=len(self._data["organization"]["facilities"]),
        )

        return snapshot


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def _build_subject(record: dict[str, Any], now: datetime) -> Subject:
    """Build a Subject from a provider/contractor/agent record."""
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

    attributes: dict[str, Any] = {
        "facility": record.get("facility", ""),
        "role_title": record.get("role", ""),
    }
    if record.get("contract_end"):
        attributes["contract_end"] = record["contract_end"]
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
            f"{record['name'].lower().replace(' ', '.').replace(',', '').replace('.rn', '')}@apexhealth.org"
            if subject_type == SubjectType.HUMAN
            else f"{record['id'].lower()}@agents.apexhealth.org"
        ),
        department=record.get("department", ""),
        status=status,
        mfa_enabled=record.get("mfa"),
        last_seen=now - timedelta(days=last_login_days) if last_login_days else now,
        created_at=now - timedelta(days=random.randint(90, 1200)),
        attributes=attributes,
    )


def _risk_keywords_for_role(role_name: str) -> list[str]:
    """Generate risk keywords for a FHIR RBAC role."""
    rn = role_name.lower()
    keywords = []
    if "admin" in rn or "system" in rn:
        keywords.append("admin_access")
    if "export" in rn:
        keywords.append("data_export")
    if "break" in rn or "emergency" in rn:
        keywords.append("break_glass")
    if "psychiatry" in rn or "restricted" in rn:
        keywords.append("42cfr_part2")
    if "pharmacy" in rn:
        keywords.append("controlled_substance")
    if "ai" in rn or "scribe" in rn or "triage" in rn or "coder" in rn:
        keywords.append("ai_agent")
    if "privileged" in rn or "contributor" in rn:
        keywords.append("write_access")
    if "billing" in rn:
        keywords.append("phi_billing")
    if "him" in rn or "information management" in rn:
        keywords.append("release_of_info")
    return keywords


def _build_escalation_steps(
    violation: dict[str, Any],
    rule_def: dict[str, Any],
) -> list[EscalationStep]:
    """Build escalation steps from a violation record."""
    v_type = violation["type"]
    evidence = violation.get("evidence", {})

    if v_type == "unauthorized_record_access":
        return [
            EscalationStep(
                action="Access PHI Outside Role Scope",
                resource="EHR Clinical Notes",
                description=f"Accessed {evidence.get('records_accessed', 'restricted records')}",
            ),
            EscalationStep(
                action="Minimum Necessary Violation",
                resource="Psychiatry Records (42 CFR Part 2)",
                description=f"Business need: {evidence.get('business_need', 'None documented')}",
            ),
        ]

    elif v_type == "peer_deviation":
        return [
            EscalationStep(
                action="Excessive Record Access",
                resource="EHR Clinical Notes",
                description=f"Accessed {evidence.get('records_accessed_30d', 'N/A')} records in 30 days (peer median: {evidence.get('peer_median_30d', 'N/A')})",
            ),
            EscalationStep(
                action="Cross-Department Access",
                resource="Multiple Departments",
                description=f"Departments: {', '.join(evidence.get('departments_accessed', []))}",
            ),
        ]

    elif v_type == "break_glass_abuse":
        return [
            EscalationStep(
                action="Break-Glass Emergency Override",
                resource="EHR Access Control",
                description=f"Used {evidence.get('break_glass_uses_30d', 'N/A')} times in 30 days (peer avg: {evidence.get('peer_break_glass_avg', 'N/A')})",
            ),
            EscalationStep(
                action="Access Without Justification",
                resource="VIP Patient Records",
                description=f"Justifications provided: {evidence.get('justifications_provided', 0)} — accessed: {', '.join(evidence.get('patients_accessed', []))}",
            ),
        ]

    elif v_type == "dormant_contractor":
        return [
            EscalationStep(
                action="Dormant Credential Active",
                resource="Healthcare Systems",
                description=f"Contract ended {evidence.get('contract_end_date', 'unknown')} — {evidence.get('days_since_contract_end', 'N/A')} days ago",
            ),
            EscalationStep(
                action="Active PHI Permissions",
                resource="EHR / Clinical Systems",
                description=f"Active permissions: {', '.join(evidence.get('active_permissions', []))}. MFA: {'enabled' if evidence.get('mfa_enabled') else 'DISABLED'}",
            ),
        ]

    elif v_type == "ai_agent_scope_drift":
        return [
            EscalationStep(
                action="AI Agent Cross-Department Access",
                resource="EHR Clinical Notes",
                description=f"Accessed departments: {', '.join(evidence.get('departments_accessed', []))}. Expected: {evidence.get('expected_scope', 'N/A')}",
            ),
            EscalationStep(
                action="Historical Record Access Beyond Scope",
                resource="Patient Records",
                description=f"Read {evidence.get('historical_records_read', 0)} historical records vs {evidence.get('active_encounter_records', 0)} active encounter records",
            ),
            EscalationStep(
                action="42 CFR Part 2 Access by AI Agent",
                resource="Psychiatry Records",
                description=evidence.get("risk_note", "AI agent accessing protected mental health records"),
            ),
        ]

    elif v_type == "cross_system_aggregation":
        return [
            EscalationStep(
                action="Cross-System PHI Access",
                resource="Multiple Clinical Systems",
                description=f"Systems accessed: {', '.join(evidence.get('systems_accessed', []))}",
            ),
            EscalationStep(
                action="Patient Profile Reconstruction Risk",
                resource="Aggregated PHI",
                description=f"Can correlate clinical + billing + pharmacy data. {evidence.get('unique_patients_accessed_30d', 0)} patients accessed in 30 days",
            ),
        ]

    elif v_type == "missing_mfa":
        return [
            EscalationStep(
                action="PHI Access Without MFA",
                resource="Healthcare Systems",
                description=f"Role: {evidence.get('role', 'N/A')} — PHI access level: {evidence.get('phi_access_level', 'N/A')}",
            ),
        ]

    elif v_type == "excessive_export":
        return [
            EscalationStep(
                action="Excessive Bulk Data Export",
                resource="FHIR Server / EHR",
                description=f"Performed {evidence.get('bulk_exports_30d', 0)} exports in 30 days (peer avg: {evidence.get('peer_avg_exports_30d', 0)})",
            ),
            EscalationStep(
                action="Data Exfiltration Risk",
                resource="Patient Data",
                description=f"{evidence.get('records_exported', 0)} records exported. Destinations: {', '.join(evidence.get('export_destinations', []))}",
            ),
        ]

    elif v_type == "celebrity_snooping":
        return [
            EscalationStep(
                action="VIP Record Access",
                resource="Patient Records",
                description=f"Accessed {evidence.get('patient_type', 'VIP')} record — care team member: {evidence.get('care_team_member', False)}",
            ),
            EscalationStep(
                action="Access Outside Clinical Need",
                resource="Patient Records",
                description=f"Department match: {evidence.get('department_match', False)}. Duration: {evidence.get('access_duration', 'N/A')}. Time: {evidence.get('access_time', 'N/A')}",
            ),
        ]

    # Fallback
    return [
        EscalationStep(
            action=rule_def["name"],
            resource="Healthcare Systems",
            description=violation["description"],
        ),
    ]
