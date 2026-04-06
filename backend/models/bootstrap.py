"""
Vektor AI — Bootstrap Labeler

Deterministic rule engine that generates "silver" labels for all 15 violation
classes. These labels bootstrap the supervised ML models on Day 1.

KEY PRINCIPLE: Rules are labelers, not detectors. Once supervised models have
enough data, rules become a fallback sanity check.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import structlog

from backend.adapters.models import (
    Permission,
    Subject,
    SubjectStatus,
    SubjectType,
    new_id,
)
from backend.adapters.aws_iam import HIGH_RISK_ACTIONS
from backend.adapters.netsuite import FINANCIAL_PERMISSIONS, SOD_PAIRS
from backend.features.compute import FeatureVector
from backend.features.store import FeatureStore
from backend.graph.store import IdentityGraph

logger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Break-glass role detection patterns
# ---------------------------------------------------------------------------
BREAKGLASS_PATTERNS = re.compile(
    r"(emergency|break[-_]?glass|firecall|elevated[-_]?access|sos[-_]?admin)",
    re.IGNORECASE,
)

# Admin-category keywords
SECURITY_ADMIN_KEYWORDS = {"securityaudit", "security", "iam", "guardduty", "securityhub", "waf"}
FINANCIAL_ADMIN_KEYWORDS = {"finance", "accounting", "payroll", "treasury", "billing", "ap", "ar", "gl"}


@dataclass
class BootstrapLabel:
    """A single label produced by the bootstrap rule engine."""

    subject_id: str
    violation_class: int            # 1-15
    label: int                      # 1 = violation, 0 = clean
    confidence: float               # rule confidence
    rule_id: str                    # which rule fired
    evidence: dict = field(default_factory=dict)
    source_systems: list[str] = field(default_factory=list)
    is_cross_boundary: bool = False


class BootstrapLabeler:
    """
    Deterministic rule engine that generates bootstrap labels for all 15
    violation classes. These are "silver" (not gold) labels.
    """

    def __init__(self, graph: IdentityGraph, feature_store: FeatureStore) -> None:
        self._graph = graph
        self._fs = feature_store

    def label_all(self) -> dict[str, list[BootstrapLabel]]:
        """
        Run all labeling rules across all subjects.
        Returns: { subject_id: [BootstrapLabel, ...] }
        """
        logger.info("bootstrap.label_all.start")
        result: dict[str, list[BootstrapLabel]] = {}

        labelers = [
            self.label_sod_violations,
            self.label_privilege_escalation,
            self.label_excessive_privilege,
            self.label_dormant_access,
            self.label_orphaned_accounts,
            self.label_permission_creep,
            self.label_open_trust,
            self.label_missing_mfa,
            self.label_cross_system_inconsistency,
            self.label_service_account_misuse,
            self.label_unauthorized_config_change,
            self.label_access_without_justification,
            self.label_toxic_role_combinations,
            self.label_breakglass_abuse,
            self.label_cross_boundary_bypass,
        ]

        for labeler in labelers:
            try:
                labels = labeler()
                for lbl in labels:
                    result.setdefault(lbl.subject_id, []).append(lbl)
            except Exception as exc:
                logger.error(
                    "bootstrap.labeler_failed",
                    labeler=labeler.__name__,
                    error=str(exc),
                )

        total = sum(len(v) for v in result.values())
        violations = sum(1 for v in result.values() for lbl in v if lbl.label == 1)
        logger.info("bootstrap.label_all.done", subjects=len(result), total_labels=total, violations=violations)
        return result

    # ------------------------------------------------------------------
    # 1. SoD Violations (violation_class=1)
    # ------------------------------------------------------------------
    def label_sod_violations(self) -> list[BootstrapLabel]:
        labels: list[BootstrapLabel] = []

        # Use the graph's SoD detection for NetSuite pairs
        sod_violations = self._graph.find_sod_violations(SOD_PAIRS)
        for v in sod_violations:
            for sid in v["subject_ids"]:
                labels.append(BootstrapLabel(
                    subject_id=sid,
                    violation_class=1,
                    label=1,
                    confidence=0.95 if not v["is_cross_boundary"] else 0.85,
                    rule_id="SOD-R1",
                    evidence={
                        "sod_pair": list(v["sod_pair"]),
                        "sources": v["sources"],
                    },
                    source_systems=v["sources"],
                    is_cross_boundary=v["is_cross_boundary"],
                ))

        # Cross-boundary: AWS IAM + NetSuite financial
        correlated = self._graph.correlate_identities()
        for group in correlated:
            subjects = group["subjects"]
            sources = {s.source for s in subjects}
            if "aws_iam" not in sources or "netsuite" not in sources:
                continue

            has_lambda_api = False
            has_netsuite_fin = False
            for subj in subjects:
                perms = self._graph.get_permissions_for_subject(subj.id)
                for p in perms:
                    for action in p.actions:
                        if action.startswith("lambda:") or action.startswith("secretsmanager:"):
                            has_lambda_api = True
                        if action.startswith("netsuite:"):
                            key = action.split(":")[1].split(".")[0]
                            if key in FINANCIAL_PERMISSIONS:
                                has_netsuite_fin = True

            if has_lambda_api and has_netsuite_fin:
                for subj in subjects:
                    labels.append(BootstrapLabel(
                        subject_id=subj.id,
                        violation_class=1,
                        label=1,
                        confidence=0.85,
                        rule_id="SOD-R1-CROSS",
                        evidence={"aws_lambda_access": True, "netsuite_financial": True},
                        source_systems=sorted(sources),
                        is_cross_boundary=True,
                    ))

        return labels

    # ------------------------------------------------------------------
    # 2. Privilege Escalation (violation_class=2)
    # ------------------------------------------------------------------
    def label_privilege_escalation(self) -> list[BootstrapLabel]:
        labels: list[BootstrapLabel] = []

        for subj in self._graph.get_all_subjects():
            paths = self._graph.find_escalation_paths(subj.id)
            for path in paths:
                # NetSuite and Okta escalation paths are SoD violations and
                # misconfigurations respectively — classified by run.py's
                # adapter-detected signal step, not as generic priv esc.
                if path.source in ("netsuite", "okta"):
                    continue
                labels.append(BootstrapLabel(
                    subject_id=subj.id,
                    violation_class=2,
                    label=1,
                    confidence=path.confidence,
                    rule_id="ESC-R1",
                    evidence={
                        "path_id": path.id,
                        "end_result": path.end_result,
                        "steps": len(path.steps),
                    },
                    source_systems=[path.source],
                ))

        return labels

    # ------------------------------------------------------------------
    # 3. Excessive Privilege (violation_class=3)
    # ------------------------------------------------------------------
    def label_excessive_privilege(self) -> list[BootstrapLabel]:
        labels: list[BootstrapLabel] = []

        for subj in self._graph.get_all_subjects():
            if subj.type == SubjectType.GROUP:
                continue
            fv = self._fs.get(subj.id)
            if fv is None:
                continue

            sf = fv.subject
            ratio = sf.permission_to_peer_median_ratio

            if ratio > 3.0:
                labels.append(BootstrapLabel(
                    subject_id=subj.id,
                    violation_class=3,
                    label=1,
                    confidence=0.8,
                    rule_id="EP-R1-HIGH",
                    evidence={"ratio": round(ratio, 2), "total_permissions": sf.total_permissions},
                    source_systems=[subj.source],
                ))
            elif ratio > 2.0:
                labels.append(BootstrapLabel(
                    subject_id=subj.id,
                    violation_class=3,
                    label=1,
                    confidence=0.6,
                    rule_id="EP-R1-MED",
                    evidence={"ratio": round(ratio, 2), "total_permissions": sf.total_permissions},
                    source_systems=[subj.source],
                ))

            # Low usage with many permissions
            if sf.usage_ratio < 0.1 and sf.total_permissions > 10:
                labels.append(BootstrapLabel(
                    subject_id=subj.id,
                    violation_class=3,
                    label=1,
                    confidence=0.7,
                    rule_id="EP-R1-UNUSED",
                    evidence={
                        "usage_ratio": sf.usage_ratio,
                        "total_permissions": sf.total_permissions,
                    },
                    source_systems=[subj.source],
                ))

        return labels

    # ------------------------------------------------------------------
    # 4. Dormant Access (violation_class=4)
    # ------------------------------------------------------------------
    def label_dormant_access(self) -> list[BootstrapLabel]:
        labels: list[BootstrapLabel] = []

        for subj in self._graph.get_all_subjects():
            if subj.type == SubjectType.GROUP:
                continue
            fv = self._fs.get(subj.id)
            if fv is None:
                continue

            sf = fv.subject
            days = sf.days_since_last_activity
            priv = sf.privileged_permissions

            if days > 90 and priv > 0:
                labels.append(BootstrapLabel(
                    subject_id=subj.id,
                    violation_class=4,
                    label=1,
                    confidence=0.9,
                    rule_id="DA-R1-90",
                    evidence={"days_inactive": days, "privileged_permissions": priv},
                    source_systems=[subj.source],
                ))
            elif days > 60 and priv > 0:
                labels.append(BootstrapLabel(
                    subject_id=subj.id,
                    violation_class=4,
                    label=1,
                    confidence=0.7,
                    rule_id="DA-R1-60",
                    evidence={"days_inactive": days, "privileged_permissions": priv},
                    source_systems=[subj.source],
                ))

        return labels

    # ------------------------------------------------------------------
    # 5. Orphaned Accounts (violation_class=5)
    # ------------------------------------------------------------------
    def label_orphaned_accounts(self) -> list[BootstrapLabel]:
        labels: list[BootstrapLabel] = []

        # Cross-system: deleted in one source but active in another
        correlated = self._graph.correlate_identities()
        for group in correlated:
            subjects = group["subjects"]
            statuses = {s.source: s.status for s in subjects}
            sources_list = sorted(statuses.keys())

            deleted_sources = [src for src, st in statuses.items() if st == SubjectStatus.DELETED]
            active_sources = [src for src, st in statuses.items() if st == SubjectStatus.ACTIVE]

            if deleted_sources and active_sources:
                for subj in subjects:
                    labels.append(BootstrapLabel(
                        subject_id=subj.id,
                        violation_class=5,
                        label=1,
                        confidence=0.95,
                        rule_id="OA-R1-CROSS",
                        evidence={
                            "deleted_in": deleted_sources,
                            "active_in": active_sources,
                        },
                        source_systems=sources_list,
                        is_cross_boundary=True,
                    ))

        # Single-system: inactive with active assignments
        for subj in self._graph.get_all_subjects():
            if subj.status == SubjectStatus.INACTIVE:
                assigns = self._graph.get_assignments_for_subject(subj.id)
                active_assigns = [a for a in assigns if a.is_active]
                if active_assigns:
                    labels.append(BootstrapLabel(
                        subject_id=subj.id,
                        violation_class=5,
                        label=1,
                        confidence=0.85,
                        rule_id="OA-R1-INACTIVE",
                        evidence={"active_assignments": len(active_assigns)},
                        source_systems=[subj.source],
                    ))

        return labels

    # ------------------------------------------------------------------
    # 6. Permission Creep (violation_class=6)
    # ------------------------------------------------------------------
    def label_permission_creep(self) -> list[BootstrapLabel]:
        labels: list[BootstrapLabel] = []

        for subj in self._graph.get_all_subjects():
            if subj.type == SubjectType.GROUP:
                continue
            fv = self._fs.get(subj.id)
            if fv is None:
                continue

            sf = fv.subject

            if sf.permissions_added_90d > 5 and sf.permissions_removed_90d == 0:
                labels.append(BootstrapLabel(
                    subject_id=subj.id,
                    violation_class=6,
                    label=1,
                    confidence=0.7,
                    rule_id="PC-R1-GROW",
                    evidence={
                        "added_90d": sf.permissions_added_90d,
                        "removed_90d": sf.permissions_removed_90d,
                    },
                    source_systems=[subj.source],
                ))

            if sf.net_drift_rate > 0.2:
                labels.append(BootstrapLabel(
                    subject_id=subj.id,
                    violation_class=6,
                    label=1,
                    confidence=0.8,
                    rule_id="PC-R1-DRIFT",
                    evidence={"net_drift_rate": round(sf.net_drift_rate, 3)},
                    source_systems=[subj.source],
                ))

        return labels

    # ------------------------------------------------------------------
    # 7. Open Trust / Overpermissive Delegation (violation_class=7)
    # ------------------------------------------------------------------
    def label_open_trust(self) -> list[BootstrapLabel]:
        labels: list[BootstrapLabel] = []

        for perm in self._graph.get_all_permissions():
            if perm.source != "aws_iam":
                continue

            attrs = perm.attributes

            # Check subjects that hold roles with open trust policies
            if perm.type.value == "role":
                continue  # We check via subject attributes

        # Check subjects (roles) with trust policy metadata
        for subj in self._graph.get_all_subjects():
            if subj.source != "aws_iam":
                continue

            attrs = subj.attributes

            if attrs.get("trust_policy_open"):
                labels.append(BootstrapLabel(
                    subject_id=subj.id,
                    violation_class=7,
                    label=1,
                    confidence=0.95,
                    rule_id="OT-R1-OPEN",
                    evidence={"trust_policy_open": True, "principal": "*"},
                    source_systems=["aws_iam"],
                ))

            if attrs.get("cross_account_trust") and attrs.get("cross_account_no_conditions"):
                labels.append(BootstrapLabel(
                    subject_id=subj.id,
                    violation_class=7,
                    label=1,
                    confidence=0.8,
                    rule_id="OT-R1-XACCT",
                    evidence={
                        "cross_account_trust": True,
                        "no_conditions": True,
                        "external_accounts": attrs.get("cross_account_ids", []),
                    },
                    source_systems=["aws_iam"],
                ))

        return labels

    # ------------------------------------------------------------------
    # 8. Missing MFA (violation_class=8)
    # ------------------------------------------------------------------
    def label_missing_mfa(self) -> list[BootstrapLabel]:
        labels: list[BootstrapLabel] = []

        for subj in self._graph.get_all_subjects():
            if subj.type != SubjectType.HUMAN:
                continue
            if subj.mfa_enabled is not False:
                continue  # skip None (unknown) and True

            fv = self._fs.get(subj.id)
            priv = fv.subject.privileged_permissions if fv else 0

            if priv > 0:
                labels.append(BootstrapLabel(
                    subject_id=subj.id,
                    violation_class=8,
                    label=1,
                    confidence=0.95,
                    rule_id="MFA-R1-PRIV",
                    evidence={
                        "mfa_enabled": False,
                        "privileged_permissions": priv,
                    },
                    source_systems=[subj.source],
                ))
            elif subj.status == SubjectStatus.ACTIVE:
                labels.append(BootstrapLabel(
                    subject_id=subj.id,
                    violation_class=8,
                    label=1,
                    confidence=0.7,
                    rule_id="MFA-R1-ACTIVE",
                    evidence={"mfa_enabled": False},
                    source_systems=[subj.source],
                ))

        return labels

    # ------------------------------------------------------------------
    # 9. Cross-System Inconsistency (violation_class=9)
    # ------------------------------------------------------------------
    def label_cross_system_inconsistency(self) -> list[BootstrapLabel]:
        labels: list[BootstrapLabel] = []

        correlated = self._graph.correlate_identities()
        for group in correlated:
            subjects = group["subjects"]
            if len(subjects) < 2:
                continue

            statuses = {s.source: s.status.value for s in subjects}
            departments = {s.source: s.department for s in subjects if s.department}
            names = {s.source: s.display_name.lower().strip() for s in subjects}

            # Status differs
            if len(set(statuses.values())) > 1:
                for subj in subjects:
                    labels.append(BootstrapLabel(
                        subject_id=subj.id,
                        violation_class=9,
                        label=1,
                        confidence=0.9,
                        rule_id="CSI-R1-STATUS",
                        evidence={"status_by_source": statuses},
                        source_systems=sorted(statuses.keys()),
                        is_cross_boundary=True,
                    ))

            # Department differs
            if len(departments) > 1 and len(set(departments.values())) > 1:
                for subj in subjects:
                    labels.append(BootstrapLabel(
                        subject_id=subj.id,
                        violation_class=9,
                        label=1,
                        confidence=0.5,
                        rule_id="CSI-R1-DEPT",
                        evidence={"department_by_source": departments},
                        source_systems=sorted(departments.keys()),
                        is_cross_boundary=True,
                    ))

            # Name inconsistency
            if len(names) > 1 and len(set(names.values())) > 1:
                for subj in subjects:
                    labels.append(BootstrapLabel(
                        subject_id=subj.id,
                        violation_class=9,
                        label=1,
                        confidence=0.3,
                        rule_id="CSI-R1-NAME",
                        evidence={"name_by_source": {k: v for k, v in names.items()}},
                        source_systems=sorted(names.keys()),
                        is_cross_boundary=True,
                    ))

        return labels

    # ------------------------------------------------------------------
    # 10. Service Account Misuse (violation_class=10)
    # ------------------------------------------------------------------
    def label_service_account_misuse(self) -> list[BootstrapLabel]:
        labels: list[BootstrapLabel] = []

        for subj in self._graph.get_all_subjects():
            if subj.type != SubjectType.SERVICE_ACCOUNT:
                continue

            fv = self._fs.get(subj.id)
            if fv is None:
                continue

            sf = fv.subject

            if sf.source_system_count > 2:
                labels.append(BootstrapLabel(
                    subject_id=subj.id,
                    violation_class=10,
                    label=1,
                    confidence=0.6,
                    rule_id="SA-R1-MULTI",
                    evidence={"source_system_count": sf.source_system_count},
                    source_systems=[subj.source],
                ))

            if sf.distinct_source_ips_30d > 10:
                labels.append(BootstrapLabel(
                    subject_id=subj.id,
                    violation_class=10,
                    label=1,
                    confidence=0.7,
                    rule_id="SA-R1-IPS",
                    evidence={"distinct_ips": sf.distinct_source_ips_30d},
                    source_systems=[subj.source],
                ))

            if sf.login_time_entropy > 3.0:  # high entropy threshold
                labels.append(BootstrapLabel(
                    subject_id=subj.id,
                    violation_class=10,
                    label=1,
                    confidence=0.6,
                    rule_id="SA-R1-ENTROPY",
                    evidence={"login_time_entropy": round(sf.login_time_entropy, 3)},
                    source_systems=[subj.source],
                ))

        return labels

    # ------------------------------------------------------------------
    # 11. Unauthorized Config Change (violation_class=11)
    # ------------------------------------------------------------------
    def label_unauthorized_config_change(self) -> list[BootstrapLabel]:
        labels: list[BootstrapLabel] = []

        config_actions = {
            "iam:UpdateAssumeRolePolicy",
            "iam:PutRolePolicy",
            "iam:PutUserPolicy",
            "iam:AttachRolePolicy",
            "iam:AttachUserPolicy",
            "iam:CreatePolicyVersion",
        }
        netsuite_config_keys = {"ADMI_SETUP", "ADMI_ACCTPERIODS"}

        for subj in self._graph.get_all_subjects():
            if subj.type == SubjectType.GROUP:
                continue

            perms = self._graph.get_permissions_for_subject(subj.id)
            all_actions: set[str] = set()
            for p in perms:
                all_actions.update(p.actions)
                # Check NetSuite permission keys
                for pk in p.attributes.get("permission_keys", []):
                    if pk in netsuite_config_keys:
                        all_actions.add(f"netsuite:{pk}")

            has_config_action = bool(all_actions & config_actions)
            has_ns_config = any(a.startswith("netsuite:ADMI_") for a in all_actions)

            if not has_config_action and not has_ns_config:
                continue

            # Check if subject is in an approved admin group
            is_admin = self._is_in_admin_group(subj.id)

            if not is_admin:
                labels.append(BootstrapLabel(
                    subject_id=subj.id,
                    violation_class=11,
                    label=1,
                    confidence=0.7,
                    rule_id="UCC-R1",
                    evidence={
                        "config_actions": sorted(all_actions & (config_actions | {a for a in all_actions if "ADMI_" in a})),
                        "is_admin_group_member": False,
                    },
                    source_systems=[subj.source],
                ))

        return labels

    # ------------------------------------------------------------------
    # 12. Access Without Business Justification (violation_class=12)
    # ------------------------------------------------------------------
    def label_access_without_justification(self) -> list[BootstrapLabel]:
        labels: list[BootstrapLabel] = []

        for subj in self._graph.get_all_subjects():
            if subj.type == SubjectType.GROUP:
                continue
            # Justification tracking applies to AWS IAM — NetSuite and Okta
            # have their own access governance models (SoD, admin roles).
            if subj.source in ("netsuite", "okta"):
                continue

            assigns = self._graph.get_assignments_for_subject(subj.id)
            for assign in assigns:
                perm = self._graph.get_permission(assign.permission_id)
                if perm is None:
                    continue

                has_justification = bool(
                    getattr(assign, "attributes", {}).get("justification")
                    if hasattr(assign, "attributes")
                    else False
                )

                if not has_justification and perm.is_privileged:
                    labels.append(BootstrapLabel(
                        subject_id=subj.id,
                        violation_class=12,
                        label=1,
                        confidence=0.6,
                        rule_id="ABJ-R1-PRIV",
                        evidence={
                            "permission": perm.name,
                            "is_privileged": True,
                            "has_justification": False,
                        },
                        source_systems=[subj.source],
                    ))

                if assign.granted_by is None or assign.granted_by == "unknown":
                    labels.append(BootstrapLabel(
                        subject_id=subj.id,
                        violation_class=12,
                        label=1,
                        confidence=0.5,
                        rule_id="ABJ-R1-UNKNOWN",
                        evidence={
                            "permission": perm.name,
                            "granted_by": assign.granted_by,
                        },
                        source_systems=[subj.source],
                    ))

        return labels

    # ------------------------------------------------------------------
    # 13. Toxic Role Combinations (violation_class=13)
    # ------------------------------------------------------------------
    def label_toxic_role_combinations(self) -> list[BootstrapLabel]:
        labels: list[BootstrapLabel] = []

        for subj in self._graph.get_all_subjects():
            if subj.type == SubjectType.GROUP:
                continue

            perms = self._graph.get_permissions_for_subject(subj.id)
            privileged_roles = [p for p in perms if p.is_privileged]

            if len(privileged_roles) > 3:
                # Check if they span different categories
                categories: set[str] = set()
                for pr in privileged_roles:
                    name_lower = pr.name.lower()
                    all_actions_lower = " ".join(pr.actions).lower()
                    combined = name_lower + " " + all_actions_lower

                    if any(k in combined for k in SECURITY_ADMIN_KEYWORDS):
                        categories.add("security")
                    if any(k in combined for k in FINANCIAL_ADMIN_KEYWORDS):
                        categories.add("financial")
                    if any(k in combined for k in ("user", "directory", "group")):
                        categories.add("identity")
                    if any(k in combined for k in ("infra", "ec2", "compute", "network")):
                        categories.add("infrastructure")

                if len(categories) >= 2:
                    labels.append(BootstrapLabel(
                        subject_id=subj.id,
                        violation_class=13,
                        label=1,
                        confidence=0.8,
                        rule_id="TRC-R1-MULTI",
                        evidence={
                            "privileged_role_count": len(privileged_roles),
                            "categories": sorted(categories),
                            "roles": [p.name for p in privileged_roles],
                        },
                        source_systems=[subj.source],
                    ))

            # Security-admin + financial-admin combo
            has_sec = False
            has_fin = False
            for pr in privileged_roles:
                combined = (pr.name + " " + " ".join(pr.actions)).lower()
                if any(k in combined for k in SECURITY_ADMIN_KEYWORDS):
                    has_sec = True
                if any(k in combined for k in FINANCIAL_ADMIN_KEYWORDS):
                    has_fin = True

            if has_sec and has_fin:
                labels.append(BootstrapLabel(
                    subject_id=subj.id,
                    violation_class=13,
                    label=1,
                    confidence=0.9,
                    rule_id="TRC-R1-SECFIN",
                    evidence={
                        "has_security_admin": True,
                        "has_financial_admin": True,
                    },
                    source_systems=[subj.source],
                ))

        return labels

    # ------------------------------------------------------------------
    # 14. Break-Glass Abuse (violation_class=14)
    # ------------------------------------------------------------------
    def label_breakglass_abuse(self) -> list[BootstrapLabel]:
        labels: list[BootstrapLabel] = []
        now = datetime.now(timezone.utc)

        for subj in self._graph.get_all_subjects():
            if subj.type == SubjectType.GROUP:
                continue

            assigns = self._graph.get_assignments_for_subject(subj.id)
            for assign in assigns:
                perm = self._graph.get_permission(assign.permission_id)
                if perm is None:
                    continue

                # Detect break-glass role by name/tags
                is_breakglass = bool(BREAKGLASS_PATTERNS.search(perm.name))
                if not is_breakglass:
                    tags = perm.attributes.get("tags", [])
                    if isinstance(tags, list):
                        is_breakglass = any(BREAKGLASS_PATTERNS.search(str(t)) for t in tags)

                if not is_breakglass:
                    continue

                # Break-glass held longer than 1 day
                age_days = 0
                if assign.granted_at:
                    age_days = (now - assign.granted_at).days

                if age_days > 1:
                    labels.append(BootstrapLabel(
                        subject_id=subj.id,
                        violation_class=14,
                        label=1,
                        confidence=0.9,
                        rule_id="BGA-R1",
                        evidence={
                            "role": perm.name,
                            "assignment_age_days": age_days,
                            "expected_max_hours": 24,
                        },
                        source_systems=[subj.source],
                    ))

        return labels

    # ------------------------------------------------------------------
    # 15. Cross-Boundary Financial Bypass (violation_class=15)
    # ------------------------------------------------------------------
    def label_cross_boundary_bypass(self) -> list[BootstrapLabel]:
        labels: list[BootstrapLabel] = []

        correlated = self._graph.correlate_identities()
        for group in correlated:
            subjects = group["subjects"]
            sources = {s.source for s in subjects}

            # Pattern 1: AWS (Lambda/API/Secrets) + NetSuite financial
            if "aws_iam" in sources and "netsuite" in sources:
                aws_subjects = [s for s in subjects if s.source == "aws_iam"]
                ns_subjects = [s for s in subjects if s.source == "netsuite"]

                has_aws_api = False
                has_escalation = False
                for subj in aws_subjects:
                    perms = self._graph.get_permissions_for_subject(subj.id)
                    for p in perms:
                        for action in p.actions:
                            if any(svc in action for svc in ("lambda:", "secretsmanager:", "sts:")):
                                has_aws_api = True
                    if self._graph.find_escalation_paths(subj.id):
                        has_escalation = True

                has_ns_fin = False
                ns_fin_keys: list[str] = []
                for subj in ns_subjects:
                    perms = self._graph.get_permissions_for_subject(subj.id)
                    for p in perms:
                        for pk in p.attributes.get("permission_keys", []):
                            if pk in FINANCIAL_PERMISSIONS:
                                has_ns_fin = True
                                ns_fin_keys.append(pk)

                if has_aws_api and has_ns_fin:
                    conf = 0.9 if has_escalation else 0.8
                    for subj in subjects:
                        labels.append(BootstrapLabel(
                            subject_id=subj.id,
                            violation_class=15,
                            label=1,
                            confidence=conf,
                            rule_id="CBFB-R1-AWS-NS",
                            evidence={
                                "aws_api_access": has_aws_api,
                                "aws_escalation": has_escalation,
                                "netsuite_financial_keys": ns_fin_keys[:10],
                            },
                            source_systems=sorted(sources),
                            is_cross_boundary=True,
                        ))

            # Pattern 2: Snowflake ACCOUNTADMIN + NetSuite REPT_FINANCIALS
            # (Snowflake adapter not yet built, but we check attributes)
            for subj in subjects:
                perms = self._graph.get_permissions_for_subject(subj.id)
                has_snowflake_admin = False
                has_ns_reports = False

                for p in perms:
                    name_lower = p.name.lower()
                    if "accountadmin" in name_lower and p.source in ("snowflake", "aws_iam"):
                        has_snowflake_admin = True
                    if "REPT_FINANCIALS" in p.attributes.get("permission_keys", []):
                        has_ns_reports = True
                    for action in p.actions:
                        if "REPT_FINANCIALS" in action:
                            has_ns_reports = True

                if has_snowflake_admin and has_ns_reports:
                    labels.append(BootstrapLabel(
                        subject_id=subj.id,
                        violation_class=15,
                        label=1,
                        confidence=0.85,
                        rule_id="CBFB-R1-SF-NS",
                        evidence={
                            "snowflake_accountadmin": True,
                            "netsuite_financial_reports": True,
                        },
                        source_systems=sorted(sources),
                        is_cross_boundary=True,
                    ))

        return labels

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _is_in_admin_group(self, subject_id: str) -> bool:
        """Check if a subject is a member of any admin-type group."""
        perms = self._graph.get_permissions_for_subject(subject_id)
        for p in perms:
            if p.type.value == "group":
                name_lower = p.name.lower()
                if any(kw in name_lower for kw in ("admin", "super", "owner", "root", "devops", "sre", "platform")):
                    return True
        return False
