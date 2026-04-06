"""
Vektor AI — Policy Suggestion Generator

Analyzes a customer's identity graph and feature store to automatically
surface suggested Tier 2 policies. These suggestions reflect observed
patterns and known-good security practices tailored to the customer's
environment.

Suggestion categories:
1. Pattern-based: Detected patterns in the customer's data that warrant monitoring
2. Best-practice: Industry-standard policies the customer hasn't enabled
3. Peer-derived: Policies approved by similar customers (cross-customer learning)
4. Drift-based: Changes detected between scans that suggest new policy needs
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

import structlog

from .engine import (
    Policy,
    PolicyAction,
    PolicyCategory,
    PolicyCondition,
    PolicyRule,
    PolicyScope,
    PolicyStatus,
)

logger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Suggestion models
# ---------------------------------------------------------------------------

class SuggestionReason(str, Enum):
    """Why Vektor is suggesting this policy."""
    PATTERN_DETECTED = "pattern_detected"
    BEST_PRACTICE = "best_practice"
    PEER_APPROVED = "peer_approved"
    DRIFT_DETECTED = "drift_detected"
    COMPLIANCE_GAP = "compliance_gap"


@dataclass
class Suggestion:
    """A policy suggestion with context for why it's being recommended."""
    policy: Policy
    reason: SuggestionReason
    evidence: dict[str, Any] = field(default_factory=dict)
    affected_subjects: list[str] = field(default_factory=list)
    estimated_impact: str = ""  # e.g., "Would flag 12 subjects"
    priority: float = 0.5      # 0.0–1.0, used for ranking suggestions
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


# ---------------------------------------------------------------------------
# Built-in best-practice policy templates
# ---------------------------------------------------------------------------

_BEST_PRACTICE_TEMPLATES: list[dict[str, Any]] = [
    {
        "name": "Dormant privileged access — 90 day threshold",
        "description": (
            "Flag human identities with privileged permissions that haven't been "
            "used in over 90 days. Dormant privileged access is a top attack vector."
        ),
        "category": PolicyCategory.ZERO_TRUST,
        "rules": [
            PolicyRule(
                conditions=[
                    PolicyCondition(feature_name="days_since_last_activity", operator="gt", threshold=90),
                    PolicyCondition(feature_name="privileged_permissions", operator="gt", threshold=0),
                    PolicyCondition(feature_name="type", operator="eq", threshold="human"),
                ],
            ),
        ],
        "action": PolicyAction.FLAG_FOR_REVIEW,
        "severity": "high",
        "base_confidence": 0.85,
    },
    {
        "name": "Missing MFA on privileged human accounts",
        "description": (
            "Detect human accounts with privileged access but no MFA enrolled. "
            "MFA is a foundational control for all privileged access per NIST IA-2."
        ),
        "category": PolicyCategory.ZERO_TRUST,
        "rules": [
            PolicyRule(
                conditions=[
                    PolicyCondition(feature_name="mfa_usage_rate", operator="lt", threshold=0.01),
                    PolicyCondition(feature_name="privileged_permissions", operator="gt", threshold=0),
                    PolicyCondition(feature_name="type", operator="eq", threshold="human"),
                ],
            ),
        ],
        "action": PolicyAction.REQUIRE_MFA,
        "severity": "critical",
        "base_confidence": 0.95,
    },
    {
        "name": "Excessive privilege — 3x peer median",
        "description": (
            "Flag identities whose permission count exceeds 3x the median of their "
            "peer group. Indicates over-provisioned access that violates least privilege."
        ),
        "category": PolicyCategory.ZERO_TRUST,
        "rules": [
            PolicyRule(
                conditions=[
                    PolicyCondition(feature_name="permission_to_peer_median_ratio", operator="gt", threshold=3.0),
                    PolicyCondition(feature_name="total_permissions", operator="gt", threshold=5),
                ],
            ),
        ],
        "action": PolicyAction.FLAG_FOR_REVIEW,
        "severity": "high",
        "base_confidence": 0.75,
    },
    {
        "name": "Service account with high IP diversity",
        "description": (
            "Service accounts should connect from a predictable set of IPs. "
            "High source IP diversity may indicate credential compromise or misuse."
        ),
        "category": PolicyCategory.ANOMALY,
        "rules": [
            PolicyRule(
                conditions=[
                    PolicyCondition(feature_name="type", operator="eq", threshold="service_account"),
                    PolicyCondition(feature_name="distinct_source_ips_30d", operator="gt", threshold=10),
                ],
            ),
        ],
        "action": PolicyAction.ALERT,
        "severity": "medium",
        "base_confidence": 0.65,
    },
    {
        "name": "AI agent permission growth",
        "description": (
            "Detect AI agents whose permissions are growing over time without "
            "corresponding access reviews. Agent scope drift is a governance risk."
        ),
        "category": PolicyCategory.AGENT_GOVERNANCE,
        "rules": [
            PolicyRule(
                conditions=[
                    PolicyCondition(feature_name="type", operator="eq", threshold="ai_agent"),
                    PolicyCondition(feature_name="permissions_added_30d", operator="gt", threshold=3),
                    PolicyCondition(feature_name="permissions_removed_30d", operator="eq", threshold=0),
                ],
            ),
        ],
        "action": PolicyAction.FLAG_FOR_REVIEW,
        "severity": "high",
        "base_confidence": 0.80,
    },
    {
        "name": "Cross-boundary financial access",
        "description": (
            "Flag identities that have both cloud IAM privileged access and "
            "ERP financial permissions. This cross-boundary access is the #1 "
            "vector for IAM-to-financial control bypass."
        ),
        "category": PolicyCategory.CROSS_BOUNDARY,
        "rules": [
            PolicyRule(
                conditions=[
                    PolicyCondition(feature_name="source_system_count", operator="gte", threshold=2),
                    PolicyCondition(feature_name="privileged_permissions", operator="gt", threshold=0),
                    PolicyCondition(feature_name="sod_pair_membership_count", operator="gt", threshold=0),
                ],
            ),
        ],
        "action": PolicyAction.ESCALATE,
        "severity": "critical",
        "base_confidence": 0.85,
    },
    {
        "name": "Open trust policy — Principal:*",
        "description": (
            "Detect IAM roles with trust policies that allow any AWS principal "
            "to assume them. This is a critical misconfiguration per CIS Benchmark."
        ),
        "category": PolicyCategory.ZERO_TRUST,
        "rules": [
            PolicyRule(
                conditions=[
                    PolicyCondition(feature_name="type", operator="in", threshold=["service_account", "ai_agent"]),
                    PolicyCondition(feature_name="trust_policy_open", operator="eq", threshold=True),
                ],
            ),
        ],
        "action": PolicyAction.ALERT,
        "severity": "critical",
        "base_confidence": 0.95,
    },
    {
        "name": "Access granted without justification — privileged",
        "description": (
            "Flag privileged assignments that lack a documented business "
            "justification. Required for SOX ITGC compliance."
        ),
        "category": PolicyCategory.SOX_COMPLIANCE,
        "rules": [
            PolicyRule(
                conditions=[
                    PolicyCondition(feature_name="has_business_justification", operator="eq", threshold=False),
                    PolicyCondition(feature_name="privileged_permissions", operator="gt", threshold=0),
                ],
            ),
        ],
        "action": PolicyAction.REQUEST_JUSTIFICATION,
        "severity": "medium",
        "base_confidence": 0.60,
    },
    {
        "name": "High graph centrality identity",
        "description": (
            "Identities with very high betweenness centrality sit at critical "
            "chokepoints in the identity graph. Compromise of these identities "
            "has outsized blast radius."
        ),
        "category": PolicyCategory.ANOMALY,
        "rules": [
            PolicyRule(
                conditions=[
                    PolicyCondition(feature_name="betweenness_centrality", operator="gt", threshold=0.15),
                    PolicyCondition(feature_name="type", operator="eq", threshold="human"),
                ],
            ),
        ],
        "action": PolicyAction.FLAG_FOR_REVIEW,
        "severity": "high",
        "base_confidence": 0.70,
    },
    {
        "name": "Orphaned cross-system identity",
        "description": (
            "Detect identities disabled or deleted in one system but still active "
            "in another. Common after employee offboarding that misses a system."
        ),
        "category": PolicyCategory.ZERO_TRUST,
        "rules": [
            PolicyRule(
                conditions=[
                    PolicyCondition(feature_name="cross_system_consistency_score", operator="lt", threshold=0.5),
                    PolicyCondition(feature_name="source_system_count", operator="gte", threshold=2),
                ],
            ),
        ],
        "action": PolicyAction.ALERT,
        "severity": "high",
        "base_confidence": 0.85,
    },
]


# ---------------------------------------------------------------------------
# Suggestion Generator
# ---------------------------------------------------------------------------

class PolicySuggestionGenerator:
    """
    Generates policy suggestions for a customer by analyzing their
    identity graph and feature store data.

    Suggestion sources:
    1. Best practices — pre-built templates that apply to most environments
    2. Pattern detection — data-driven anomalies in the customer's graph
    3. Peer suggestions — policies approved by similar customers
    4. Drift detection — changes between consecutive scans
    """

    def __init__(self) -> None:
        self._generated_suggestions: dict[str, list[Suggestion]] = {}

    def generate_suggestions(
        self,
        customer_id: str,
        feature_data: dict[str, dict[str, Any]],
        existing_policies: list[Policy],
        graph_stats: dict[str, Any] | None = None,
    ) -> list[Suggestion]:
        """
        Generate all policy suggestions for a customer.

        Args:
            customer_id: Customer identifier.
            feature_data: { subject_id: { feature_name: value } } from FeatureStore.
            existing_policies: Already registered policies (to avoid duplicates).
            graph_stats: Summary stats from IdentityGraph (node/edge counts, etc.).

        Returns:
            Ranked list of Suggestion objects.
        """
        existing_names = {p.name for p in existing_policies}
        suggestions: list[Suggestion] = []

        # 1. Best-practice suggestions
        bp_suggestions = self._generate_best_practice_suggestions(
            customer_id, feature_data, existing_names,
        )
        suggestions.extend(bp_suggestions)

        # 2. Pattern-based suggestions
        pattern_suggestions = self._generate_pattern_suggestions(
            customer_id, feature_data, existing_names,
        )
        suggestions.extend(pattern_suggestions)

        # 3. Compliance gap suggestions
        compliance_suggestions = self._generate_compliance_suggestions(
            customer_id, feature_data, existing_names, graph_stats,
        )
        suggestions.extend(compliance_suggestions)

        # Rank by priority
        suggestions.sort(key=lambda s: s.priority, reverse=True)

        self._generated_suggestions[customer_id] = suggestions

        logger.info(
            "suggestions_generated",
            customer_id=customer_id,
            total_suggestions=len(suggestions),
            best_practice=len(bp_suggestions),
            pattern_based=len(pattern_suggestions),
            compliance=len(compliance_suggestions),
        )

        return suggestions

    def _generate_best_practice_suggestions(
        self,
        customer_id: str,
        feature_data: dict[str, dict[str, Any]],
        existing_names: set[str],
    ) -> list[Suggestion]:
        """Generate suggestions from built-in best-practice templates."""
        suggestions: list[Suggestion] = []

        for template in _BEST_PRACTICE_TEMPLATES:
            if template["name"] in existing_names:
                continue

            # Check if this template would actually fire on any subjects
            affected: list[str] = []
            for subject_id, features in feature_data.items():
                for rule in template["rules"]:
                    if rule.evaluate(features):
                        affected.append(subject_id)
                        break

            # Only suggest if it would affect at least one subject
            if not affected:
                continue

            policy = Policy(
                id=str(uuid.uuid4()),
                customer_id=customer_id,
                name=template["name"],
                description=template["description"],
                category=template["category"],
                status=PolicyStatus.SUGGESTED,
                rules=template["rules"],
                action=template["action"],
                severity=template["severity"],
                base_confidence=template["base_confidence"],
            )

            # Priority scales with number of affected subjects
            priority = min(1.0, 0.3 + (len(affected) / max(len(feature_data), 1)) * 0.7)
            if template["severity"] == "critical":
                priority = min(1.0, priority + 0.2)

            suggestion = Suggestion(
                policy=policy,
                reason=SuggestionReason.BEST_PRACTICE,
                evidence={
                    "template_name": template["name"],
                    "affected_count": len(affected),
                    "total_subjects": len(feature_data),
                    "sample_affected": affected[:5],
                },
                affected_subjects=affected,
                estimated_impact=f"Would flag {len(affected)} identities",
                priority=priority,
            )
            suggestions.append(suggestion)

        return suggestions

    def _generate_pattern_suggestions(
        self,
        customer_id: str,
        feature_data: dict[str, dict[str, Any]],
        existing_names: set[str],
    ) -> list[Suggestion]:
        """
        Detect patterns in customer data that warrant new policies.
        These are data-driven — not from templates.
        """
        suggestions: list[Suggestion] = []

        if not feature_data:
            return suggestions

        # --- Pattern 1: Cluster of high-permission subjects in one department ---
        dept_perm_counts: dict[str, list[float]] = {}
        for sid, feats in feature_data.items():
            dept = feats.get("department", "unknown")
            perms = feats.get("total_permissions", 0)
            dept_perm_counts.setdefault(dept, []).append(perms)

        for dept, counts in dept_perm_counts.items():
            if dept == "unknown" or len(counts) < 3:
                continue
            import statistics
            avg = statistics.mean(counts)
            if avg > 15:  # department with unusually high average permissions
                policy_name = f"High average permissions in {dept}"
                if policy_name in existing_names:
                    continue

                affected = [
                    sid for sid, f in feature_data.items()
                    if f.get("department") == dept and f.get("total_permissions", 0) > avg
                ]
                if not affected:
                    continue

                policy = Policy(
                    id=str(uuid.uuid4()),
                    customer_id=customer_id,
                    name=policy_name,
                    description=(
                        f"The {dept} department has an unusually high average permission "
                        f"count ({avg:.0f}). Monitor identities in this department for "
                        f"over-provisioning."
                    ),
                    category=PolicyCategory.ZERO_TRUST,
                    status=PolicyStatus.SUGGESTED,
                    rules=[
                        PolicyRule(
                            conditions=[
                                PolicyCondition(
                                    feature_name="department",
                                    operator="eq",
                                    threshold=dept,
                                ),
                                PolicyCondition(
                                    feature_name="total_permissions",
                                    operator="gt",
                                    threshold=int(avg * 1.5),
                                ),
                            ],
                        ),
                    ],
                    action=PolicyAction.FLAG_FOR_REVIEW,
                    severity="medium",
                    base_confidence=0.65,
                )
                suggestions.append(Suggestion(
                    policy=policy,
                    reason=SuggestionReason.PATTERN_DETECTED,
                    evidence={"department": dept, "avg_permissions": avg, "count": len(counts)},
                    affected_subjects=affected,
                    estimated_impact=f"Would flag {len(affected)} identities in {dept}",
                    priority=0.5,
                ))

        # --- Pattern 2: Many subjects with zero usage ratio ---
        zero_usage = [
            sid for sid, f in feature_data.items()
            if f.get("usage_ratio", 1.0) < 0.05
            and f.get("total_permissions", 0) > 3
            and f.get("type") == "human"
        ]
        zero_usage_name = "Low usage ratio — under 5% utilization"
        if zero_usage and zero_usage_name not in existing_names:
            ratio = len(zero_usage) / max(len(feature_data), 1)
            if ratio > 0.1:  # More than 10% of subjects
                policy = Policy(
                    id=str(uuid.uuid4()),
                    customer_id=customer_id,
                    name=zero_usage_name,
                    description=(
                        f"{len(zero_usage)} human identities ({ratio:.0%} of total) "
                        f"are using less than 5% of their granted permissions. "
                        f"This indicates systemic over-provisioning."
                    ),
                    category=PolicyCategory.ZERO_TRUST,
                    status=PolicyStatus.SUGGESTED,
                    rules=[
                        PolicyRule(
                            conditions=[
                                PolicyCondition(feature_name="usage_ratio", operator="lt", threshold=0.05),
                                PolicyCondition(feature_name="total_permissions", operator="gt", threshold=3),
                                PolicyCondition(feature_name="type", operator="eq", threshold="human"),
                            ],
                        ),
                    ],
                    action=PolicyAction.FLAG_FOR_REVIEW,
                    severity="medium",
                    base_confidence=0.70,
                )
                suggestions.append(Suggestion(
                    policy=policy,
                    reason=SuggestionReason.PATTERN_DETECTED,
                    evidence={"zero_usage_count": len(zero_usage), "ratio": ratio},
                    affected_subjects=zero_usage,
                    estimated_impact=f"Would flag {len(zero_usage)} under-utilizing identities",
                    priority=0.6,
                ))

        # --- Pattern 3: Multi-system AI agents ---
        multi_system_agents = [
            sid for sid, f in feature_data.items()
            if f.get("type") == "ai_agent" and f.get("source_system_count", 1) >= 2
        ]
        agent_name = "AI agents spanning multiple systems"
        if multi_system_agents and agent_name not in existing_names:
            policy = Policy(
                id=str(uuid.uuid4()),
                customer_id=customer_id,
                name=agent_name,
                description=(
                    f"{len(multi_system_agents)} AI agents have access across 2+ identity "
                    f"systems. Cross-system agent access requires governance to prevent "
                    f"scope drift and SoD violations."
                ),
                category=PolicyCategory.AGENT_GOVERNANCE,
                status=PolicyStatus.SUGGESTED,
                rules=[
                    PolicyRule(
                        conditions=[
                            PolicyCondition(feature_name="type", operator="eq", threshold="ai_agent"),
                            PolicyCondition(feature_name="source_system_count", operator="gte", threshold=2),
                        ],
                    ),
                ],
                action=PolicyAction.FLAG_FOR_REVIEW,
                severity="high",
                base_confidence=0.80,
            )
            suggestions.append(Suggestion(
                policy=policy,
                reason=SuggestionReason.PATTERN_DETECTED,
                evidence={"agent_count": len(multi_system_agents)},
                affected_subjects=multi_system_agents,
                estimated_impact=f"Would monitor {len(multi_system_agents)} cross-system agents",
                priority=0.75,
            ))

        return suggestions

    def _generate_compliance_suggestions(
        self,
        customer_id: str,
        feature_data: dict[str, dict[str, Any]],
        existing_names: set[str],
        graph_stats: dict[str, Any] | None = None,
    ) -> list[Suggestion]:
        """
        Identify compliance gaps based on the customer's environment.
        If they have ERP data, suggest SOX-relevant policies.
        If they have cloud IAM, suggest Zero Trust policies.
        """
        suggestions: list[Suggestion] = []

        if not feature_data:
            return suggestions

        # Detect which source systems are present
        sources = set()
        for feats in feature_data.values():
            src = feats.get("source", "")
            if isinstance(src, list):
                sources.update(src)
            else:
                sources.add(src)

        has_erp = bool(sources & {"netsuite", "sap", "oracle_erp"})
        has_cloud_iam = bool(sources & {"aws_iam", "entra", "okta"})

        # SOX policies if ERP is connected
        if has_erp:
            sox_name = "SOX SoD monitoring — financial process conflicts"
            if sox_name not in existing_names:
                sod_subjects = [
                    sid for sid, f in feature_data.items()
                    if f.get("sod_pair_membership_count", 0) > 0
                ]
                if sod_subjects:
                    policy = Policy(
                        id=str(uuid.uuid4()),
                        customer_id=customer_id,
                        name=sox_name,
                        description=(
                            "Monitor segregation of duties violations in financial "
                            "processes. Required for SOX compliance (NIST AC-5)."
                        ),
                        category=PolicyCategory.SOX_COMPLIANCE,
                        status=PolicyStatus.SUGGESTED,
                        rules=[
                            PolicyRule(
                                conditions=[
                                    PolicyCondition(
                                        feature_name="sod_pair_membership_count",
                                        operator="gt",
                                        threshold=0,
                                    ),
                                ],
                            ),
                        ],
                        action=PolicyAction.ESCALATE,
                        severity="critical",
                        base_confidence=0.90,
                    )
                    suggestions.append(Suggestion(
                        policy=policy,
                        reason=SuggestionReason.COMPLIANCE_GAP,
                        evidence={
                            "framework": "SOX",
                            "control": "AC-5",
                            "affected_count": len(sod_subjects),
                        },
                        affected_subjects=sod_subjects,
                        estimated_impact=f"Would flag {len(sod_subjects)} SoD violations",
                        priority=0.9,
                    ))

        # Cross-boundary policy if both cloud IAM and ERP are present
        if has_erp and has_cloud_iam:
            cb_name = "Cross-boundary IAM-to-ERP access monitoring"
            if cb_name not in existing_names:
                cross_subjects = [
                    sid for sid, f in feature_data.items()
                    if f.get("source_system_count", 1) >= 2
                    and f.get("privileged_permissions", 0) > 0
                ]
                if cross_subjects:
                    policy = Policy(
                        id=str(uuid.uuid4()),
                        customer_id=customer_id,
                        name=cb_name,
                        description=(
                            "Monitor identities that span both cloud IAM and ERP systems "
                            "with privileged access in either. This cross-boundary access "
                            "is Vektor's unique detection capability."
                        ),
                        category=PolicyCategory.CROSS_BOUNDARY,
                        status=PolicyStatus.SUGGESTED,
                        rules=[
                            PolicyRule(
                                conditions=[
                                    PolicyCondition(
                                        feature_name="source_system_count",
                                        operator="gte",
                                        threshold=2,
                                    ),
                                    PolicyCondition(
                                        feature_name="privileged_permissions",
                                        operator="gt",
                                        threshold=0,
                                    ),
                                ],
                            ),
                        ],
                        action=PolicyAction.ESCALATE,
                        severity="critical",
                        base_confidence=0.85,
                    )
                    suggestions.append(Suggestion(
                        policy=policy,
                        reason=SuggestionReason.COMPLIANCE_GAP,
                        evidence={
                            "sources_detected": sorted(sources),
                            "cross_system_subjects": len(cross_subjects),
                        },
                        affected_subjects=cross_subjects,
                        estimated_impact=(
                            f"Would monitor {len(cross_subjects)} cross-boundary identities"
                        ),
                        priority=0.95,
                    ))

        return suggestions

    def get_suggestions(self, customer_id: str) -> list[Suggestion]:
        """Retrieve previously generated suggestions for a customer."""
        return self._generated_suggestions.get(customer_id, [])
