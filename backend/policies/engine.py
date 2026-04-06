"""
Vektor AI — Tier 2 Policy Evaluation Engine

Manages the full lifecycle of customer-specific policies:
  1. Suggestion: Vektor surfaces suggested policies from observed patterns
  2. Approval: Customer reviews and approves/dismisses
  3. Instantiation: Approved policy becomes a lightweight classifier
  4. Learning: Model fine-tunes on customer feedback
  5. Graduation: Enough cross-customer approvals → graduates to Tier 1

Policies are NOT hardcoded rules. Each approved policy instantiates a
lightweight classifier on the universal feature backbone, scoped by a
policy graph query.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

import numpy as np
import structlog
from pydantic import BaseModel as PydanticBaseModel, Field, field_validator

logger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class PolicyStatus(str, Enum):
    """Lifecycle states of a Tier 2 policy."""
    SUGGESTED = "suggested"       # Vektor suggested, awaiting review
    APPROVED = "approved"         # Customer approved, classifier instantiated
    ACTIVE = "active"             # Classifier trained and scoring
    DISMISSED = "dismissed"       # Customer rejected the suggestion
    PAUSED = "paused"             # Temporarily disabled by customer
    GRADUATED = "graduated"       # Promoted to Tier 1 (cross-customer validation)
    ARCHIVED = "archived"         # Superseded or retired


class PolicyCategory(str, Enum):
    """Categories aligning with the violation taxonomy."""
    SOX_COMPLIANCE = "sox_compliance"
    ZERO_TRUST = "zero_trust"
    ANOMALY = "anomaly"
    AGENT_GOVERNANCE = "agent_governance"
    CROSS_BOUNDARY = "cross_boundary"
    CUSTOM = "custom"


class PolicyAction(str, Enum):
    """Actions a policy can prescribe when triggered."""
    ALERT = "alert"
    FLAG_FOR_REVIEW = "flag_for_review"
    REVOKE_PERMISSION = "revoke_permission"
    DISABLE_ACCOUNT = "disable_account"
    REQUIRE_MFA = "require_mfa"
    REQUEST_JUSTIFICATION = "request_justification"
    ESCALATE = "escalate"
    CUSTOM = "custom"


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class PolicyScope(PydanticBaseModel):
    """
    Defines what subset of the identity graph a policy applies to.
    Scoping is done via graph query predicates — not feature vector shape.
    """
    source_systems: list[str] = Field(
        default_factory=list,
        description="Limit to specific sources (e.g., ['aws_iam', 'netsuite']). Empty = all.",
    )
    subject_types: list[str] = Field(
        default_factory=list,
        description="Limit to subject types (e.g., ['human', 'ai_agent']). Empty = all.",
    )
    departments: list[str] = Field(
        default_factory=list,
        description="Limit to departments. Empty = all.",
    )
    include_privileged_only: bool = Field(
        default=False,
        description="If True, only evaluate subjects with privileged permissions.",
    )
    custom_filter: Optional[dict[str, Any]] = Field(
        default=None,
        description="Arbitrary key-value filter applied to subject attributes.",
    )

    def matches_subject(self, subject_attrs: dict[str, Any]) -> bool:
        """Check if a subject matches this policy's scope."""
        if self.source_systems and subject_attrs.get("source") not in self.source_systems:
            return False
        if self.subject_types and subject_attrs.get("type") not in self.subject_types:
            return False
        if self.departments and subject_attrs.get("department") not in self.departments:
            return False
        if self.include_privileged_only and not subject_attrs.get("has_privileged", False):
            return False
        if self.custom_filter:
            attrs = subject_attrs.get("attributes", {})
            for key, value in self.custom_filter.items():
                if attrs.get(key) != value:
                    return False
        return True


class PolicyCondition(PydanticBaseModel):
    """A single condition in a policy rule, evaluated against feature vectors."""
    feature_name: str = Field(description="Name of the feature to evaluate.")
    operator: str = Field(description="Comparison operator: gt, lt, gte, lte, eq, neq, in, not_in.")
    threshold: Any = Field(description="Value to compare against.")

    _OPERATORS = {
        "gt": lambda a, b: a > b,
        "lt": lambda a, b: a < b,
        "gte": lambda a, b: a >= b,
        "lte": lambda a, b: a <= b,
        "eq": lambda a, b: a == b,
        "neq": lambda a, b: a != b,
        "in": lambda a, b: a in b,
        "not_in": lambda a, b: a not in b,
    }

    @field_validator("operator")
    @classmethod
    def validate_operator(cls, v: str) -> str:
        valid = {"gt", "lt", "gte", "lte", "eq", "neq", "in", "not_in"}
        if v not in valid:
            raise ValueError(f"Operator must be one of {valid}, got '{v}'")
        return v

    def evaluate(self, feature_value: Any) -> bool:
        """Evaluate this condition against a feature value."""
        op_fn = self._OPERATORS.get(self.operator)
        if op_fn is None:
            return False
        try:
            return op_fn(feature_value, self.threshold)
        except (TypeError, ValueError):
            return False


class PolicyRule(PydanticBaseModel):
    """
    A set of conditions combined with AND logic.
    All conditions must be true for the rule to fire.
    """
    conditions: list[PolicyCondition] = Field(min_length=1)
    confidence_boost: float = Field(
        default=0.0,
        ge=-0.5,
        le=0.5,
        description="Adjustment to base confidence when this rule fires.",
    )

    def evaluate(self, features: dict[str, Any]) -> bool:
        """Evaluate all conditions against a feature dict. AND logic."""
        return all(
            cond.evaluate(features.get(cond.feature_name))
            for cond in self.conditions
        )


class Policy(PydanticBaseModel):
    """
    A Tier 2 customer-specific policy.

    When approved, a lightweight classifier is instantiated on the universal
    feature backbone, scoped by the policy's graph query (PolicyScope).
    The classifier starts with rule-based logic (PolicyRules) and transitions
    to a trained model as feedback accumulates.
    """
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    customer_id: str = Field(description="Customer that owns this policy.")
    name: str = Field(description="Human-readable policy name.")
    description: str = Field(description="What this policy detects and why it matters.")
    category: PolicyCategory
    status: PolicyStatus = PolicyStatus.SUGGESTED
    scope: PolicyScope = Field(default_factory=PolicyScope)
    rules: list[PolicyRule] = Field(
        default_factory=list,
        description="Rule-based conditions. Used until ML classifier is trained.",
    )
    action: PolicyAction = PolicyAction.FLAG_FOR_REVIEW
    base_confidence: float = Field(
        default=0.7,
        ge=0.0,
        le=1.0,
        description="Default confidence score when the policy fires.",
    )
    severity: str = Field(default="medium", pattern=r"^(critical|high|medium|low)$")

    # Lifecycle metadata
    suggested_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    approved_at: Optional[datetime] = None
    approved_by: Optional[str] = None
    dismissed_at: Optional[datetime] = None
    dismissed_reason: Optional[str] = None

    # ML model reference (populated after training)
    model_path: Optional[str] = None
    model_version: Optional[str] = None
    model_accuracy: Optional[float] = None

    # Cross-customer graduation tracking
    cross_customer_approvals: int = Field(
        default=0,
        description="Number of distinct customers who approved similar policies.",
    )
    graduation_threshold: int = Field(
        default=10,
        description="Approvals needed across customers to graduate to Tier 1.",
    )

    # Feedback counters
    true_positives: int = 0
    false_positives: int = 0
    true_negatives: int = 0
    false_negatives: int = 0

    @property
    def is_ready_for_graduation(self) -> bool:
        return self.cross_customer_approvals >= self.graduation_threshold

    @property
    def precision(self) -> float:
        total = self.true_positives + self.false_positives
        return self.true_positives / total if total > 0 else 0.0

    @property
    def recall(self) -> float:
        total = self.true_positives + self.false_negatives
        return self.true_positives / total if total > 0 else 0.0

    @property
    def f1_score(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) > 0 else 0.0


class PolicyEvalResult(PydanticBaseModel):
    """Result of evaluating a single policy against a single subject."""
    policy_id: str
    subject_id: str
    triggered: bool
    confidence: float
    matched_rules: list[int] = Field(
        default_factory=list,
        description="Indices of rules that fired.",
    )
    feature_snapshot: dict[str, Any] = Field(
        default_factory=dict,
        description="Subset of features relevant to this evaluation.",
    )
    evaluated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ---------------------------------------------------------------------------
# Policy Engine
# ---------------------------------------------------------------------------

class PolicyEngine:
    """
    Tier 2 Policy Evaluation Engine.

    Manages policy lifecycle and evaluation:
    - Register/approve/dismiss/pause/archive policies
    - Evaluate all active policies against the feature store
    - Record feedback for model improvement
    - Track cross-customer graduation
    """

    def __init__(self) -> None:
        self._policies: dict[str, Policy] = {}
        self._customer_policies: dict[str, list[str]] = {}  # customer_id → [policy_ids]
        self._evaluation_history: list[PolicyEvalResult] = []

    # -------------------------------------------------------------------
    # Policy CRUD
    # -------------------------------------------------------------------

    def register_policy(self, policy: Policy) -> Policy:
        """Register a new policy (typically from suggestion generator)."""
        self._policies[policy.id] = policy
        customer_list = self._customer_policies.setdefault(policy.customer_id, [])
        if policy.id not in customer_list:
            customer_list.append(policy.id)
        logger.info(
            "policy_registered",
            policy_id=policy.id,
            name=policy.name,
            customer_id=policy.customer_id,
            status=policy.status.value,
        )
        return policy

    def get_policy(self, policy_id: str) -> Policy | None:
        return self._policies.get(policy_id)

    def list_policies(
        self,
        customer_id: str | None = None,
        status: PolicyStatus | None = None,
        category: PolicyCategory | None = None,
    ) -> list[Policy]:
        """List policies with optional filters."""
        policies = self._policies.values()
        if customer_id is not None:
            policy_ids = set(self._customer_policies.get(customer_id, []))
            policies = [p for p in policies if p.id in policy_ids]
        if status is not None:
            policies = [p for p in policies if p.status == status]
        if category is not None:
            policies = [p for p in policies if p.category == category]
        return sorted(policies, key=lambda p: p.suggested_at, reverse=True)

    def approve_policy(
        self,
        policy_id: str,
        approved_by: str,
        action_override: PolicyAction | None = None,
        severity_override: str | None = None,
    ) -> Policy:
        """
        Customer approves a suggested policy.
        Transitions: SUGGESTED → APPROVED → ACTIVE (once classifier is ready).
        """
        policy = self._policies.get(policy_id)
        if policy is None:
            raise ValueError(f"Policy {policy_id} not found")
        if policy.status not in (PolicyStatus.SUGGESTED, PolicyStatus.PAUSED):
            raise ValueError(
                f"Cannot approve policy in status '{policy.status.value}'. "
                f"Must be 'suggested' or 'paused'."
            )

        policy.status = PolicyStatus.APPROVED
        policy.approved_at = datetime.now(timezone.utc)
        policy.approved_by = approved_by
        if action_override:
            policy.action = action_override
        if severity_override:
            policy.severity = severity_override

        # Increment cross-customer approval tracking
        policy.cross_customer_approvals += 1

        logger.info(
            "policy_approved",
            policy_id=policy_id,
            approved_by=approved_by,
            cross_customer_approvals=policy.cross_customer_approvals,
        )

        # Auto-activate if rules are present (ML model comes later)
        if policy.rules:
            policy.status = PolicyStatus.ACTIVE
            logger.info("policy_activated", policy_id=policy_id)

        # Check graduation eligibility
        if policy.is_ready_for_graduation:
            logger.info(
                "policy_graduation_eligible",
                policy_id=policy_id,
                approvals=policy.cross_customer_approvals,
            )

        return policy

    def dismiss_policy(self, policy_id: str, reason: str = "") -> Policy:
        """Customer dismisses a suggested policy."""
        policy = self._policies.get(policy_id)
        if policy is None:
            raise ValueError(f"Policy {policy_id} not found")

        policy.status = PolicyStatus.DISMISSED
        policy.dismissed_at = datetime.now(timezone.utc)
        policy.dismissed_reason = reason

        logger.info(
            "policy_dismissed",
            policy_id=policy_id,
            reason=reason,
        )
        return policy

    def pause_policy(self, policy_id: str) -> Policy:
        """Temporarily pause an active policy."""
        policy = self._policies.get(policy_id)
        if policy is None:
            raise ValueError(f"Policy {policy_id} not found")
        if policy.status != PolicyStatus.ACTIVE:
            raise ValueError(f"Can only pause active policies, got '{policy.status.value}'")

        policy.status = PolicyStatus.PAUSED
        logger.info("policy_paused", policy_id=policy_id)
        return policy

    def archive_policy(self, policy_id: str) -> Policy:
        """Archive a policy (soft delete)."""
        policy = self._policies.get(policy_id)
        if policy is None:
            raise ValueError(f"Policy {policy_id} not found")

        policy.status = PolicyStatus.ARCHIVED
        logger.info("policy_archived", policy_id=policy_id)
        return policy

    def graduate_policy(self, policy_id: str) -> Policy:
        """Promote a policy to Tier 1 after cross-customer validation."""
        policy = self._policies.get(policy_id)
        if policy is None:
            raise ValueError(f"Policy {policy_id} not found")
        if not policy.is_ready_for_graduation:
            raise ValueError(
                f"Policy needs {policy.graduation_threshold} approvals, "
                f"has {policy.cross_customer_approvals}"
            )

        policy.status = PolicyStatus.GRADUATED
        logger.info(
            "policy_graduated",
            policy_id=policy_id,
            approvals=policy.cross_customer_approvals,
            f1=policy.f1_score,
        )
        return policy

    # -------------------------------------------------------------------
    # Evaluation
    # -------------------------------------------------------------------

    def evaluate_subject(
        self,
        subject_id: str,
        subject_attrs: dict[str, Any],
        features: dict[str, Any],
        customer_id: str,
    ) -> list[PolicyEvalResult]:
        """
        Evaluate all active policies for a customer against a single subject.
        Returns list of evaluation results (only triggered policies).
        """
        results: list[PolicyEvalResult] = []
        active_policies = self.list_policies(
            customer_id=customer_id,
            status=PolicyStatus.ACTIVE,
        )

        for policy in active_policies:
            # Check scope
            if not policy.scope.matches_subject(subject_attrs):
                continue

            # Evaluate rules (OR logic across rules — any rule can trigger)
            triggered = False
            matched_rules: list[int] = []
            confidence = policy.base_confidence

            if policy.rules:
                for idx, rule in enumerate(policy.rules):
                    if rule.evaluate(features):
                        triggered = True
                        matched_rules.append(idx)
                        confidence = min(1.0, max(0.0, confidence + rule.confidence_boost))
            else:
                # No rules yet — skip (policy needs rules or a trained model)
                continue

            # TODO: If policy has a trained ML model, run inference here
            # and combine with rule-based result

            if triggered:
                result = PolicyEvalResult(
                    policy_id=policy.id,
                    subject_id=subject_id,
                    triggered=True,
                    confidence=confidence,
                    matched_rules=matched_rules,
                    feature_snapshot={
                        cond.feature_name: features.get(cond.feature_name)
                        for rule in policy.rules
                        for cond in rule.conditions
                    },
                )
                results.append(result)
                self._evaluation_history.append(result)

        return results

    def evaluate_all(
        self,
        subjects: dict[str, dict[str, Any]],
        feature_store_data: dict[str, dict[str, Any]],
        customer_id: str,
    ) -> list[PolicyEvalResult]:
        """
        Evaluate all active policies against all subjects.

        Args:
            subjects: { subject_id: { "source": ..., "type": ..., ... } }
            feature_store_data: { subject_id: { feature_name: value, ... } }
            customer_id: Customer to evaluate for.

        Returns:
            All triggered policy evaluations.
        """
        all_results: list[PolicyEvalResult] = []

        for subject_id, attrs in subjects.items():
            features = feature_store_data.get(subject_id, {})
            results = self.evaluate_subject(subject_id, attrs, features, customer_id)
            all_results.extend(results)

        logger.info(
            "policy_evaluation_complete",
            customer_id=customer_id,
            subjects_evaluated=len(subjects),
            signals_generated=len(all_results),
        )
        return all_results

    # -------------------------------------------------------------------
    # Feedback & Learning
    # -------------------------------------------------------------------

    def record_feedback(
        self,
        policy_id: str,
        subject_id: str,
        is_true_positive: bool,
    ) -> None:
        """
        Record feedback on a policy evaluation.
        Every interaction generates training data:
        - Signal executed → true positive
        - Signal dismissed → false positive
        - Manual report of missed violation → false negative
        """
        policy = self._policies.get(policy_id)
        if policy is None:
            raise ValueError(f"Policy {policy_id} not found")

        if is_true_positive:
            policy.true_positives += 1
        else:
            policy.false_positives += 1

        logger.info(
            "policy_feedback_recorded",
            policy_id=policy_id,
            subject_id=subject_id,
            is_true_positive=is_true_positive,
            precision=f"{policy.precision:.3f}",
            total_feedback=policy.true_positives + policy.false_positives,
        )

    def record_missed_violation(self, policy_id: str) -> None:
        """Record a false negative — a violation the policy should have caught."""
        policy = self._policies.get(policy_id)
        if policy is None:
            raise ValueError(f"Policy {policy_id} not found")
        policy.false_negatives += 1

    def get_policy_performance(self, policy_id: str) -> dict[str, Any]:
        """Get performance metrics for a policy."""
        policy = self._policies.get(policy_id)
        if policy is None:
            raise ValueError(f"Policy {policy_id} not found")

        total_feedback = (
            policy.true_positives
            + policy.false_positives
            + policy.true_negatives
            + policy.false_negatives
        )

        return {
            "policy_id": policy_id,
            "name": policy.name,
            "status": policy.status.value,
            "true_positives": policy.true_positives,
            "false_positives": policy.false_positives,
            "true_negatives": policy.true_negatives,
            "false_negatives": policy.false_negatives,
            "precision": policy.precision,
            "recall": policy.recall,
            "f1_score": policy.f1_score,
            "total_feedback": total_feedback,
            "cross_customer_approvals": policy.cross_customer_approvals,
            "ready_for_graduation": policy.is_ready_for_graduation,
        }

    # -------------------------------------------------------------------
    # Cross-Customer Aggregation
    # -------------------------------------------------------------------

    def find_graduation_candidates(self) -> list[Policy]:
        """Find policies that have enough cross-customer approvals to graduate."""
        return [
            p for p in self._policies.values()
            if p.status == PolicyStatus.ACTIVE and p.is_ready_for_graduation
        ]

    def get_similar_policies(self, policy: Policy) -> list[Policy]:
        """
        Find policies across all customers that are structurally similar.
        Used for cross-customer aggregation and graduation tracking.

        Similarity heuristic:
        - Same category
        - Overlapping scope (at least one common source system or subject type)
        - Similar rule structure (same feature names referenced)
        """
        similar: list[Policy] = []
        policy_features = {
            cond.feature_name
            for rule in policy.rules
            for cond in rule.conditions
        }

        for other in self._policies.values():
            if other.id == policy.id:
                continue
            if other.category != policy.category:
                continue

            other_features = {
                cond.feature_name
                for rule in other.rules
                for cond in rule.conditions
            }
            # Jaccard similarity on referenced features
            if not policy_features or not other_features:
                continue
            intersection = policy_features & other_features
            union = policy_features | other_features
            similarity = len(intersection) / len(union)

            if similarity >= 0.5:
                similar.append(other)

        return similar
