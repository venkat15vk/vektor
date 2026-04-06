"""
Vektor AI — Feature Computation Engine

Computes the universal feature vector (~45 features) for every entity in the
identity graph. All 22 ML models consume from this single feature set.
"""

from __future__ import annotations

import math
from collections import defaultdict
from dataclasses import dataclass, field, fields
from datetime import datetime, timezone
from typing import Any

import numpy as np
import structlog
from scipy.spatial.distance import cosine as cosine_distance

from backend.adapters.models import (
    Permission,
    Subject,
    SubjectType,
)
from backend.graph.store import IdentityGraph

logger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Feature dataclasses
# ---------------------------------------------------------------------------

@dataclass
class SubjectFeatures:
    """~28 features describing the subject's identity, permissions, behaviour, graph position, and temporal drift."""

    # Identity profile
    type: str = "human"
    status: str = "active"
    account_age_days: int = 0
    source_system_count: int = 1
    department: str = "unknown"
    manager_depth: int = 0

    # Permission profile
    total_permissions: int = 0
    privileged_permissions: int = 0
    unique_actions: int = 0
    unique_resources_reachable: int = 0
    permission_to_peer_median_ratio: float = 1.0
    permission_concentration: float = 0.0  # HHI

    # Behavioural profile (defaults until Module 6)
    days_since_last_activity: int = -1
    avg_daily_api_calls_30d: float = 0.0
    usage_ratio: float = 0.0
    login_time_entropy: float = 0.0
    distinct_source_ips_30d: int = 0
    mfa_usage_rate: float = 1.0

    # Graph structural
    degree_centrality: float = 0.0
    betweenness_centrality: float = 0.0
    distance_to_nearest_critical_resource: int = -1
    escalation_paths_through_identity: int = 0
    peer_group_cosine_similarity: float = 1.0

    # Temporal (defaults until historical snapshots accumulate)
    permissions_added_7d: int = 0
    permissions_added_30d: int = 0
    permissions_added_90d: int = 0
    permissions_removed_7d: int = 0
    permissions_removed_30d: int = 0
    permissions_removed_90d: int = 0
    net_drift_rate: float = 0.0
    days_since_last_access_review: int = -1


@dataclass
class PermissionFeatures:
    """~10 features per permission."""

    total_actions: int = 0
    high_risk_action_count: int = 0
    wildcard_presence: bool = False
    resource_scope_breadth: int = 0
    holder_count: int = 0
    human_vs_service_vs_agent_ratio: tuple[float, float, float] = (1.0, 0.0, 0.0)
    average_usage_rate_across_holders: float = 0.0
    is_privileged: bool = False
    risk_keyword_count: int = 0
    escalation_chain_participation_count: int = 0


@dataclass
class AssignmentFeatures:
    """~5 features per assignment."""

    assignment_age_days: int = 0
    days_since_last_used: int = -1
    granted_by_type: str = "unknown"
    has_business_justification: bool = False
    is_sod_pair_member: bool = False


@dataclass
class RelationshipFeatures:
    """~3 cross-system relationship features."""

    cross_system_consistency_score: float = 1.0
    sod_pair_membership_count: int = 0
    peer_group_deviation_score: float = 0.0


@dataclass
class FeatureVector:
    """Combined feature vector for one subject."""

    subject_id: str = ""
    computed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    subject: SubjectFeatures = field(default_factory=SubjectFeatures)
    permissions: dict[str, PermissionFeatures] = field(default_factory=dict)
    assignments: dict[str, AssignmentFeatures] = field(default_factory=dict)
    relationships: RelationshipFeatures = field(default_factory=RelationshipFeatures)

    def to_flat_array(self) -> np.ndarray:
        """Flatten subject + relationship features into a 1-D numpy array for model input."""
        vals: list[float] = []
        sf = self.subject

        # Encode categoricals as floats
        type_map = {"human": 0.0, "service_account": 1.0, "ai_agent": 2.0, "group": 3.0}
        status_map = {"active": 0.0, "inactive": 1.0, "suspended": 2.0, "deleted": 3.0}

        vals.append(type_map.get(sf.type, 0.0))
        vals.append(status_map.get(sf.status, 0.0))
        vals.append(float(sf.account_age_days))
        vals.append(float(sf.source_system_count))
        vals.append(float(hash(sf.department) % 10000) / 10000.0)  # hashed encoding
        vals.append(float(sf.manager_depth))

        vals.append(float(sf.total_permissions))
        vals.append(float(sf.privileged_permissions))
        vals.append(float(sf.unique_actions))
        vals.append(float(sf.unique_resources_reachable))
        vals.append(sf.permission_to_peer_median_ratio)
        vals.append(sf.permission_concentration)

        vals.append(float(sf.days_since_last_activity))
        vals.append(sf.avg_daily_api_calls_30d)
        vals.append(sf.usage_ratio)
        vals.append(sf.login_time_entropy)
        vals.append(float(sf.distinct_source_ips_30d))
        vals.append(sf.mfa_usage_rate)

        vals.append(sf.degree_centrality)
        vals.append(sf.betweenness_centrality)
        vals.append(float(sf.distance_to_nearest_critical_resource))
        vals.append(float(sf.escalation_paths_through_identity))
        vals.append(sf.peer_group_cosine_similarity)

        vals.append(float(sf.permissions_added_7d))
        vals.append(float(sf.permissions_added_30d))
        vals.append(float(sf.permissions_added_90d))
        vals.append(float(sf.permissions_removed_7d))
        vals.append(float(sf.permissions_removed_30d))
        vals.append(float(sf.permissions_removed_90d))
        vals.append(sf.net_drift_rate)
        vals.append(float(sf.days_since_last_access_review))

        # Relationship features
        rf = self.relationships
        vals.append(rf.cross_system_consistency_score)
        vals.append(float(rf.sod_pair_membership_count))
        vals.append(rf.peer_group_deviation_score)

        return np.array(vals, dtype=np.float64)


# ---------------------------------------------------------------------------
# Feature computer
# ---------------------------------------------------------------------------

# Import here to avoid circular
from backend.adapters.aws_iam import HIGH_RISK_ACTIONS  # noqa: E402
from backend.adapters.netsuite import SOD_PAIRS  # noqa: E402


class FeatureComputer:
    """
    Computes the universal feature vector for every entity in the identity graph.
    Called after every extraction/scan cycle.
    """

    def __init__(self, graph: IdentityGraph) -> None:
        self._graph = graph
        self._degree_centrality: dict[str, float] = {}
        self._betweenness_centrality: dict[str, float] = {}
        self._peer_groups: dict[str, list[str]] = {}
        self._permission_vectors: dict[str, np.ndarray] = {}
        self._action_index: dict[str, int] = {}

    def compute_all(self) -> dict[str, FeatureVector]:
        """Compute feature vectors for ALL subjects in the graph."""
        logger.info("features.compute_all.start")

        # Pre-compute graph centrality
        self._degree_centrality = self._graph.compute_degree_centrality()
        try:
            self._betweenness_centrality = self._graph.compute_betweenness_centrality()
        except Exception:
            self._betweenness_centrality = {}

        # Build action index for permission vectors
        self._build_action_index()

        # Build permission vectors
        self._build_permission_vectors()

        # Compute peer groups
        self._peer_groups = self.compute_peer_groups()

        # Compute features for each subject
        results: dict[str, FeatureVector] = {}
        subjects = self._graph.get_all_subjects()

        for subj in subjects:
            fv = FeatureVector(
                subject_id=subj.id,
                subject=self.compute_subject_features(subj.id),
                permissions={
                    p.id: self.compute_permission_features(p.id)
                    for p in self._graph.get_permissions_for_subject(subj.id)
                },
                assignments={
                    a.id: self.compute_assignment_features(a)
                    for a in self._graph.get_assignments_for_subject(subj.id)
                },
                relationships=self.compute_relationship_features(subj.id),
            )
            results[subj.id] = fv

        logger.info("features.compute_all.done", count=len(results))
        return results

    # ---- subject features --------------------------------------------------

    def compute_subject_features(self, subject_id: str) -> SubjectFeatures:
        subj = self._graph.get_subject(subject_id)
        if subj is None:
            return SubjectFeatures()

        perms = self._graph.get_permissions_for_subject(subject_id)
        assigns = self._graph.get_assignments_for_subject(subject_id)

        now = datetime.now(timezone.utc)

        # Permission profile
        total_perms = len(perms)
        privileged = sum(1 for p in perms if p.is_privileged)
        all_actions: set[str] = set()
        for p in perms:
            all_actions.update(p.actions)

        blast = self._graph.get_blast_radius(subject_id)
        unique_resources = len(blast["direct_resources"])

        # Peer group ratio
        peer_median = self._get_peer_median_permissions(subject_id)
        ratio = total_perms / peer_median if peer_median > 0 else 1.0

        # HHI concentration
        concentration = self._compute_permission_hhi(perms)

        # Days since last activity
        days_since = -1
        if subj.last_seen:
            days_since = (now - subj.last_seen).days

        # MFA
        mfa_rate = 1.0 if subj.mfa_enabled else 0.0 if subj.mfa_enabled is False else 0.5

        # Account age
        age_days = (now - subj.created_at).days if subj.created_at else 0

        # Source system count (via correlation)
        source_count = 1
        correlated = self._graph.correlate_identities()
        for group in correlated:
            if any(s.id == subject_id for s in group["subjects"]):
                source_count = len(group["sources"])
                break

        # Manager depth
        depth = self._compute_manager_depth(subject_id)

        # Graph centrality
        dc = self._degree_centrality.get(subject_id, 0.0)
        bc = self._betweenness_centrality.get(subject_id, 0.0)

        # Distance to critical
        dist_critical = self._graph.shortest_path_to_critical(subject_id)

        # Escalation paths
        esc_count = len(self._graph.find_escalation_paths(subject_id))

        # Peer similarity
        peer_sim = self._compute_peer_cosine_similarity(subject_id)

        return SubjectFeatures(
            type=subj.type.value,
            status=subj.status.value,
            account_age_days=age_days,
            source_system_count=source_count,
            department=subj.department or "unknown",
            manager_depth=depth,
            total_permissions=total_perms,
            privileged_permissions=privileged,
            unique_actions=len(all_actions),
            unique_resources_reachable=unique_resources,
            permission_to_peer_median_ratio=ratio,
            permission_concentration=concentration,
            days_since_last_activity=days_since,
            mfa_usage_rate=mfa_rate,
            degree_centrality=dc,
            betweenness_centrality=bc,
            distance_to_nearest_critical_resource=dist_critical,
            escalation_paths_through_identity=esc_count,
            peer_group_cosine_similarity=peer_sim,
        )

    # ---- permission features -----------------------------------------------

    def compute_permission_features(self, permission_id: str) -> PermissionFeatures:
        perm = self._graph.get_permission(permission_id)
        if perm is None:
            return PermissionFeatures()

        holders = self._graph.get_subjects_with_permission(permission_id)
        humans = sum(1 for h in holders if h.type == SubjectType.HUMAN)
        services = sum(1 for h in holders if h.type == SubjectType.SERVICE_ACCOUNT)
        agents = sum(1 for h in holders if h.type == SubjectType.AI_AGENT)
        total_holders = max(len(holders), 1)

        high_risk = sum(1 for a in perm.actions if a in HIGH_RISK_ACTIONS or a.endswith(":*") or a == "*")
        wildcard = any("*" in a for a in perm.actions) or any("*" in r for r in perm.resources)

        esc_count = sum(
            1 for ep in self._graph._escalation_paths
            if any(step.action in perm.actions for step in ep.steps)
        )

        return PermissionFeatures(
            total_actions=len(perm.actions),
            high_risk_action_count=high_risk,
            wildcard_presence=wildcard,
            resource_scope_breadth=len(perm.resources),
            holder_count=len(holders),
            human_vs_service_vs_agent_ratio=(
                humans / total_holders,
                services / total_holders,
                agents / total_holders,
            ),
            average_usage_rate_across_holders=0.0,  # populated by Module 6
            is_privileged=perm.is_privileged,
            risk_keyword_count=len(perm.risk_keywords),
            escalation_chain_participation_count=esc_count,
        )

    # ---- assignment features -----------------------------------------------

    def compute_assignment_features(self, assignment: Any) -> AssignmentFeatures:
        now = datetime.now(timezone.utc)

        age_days = 0
        if assignment.granted_at:
            age_days = (now - assignment.granted_at).days

        days_since_used = -1
        if assignment.last_used:
            days_since_used = (now - assignment.last_used).days

        granted_by = assignment.granted_by or "unknown"
        granted_type = "system" if granted_by in ("aws_iam", "okta", "entra", "netsuite") else (
            "automation" if "auto" in granted_by.lower() else "human" if "@" in granted_by else "unknown"
        )

        # SoD check
        is_sod = False
        perm = self._graph.get_permission(assignment.permission_id)
        if perm:
            perm_keys: set[str] = set()
            for action in perm.actions:
                if action.startswith("netsuite:"):
                    perm_keys.add(action.split(":")[1].split(".")[0])
            subj_perms = self._graph.get_permissions_for_subject(assignment.subject_id)
            all_keys: set[str] = set()
            for sp in subj_perms:
                for a in sp.actions:
                    if a.startswith("netsuite:"):
                        all_keys.add(a.split(":")[1].split(".")[0])
            for pair_a, pair_b in SOD_PAIRS:
                if (pair_a in perm_keys and pair_b in all_keys) or (pair_b in perm_keys and pair_a in all_keys):
                    is_sod = True
                    break

        return AssignmentFeatures(
            assignment_age_days=age_days,
            days_since_last_used=days_since_used,
            granted_by_type=granted_type,
            has_business_justification=bool(getattr(assignment, "attributes", {}).get("justification")),
            is_sod_pair_member=is_sod,
        )

    # ---- relationship features ---------------------------------------------

    def compute_relationship_features(self, subject_id: str) -> RelationshipFeatures:
        subj = self._graph.get_subject(subject_id)
        if subj is None:
            return RelationshipFeatures()

        # Cross-system consistency
        consistency = 1.0
        correlated = self._graph.correlate_identities()
        for group in correlated:
            if any(s.id == subject_id for s in group["subjects"]):
                subjects_in = group["subjects"]
                if len(subjects_in) > 1:
                    statuses = {s.status.value for s in subjects_in}
                    depts = {s.department for s in subjects_in if s.department}
                    names = {s.display_name.lower().strip() for s in subjects_in}

                    score = 1.0
                    if len(statuses) > 1:
                        score -= 0.4
                    if len(depts) > 1:
                        score -= 0.3
                    if len(names) > 1:
                        score -= 0.2
                    consistency = max(0.0, score)
                break

        # SoD pair membership
        sod_violations = self._graph.find_sod_violations(SOD_PAIRS)
        sod_count = sum(
            1 for v in sod_violations
            if subject_id in v.get("subject_ids", [])
        )

        # Peer group deviation
        deviation = self._compute_peer_deviation(subject_id)

        return RelationshipFeatures(
            cross_system_consistency_score=consistency,
            sod_pair_membership_count=sod_count,
            peer_group_deviation_score=deviation,
        )

    # ---- peer group computation --------------------------------------------

    def compute_peer_groups(self) -> dict[str, list[str]]:
        """Group subjects by department + type + similar permission count."""
        groups: dict[str, list[str]] = defaultdict(list)
        subjects = self._graph.get_all_subjects()

        for subj in subjects:
            if subj.type == SubjectType.GROUP:
                continue
            dept = (subj.department or "unknown").lower().strip()
            key = f"{dept}:{subj.type.value}"
            groups[key].append(subj.id)

        return dict(groups)

    # ---- internal helpers --------------------------------------------------

    def _get_peer_median_permissions(self, subject_id: str) -> float:
        subj = self._graph.get_subject(subject_id)
        if subj is None:
            return 1.0

        dept = (subj.department or "unknown").lower().strip()
        key = f"{dept}:{subj.type.value}"
        peers = self._peer_groups.get(key, [])
        if len(peers) < 2:
            return 1.0

        counts = []
        for pid in peers:
            n = len(self._graph.get_permissions_for_subject(pid))
            counts.append(n)

        counts.sort()
        mid = len(counts) // 2
        return float(counts[mid]) if counts else 1.0

    def _compute_permission_hhi(self, perms: list[Permission]) -> float:
        """Herfindahl-Hirschman Index for permission action concentration."""
        if not perms:
            return 0.0
        total_actions = sum(len(p.actions) for p in perms)
        if total_actions == 0:
            return 0.0
        shares = [len(p.actions) / total_actions for p in perms]
        return sum(s * s for s in shares)

    def _compute_manager_depth(self, subject_id: str) -> int:
        """Compute depth from subject to root in manager hierarchy."""
        depth = 0
        visited: set[str] = set()
        current = subject_id
        while depth < 20:  # safety
            subj = self._graph.get_subject(current)
            if subj is None or subj.manager_id is None or subj.manager_id in visited:
                break
            visited.add(current)
            current = subj.manager_id
            depth += 1
        return depth

    def _build_action_index(self) -> None:
        """Build a global action→index mapping for permission vectors."""
        all_actions: set[str] = set()
        for perm in self._graph.get_all_permissions():
            all_actions.update(perm.actions)
        self._action_index = {a: i for i, a in enumerate(sorted(all_actions))}

    def _build_permission_vectors(self) -> None:
        """Build binary permission vectors for each subject."""
        n_actions = len(self._action_index)
        if n_actions == 0:
            return

        for subj in self._graph.get_all_subjects():
            vec = np.zeros(n_actions, dtype=np.float64)
            for perm in self._graph.get_permissions_for_subject(subj.id):
                for action in perm.actions:
                    idx = self._action_index.get(action)
                    if idx is not None:
                        vec[idx] = 1.0
            self._permission_vectors[subj.id] = vec

    def _compute_peer_cosine_similarity(self, subject_id: str) -> float:
        """Cosine similarity of this subject's permission vector vs peer centroid."""
        subj = self._graph.get_subject(subject_id)
        if subj is None:
            return 1.0

        subj_vec = self._permission_vectors.get(subject_id)
        if subj_vec is None or np.sum(subj_vec) == 0:
            return 0.0

        dept = (subj.department or "unknown").lower().strip()
        key = f"{dept}:{subj.type.value}"
        peers = self._peer_groups.get(key, [])
        peer_vecs = [self._permission_vectors[p] for p in peers if p != subject_id and p in self._permission_vectors]

        if not peer_vecs:
            return 1.0

        centroid = np.mean(peer_vecs, axis=0)
        if np.sum(centroid) == 0:
            return 0.0

        dist = cosine_distance(subj_vec, centroid)
        return max(0.0, 1.0 - dist)

    def _compute_peer_deviation(self, subject_id: str) -> float:
        """Z-score of this subject's permission count vs peer group."""
        subj = self._graph.get_subject(subject_id)
        if subj is None:
            return 0.0

        dept = (subj.department or "unknown").lower().strip()
        key = f"{dept}:{subj.type.value}"
        peers = self._peer_groups.get(key, [])
        if len(peers) < 3:
            return 0.0

        counts = [len(self._graph.get_permissions_for_subject(p)) for p in peers]
        mean = np.mean(counts)
        std = np.std(counts)
        if std == 0:
            return 0.0

        subj_count = len(self._graph.get_permissions_for_subject(subject_id))
        return float((subj_count - mean) / std)
