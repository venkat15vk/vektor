"""
Vektor AI — Identity Graph Store (Phase 1: NetworkX)

Merges ``GraphSnapshot`` objects from multiple adapters into a single unified
identity graph. Supports cross-boundary queries, identity correlation, SoD
detection, and blast-radius computation.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

import networkx as nx
import structlog

from backend.adapters.models import (
    Assignment,
    EscalationPath,
    GraphSnapshot,
    Permission,
    Resource,
    Sensitivity,
    Subject,
    SubjectType,
)

logger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Node/edge type prefixes
# ---------------------------------------------------------------------------
_SUBJECT_PFX = "subject"
_PERMISSION_PFX = "permission"
_RESOURCE_PFX = "resource"


def _node_id(prefix: str, entity_id: str) -> str:
    return f"{prefix}:{entity_id}"


class IdentityGraph:
    """
    Unified identity graph built from multiple adapter snapshots.

    Phase 1: NetworkX in-memory directed graph.
    Phase 2: Migrate to Neo4j for persistence and Cypher queries.
    """

    def __init__(self) -> None:
        self.graph = nx.DiGraph()
        self._snapshots: list[GraphSnapshot] = []
        self._subjects: dict[str, Subject] = {}
        self._permissions: dict[str, Permission] = {}
        self._resources: dict[str, Resource] = {}
        self._assignments: dict[str, Assignment] = {}
        self._escalation_paths: list[EscalationPath] = []

    # ---- ingestion ---------------------------------------------------------

    def ingest(self, snapshot: GraphSnapshot) -> None:
        """Merge a GraphSnapshot into the unified graph."""
        logger.info(
            "graph.ingest",
            source=snapshot.source,
            subjects=len(snapshot.subjects),
            permissions=len(snapshot.permissions),
            resources=len(snapshot.resources),
            assignments=len(snapshot.assignments),
            escalation_paths=len(snapshot.escalation_paths),
        )
        self._snapshots.append(snapshot)

        # Add subject nodes
        for s in snapshot.subjects:
            nid = _node_id(_SUBJECT_PFX, s.id)
            self._subjects[s.id] = s
            self.graph.add_node(
                nid,
                node_type="subject",
                entity=s,
                source=s.source,
                subject_type=s.type.value,
                display_name=s.display_name,
                email=s.email,
                status=s.status.value,
            )
            # Manager edge
            if s.manager_id:
                mgr_nid = _node_id(_SUBJECT_PFX, s.manager_id)
                self.graph.add_edge(mgr_nid, nid, edge_type="manages")

        # Add permission nodes
        for p in snapshot.permissions:
            nid = _node_id(_PERMISSION_PFX, p.id)
            self._permissions[p.id] = p
            self.graph.add_node(
                nid,
                node_type="permission",
                entity=p,
                source=p.source,
                is_privileged=p.is_privileged,
            )

        # Add resource nodes
        for r in snapshot.resources:
            nid = _node_id(_RESOURCE_PFX, r.id)
            self._resources[r.id] = r
            self.graph.add_node(
                nid,
                node_type="resource",
                entity=r,
                source=r.source,
                sensitivity=r.sensitivity.value,
            )

        # Add edges: subject → permission (via assignment)
        for a in snapshot.assignments:
            self._assignments[a.id] = a
            subj_nid = _node_id(_SUBJECT_PFX, a.subject_id)
            perm_nid = _node_id(_PERMISSION_PFX, a.permission_id)
            self.graph.add_edge(
                subj_nid,
                perm_nid,
                edge_type="has_permission",
                assignment=a,
                is_active=a.is_active,
            )
            # Permission → resource scope edge
            if a.resource_id:
                res_nid = _node_id(_RESOURCE_PFX, a.resource_id)
                self.graph.add_edge(
                    perm_nid,
                    res_nid,
                    edge_type="grants_access",
                )

        # Add permission → resource edges from policy resource lists
        for p in snapshot.permissions:
            perm_nid = _node_id(_PERMISSION_PFX, p.id)
            for res_str in p.resources:
                if res_str == "*":
                    continue
                # Try to find the resource node by matching ARN/name
                for rid, r in self._resources.items():
                    arn = r.attributes.get("arn", "")
                    if arn == res_str or r.name == res_str:
                        res_nid = _node_id(_RESOURCE_PFX, rid)
                        self.graph.add_edge(
                            perm_nid, res_nid, edge_type="grants_access"
                        )

        # Group membership edges (subject → subject for group membership)
        for a in snapshot.assignments:
            perm = self._permissions.get(a.permission_id)
            if perm and perm.type.value == "group":
                # Also add direct subject→subject membership edge
                subj_nid = _node_id(_SUBJECT_PFX, a.subject_id)
                group_nid = _node_id(_SUBJECT_PFX, a.permission_id)
                if self.graph.has_node(group_nid):
                    self.graph.add_edge(subj_nid, group_nid, edge_type="member_of")

        # Store escalation paths
        self._escalation_paths.extend(snapshot.escalation_paths)
        for ep in snapshot.escalation_paths:
            subj_nid = _node_id(_SUBJECT_PFX, ep.subject_id)
            self.graph.nodes[subj_nid]["has_escalation"] = True if self.graph.has_node(subj_nid) else False

        logger.info(
            "graph.ingest.done",
            total_nodes=self.graph.number_of_nodes(),
            total_edges=self.graph.number_of_edges(),
        )

    # ---- basic queries -----------------------------------------------------

    def get_subject(self, subject_id: str) -> Subject | None:
        return self._subjects.get(subject_id)

    def get_permission(self, permission_id: str) -> Permission | None:
        return self._permissions.get(permission_id)

    def get_resource(self, resource_id: str) -> Resource | None:
        return self._resources.get(resource_id)

    def get_all_subjects(self) -> list[Subject]:
        return list(self._subjects.values())

    def get_all_permissions(self) -> list[Permission]:
        return list(self._permissions.values())

    def get_assignments_for_subject(self, subject_id: str) -> list[Assignment]:
        return [a for a in self._assignments.values() if a.subject_id == subject_id and a.is_active]

    def get_permissions_for_subject(self, subject_id: str) -> list[Permission]:
        assigns = self.get_assignments_for_subject(subject_id)
        perm_ids = {a.permission_id for a in assigns}
        return [self._permissions[pid] for pid in perm_ids if pid in self._permissions]

    def get_subjects_with_permission(self, permission_id: str) -> list[Subject]:
        holders = [
            a.subject_id
            for a in self._assignments.values()
            if a.permission_id == permission_id and a.is_active
        ]
        return [self._subjects[sid] for sid in set(holders) if sid in self._subjects]

    # ---- cross-boundary queries --------------------------------------------

    def find_cross_system_subjects(self) -> list[tuple[Subject, list[str]]]:
        """Find subjects present in multiple source systems (via correlation)."""
        correlated = self.correlate_identities()
        results: list[tuple[Subject, list[str]]] = []
        for group in correlated:
            subjects_in_group = group["subjects"]
            sources = list({s.source for s in subjects_in_group})
            if len(sources) > 1:
                for s in subjects_in_group:
                    results.append((s, sources))
        return results

    def find_escalation_paths(self, subject_id: str) -> list[EscalationPath]:
        return [ep for ep in self._escalation_paths if ep.subject_id == subject_id]

    def find_sod_violations(
        self, sod_pairs: list[tuple[str, str]]
    ) -> list[dict[str, Any]]:
        """
        Find subjects holding both sides of any SoD pair.
        Works cross-boundary: checks aggregated permissions from all sources.
        """
        violations: list[dict[str, Any]] = []

        # Build correlated identity groups
        correlated = self.correlate_identities()
        identity_groups = correlated + [
            {"unified_id": s.id, "subjects": [s]}
            for s in self._subjects.values()
            if not any(s in g["subjects"] for g in correlated)
        ]

        for group in identity_groups:
            # Aggregate all permission keys across all correlated subjects
            all_perm_keys: set[str] = set()
            group_sources: set[str] = set()
            group_subject_ids: list[str] = []

            for subj in group["subjects"]:
                group_subject_ids.append(subj.id)
                group_sources.add(subj.source)
                for perm in self.get_permissions_for_subject(subj.id):
                    # Extract NetSuite permission keys from actions
                    for action in perm.actions:
                        if action.startswith("netsuite:"):
                            key = action.split(":")[1].split(".")[0]
                            all_perm_keys.add(key)
                        else:
                            all_perm_keys.add(action)
                    # Also check permission attributes
                    for pk in perm.attributes.get("permission_keys", []):
                        all_perm_keys.add(pk)

            for pair_a, pair_b in sod_pairs:
                if pair_a in all_perm_keys and pair_b in all_perm_keys:
                    violations.append({
                        "unified_id": group.get("unified_id"),
                        "subject_ids": group_subject_ids,
                        "display_names": [s.display_name for s in group["subjects"]],
                        "sod_pair": (pair_a, pair_b),
                        "sources": sorted(group_sources),
                        "is_cross_boundary": len(group_sources) > 1,
                    })

        logger.info("graph.sod_violations", count=len(violations))
        return violations

    def get_blast_radius(self, subject_id: str) -> dict[str, Any]:
        """
        Calculate blast radius: what resources can this subject reach,
        directly or through escalation paths?
        """
        subj_nid = _node_id(_SUBJECT_PFX, subject_id)
        if not self.graph.has_node(subj_nid):
            return {
                "direct_resources": [],
                "escalation_resources": [],
                "critical_resources": [],
                "total_reach": 0,
            }

        # Direct resources: subject → permission → resource
        direct_resources: list[dict] = []
        for _, perm_nid, edata in self.graph.out_edges(subj_nid, data=True):
            if edata.get("edge_type") != "has_permission":
                continue
            for _, res_nid, rdata in self.graph.out_edges(perm_nid, data=True):
                if rdata.get("edge_type") != "grants_access":
                    continue
                node_data = self.graph.nodes.get(res_nid, {})
                entity = node_data.get("entity")
                if entity and isinstance(entity, Resource):
                    direct_resources.append({
                        "id": entity.id,
                        "name": entity.name,
                        "type": entity.type,
                        "sensitivity": entity.sensitivity.value,
                        "source": entity.source,
                    })

        # Escalation resources
        escalation_resources: list[dict] = []
        for ep in self.find_escalation_paths(subject_id):
            escalation_resources.append({
                "path_id": ep.id,
                "end_result": ep.end_result,
                "confidence": ep.confidence,
                "steps": len(ep.steps),
            })

        # Critical resources (sensitivity = critical)
        critical = [r for r in direct_resources if r["sensitivity"] == "critical"]

        # Deduplicate
        seen_ids: set[str] = set()
        unique_direct: list[dict] = []
        for r in direct_resources:
            if r["id"] not in seen_ids:
                seen_ids.add(r["id"])
                unique_direct.append(r)

        return {
            "direct_resources": unique_direct,
            "escalation_resources": escalation_resources,
            "critical_resources": critical,
            "total_reach": len(unique_direct) + len(escalation_resources),
        }

    # ---- identity correlation ----------------------------------------------

    def correlate_identities(self) -> list[dict[str, Any]]:
        """
        Match identities across systems using email, name, external_id patterns.
        Returns groups of subjects that represent the same real-world identity.
        """
        # Index by email
        by_email: dict[str, list[Subject]] = defaultdict(list)
        # Index by normalised name
        by_name: dict[str, list[Subject]] = defaultdict(list)

        for s in self._subjects.values():
            if s.type == SubjectType.GROUP:
                continue
            if s.email:
                by_email[s.email.lower().strip()].append(s)
            name_key = s.display_name.lower().strip().replace("  ", " ")
            if name_key:
                by_name[name_key].append(s)

        # Union-find to merge groups
        parent: dict[str, str] = {}

        def find(x: str) -> str:
            while parent.get(x, x) != x:
                parent[x] = parent.get(parent[x], parent[x])
                x = parent[x]
            return x

        def union(a: str, b: str) -> None:
            ra, rb = find(a), find(b)
            if ra != rb:
                parent[ra] = rb

        # Merge by email
        for email, subjects in by_email.items():
            if len(subjects) > 1:
                for s in subjects[1:]:
                    union(subjects[0].id, s.id)

        # Merge by name (only if subjects are from different sources)
        for name, subjects in by_name.items():
            sources = {s.source for s in subjects}
            if len(sources) > 1 and len(subjects) > 1:
                for s in subjects[1:]:
                    union(subjects[0].id, s.id)

        # Build groups
        groups: dict[str, list[Subject]] = defaultdict(list)
        for sid, subj in self._subjects.items():
            if subj.type == SubjectType.GROUP:
                continue
            root = find(sid)
            groups[root].append(subj)

        # Only return groups with multiple subjects (cross-system)
        results: list[dict[str, Any]] = []
        for root, subjects in groups.items():
            sources = {s.source for s in subjects}
            if len(sources) > 1:
                results.append({
                    "unified_id": root,
                    "subjects": subjects,
                    "sources": sorted(sources),
                    "emails": list({s.email for s in subjects if s.email}),
                    "names": list({s.display_name for s in subjects}),
                })

        logger.info("graph.correlation", groups=len(results))
        return results

    # ---- graph statistics --------------------------------------------------

    def get_graph_stats(self) -> dict[str, Any]:
        """Node/edge counts, sources represented, coverage metrics."""
        node_types: dict[str, int] = defaultdict(int)
        for _, data in self.graph.nodes(data=True):
            node_types[data.get("node_type", "unknown")] += 1

        edge_types: dict[str, int] = defaultdict(int)
        for _, _, data in self.graph.edges(data=True):
            edge_types[data.get("edge_type", "unknown")] += 1

        sources = {snap.source for snap in self._snapshots}

        return {
            "total_nodes": self.graph.number_of_nodes(),
            "total_edges": self.graph.number_of_edges(),
            "node_types": dict(node_types),
            "edge_types": dict(edge_types),
            "sources": sorted(sources),
            "subjects": len(self._subjects),
            "permissions": len(self._permissions),
            "resources": len(self._resources),
            "assignments": len(self._assignments),
            "escalation_paths": len(self._escalation_paths),
            "snapshots_ingested": len(self._snapshots),
        }

    # ---- graph centrality helpers ------------------------------------------

    def compute_degree_centrality(self) -> dict[str, float]:
        """Degree centrality for all subject nodes."""
        centrality = nx.degree_centrality(self.graph)
        return {
            nid.removeprefix(f"{_SUBJECT_PFX}:"): val
            for nid, val in centrality.items()
            if nid.startswith(f"{_SUBJECT_PFX}:")
        }

    def compute_betweenness_centrality(self) -> dict[str, float]:
        """Betweenness centrality for all subject nodes."""
        centrality = nx.betweenness_centrality(self.graph)
        return {
            nid.removeprefix(f"{_SUBJECT_PFX}:"): val
            for nid, val in centrality.items()
            if nid.startswith(f"{_SUBJECT_PFX}:")
        }

    def shortest_path_to_critical(self, subject_id: str) -> int:
        """Shortest path length from a subject to any critical resource."""
        subj_nid = _node_id(_SUBJECT_PFX, subject_id)
        if not self.graph.has_node(subj_nid):
            return -1

        critical_nodes = [
            nid
            for nid, data in self.graph.nodes(data=True)
            if data.get("sensitivity") == "critical"
        ]
        if not critical_nodes:
            return -1

        min_dist = float("inf")
        for cn in critical_nodes:
            try:
                dist = nx.shortest_path_length(self.graph, subj_nid, cn)
                min_dist = min(min_dist, dist)
            except nx.NetworkXNoPath:
                continue

        return int(min_dist) if min_dist != float("inf") else -1
