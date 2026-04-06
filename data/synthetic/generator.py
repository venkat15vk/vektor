"""
Vektor AI — Synthetic Data Generator

Generates realistic identity graphs with injected violations for model
pre-training. Critical for cold start: models need training data before any
customer connects.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

import structlog
from faker import Faker

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
    new_id,
    utcnow,
    vektor_id,
)
from backend.adapters.aws_iam import HIGH_RISK_ACTIONS, ESCALATION_PATTERNS
from backend.adapters.netsuite import FINANCIAL_PERMISSIONS, SOD_PAIRS
from backend.graph.store import IdentityGraph
from backend.models.bootstrap import BootstrapLabel, BootstrapLabeler
from backend.features.compute import FeatureComputer
from backend.features.store import FeatureStore

logger = structlog.get_logger(__name__)
fake = Faker()
Faker.seed(42)


@dataclass
class SyntheticConfig:
    num_humans: int = 200
    num_service_accounts: int = 50
    num_ai_agents: int = 10
    num_groups: int = 30
    num_roles: int = 80
    num_resources: int = 150
    sources: list[str] = field(default_factory=lambda: ["aws_iam", "okta", "entra", "netsuite"])

    # Violation injection rates
    sod_violation_rate: float = 0.05
    excessive_privilege_rate: float = 0.10
    dormant_access_rate: float = 0.08
    orphaned_account_rate: float = 0.03
    permission_creep_rate: float = 0.07
    missing_mfa_rate: float = 0.15
    escalation_chain_rate: float = 0.04
    cross_boundary_rate: float = 0.03
    open_trust_rate: float = 0.05
    toxic_combo_rate: float = 0.02
    breakglass_abuse_rate: float = 0.01

    seed: int = 42


# ---------------------------------------------------------------------------
# Department / Role templates
# ---------------------------------------------------------------------------
DEPARTMENTS = [
    ("Engineering", 0.40),
    ("Finance", 0.15),
    ("Sales", 0.20),
    ("Operations", 0.15),
    ("Admin", 0.10),
]

AWS_ROLE_TEMPLATES = [
    {"name": "EC2ReadOnly", "actions": ["ec2:Describe*", "ec2:List*"], "privileged": False},
    {"name": "S3FullAccess", "actions": ["s3:*"], "privileged": True},
    {"name": "LambdaDev", "actions": ["lambda:CreateFunction", "lambda:UpdateFunctionCode", "lambda:InvokeFunction"], "privileged": False},
    {"name": "IAMAdmin", "actions": ["iam:*"], "privileged": True},
    {"name": "SecurityAudit", "actions": ["iam:List*", "iam:Get*", "sts:GetCallerIdentity"], "privileged": False},
    {"name": "PowerUser", "actions": ["ec2:*", "s3:*", "lambda:*", "dynamodb:*"], "privileged": True},
    {"name": "BillingViewer", "actions": ["aws-portal:View*", "budgets:View*"], "privileged": False},
    {"name": "SecretsReader", "actions": ["secretsmanager:GetSecretValue", "kms:Decrypt"], "privileged": True},
    {"name": "CloudFormationAdmin", "actions": ["cloudformation:*", "iam:PassRole"], "privileged": True},
    {"name": "ReadOnlyAccess", "actions": ["*:Describe*", "*:Get*", "*:List*"], "privileged": False},
]

NETSUITE_ROLE_TEMPLATES = [
    {"name": "AP Clerk", "keys": ["TRAN_VENDBILL", "LIST_VENDOR"], "levels": [2, 1]},
    {"name": "AP Manager", "keys": ["TRAN_VENDBILL", "TRAN_VENDPYMT", "LIST_VENDOR"], "levels": [4, 4, 3]},
    {"name": "AR Clerk", "keys": ["TRAN_INVOICE", "LIST_CUSTJOB"], "levels": [2, 1]},
    {"name": "AR Manager", "keys": ["TRAN_INVOICE", "TRAN_CUSTPYMT", "LIST_CUSTJOB"], "levels": [4, 4, 3]},
    {"name": "GL Accountant", "keys": ["TRAN_JOURNAL", "LIST_ACCOUNT", "REPT_FINANCIALS"], "levels": [3, 1, 2]},
    {"name": "Controller", "keys": ["TRAN_JOURNAL", "LIST_ACCOUNT", "ADMI_ACCTPERIODS", "REPT_FINANCIALS"], "levels": [4, 3, 4, 4]},
    {"name": "Procurement", "keys": ["TRAN_PURCHORD", "LIST_VENDOR"], "levels": [3, 2]},
    {"name": "Payroll Admin", "keys": ["TRAN_PAYROLL"], "levels": [4]},
    {"name": "Admin", "keys": ["ADMI_SETUP", "ADMI_ACCTPERIODS"], "levels": [4, 4]},
    {"name": "Viewer", "keys": ["REPT_FINANCIALS"], "levels": [1]},
]

OKTA_GROUP_TEMPLATES = [
    "Engineering", "Finance", "Sales", "Ops", "Admins",
    "AWS-Console-Users", "VPN-Users", "GitHub-Users", "Slack-Users", "Jira-Users",
]

ENTRA_ROLE_TEMPLATES = [
    "Global Administrator", "User Administrator", "Application Administrator",
    "Security Reader", "Helpdesk Administrator", "Exchange Administrator",
    "SharePoint Administrator", "Compliance Administrator",
]


class SyntheticDataGenerator:
    """Generates realistic identity graphs with injected violations."""

    def __init__(self, config: SyntheticConfig | None = None) -> None:
        self.config = config or SyntheticConfig()
        random.seed(self.config.seed)
        self._ground_truth: dict[str, list[BootstrapLabel]] = {}

    def generate(
        self, config: SyntheticConfig | None = None
    ) -> tuple[IdentityGraph, dict[str, list[BootstrapLabel]]]:
        """
        Generate a synthetic identity graph with known violations.
        Returns: (graph, ground_truth_labels)
        """
        cfg = config or self.config
        random.seed(cfg.seed)
        self._ground_truth = {}

        logger.info("synthetic.generate.start", config=cfg)

        graph = IdentityGraph()

        # Generate snapshots per source
        for source in cfg.sources:
            snapshot = self._generate_source_snapshot(source, cfg)
            graph.ingest(snapshot)

        # Inject violations (mutates the graph in place)
        self._inject_violations(graph, cfg)

        logger.info(
            "synthetic.generate.done",
            stats=graph.get_graph_stats(),
            violations=sum(len(v) for v in self._ground_truth.values()),
        )
        return graph, self._ground_truth

    def _generate_source_snapshot(
        self, source: str, cfg: SyntheticConfig
    ) -> GraphSnapshot:
        """Generate a snapshot for a single source system."""
        subjects: list[Subject] = []
        permissions: list[Permission] = []
        resources: list[Resource] = []
        assignments: list[Assignment] = []

        # Scale per source (not all identities in all systems)
        scale = random.uniform(0.5, 1.0)
        n_humans = int(cfg.num_humans * scale)
        n_svc = int(cfg.num_service_accounts * scale * 0.5)
        n_agents = int(cfg.num_ai_agents * scale * 0.3)
        n_groups = int(cfg.num_groups * scale * 0.5)

        # 1. Generate org hierarchy
        departments = self._pick_departments(n_humans)

        # 2. Generate human subjects
        manager_ids: list[str] = []
        for i in range(n_humans):
            dept = departments[i]
            is_manager = random.random() < 0.15
            mgr = random.choice(manager_ids) if manager_ids and not is_manager else None

            subj = Subject(
                id=vektor_id(source, f"human-{i}"),
                external_id=f"{source}-user-{i}",
                source=source,
                type=SubjectType.HUMAN,
                display_name=fake.name(),
                email=fake.email(),
                department=dept,
                manager_id=mgr,
                status=SubjectStatus.ACTIVE,
                last_seen=utcnow() - timedelta(days=random.randint(0, 30)),
                mfa_enabled=random.random() > 0.2,  # 80% have MFA
                created_at=utcnow() - timedelta(days=random.randint(30, 1000)),
            )
            subjects.append(subj)
            if is_manager:
                manager_ids.append(subj.id)

        # 3. Generate service accounts
        for i in range(n_svc):
            subjects.append(Subject(
                id=vektor_id(source, f"svc-{i}"),
                external_id=f"{source}-svc-{i}",
                source=source,
                type=SubjectType.SERVICE_ACCOUNT,
                display_name=f"svc-{fake.slug()}-{i}",
                status=SubjectStatus.ACTIVE,
                last_seen=utcnow() - timedelta(days=random.randint(0, 10)),
                created_at=utcnow() - timedelta(days=random.randint(60, 800)),
            ))

        # 4. Generate AI agents
        for i in range(n_agents):
            subjects.append(Subject(
                id=vektor_id(source, f"agent-{i}"),
                external_id=f"{source}-agent-{i}",
                source=source,
                type=SubjectType.AI_AGENT,
                display_name=f"ai-agent-{fake.word()}-{i}",
                status=SubjectStatus.ACTIVE,
                created_at=utcnow() - timedelta(days=random.randint(10, 200)),
            ))

        # 5. Generate permissions (source-specific)
        permissions = self._generate_permissions(source, cfg.num_roles)

        # 6. Generate groups
        for i in range(n_groups):
            g_name = random.choice(OKTA_GROUP_TEMPLATES) if source == "okta" else f"group-{i}"
            subjects.append(Subject(
                id=vektor_id(source, f"group-{i}"),
                external_id=f"{source}-group-{i}",
                source=source,
                type=SubjectType.GROUP,
                display_name=g_name,
                status=SubjectStatus.ACTIVE,
            ))

        # 7. Generate resources
        resources = self._generate_resources(source, cfg.num_resources)

        # 8. Generate normal assignments
        for subj in subjects:
            if subj.type == SubjectType.GROUP:
                continue
            # Each subject gets 2-8 random permissions
            n_perms = random.randint(2, min(8, len(permissions)))
            chosen = random.sample(permissions, n_perms)
            for perm in chosen:
                res_id = random.choice(resources).id if resources and random.random() > 0.5 else None
                assignments.append(Assignment(
                    subject_id=subj.id,
                    permission_id=perm.id,
                    resource_id=res_id,
                    source=source,
                    granted_at=utcnow() - timedelta(days=random.randint(1, 365)),
                    granted_by=random.choice(["system", "admin@company.com", "automation", None]),
                    last_used=utcnow() - timedelta(days=random.randint(0, 90)) if random.random() > 0.3 else None,
                    is_active=True,
                ))

        return GraphSnapshot(
            source=source,
            subjects=subjects,
            permissions=permissions,
            resources=resources,
            assignments=assignments,
        )

    def _generate_permissions(self, source: str, count: int) -> list[Permission]:
        perms: list[Permission] = []
        if source == "aws_iam":
            for i, tmpl in enumerate(AWS_ROLE_TEMPLATES):
                perms.append(Permission(
                    id=vektor_id(source, f"policy-{tmpl['name']}"),
                    source=source,
                    name=tmpl["name"],
                    type=PermissionType.POLICY,
                    actions=tmpl["actions"],
                    resources=["*"],
                    is_privileged=tmpl["privileged"],
                    risk_keywords=["admin"] if tmpl["privileged"] else [],
                ))
        elif source == "netsuite":
            for tmpl in NETSUITE_ROLE_TEMPLATES:
                actions = [f"netsuite:{k}.{['none','view','create','edit','full'][l]}"
                           for k, l in zip(tmpl["keys"], tmpl["levels"])]
                perms.append(Permission(
                    id=vektor_id(source, f"role-{tmpl['name']}"),
                    source=source,
                    name=tmpl["name"],
                    type=PermissionType.ROLE,
                    actions=actions,
                    is_privileged=any(l >= 3 for l in tmpl["levels"]),
                    attributes={
                        "permission_keys": tmpl["keys"],
                        "permission_levels": dict(zip(tmpl["keys"], tmpl["levels"])),
                    },
                ))
        elif source == "okta":
            for gname in OKTA_GROUP_TEMPLATES:
                perms.append(Permission(
                    id=vektor_id(source, f"group-{gname}"),
                    source=source,
                    name=gname,
                    type=PermissionType.GROUP,
                    is_privileged="Admin" in gname,
                ))
        elif source == "entra":
            for rname in ENTRA_ROLE_TEMPLATES:
                perms.append(Permission(
                    id=vektor_id(source, f"role-{rname}"),
                    source=source,
                    name=rname,
                    type=PermissionType.ROLE,
                    actions=[rname],
                    is_privileged="Administrator" in rname,
                ))

        # Pad with generic roles if needed
        while len(perms) < count // len(self.config.sources):
            i = len(perms)
            perms.append(Permission(
                id=vektor_id(source, f"perm-{i}"),
                source=source,
                name=f"{source}-role-{i}",
                type=PermissionType.ROLE,
                actions=[f"{source}:action-{j}" for j in range(random.randint(1, 5))],
                is_privileged=random.random() < 0.1,
            ))

        return perms

    def _generate_resources(self, source: str, count: int) -> list[Resource]:
        resources: list[Resource] = []
        n = count // len(self.config.sources)

        if source == "aws_iam":
            types_and_sens = [
                ("s3_bucket", Sensitivity.HIGH),
                ("lambda_function", Sensitivity.MEDIUM),
                ("ec2_instance", Sensitivity.MEDIUM),
                ("secrets_manager_secret", Sensitivity.CRITICAL),
                ("kms_key", Sensitivity.CRITICAL),
                ("rds_instance", Sensitivity.HIGH),
            ]
        elif source == "netsuite":
            types_and_sens = [
                ("netsuite_module", Sensitivity.CRITICAL),
                ("netsuite_subsidiary", Sensitivity.HIGH),
            ]
        elif source == "okta":
            types_and_sens = [
                ("okta_application", Sensitivity.MEDIUM),
            ]
        else:
            types_and_sens = [
                ("entra_application", Sensitivity.MEDIUM),
            ]

        for i in range(n):
            rtype, sens = random.choice(types_and_sens)
            resources.append(Resource(
                id=vektor_id(source, f"res-{i}"),
                source=source,
                type=rtype,
                name=f"{rtype}-{fake.slug()}-{i}",
                sensitivity=sens,
            ))

        return resources

    def _pick_departments(self, n: int) -> list[str]:
        depts: list[str] = []
        for dept, weight in DEPARTMENTS:
            depts.extend([dept] * int(n * weight))
        while len(depts) < n:
            depts.append(random.choice([d for d, _ in DEPARTMENTS]))
        random.shuffle(depts)
        return depts[:n]

    # ------------------------------------------------------------------
    # Violation injection
    # ------------------------------------------------------------------

    def _inject_violations(self, graph: IdentityGraph, cfg: SyntheticConfig) -> None:
        """Inject known violations into the graph and record ground truth."""
        subjects = [s for s in graph.get_all_subjects() if s.type != SubjectType.GROUP]
        random.shuffle(subjects)

        idx = 0

        # SoD violations
        n = int(len(subjects) * cfg.sod_violation_rate)
        for subj in subjects[idx:idx + n]:
            self._inject_sod(graph, subj)
        idx += n

        # Excessive privilege
        n = int(len(subjects) * cfg.excessive_privilege_rate)
        for subj in subjects[idx:idx + n]:
            self._inject_excessive_privilege(graph, subj)
        idx += n

        # Dormant access
        n = int(len(subjects) * cfg.dormant_access_rate)
        for subj in subjects[idx:idx + n]:
            self._inject_dormant(graph, subj)
        idx += n

        # Orphaned accounts
        n = int(len(subjects) * cfg.orphaned_account_rate)
        for subj in subjects[idx:idx + n]:
            self._inject_orphaned(graph, subj)
        idx += n

        # Escalation chains
        n = int(len(subjects) * cfg.escalation_chain_rate)
        for subj in subjects[idx:idx + n]:
            self._inject_escalation(graph, subj)
        idx += n

        # Missing MFA (on top of existing, targeted at privileged)
        n = int(len(subjects) * cfg.missing_mfa_rate)
        for subj in subjects[idx:idx + n]:
            self._inject_missing_mfa(graph, subj)
        idx += n

        # Open trust
        n = int(len(subjects) * cfg.open_trust_rate)
        for subj in subjects[idx:idx + n]:
            self._inject_open_trust(graph, subj)
        idx += n

        # Toxic combos
        n = int(len(subjects) * cfg.toxic_combo_rate)
        for subj in subjects[idx:idx + n]:
            self._inject_toxic_combo(graph, subj)
        idx += n

        # Break-glass abuse
        n = int(len(subjects) * cfg.breakglass_abuse_rate)
        for subj in subjects[idx:idx + n]:
            self._inject_breakglass(graph, subj)
        idx += n

    def _record(self, label: BootstrapLabel) -> None:
        self._ground_truth.setdefault(label.subject_id, []).append(label)

    def _inject_sod(self, graph: IdentityGraph, subj: Subject) -> None:
        pair = random.choice(SOD_PAIRS)
        for key in pair:
            perm = Permission(
                id=new_id(),
                source=subj.source,
                name=f"SoD-{key}",
                type=PermissionType.ROLE,
                actions=[f"netsuite:{key}.full"],
                is_privileged=True,
                attributes={"permission_keys": [key], "permission_levels": {key: 4}},
            )
            graph._permissions[perm.id] = perm
            assign = Assignment(
                subject_id=subj.id, permission_id=perm.id,
                source=subj.source, is_active=True,
                granted_at=utcnow() - timedelta(days=random.randint(1, 200)),
            )
            graph._assignments[assign.id] = assign

        self._record(BootstrapLabel(
            subject_id=subj.id, violation_class=1, label=1,
            confidence=0.95, rule_id="SYNTH-SOD",
            evidence={"sod_pair": list(pair)},
            source_systems=[subj.source],
        ))

    def _inject_excessive_privilege(self, graph: IdentityGraph, subj: Subject) -> None:
        # Add 15+ extra permissions
        for i in range(15):
            perm = Permission(
                id=new_id(), source=subj.source,
                name=f"ExcessPerm-{i}", type=PermissionType.POLICY,
                actions=[f"extra:action-{i}"],
                is_privileged=random.random() < 0.3,
            )
            graph._permissions[perm.id] = perm
            assign = Assignment(
                subject_id=subj.id, permission_id=perm.id,
                source=subj.source, is_active=True,
            )
            graph._assignments[assign.id] = assign

        self._record(BootstrapLabel(
            subject_id=subj.id, violation_class=3, label=1,
            confidence=0.8, rule_id="SYNTH-EP",
            evidence={"extra_permissions": 15},
            source_systems=[subj.source],
        ))

    def _inject_dormant(self, graph: IdentityGraph, subj: Subject) -> None:
        subj.last_seen = utcnow() - timedelta(days=random.randint(100, 365))
        # Ensure they have privileged permissions
        perm = Permission(
            id=new_id(), source=subj.source,
            name="DormantPrivRole", type=PermissionType.ROLE,
            actions=["iam:*"], is_privileged=True,
        )
        graph._permissions[perm.id] = perm
        assign = Assignment(
            subject_id=subj.id, permission_id=perm.id,
            source=subj.source, is_active=True,
        )
        graph._assignments[assign.id] = assign

        self._record(BootstrapLabel(
            subject_id=subj.id, violation_class=4, label=1,
            confidence=0.9, rule_id="SYNTH-DORMANT",
            evidence={"days_inactive": (utcnow() - subj.last_seen).days},
            source_systems=[subj.source],
        ))

    def _inject_orphaned(self, graph: IdentityGraph, subj: Subject) -> None:
        subj.status = SubjectStatus.DELETED
        # But keep active assignments
        self._record(BootstrapLabel(
            subject_id=subj.id, violation_class=5, label=1,
            confidence=0.85, rule_id="SYNTH-ORPHAN",
            evidence={"status": "deleted", "has_active_assignments": True},
            source_systems=[subj.source],
        ))

    def _inject_escalation(self, graph: IdentityGraph, subj: Subject) -> None:
        pattern = random.choice(ESCALATION_PATTERNS)
        for action in pattern["actions"]:
            perm = Permission(
                id=new_id(), source=subj.source,
                name=f"EscPerm-{action}", type=PermissionType.POLICY,
                actions=[action], is_privileged=True,
            )
            graph._permissions[perm.id] = perm
            assign = Assignment(
                subject_id=subj.id, permission_id=perm.id,
                source=subj.source, is_active=True,
            )
            graph._assignments[assign.id] = assign

        ep = EscalationPath(
            subject_id=subj.id,
            steps=[EscalationStep(action=a, resource="*", description=f"Has {a}")
                   for a in sorted(pattern["actions"])],
            end_result=pattern["end_result"],
            confidence=pattern["confidence"],
            source=subj.source,
        )
        graph._escalation_paths.append(ep)

        self._record(BootstrapLabel(
            subject_id=subj.id, violation_class=2, label=1,
            confidence=pattern["confidence"], rule_id="SYNTH-ESC",
            evidence={"pattern": pattern["name"]},
            source_systems=[subj.source],
        ))

    def _inject_missing_mfa(self, graph: IdentityGraph, subj: Subject) -> None:
        if subj.type != SubjectType.HUMAN:
            return
        subj.mfa_enabled = False
        self._record(BootstrapLabel(
            subject_id=subj.id, violation_class=8, label=1,
            confidence=0.7, rule_id="SYNTH-MFA",
            evidence={"mfa_enabled": False},
            source_systems=[subj.source],
        ))

    def _inject_open_trust(self, graph: IdentityGraph, subj: Subject) -> None:
        if subj.source != "aws_iam":
            subj.attributes["source_override"] = "aws_iam"
        subj.attributes["trust_policy_open"] = True
        self._record(BootstrapLabel(
            subject_id=subj.id, violation_class=7, label=1,
            confidence=0.95, rule_id="SYNTH-OPEN-TRUST",
            evidence={"trust_policy_open": True},
            source_systems=[subj.source],
        ))

    def _inject_toxic_combo(self, graph: IdentityGraph, subj: Subject) -> None:
        # Give security + financial admin roles
        sec_perm = Permission(
            id=new_id(), source=subj.source,
            name="SecurityAdmin", type=PermissionType.ROLE,
            actions=["iam:*", "guardduty:*"], is_privileged=True,
        )
        fin_perm = Permission(
            id=new_id(), source=subj.source,
            name="FinanceAdmin", type=PermissionType.ROLE,
            actions=["netsuite:TRAN_JOURNAL.full", "netsuite:ADMI_SETUP.full"],
            is_privileged=True,
        )
        for p in (sec_perm, fin_perm):
            graph._permissions[p.id] = p
            assign = Assignment(
                subject_id=subj.id, permission_id=p.id,
                source=subj.source, is_active=True,
            )
            graph._assignments[assign.id] = assign

        self._record(BootstrapLabel(
            subject_id=subj.id, violation_class=13, label=1,
            confidence=0.9, rule_id="SYNTH-TOXIC",
            evidence={"security_admin": True, "financial_admin": True},
            source_systems=[subj.source],
        ))

    def _inject_breakglass(self, graph: IdentityGraph, subj: Subject) -> None:
        perm = Permission(
            id=new_id(), source=subj.source,
            name="emergency-break-glass-admin", type=PermissionType.ROLE,
            actions=["iam:*", "s3:*", "ec2:*"], is_privileged=True,
        )
        graph._permissions[perm.id] = perm
        assign = Assignment(
            subject_id=subj.id, permission_id=perm.id,
            source=subj.source, is_active=True,
            granted_at=utcnow() - timedelta(days=random.randint(3, 30)),
        )
        graph._assignments[assign.id] = assign

        self._record(BootstrapLabel(
            subject_id=subj.id, violation_class=14, label=1,
            confidence=0.9, rule_id="SYNTH-BGA",
            evidence={"role": "emergency-break-glass-admin", "days_held": (utcnow() - assign.granted_at).days},
            source_systems=[subj.source],
        ))
