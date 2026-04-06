"""
Vektor AI — Local File Adapter

Reads real AWS IAM policy data from local JSON files (e.g., MAMIP dataset)
and produces the same GraphSnapshot that the live AWS IAM adapter would.

This adapter is a drop-in replacement for the AWS IAM adapter during local
testing. The rest of the pipeline (graph → features → models → signals)
doesn't know or care that the data came from disk instead of the AWS API.

Data sources:
  - MAMIP policies (demo/data/aws_policies/*.json) — real AWS managed policies
  - Simulated IAM users/roles with realistic assignments

The adapter:
  1. Reads every policy JSON → Permission objects
  2. Creates realistic Subject objects (users, roles, service accounts)
     assigned to those real policies
  3. Detects escalation paths using real policy action sets
  4. Returns a complete GraphSnapshot
"""

from __future__ import annotations

import json
import random
import re
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

SOURCE = "aws_iam"  # Same source as live adapter — data format is identical

# ---------------------------------------------------------------------------
# Escalation patterns (same as aws_iam.py — detecting real privilege chains)
# ---------------------------------------------------------------------------
ESCALATION_PATTERNS: list[dict[str, Any]] = [
    {
        "name": "CreateRole + AttachRolePolicy + AssumeRole",
        "actions": {"iam:CreateRole", "iam:AttachRolePolicy", "sts:AssumeRole"},
        "confidence": 0.99,
        "end_result": "Can create an IAM role, attach an admin policy, and assume it",
    },
    {
        "name": "CreateRole + PutRolePolicy + AssumeRole",
        "actions": {"iam:CreateRole", "iam:PutRolePolicy", "sts:AssumeRole"},
        "confidence": 0.99,
        "end_result": "Can create an IAM role with inline admin policy and assume it",
    },
    {
        "name": "CreateUser + AttachUserPolicy",
        "actions": {"iam:CreateUser", "iam:AttachUserPolicy"},
        "confidence": 0.90,
        "end_result": "Can create a new IAM user with arbitrary policies",
    },
    {
        "name": "PassRole + Lambda",
        "actions": {"iam:PassRole", "lambda:CreateFunction"},
        "confidence": 0.95,
        "end_result": "Can pass a high-privilege role to a Lambda and execute it",
    },
    {
        "name": "PassRole + EC2",
        "actions": {"iam:PassRole", "ec2:RunInstances"},
        "confidence": 0.90,
        "end_result": "Can pass a high-privilege role to an EC2 instance",
    },
    {
        "name": "CreateAccessKey for other users",
        "actions": {"iam:CreateAccessKey"},
        "confidence": 0.80,
        "end_result": "Can create access keys for other IAM users (credential theft)",
    },
    {
        "name": "UpdateAssumeRolePolicy + AssumeRole",
        "actions": {"iam:UpdateAssumeRolePolicy", "sts:AssumeRole"},
        "confidence": 0.95,
        "end_result": "Can modify trust policy of existing role and assume it",
    },
]

HIGH_RISK_ACTIONS: set[str] = {
    "iam:CreateRole", "iam:AttachRolePolicy", "iam:PutRolePolicy",
    "iam:CreateUser", "iam:AttachUserPolicy", "iam:PutUserPolicy",
    "iam:PassRole", "iam:CreateAccessKey", "iam:UpdateAssumeRolePolicy",
    "sts:AssumeRole", "iam:AddUserToGroup", "iam:CreatePolicy",
    "iam:CreatePolicyVersion", "lambda:CreateFunction",
    "lambda:UpdateFunctionCode", "lambda:InvokeFunction",
    "s3:PutBucketPolicy", "s3:DeleteBucket", "ec2:RunInstances",
    "secretsmanager:GetSecretValue", "kms:Decrypt", "iam:*", "sts:*",
}

# ---------------------------------------------------------------------------
# Realistic IAM entity templates
# ---------------------------------------------------------------------------

# Departments for simulated users
DEPARTMENTS = [
    "Engineering", "DevOps", "Security", "Finance", "Data Science",
    "Platform", "Infrastructure", "Product", "SRE", "Compliance",
]

# Realistic IAM user templates — these get assigned real MAMIP policies
USER_TEMPLATES = [
    {"name": "alice.johnson", "dept": "Engineering", "type": "human", "role": "developer"},
    {"name": "bob.chen", "dept": "DevOps", "type": "human", "role": "devops_engineer"},
    {"name": "carol.martinez", "dept": "Security", "type": "human", "role": "security_analyst"},
    {"name": "dave.kumar", "dept": "Finance", "type": "human", "role": "finance_manager"},
    {"name": "eve.wilson", "dept": "Data Science", "type": "human", "role": "data_scientist"},
    {"name": "frank.lee", "dept": "Platform", "type": "human", "role": "platform_engineer"},
    {"name": "grace.taylor", "dept": "Infrastructure", "type": "human", "role": "infra_lead"},
    {"name": "henry.garcia", "dept": "SRE", "type": "human", "role": "sre_engineer"},
    {"name": "iris.patel", "dept": "Compliance", "type": "human", "role": "compliance_officer"},
    {"name": "jack.brown", "dept": "Engineering", "type": "human", "role": "senior_developer"},
    {"name": "karen.smith", "dept": "DevOps", "type": "human", "role": "devops_lead"},
    {"name": "leo.wang", "dept": "Engineering", "type": "human", "role": "intern"},
    # Service accounts
    {"name": "svc-deploy-prod", "dept": "DevOps", "type": "service_account", "role": "deployment_service"},
    {"name": "svc-monitoring", "dept": "SRE", "type": "service_account", "role": "monitoring_service"},
    {"name": "svc-data-pipeline", "dept": "Data Science", "type": "service_account", "role": "data_pipeline"},
    {"name": "svc-backup", "dept": "Infrastructure", "type": "service_account", "role": "backup_service"},
    {"name": "svc-ci-runner", "dept": "Engineering", "type": "service_account", "role": "ci_runner"},
    {"name": "svc-lambda-exec", "dept": "Platform", "type": "service_account", "role": "lambda_executor"},
    # AI agents
    {"name": "agent-cost-optimizer", "dept": "Platform", "type": "ai_agent", "role": "cost_agent"},
    {"name": "agent-security-scanner", "dept": "Security", "type": "ai_agent", "role": "security_agent"},
]

# Policy assignment map — which policies each role should get
# These reference real MAMIP policy names (without .json extension)
ROLE_POLICY_MAP: dict[str, list[str]] = {
    "developer": [
        "AmazonS3ReadOnlyAccess", "AmazonDynamoDBReadOnlyAccess",
        "CloudWatchLogsReadOnlyAccess", "AWSCodeCommitReadOnly",
    ],
    "devops_engineer": [
        "AmazonEC2FullAccess", "AmazonS3FullAccess",
        "AmazonECS_FullAccess", "CloudWatchFullAccess",
        "AWSCodeBuildAdminAccess", "AWSCodeDeployFullAccess",
    ],
    "security_analyst": [
        "SecurityAudit", "AmazonGuardDutyReadOnlyAccess",
        "AWSSecurityHubReadOnlyAccess", "AmazonInspector2ReadOnlyAccess",
        "CloudWatchLogsReadOnlyAccess",
    ],
    "finance_manager": [
        "AWSBillingReadOnlyAccess", "AWSCostAndUsageReportAutomationPolicy",
    ],
    "data_scientist": [
        "AmazonSageMakerFullAccess", "AmazonS3FullAccess",
        "AmazonAthenaFullAccess", "AWSGlueConsoleFullAccess",
    ],
    "platform_engineer": [
        "AmazonEKSClusterPolicy", "AmazonEC2FullAccess",
        "AmazonVPCFullAccess", "ElasticLoadBalancingFullAccess",
    ],
    "infra_lead": [
        # OVERPRIVILEGED — this is an intentional finding for Vektor to detect
        "AdministratorAccess",
    ],
    "sre_engineer": [
        "AmazonEC2FullAccess", "CloudWatchFullAccess",
        "AmazonRoute53FullAccess", "AmazonSNSFullAccess",
    ],
    "compliance_officer": [
        "SecurityAudit", "AWSConfigRole",
        "AWSCloudTrailReadOnlyAccess",
    ],
    "senior_developer": [
        "AmazonS3FullAccess", "AmazonDynamoDBFullAccess",
        "AWSLambda_FullAccess", "AmazonSQSFullAccess",
        "AmazonSNSFullAccess",
    ],
    "devops_lead": [
        # OVERPRIVILEGED — intentional finding
        "AdministratorAccess", "IAMFullAccess",
    ],
    "intern": [
        "AmazonS3ReadOnlyAccess", "CloudWatchLogsReadOnlyAccess",
    ],
    "deployment_service": [
        # OVERPRIVILEGED SERVICE ACCOUNT — intentional finding
        "AdministratorAccess",
    ],
    "monitoring_service": [
        "CloudWatchReadOnlyAccess", "AmazonEC2ReadOnlyAccess",
    ],
    "data_pipeline": [
        "AmazonS3FullAccess", "AWSGlueServiceRole",
        "AmazonAthenaFullAccess",
    ],
    "backup_service": [
        "AWSBackupFullAccess", "AmazonS3FullAccess",
    ],
    "ci_runner": [
        "AmazonEC2ContainerRegistryFullAccess", "AWSCodeBuildAdminAccess",
        "AmazonS3FullAccess", "AWSLambda_FullAccess",
    ],
    "lambda_executor": [
        "AWSLambda_FullAccess", "AmazonDynamoDBFullAccess",
        "AmazonSQSFullAccess",
    ],
    "cost_agent": [
        # AI AGENT with too much access — intentional finding
        "AmazonEC2FullAccess", "AWSBillingReadOnlyAccess",
        "AmazonRDSFullAccess",
    ],
    "security_agent": [
        "SecurityAudit", "AmazonGuardDutyFullAccess",
        "AWSSecurityHubFullAccess",
    ],
}


class LocalFileAdapter(BaseAdapter):
    """
    Reads real AWS managed IAM policies from local JSON files and builds
    a realistic identity graph. Drop-in replacement for the live AWS adapter.
    """

    source_name = SOURCE

    def __init__(self, policies_dir: str | Path, seed: int = 42) -> None:
        self._policies_dir = Path(policies_dir)
        self._seed = seed
        self._connected = False

    async def connect(self, credentials: dict | None = None) -> None:
        """No credentials needed — just verify directory exists."""
        if not self._policies_dir.exists():
            raise FileNotFoundError(f"Policies directory not found: {self._policies_dir}")
        policy_files = list(self._policies_dir.glob("*.json"))
        if not policy_files:
            raise FileNotFoundError(f"No JSON policy files in {self._policies_dir}")
        self._connected = True
        logger.info("local_adapter.connected", policies_dir=str(self._policies_dir),
                     policy_count=len(policy_files))

    async def test_connection(self) -> bool:
        return self._connected and self._policies_dir.exists()

    async def extract(self) -> GraphSnapshot:
        """
        Full extraction:
          1. Load real MAMIP policy JSONs → Permission objects
          2. Create realistic Subjects with deterministic assignments
          3. Detect escalation paths from real action sets
          4. Return GraphSnapshot
        """
        if not self._connected:
            await self.connect()

        random.seed(self._seed)
        now = utcnow()

        # ── Step 1: Load all real policies ──────────────────────────
        permissions: list[Permission] = []
        perm_by_name: dict[str, Permission] = {}

        for pf in sorted(self._policies_dir.glob("*.json")):
            try:
                perm = self._parse_policy_file(pf)
                if perm:
                    permissions.append(perm)
                    # Index by policy name (filename without .json)
                    perm_by_name[pf.stem] = perm
            except Exception as e:
                logger.debug("local_adapter.skip_policy", file=pf.name, error=str(e))

        logger.info("local_adapter.policies_loaded", count=len(permissions))

        # ── Step 2: Create subjects ─────────────────────────────────
        subjects: list[Subject] = []
        for tmpl in USER_TEMPLATES:
            subj_type = {
                "human": SubjectType.HUMAN,
                "service_account": SubjectType.SERVICE_ACCOUNT,
                "ai_agent": SubjectType.AI_AGENT,
            }[tmpl["type"]]

            # Vary account ages and last_seen for realism
            age_days = random.randint(30, 1200)
            # Some users are stale (haven't been seen in months)
            is_stale = random.random() < 0.15
            last_seen_offset = random.randint(120, 400) if is_stale else random.randint(0, 14)

            subj = Subject(
                id=vektor_id(SOURCE, tmpl["name"]),
                external_id=tmpl["name"],
                source=SOURCE,
                type=subj_type,
                display_name=tmpl["name"],
                email=f"{tmpl['name']}@acme-corp.com" if subj_type == SubjectType.HUMAN else None,
                department=tmpl["dept"],
                status=SubjectStatus.ACTIVE,
                last_seen=now - timedelta(days=last_seen_offset),
                mfa_enabled=(subj_type == SubjectType.HUMAN and random.random() > 0.2),
                attributes={"role_template": tmpl["role"], "account_age_days": age_days},
                created_at=now - timedelta(days=age_days),
            )
            subjects.append(subj)

        # ── Step 3: Create assignments (real policies → subjects) ───
        assignments: list[Assignment] = []
        for subj, tmpl in zip(subjects, USER_TEMPLATES):
            role_key = tmpl["role"]
            policy_names = ROLE_POLICY_MAP.get(role_key, [])

            for pname in policy_names:
                perm = perm_by_name.get(pname)
                if not perm:
                    # Policy not in our downloaded set — skip
                    continue

                # Vary grant dates
                grant_age = random.randint(7, 600)
                # Usage: some assignments were never used (finding: unused permission)
                was_used = random.random() > 0.25
                last_used = (now - timedelta(days=random.randint(0, 30))
                             if was_used else None)

                assignment = Assignment(
                    subject_id=subj.id,
                    permission_id=perm.id,
                    source=SOURCE,
                    granted_at=now - timedelta(days=grant_age),
                    last_used=last_used,
                    is_active=True,
                )
                assignments.append(assignment)

        # ── Step 4: Create resources ────────────────────────────────
        resources = self._create_resources(now)

        # ── Step 5: Detect escalation paths from real action sets ───
        escalation_paths: list[EscalationPath] = []
        for subj in subjects:
            # Collect all actions this subject has via their assigned policies
            subj_actions: set[str] = set()
            for a in assignments:
                if a.subject_id == subj.id:
                    perm = next((p for p in permissions if p.id == a.permission_id), None)
                    if perm:
                        subj_actions.update(perm.actions)

            # Check escalation patterns
            for pattern in ESCALATION_PATTERNS:
                if pattern["actions"].issubset(subj_actions):
                    ep = EscalationPath(
                        subject_id=subj.id,
                        steps=[
                            EscalationStep(
                                action=act,
                                resource="*",
                                description=f"Subject can perform {act}",
                            )
                            for act in sorted(pattern["actions"])
                        ],
                        end_result=pattern["end_result"],
                        confidence=pattern["confidence"],
                        source=SOURCE,
                    )
                    escalation_paths.append(ep)

        logger.info(
            "local_adapter.extract.done",
            subjects=len(subjects),
            permissions=len(permissions),
            resources=len(resources),
            assignments=len(assignments),
            escalation_paths=len(escalation_paths),
        )

        return GraphSnapshot(
            source=SOURCE,
            subjects=subjects,
            permissions=permissions,
            resources=resources,
            assignments=assignments,
            escalation_paths=escalation_paths,
        )

    # ── Internal helpers ────────────────────────────────────────────

    def _parse_policy_file(self, path: Path) -> Permission | None:
        """Parse a MAMIP policy JSON file into a Permission object."""
        with open(path) as f:
            data = json.load(f)

        # Strip .json from filename to get policy name
        policy_name = path.stem
        if policy_name.endswith(".json"):
            policy_name = policy_name[:-5]

        # MAMIP actual format: {"PolicyVersion": {"Document": {...}, ...}}
        # Also handle: {"document": {...}} and direct {"Version": ..., "Statement": [...]}
        doc = None
        if "PolicyVersion" in data:
            doc = data["PolicyVersion"].get("Document")
        elif "document" in data:
            doc = data["document"]
        elif "Statement" in data:
            doc = data

        if not doc:
            return None

        statements = doc.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]

        # Extract all actions and resources from Allow statements
        actions: set[str] = set()
        resources: set[str] = set()
        for stmt in statements:
            if stmt.get("Effect") != "Allow":
                continue

            # Actions
            stmt_actions = stmt.get("Action", [])
            if isinstance(stmt_actions, str):
                stmt_actions = [stmt_actions]
            for a in stmt_actions:
                actions.add(a)

            # Resources
            stmt_resources = stmt.get("Resource", [])
            if isinstance(stmt_resources, str):
                stmt_resources = [stmt_resources]
            for r in stmt_resources:
                resources.add(r)

        if not actions:
            return None

        # Determine if this is a privileged policy
        is_privileged = False
        risk_keywords: list[str] = []

        for action in actions:
            if action in HIGH_RISK_ACTIONS or action == "*":
                is_privileged = True
            # Check for wildcard service permissions
            if action.endswith(":*") or action == "*":
                is_privileged = True
                risk_keywords.append(f"wildcard:{action}")
            # Check for high-risk prefixes
            if any(action.startswith(prefix) for prefix in ["iam:", "sts:", "organizations:"]):
                if any(kw in action.lower() for kw in ["create", "delete", "attach", "put", "update"]):
                    risk_keywords.append(action)

        # Use MAMIP metadata if available
        if data.get("privesc"):
            is_privileged = True
            risk_keywords.append("mamip:privesc")
        if data.get("resource_exposure"):
            risk_keywords.append("mamip:resource_exposure")
        if data.get("credentials_exposure"):
            risk_keywords.append("mamip:credentials_exposure")

        return Permission(
            id=vektor_id(SOURCE, f"policy:{policy_name}"),
            source=SOURCE,
            name=policy_name,
            type=PermissionType.POLICY,
            actions=sorted(actions),
            resources=sorted(resources),
            is_privileged=is_privileged,
            risk_keywords=risk_keywords,
            attributes={
                "policy_type": "aws_managed",
                "action_count": len(actions),
                "resource_count": len(resources),
                "has_wildcard_action": "*" in actions,
                "has_wildcard_resource": "*" in resources,
                "deprecated": data.get("deprecated", False),
            },
        )

    def _create_resources(self, now: datetime) -> list[Resource]:
        """Create realistic AWS resource objects."""
        resources = [
            Resource(
                id=vektor_id(SOURCE, "s3:acme-prod-data"),
                source=SOURCE, type="s3_bucket", name="acme-prod-data",
                sensitivity=Sensitivity.CRITICAL,
                attributes={"arn": "arn:aws:s3:::acme-prod-data", "region": "us-east-1"},
            ),
            Resource(
                id=vektor_id(SOURCE, "s3:acme-logs"),
                source=SOURCE, type="s3_bucket", name="acme-logs",
                sensitivity=Sensitivity.HIGH,
                attributes={"arn": "arn:aws:s3:::acme-logs", "region": "us-east-1"},
            ),
            Resource(
                id=vektor_id(SOURCE, "s3:acme-backups"),
                source=SOURCE, type="s3_bucket", name="acme-backups",
                sensitivity=Sensitivity.HIGH,
                attributes={"arn": "arn:aws:s3:::acme-backups", "region": "us-east-1"},
            ),
            Resource(
                id=vektor_id(SOURCE, "rds:acme-prod-db"),
                source=SOURCE, type="rds_instance", name="acme-prod-db",
                sensitivity=Sensitivity.CRITICAL,
                attributes={"arn": "arn:aws:rds:us-east-1:123456789012:db:acme-prod-db"},
            ),
            Resource(
                id=vektor_id(SOURCE, "dynamodb:user-sessions"),
                source=SOURCE, type="dynamodb_table", name="user-sessions",
                sensitivity=Sensitivity.HIGH,
                attributes={"arn": "arn:aws:dynamodb:us-east-1:123456789012:table/user-sessions"},
            ),
            Resource(
                id=vektor_id(SOURCE, "lambda:payment-processor"),
                source=SOURCE, type="lambda_function", name="payment-processor",
                sensitivity=Sensitivity.CRITICAL,
                attributes={"arn": "arn:aws:lambda:us-east-1:123456789012:function:payment-processor"},
            ),
            Resource(
                id=vektor_id(SOURCE, "secretsmanager:prod-api-keys"),
                source=SOURCE, type="secret", name="prod-api-keys",
                sensitivity=Sensitivity.CRITICAL,
                attributes={"arn": "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod-api-keys"},
            ),
            Resource(
                id=vektor_id(SOURCE, "ec2:prod-web-cluster"),
                source=SOURCE, type="ec2_fleet", name="prod-web-cluster",
                sensitivity=Sensitivity.HIGH,
                attributes={"region": "us-east-1", "instance_count": 12},
            ),
            Resource(
                id=vektor_id(SOURCE, "eks:acme-platform"),
                source=SOURCE, type="eks_cluster", name="acme-platform",
                sensitivity=Sensitivity.CRITICAL,
                attributes={"arn": "arn:aws:eks:us-east-1:123456789012:cluster/acme-platform"},
            ),
            Resource(
                id=vektor_id(SOURCE, "kms:master-key"),
                source=SOURCE, type="kms_key", name="master-key",
                sensitivity=Sensitivity.CRITICAL,
                attributes={"arn": "arn:aws:kms:us-east-1:123456789012:key/master-key"},
            ),
        ]
        return resources
