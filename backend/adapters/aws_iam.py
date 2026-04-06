"""
Vektor AI — AWS IAM Adapter

Read-only extraction of the full IAM configuration via
``iam.get_account_authorization_details()``. Detects privilege-escalation
chains and parses trust policies for open/cross-account delegation.
"""

from __future__ import annotations

import json
import re
import urllib.parse
from datetime import datetime, timezone
from typing import Any

import boto3
import structlog
from botocore.exceptions import BotoCoreError, ClientError

from .base import BaseAdapter
from .models import (
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

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
SOURCE = "aws_iam"

HIGH_RISK_ACTIONS: set[str] = {
    "iam:CreateRole",
    "iam:AttachRolePolicy",
    "iam:PutRolePolicy",
    "iam:CreateUser",
    "iam:AttachUserPolicy",
    "iam:PutUserPolicy",
    "iam:PassRole",
    "iam:CreateAccessKey",
    "iam:UpdateAssumeRolePolicy",
    "sts:AssumeRole",
    "iam:AddUserToGroup",
    "iam:CreatePolicy",
    "iam:CreatePolicyVersion",
    "lambda:CreateFunction",
    "lambda:UpdateFunctionCode",
    "lambda:InvokeFunction",
    "lambda:AddPermission",
    "s3:PutBucketPolicy",
    "s3:DeleteBucket",
    "ec2:RunInstances",
    "ec2:ModifyInstanceAttribute",
    "secretsmanager:GetSecretValue",
    "kms:Decrypt",
    "organizations:*",
    "iam:*",
    "sts:*",
}

RISK_KEYWORDS_RE = re.compile(
    r"(Create|Delete|Attach|Put|PassRole|Admin|Update|Remove|Modify|Invoke|Decrypt)",
    re.IGNORECASE,
)

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
        "confidence": 0.85,
        "end_result": "Can pass a high-privilege role to a new Lambda function",
    },
    {
        "name": "PassRole + EC2",
        "actions": {"iam:PassRole", "ec2:RunInstances"},
        "confidence": 0.85,
        "end_result": "Can launch EC2 with a high-privilege instance profile",
    },
    {
        "name": "CreateAccessKey for other users",
        "actions": {"iam:CreateAccessKey"},
        "confidence": 0.80,
        "end_result": "Can create access keys for other IAM users",
    },
    {
        "name": "UpdateAssumeRolePolicy",
        "actions": {"iam:UpdateAssumeRolePolicy"},
        "confidence": 0.75,
        "end_result": "Can modify role trust policies to allow self-assumption",
    },
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _decode_policy_doc(raw: str | dict) -> dict:
    """Decode an IAM policy document (may be URL-encoded JSON string or dict)."""
    if isinstance(raw, dict):
        return raw
    return json.loads(urllib.parse.unquote(raw))


def _extract_actions_from_policy(doc: dict) -> list[str]:
    """Flatten all Action entries from every Statement in a policy document."""
    actions: list[str] = []
    for stmt in doc.get("Statement", []):
        if stmt.get("Effect") != "Allow":
            continue
        raw = stmt.get("Action", [])
        if isinstance(raw, str):
            raw = [raw]
        actions.extend(raw)
    return actions


def _extract_resources_from_policy(doc: dict) -> list[str]:
    """Flatten all Resource entries from every Allow statement."""
    resources: list[str] = []
    for stmt in doc.get("Statement", []):
        if stmt.get("Effect") != "Allow":
            continue
        raw = stmt.get("Resource", [])
        if isinstance(raw, str):
            raw = [raw]
        resources.extend(raw)
    return resources


def _compute_risk_keywords(actions: list[str]) -> list[str]:
    keywords: set[str] = set()
    for action in actions:
        matches = RISK_KEYWORDS_RE.findall(action)
        keywords.update(m.lower() for m in matches)
    return sorted(keywords)


def _is_privileged(actions: list[str]) -> bool:
    """Return True if any action matches a high-risk pattern."""
    action_set = set(actions)
    for hra in HIGH_RISK_ACTIONS:
        if hra in action_set:
            return True
        # Handle wildcard matches like "iam:*"
        if hra.endswith("*"):
            prefix = hra[:-1]
            if any(a.startswith(prefix) for a in action_set):
                return True
    # Also check if the subject's actions contain wildcards that cover high-risk
    if "*" in action_set or any(a.endswith(":*") for a in action_set):
        return True
    return False


def _classify_subject_type(entity: dict, entity_kind: str) -> SubjectType:
    """Map AWS IAM entity to SubjectType."""
    if entity_kind == "Group":
        return SubjectType.GROUP
    if entity_kind == "User":
        # Service account heuristic: no console access / programmatic only
        has_password = entity.get("PasswordLastUsed") is not None
        login_profile = entity.get("LoginProfile")
        if not has_password and login_profile is None:
            return SubjectType.SERVICE_ACCOUNT
        return SubjectType.HUMAN
    if entity_kind == "Role":
        name_lower = entity.get("RoleName", "").lower()
        tags = {t["Key"]: t["Value"] for t in entity.get("Tags", [])}
        if tags.get("vektor:type") == "agent" or any(
            kw in name_lower for kw in ("agent", "ai", "llm")
        ):
            return SubjectType.AI_AGENT
        return SubjectType.SERVICE_ACCOUNT
    return SubjectType.HUMAN


def _sensitivity_from_arn(arn: str) -> Sensitivity:
    """Heuristic sensitivity classification from a resource ARN."""
    arn_lower = arn.lower()
    if any(k in arn_lower for k in ("secretsmanager", "kms", "iam", "organizations")):
        return Sensitivity.CRITICAL
    if any(k in arn_lower for k in ("s3", "rds", "dynamodb", "ecr")):
        return Sensitivity.HIGH
    if any(k in arn_lower for k in ("lambda", "ec2", "ecs", "sqs", "sns")):
        return Sensitivity.MEDIUM
    return Sensitivity.LOW


def _resource_type_from_arn(arn: str) -> str:
    """Extract a human-friendly resource type from an ARN."""
    parts = arn.split(":")
    if len(parts) >= 3:
        service = parts[2]
        return f"{service}_resource"
    return "aws_resource"


# ---------------------------------------------------------------------------
# Adapter
# ---------------------------------------------------------------------------
class AWSIAMAdapter(BaseAdapter):
    """Read-only adapter for AWS IAM using get_account_authorization_details."""

    source_name: str = SOURCE

    def __init__(self) -> None:
        self._iam_client: Any = None
        self._sts_client: Any = None
        self._account_id: str = ""

    # ---- lifecycle ---------------------------------------------------------

    async def connect(self, credentials: dict) -> None:
        """
        Assume a cross-account role and create an IAM client.

        Expected credentials keys:
          - role_arn: str
          - external_id: str
          - region: str (optional, default us-east-1)
        """
        role_arn = credentials["role_arn"]
        external_id = credentials["external_id"]
        region = credentials.get("region", "us-east-1")

        logger.info("aws_iam.connect", role_arn=role_arn, region=region)

        try:
            sts = boto3.client("sts", region_name=region)
            assumed = sts.assume_role(
                RoleArn=role_arn,
                RoleSessionName="vektor-extraction",
                ExternalId=external_id,
                DurationSeconds=3600,
            )
            creds = assumed["Credentials"]
            self._iam_client = boto3.client(
                "iam",
                aws_access_key_id=creds["AccessKeyId"],
                aws_secret_access_key=creds["SecretAccessKey"],
                aws_session_token=creds["SessionToken"],
                region_name=region,
            )
            self._sts_client = boto3.client(
                "sts",
                aws_access_key_id=creds["AccessKeyId"],
                aws_secret_access_key=creds["SecretAccessKey"],
                aws_session_token=creds["SessionToken"],
                region_name=region,
            )
            identity = self._sts_client.get_caller_identity()
            self._account_id = identity["Account"]
            logger.info("aws_iam.connected", account_id=self._account_id)

        except (ClientError, BotoCoreError) as exc:
            logger.error("aws_iam.connect_failed", error=str(exc))
            raise ConnectionError(f"AWS IAM connection failed: {exc}") from exc

    async def test_connection(self) -> bool:
        """Lightweight check — try get_caller_identity."""
        try:
            if self._sts_client is None:
                return False
            self._sts_client.get_caller_identity()
            return True
        except Exception:
            return False

    async def disconnect(self) -> None:
        self._iam_client = None
        self._sts_client = None
        logger.info("aws_iam.disconnected")

    # ---- extraction --------------------------------------------------------

    async def extract(self) -> GraphSnapshot:
        """Full IAM extraction via get_account_authorization_details."""
        if self._iam_client is None:
            raise RuntimeError("Adapter not connected — call connect() first")

        logger.info("aws_iam.extract.start")

        # 1. Fetch the entire IAM config (paginated)
        auth_details = await self._get_account_authorization_details()

        subjects: list[Subject] = []
        permissions: list[Permission] = []
        resources: list[Resource] = []
        assignments: list[Assignment] = []
        resource_cache: dict[str, Resource] = {}

        # 2. Process Users
        for user in auth_details.get("UserDetailList", []):
            subj = self._map_user(user)
            subjects.append(subj)
            user_perms, user_assigns, user_resources = self._extract_policies(
                user, subj.id, resource_cache
            )
            permissions.extend(user_perms)
            assignments.extend(user_assigns)
            resources.extend(user_resources)

        # 3. Process Groups
        for group in auth_details.get("GroupDetailList", []):
            subj = self._map_group(group)
            subjects.append(subj)
            grp_perms, grp_assigns, grp_resources = self._extract_policies(
                group, subj.id, resource_cache
            )
            permissions.extend(grp_perms)
            assignments.extend(grp_assigns)
            resources.extend(grp_resources)

        # 4. Process Roles
        for role in auth_details.get("RoleDetailList", []):
            subj = self._map_role(role)
            subjects.append(subj)
            role_perms, role_assigns, role_resources = self._extract_policies(
                role, subj.id, resource_cache
            )
            permissions.extend(role_perms)
            assignments.extend(role_assigns)
            resources.extend(role_resources)

        # 5. Map user → group membership
        group_membership_assigns = self._map_group_memberships(auth_details, subjects)
        assignments.extend(group_membership_assigns)

        # 6. Check MFA for users
        await self._enrich_mfa(subjects)

        # 7. Deduplicate resources
        resources = list(resource_cache.values())

        # 8. Aggregate actions per subject for escalation detection
        subject_actions = self._aggregate_subject_actions(subjects, permissions, assignments)

        # 9. Detect escalation paths
        escalation_paths = self._detect_escalation_paths(subject_actions)

        # 10. Parse trust policies for roles
        self._parse_trust_policies(auth_details.get("RoleDetailList", []), subjects)

        logger.info(
            "aws_iam.extract.done",
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

    # ---- internal: API calls -----------------------------------------------

    async def _get_account_authorization_details(self) -> dict:
        """Paginated fetch of the full IAM account authorization details."""
        combined: dict[str, list] = {
            "UserDetailList": [],
            "GroupDetailList": [],
            "RoleDetailList": [],
            "Policies": [],
        }
        paginator = self._iam_client.get_paginator(
            "get_account_authorization_details"
        )
        for page in paginator.paginate():
            for key in combined:
                combined[key].extend(page.get(key, []))

        logger.info(
            "aws_iam.auth_details_fetched",
            users=len(combined["UserDetailList"]),
            groups=len(combined["GroupDetailList"]),
            roles=len(combined["RoleDetailList"]),
            policies=len(combined["Policies"]),
        )
        return combined

    # ---- internal: mapping -------------------------------------------------

    def _map_user(self, user: dict) -> Subject:
        arn = user["Arn"]
        username = user["UserName"]
        ext_id = arn

        last_seen = user.get("PasswordLastUsed")
        if last_seen and not last_seen.tzinfo:
            last_seen = last_seen.replace(tzinfo=timezone.utc)

        create_date = user.get("CreateDate", utcnow())
        if create_date and not getattr(create_date, "tzinfo", None):
            create_date = create_date.replace(tzinfo=timezone.utc)

        return Subject(
            id=vektor_id(SOURCE, ext_id),
            external_id=ext_id,
            source=SOURCE,
            type=_classify_subject_type(user, "User"),
            display_name=username,
            email=user.get("Tags", {}).get("email"),  # tag-based
            status=SubjectStatus.ACTIVE,
            last_seen=last_seen,
            mfa_enabled=False,  # enriched later
            attributes={"arn": arn, "path": user.get("Path", "/")},
            created_at=create_date,
            updated_at=utcnow(),
        )

    def _map_group(self, group: dict) -> Subject:
        arn = group["Arn"]
        return Subject(
            id=vektor_id(SOURCE, arn),
            external_id=arn,
            source=SOURCE,
            type=SubjectType.GROUP,
            display_name=group["GroupName"],
            status=SubjectStatus.ACTIVE,
            attributes={"arn": arn, "path": group.get("Path", "/")},
            created_at=group.get("CreateDate", utcnow()),
            updated_at=utcnow(),
        )

    def _map_role(self, role: dict) -> Subject:
        arn = role["Arn"]
        last_used = role.get("RoleLastUsed", {}).get("LastUsedDate")
        if last_used and not last_used.tzinfo:
            last_used = last_used.replace(tzinfo=timezone.utc)

        create_date = role.get("CreateDate", utcnow())
        if create_date and not getattr(create_date, "tzinfo", None):
            create_date = create_date.replace(tzinfo=timezone.utc)

        return Subject(
            id=vektor_id(SOURCE, arn),
            external_id=arn,
            source=SOURCE,
            type=_classify_subject_type(role, "Role"),
            display_name=role["RoleName"],
            status=SubjectStatus.ACTIVE,
            last_seen=last_used,
            attributes={
                "arn": arn,
                "path": role.get("Path", "/"),
                "max_session_duration": role.get("MaxSessionDuration"),
            },
            created_at=create_date,
            updated_at=utcnow(),
        )

    # ---- internal: policies ------------------------------------------------

    def _extract_policies(
        self,
        entity: dict,
        subject_id: str,
        resource_cache: dict[str, Resource],
    ) -> tuple[list[Permission], list[Assignment], list[Resource]]:
        """Extract permissions and assignments from an IAM entity's policies."""
        perms: list[Permission] = []
        assigns: list[Assignment] = []
        resources: list[Resource] = []

        # Inline policies
        for inline in entity.get("UserPolicyList", []) + entity.get(
            "GroupPolicyList", []
        ) + entity.get("RolePolicyList", []):
            perm, res_list = self._map_inline_policy(inline, resource_cache)
            perms.append(perm)
            resources.extend(res_list)
            assigns.append(
                Assignment(
                    subject_id=subject_id,
                    permission_id=perm.id,
                    source=SOURCE,
                    is_active=True,
                )
            )

        # Attached managed policies
        for attached in entity.get("AttachedManagedPolicies", []):
            perm = self._map_managed_policy_ref(attached)
            perms.append(perm)
            assigns.append(
                Assignment(
                    subject_id=subject_id,
                    permission_id=perm.id,
                    source=SOURCE,
                    is_active=True,
                )
            )

        return perms, assigns, resources

    def _map_inline_policy(
        self, policy: dict, resource_cache: dict[str, Resource]
    ) -> tuple[Permission, list[Resource]]:
        doc = _decode_policy_doc(policy["PolicyDocument"])
        actions = _extract_actions_from_policy(doc)
        res_arns = _extract_resources_from_policy(doc)

        new_resources: list[Resource] = []
        for arn in res_arns:
            if arn != "*" and arn not in resource_cache:
                r = Resource(
                    id=vektor_id(SOURCE, arn),
                    source=SOURCE,
                    type=_resource_type_from_arn(arn),
                    name=arn.split(":")[-1] or arn,
                    sensitivity=_sensitivity_from_arn(arn),
                    attributes={"arn": arn},
                )
                resource_cache[arn] = r
                new_resources.append(r)

        perm = Permission(
            id=vektor_id(SOURCE, f"inline:{policy['PolicyName']}:{hash(json.dumps(doc, sort_keys=True))}"),
            source=SOURCE,
            name=policy["PolicyName"],
            type=PermissionType.POLICY,
            actions=actions,
            resources=res_arns,
            is_privileged=_is_privileged(actions),
            risk_keywords=_compute_risk_keywords(actions),
            attributes={"inline": True, "policy_document": doc},
        )
        return perm, new_resources

    def _map_managed_policy_ref(self, attached: dict) -> Permission:
        """Map an attached managed policy reference (without full doc)."""
        arn = attached["PolicyArn"]
        name = attached["PolicyName"]
        return Permission(
            id=vektor_id(SOURCE, arn),
            source=SOURCE,
            name=name,
            type=PermissionType.POLICY,
            actions=[],  # Populated when we process the Policies list
            resources=[],
            is_privileged=any(
                kw in name.lower()
                for kw in ("admin", "fullaccess", "poweruser")
            ),
            risk_keywords=_compute_risk_keywords([name]),
            attributes={"arn": arn, "managed": True},
        )

    # ---- internal: group membership ----------------------------------------

    def _map_group_memberships(
        self, auth_details: dict, subjects: list[Subject]
    ) -> list[Assignment]:
        """Map IAM user → group membership edges."""
        assigns: list[Assignment] = []
        group_id_map: dict[str, str] = {}
        for group in auth_details.get("GroupDetailList", []):
            group_id_map[group["GroupName"]] = vektor_id(SOURCE, group["Arn"])

        for user in auth_details.get("UserDetailList", []):
            user_subj_id = vektor_id(SOURCE, user["Arn"])
            for gm in user.get("GroupList", []):
                group_subj_id = group_id_map.get(gm)
                if group_subj_id:
                    assigns.append(
                        Assignment(
                            subject_id=user_subj_id,
                            permission_id=group_subj_id,  # group acts as permission container
                            source=SOURCE,
                            is_active=True,
                            granted_by="aws_iam",
                            attributes={"membership_type": "group"},
                        )
                    )
        return assigns

    # ---- internal: MFA enrichment ------------------------------------------

    async def _enrich_mfa(self, subjects: list[Subject]) -> None:
        """Check MFA device enrollment for each IAM user."""
        for subj in subjects:
            if subj.type not in (SubjectType.HUMAN, SubjectType.SERVICE_ACCOUNT):
                continue
            if not subj.external_id.startswith("arn:aws:iam"):
                continue
            # Extract username from ARN
            parts = subj.external_id.split("/")
            if len(parts) < 2:
                continue
            username = parts[-1]
            try:
                resp = self._iam_client.list_mfa_devices(UserName=username)
                subj.mfa_enabled = len(resp.get("MFADevices", [])) > 0
            except ClientError as exc:
                logger.warning(
                    "aws_iam.mfa_check_failed",
                    username=username,
                    error=str(exc),
                )

    # ---- internal: escalation detection ------------------------------------

    def _aggregate_subject_actions(
        self,
        subjects: list[Subject],
        permissions: list[Permission],
        assignments: list[Assignment],
    ) -> dict[str, set[str]]:
        """Build a map of subject_id → set of all allowed actions."""
        perm_map: dict[str, Permission] = {p.id: p for p in permissions}
        result: dict[str, set[str]] = {}

        for assign in assignments:
            if not assign.is_active:
                continue
            perm = perm_map.get(assign.permission_id)
            if perm is None:
                continue
            actions = result.setdefault(assign.subject_id, set())
            actions.update(perm.actions)

        return result

    def _detect_escalation_paths(
        self, subject_actions: dict[str, set[str]]
    ) -> list[EscalationPath]:
        """Detect privilege escalation chains for each subject."""
        paths: list[EscalationPath] = []

        for subject_id, actions in subject_actions.items():
            # Expand wildcards for matching
            expanded = set(actions)
            for a in actions:
                if a == "*" or a.endswith(":*"):
                    # This subject can do anything (or anything in that service)
                    expanded.add(a)

            for pattern in ESCALATION_PATTERNS:
                required = pattern["actions"]
                if self._actions_match(expanded, required):
                    steps = [
                        EscalationStep(
                            action=act,
                            resource="*",
                            description=f"Has permission to {act}",
                        )
                        for act in sorted(required)
                    ]
                    paths.append(
                        EscalationPath(
                            subject_id=subject_id,
                            steps=steps,
                            end_result=pattern["end_result"],
                            confidence=pattern["confidence"],
                            source=SOURCE,
                        )
                    )

        logger.info("aws_iam.escalation_paths_detected", count=len(paths))
        return paths

    def _actions_match(self, subject_actions: set[str], required: set[str]) -> bool:
        """Check if subject's actions cover all required actions (with wildcard expansion)."""
        for req in required:
            if req in subject_actions:
                continue
            # Check wildcard coverage
            service = req.split(":")[0] if ":" in req else ""
            wildcard = f"{service}:*"
            if wildcard in subject_actions or "*" in subject_actions:
                continue
            return False
        return True

    # ---- internal: trust policy parsing ------------------------------------

    def _parse_trust_policies(
        self, roles: list[dict], subjects: list[Subject]
    ) -> None:
        """Parse AssumeRolePolicyDocument for each role and annotate the subject."""
        role_subject_map: dict[str, Subject] = {}
        for subj in subjects:
            if subj.source == SOURCE and "arn" in subj.attributes:
                role_subject_map[subj.attributes["arn"]] = subj

        for role in roles:
            arn = role["Arn"]
            subj = role_subject_map.get(arn)
            if subj is None:
                continue

            raw_doc = role.get("AssumeRolePolicyDocument")
            if raw_doc is None:
                continue

            doc = _decode_policy_doc(raw_doc)
            trust_info = self._analyse_trust_doc(doc)
            subj.attributes.update(trust_info)

    def _analyse_trust_doc(self, doc: dict) -> dict[str, Any]:
        """Analyse an AssumeRolePolicyDocument and return trust metadata."""
        result: dict[str, Any] = {
            "trust_policy_open": False,
            "cross_account_trust": False,
            "cross_account_ids": [],
            "service_principals": [],
            "federated_principals": [],
        }

        for stmt in doc.get("Statement", []):
            if stmt.get("Effect") != "Allow":
                continue

            principal = stmt.get("Principal", {})
            if principal == "*" or principal == {"AWS": "*"}:
                result["trust_policy_open"] = True
                continue

            # AWS principals
            aws_principals = principal.get("AWS", [])
            if isinstance(aws_principals, str):
                aws_principals = [aws_principals]
            for p in aws_principals:
                if p == "*":
                    result["trust_policy_open"] = True
                elif ":root" in p or "arn:aws:iam::" in p:
                    # Extract account ID
                    parts = p.split(":")
                    if len(parts) >= 5:
                        acct_id = parts[4]
                        if acct_id and acct_id != self._account_id:
                            result["cross_account_trust"] = True
                            result["cross_account_ids"].append(acct_id)

            # Service principals
            svc_principals = principal.get("Service", [])
            if isinstance(svc_principals, str):
                svc_principals = [svc_principals]
            result["service_principals"].extend(svc_principals)

            # Federated principals
            fed_principals = principal.get("Federated", [])
            if isinstance(fed_principals, str):
                fed_principals = [fed_principals]
            result["federated_principals"].extend(fed_principals)

            # Check conditions
            condition = stmt.get("Condition", {})
            if not condition and result["cross_account_trust"]:
                result["cross_account_no_conditions"] = True

        return result
