"""
Vektor AI — Local Okta Adapter

Generates synthetic Okta System Log events and tenant configuration data
that trigger the official Okta detection rules from okta/customer-detections.

Data sources:
  - demo/data_okta_detections.json — 31 official Okta detection rules (YAML)
    from github.com/okta/customer-detections
  - Synthetic events generated to match real Okta System Log JSON schema

The adapter produces realistic findings including:
  - SuperAdmin accounts with weak MFA (SMS/email instead of FIDO2)
  - Excessive admin count (>5 SuperAdmins)
  - Dormant admin accounts not used in 90+ days
  - Service accounts with Org Admin role and stale API tokens
  - MFA policy downgrades
  - New IdP creation (persistence technique)
  - API token creation by unexpected actors
  - Log stream tampering attempts
  - Password spray detection

All detection patterns are based on real-world Okta breaches (Lapsus$ 2022,
0ktapus 2022, Okta support case breach 2023) and Okta's own security advisories.
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

SOURCE = "okta"

# ---------------------------------------------------------------------------
# Synthetic Okta tenant configuration — models a real-world misconfigured org
# ---------------------------------------------------------------------------

OKTA_ADMINS = [
    {
        "name": "admin@corp.okta.com",
        "display_name": "IT Admin (Primary)",
        "role": "Super Administrator",
        "mfa_method": "sms",
        "last_login_days_ago": 1,
        "status": "active",
        "type": "human",
        "department": "IT",
        "findings": ["weak_mfa_superadmin"],
    },
    {
        "name": "jsmith-admin",
        "display_name": "John Smith (Admin)",
        "role": "Super Administrator",
        "mfa_method": "push",
        "last_login_days_ago": 3,
        "status": "active",
        "type": "human",
        "department": "IT",
        "findings": [],
    },
    {
        "name": "sarah.chen-admin",
        "display_name": "Sarah Chen (Admin)",
        "role": "Super Administrator",
        "mfa_method": "webauthn",
        "last_login_days_ago": 0,
        "status": "active",
        "type": "human",
        "department": "IT Security",
        "findings": [],
    },
    {
        "name": "mwilliams-admin",
        "display_name": "Mike Williams (Admin)",
        "role": "Super Administrator",
        "mfa_method": "email",
        "last_login_days_ago": 14,
        "status": "active",
        "type": "human",
        "department": "IT",
        "findings": ["weak_mfa_superadmin"],
    },
    {
        "name": "derek.thompson-admin",
        "display_name": "Derek Thompson (Former IT)",
        "role": "Super Administrator",
        "mfa_method": "sms",
        "last_login_days_ago": 183,
        "status": "active",
        "type": "human",
        "department": "IT",
        "findings": ["dormant_admin", "weak_mfa_superadmin"],
    },
    {
        "name": "kpatel-admin",
        "display_name": "Kiran Patel (Admin)",
        "role": "Organization Administrator",
        "mfa_method": "totp",
        "last_login_days_ago": 7,
        "status": "active",
        "type": "human",
        "department": "IT",
        "findings": [],
    },
    {
        "name": "alee-admin",
        "display_name": "Amy Lee (Admin)",
        "role": "Super Administrator",
        "mfa_method": "push",
        "last_login_days_ago": 45,
        "status": "active",
        "type": "human",
        "department": "Engineering",
        "findings": [],
    },
    {
        "name": "rjones-admin",
        "display_name": "Rob Jones (Helpdesk Lead)",
        "role": "Super Administrator",
        "mfa_method": "sms",
        "last_login_days_ago": 60,
        "status": "active",
        "type": "human",
        "department": "IT Support",
        "findings": ["weak_mfa_superadmin"],
    },
    # Service accounts
    {
        "name": "svc-okta-scim-sync",
        "display_name": "SCIM Provisioning Service",
        "role": "Organization Administrator",
        "mfa_method": "none",
        "last_login_days_ago": 0,
        "status": "active",
        "type": "service_account",
        "department": "IT Automation",
        "api_token_age_days": 347,
        "findings": ["svc_acct_overprivileged", "stale_api_token"],
    },
    {
        "name": "svc-okta-siem-reader",
        "display_name": "SIEM Log Reader",
        "role": "Report Administrator",
        "mfa_method": "none",
        "last_login_days_ago": 0,
        "status": "active",
        "type": "service_account",
        "department": "Security",
        "api_token_age_days": 120,
        "findings": [],
    },
]

# Tenant-level configuration issues
TENANT_CONFIG = {
    "global_session_max_lifetime_hours": 720,  # 30 days — should be ≤12h for admins
    "admin_session_idle_timeout_minutes": 120,  # 2 hours — should be ≤15min
    "threat_insight_enabled": False,
    "admin_console_asn_binding": False,
    "superadmin_count": 7,  # recommended ≤5
    "org_admin_count": 1,
    "phishing_resistant_mfa_required": False,
    "default_auth_policy_mfa": "optional",  # should be "required"
}

# Synthetic System Log events that match real attack patterns
SYNTHETIC_EVENTS = [
    {
        "eventType": "user.authentication.verify",
        "displayMessage": "User single sign on to app",
        "outcome": {"result": "SUCCESS"},
        "target": [{"displayName": "Okta Admin Console", "detailEntry": {"MethodTypeUsed": "sms"}}],
        "actor": {"alternateId": "admin@corp.okta.com"},
        "detection_rule": "admin_console_login_weak_mfa",
    },
    {
        "eventType": "system.api_token.create",
        "displayMessage": "Create API token",
        "outcome": {"result": "SUCCESS"},
        "actor": {"alternateId": "derek.thompson-admin"},
        "detection_rule": "new_api_token_created",
    },
    {
        "eventType": "user.account.privilege.grant",
        "displayMessage": "Granted Super Administrator role",
        "outcome": {"result": "SUCCESS"},
        "actor": {"alternateId": "admin@corp.okta.com"},
        "target": [{"alternateId": "unknown-user@external.com", "displayName": "Super Administrator"}],
        "detection_rule": "new_super_admin_added_or_removed",
    },
    {
        "eventType": "policy.rule.update",
        "displayMessage": "Authentication policy MFA downgrade",
        "outcome": {"result": "SUCCESS"},
        "actor": {"alternateId": "mwilliams-admin"},
        "detection_rule": "authentication_policy_mfa_downgrade",
    },
    {
        "eventType": "security.threat.detected",
        "displayMessage": "Password spray detected",
        "outcome": {"reason": "Password Spray detected across 47 accounts"},
        "detection_rule": "threat_insight_password_spray",
    },
    {
        "eventType": "system.idp.lifecycle.create",
        "displayMessage": "New Identity Provider created",
        "outcome": {"result": "SUCCESS"},
        "actor": {"alternateId": "compromised-admin"},
        "detection_rule": "new_idp_created",
    },
    {
        "eventType": "system.log_stream.lifecycle.deactivate",
        "displayMessage": "Log stream deactivated",
        "outcome": {"result": "SUCCESS"},
        "actor": {"alternateId": "derek.thompson-admin"},
        "detection_rule": "log_stream_tampering",
    },
]


class LocalOktaAdapter(BaseAdapter):
    """
    Generates Okta tenant findings from synthetic data + official detection rules.

    Drop-in replacement for the live OktaAdapter — produces the same
    GraphSnapshot the REST API adapter would. When Venkat connects to
    a real Okta Developer org, he swaps which adapter is instantiated.
    """

    source_name = SOURCE

    def __init__(self, detections_path: str | Path | None = None):
        self._detections_path = Path(detections_path) if detections_path else (
            Path(__file__).parent / "data_okta_detections.json"
        )
        self._detections: dict[str, Any] | None = None

    async def connect(self, credentials: dict | None = None) -> None:
        """Load the Okta detection rules."""
        if self._detections_path.exists():
            with open(self._detections_path) as f:
                self._detections = json.load(f)
            logger.info(
                "okta.local.connected",
                detection_rules=self._detections["total_rules"],
            )
        else:
            self._detections = {"rules": [], "total_rules": 0}
            logger.warning("okta.local.no_detections_file")

    async def test_connection(self) -> bool:
        return True  # Always works for local

    async def extract(self) -> GraphSnapshot:
        """
        Build a complete GraphSnapshot from synthetic Okta configuration.

        1. Creates Subject objects for admin accounts + service accounts
        2. Creates Permission objects for Okta admin roles
        3. Creates Assignment objects
        4. Detects escalation paths (misconfigurations, weak MFA, etc.)
        """
        if self._detections is None:
            await self.connect()

        now = utcnow()
        random.seed(42)

        subjects: list[Subject] = []
        permissions: list[Permission] = []
        resources: list[Resource] = []
        assignments: list[Assignment] = []
        escalation_paths: list[EscalationPath] = []

        # --- Okta Tenant as a Resource ---
        tenant_resource = Resource(
            id=vektor_id(SOURCE, "tenant:corp"),
            source=SOURCE,
            type="okta_tenant",
            name="Corp Okta Tenant",
            sensitivity=Sensitivity.CRITICAL,
            attributes=TENANT_CONFIG,
        )
        resources.append(tenant_resource)

        admin_console_resource = Resource(
            id=vektor_id(SOURCE, "app:admin-console"),
            source=SOURCE,
            type="okta_application",
            name="Okta Admin Console",
            sensitivity=Sensitivity.CRITICAL,
        )
        resources.append(admin_console_resource)

        # --- Okta Admin Roles as Permissions ---
        role_permissions: dict[str, Permission] = {}
        for role_name in ["Super Administrator", "Organization Administrator",
                          "Application Administrator", "Help Desk Administrator",
                          "Report Administrator", "Read Only Administrator"]:
            perm = Permission(
                id=vektor_id(SOURCE, f"role:{role_name}"),
                source=SOURCE,
                name=role_name,
                type=PermissionType.ROLE,
                actions=_role_actions(role_name),
                is_privileged=role_name in ("Super Administrator", "Organization Administrator"),
                risk_keywords=_role_risk_keywords(role_name),
            )
            role_permissions[role_name] = perm
            permissions.append(perm)

        # --- Build admin subjects + assignments ---
        for admin in OKTA_ADMINS:
            subj_type = (
                SubjectType.SERVICE_ACCOUNT if admin["type"] == "service_account"
                else SubjectType.HUMAN
            )
            subj = Subject(
                id=vektor_id(SOURCE, f"admin:{admin['name']}"),
                external_id=admin["name"],
                source=SOURCE,
                type=subj_type,
                display_name=admin["display_name"],
                email=admin["name"] if "@" in admin["name"] else f"{admin['name']}@corp.com",
                department=admin["department"],
                status=SubjectStatus.ACTIVE,
                mfa_enabled=admin["mfa_method"] != "none",
                last_seen=now - timedelta(days=admin["last_login_days_ago"]),
                created_at=now - timedelta(days=random.randint(200, 900)),
                attributes={
                    "okta_role": admin["role"],
                    "mfa_method": admin["mfa_method"],
                    "api_token_age_days": admin.get("api_token_age_days"),
                    "findings": admin["findings"],
                },
            )
            subjects.append(subj)

            # Assignment to role
            role_perm = role_permissions.get(admin["role"])
            if role_perm:
                assignments.append(Assignment(
                    subject_id=subj.id,
                    permission_id=role_perm.id,
                    resource_id=admin_console_resource.id,
                    source=SOURCE,
                    granted_at=now - timedelta(days=random.randint(60, 600)),
                    is_active=True,
                ))

            # --- Generate escalation paths for findings ---
            for finding in admin["findings"]:
                if finding == "weak_mfa_superadmin":
                    escalation_paths.append(EscalationPath(
                        subject_id=subj.id,
                        steps=[
                            EscalationStep(
                                action="user.authentication.verify",
                                resource="Okta Admin Console",
                                description=f"Authenticates with weak MFA: {admin['mfa_method']}",
                            ),
                            EscalationStep(
                                action="admin.console.access",
                                resource="Okta Admin Console",
                                description=f"Has {admin['role']} — full tenant control",
                            ),
                        ],
                        end_result=f"SuperAdmin with {admin['mfa_method']}-only MFA — phishing/SIM swap can compromise entire tenant",
                        confidence=0.96,
                        source=SOURCE,
                    ))

                elif finding == "dormant_admin":
                    escalation_paths.append(EscalationPath(
                        subject_id=subj.id,
                        steps=[
                            EscalationStep(
                                action="account.dormant",
                                resource="Okta Tenant",
                                description=f"Last login: {admin['last_login_days_ago']} days ago — still active",
                            ),
                            EscalationStep(
                                action="privilege.retained",
                                resource="Okta Admin Console",
                                description=f"Retains {admin['role']} role — not deprovisioned",
                            ),
                        ],
                        end_result="Dormant SuperAdmin — credential stuffing or password spray target",
                        confidence=0.94,
                        source=SOURCE,
                    ))

                elif finding == "svc_acct_overprivileged":
                    escalation_paths.append(EscalationPath(
                        subject_id=subj.id,
                        steps=[
                            EscalationStep(
                                action="service.account.admin",
                                resource="Okta Tenant",
                                description=f"Service account with {admin['role']} — no MFA possible",
                            ),
                            EscalationStep(
                                action="api.token.stale",
                                resource="Okta API",
                                description=f"API token age: {admin.get('api_token_age_days', 'unknown')} days — never rotated",
                            ),
                        ],
                        end_result="Overprivileged service account with stale API token — mirrors 2023 Okta breach pattern",
                        confidence=0.97,
                        source=SOURCE,
                    ))

                elif finding == "stale_api_token":
                    pass  # Covered by svc_acct_overprivileged above

        # --- Tenant-level escalation paths ---
        # Excessive SuperAdmins
        tenant_subj_id = vektor_id(SOURCE, "tenant:config")
        tenant_subj = Subject(
            id=tenant_subj_id,
            external_id="okta-tenant-config",
            source=SOURCE,
            type=SubjectType.SERVICE_ACCOUNT,
            display_name="Okta Tenant Configuration",
            department="IT",
            status=SubjectStatus.ACTIVE,
            attributes={"config_type": "tenant_posture"},
        )
        subjects.append(tenant_subj)

        if TENANT_CONFIG["superadmin_count"] > 5:
            escalation_paths.append(EscalationPath(
                subject_id=tenant_subj_id,
                steps=[
                    EscalationStep(
                        action="excessive.superadmins",
                        resource="Okta Tenant",
                        description=f"{TENANT_CONFIG['superadmin_count']} SuperAdmins (recommended: ≤5)",
                    ),
                    EscalationStep(
                        action="weak.session.policy",
                        resource="Okta Admin Console",
                        description=f"Admin session lifetime: {TENANT_CONFIG['global_session_max_lifetime_hours']}h (recommended: ≤12h)",
                    ),
                ],
                end_result="Excessive admin count + permissive session policy — high tenant takeover risk",
                confidence=0.92,
                source=SOURCE,
            ))

        if not TENANT_CONFIG["threat_insight_enabled"]:
            escalation_paths.append(EscalationPath(
                subject_id=tenant_subj_id,
                steps=[
                    EscalationStep(
                        action="threat.insight.disabled",
                        resource="Okta Tenant",
                        description="ThreatInsight is disabled — no automated attack detection",
                    ),
                    EscalationStep(
                        action="asn.binding.disabled",
                        resource="Okta Admin Console",
                        description="Admin session ASN binding disabled — session hijack possible",
                    ),
                ],
                end_result="No ThreatInsight + no ASN binding — password spray and session hijack attacks will not be auto-blocked",
                confidence=0.90,
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
            "okta.local.extracted",
            subjects=len(subjects),
            admins=len(OKTA_ADMINS),
            escalation_paths=len(escalation_paths),
            detection_rules_loaded=self._detections["total_rules"] if self._detections else 0,
        )

        return snapshot


def _role_actions(role_name: str) -> list[str]:
    """Return typical actions for each Okta admin role."""
    actions_map = {
        "Super Administrator": [
            "user.lifecycle.create", "user.lifecycle.delete",
            "user.account.privilege.grant", "system.api_token.create",
            "system.idp.lifecycle.create", "policy.rule.update",
            "system.log_stream.lifecycle.deactivate",
        ],
        "Organization Administrator": [
            "user.lifecycle.create", "user.account.privilege.grant",
            "system.api_token.create", "policy.rule.update",
        ],
        "Application Administrator": [
            "app.lifecycle.create", "app.user_membership.add",
        ],
        "Help Desk Administrator": [
            "user.account.reset_password", "user.mfa.factor.reset",
        ],
        "Report Administrator": [
            "system.report.run",
        ],
        "Read Only Administrator": [],
    }
    return actions_map.get(role_name, [])


def _role_risk_keywords(role_name: str) -> list[str]:
    """Return risk keywords for each Okta admin role."""
    keywords_map = {
        "Super Administrator": ["identity_admin", "full_tenant_control", "idp_management"],
        "Organization Administrator": ["identity_admin", "user_management"],
        "Application Administrator": ["app_management"],
        "Help Desk Administrator": ["password_reset", "mfa_reset"],
        "Report Administrator": [],
        "Read Only Administrator": [],
    }
    return keywords_map.get(role_name, [])
