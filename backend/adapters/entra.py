"""
Vektor AI — Microsoft Entra ID Adapter

Read-only extraction from Microsoft Graph API v1.0.
Pulls users, service principals, groups, directory roles, and app-role assignments.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any

import httpx
import msal
import structlog

from .base import BaseAdapter
from .models import (
    Assignment,
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

SOURCE = "entra"
GRAPH_BASE = "https://graph.microsoft.com/v1.0"

PRIVILEGED_ROLES: set[str] = {
    "Global Administrator",
    "Privileged Role Administrator",
    "Exchange Administrator",
    "SharePoint Administrator",
    "Application Administrator",
    "User Administrator",
    "Security Administrator",
    "Compliance Administrator",
    "Intune Administrator",
    "Cloud Application Administrator",
    "Authentication Administrator",
    "Helpdesk Administrator",
    "Conditional Access Administrator",
}

# Exponential backoff settings
_MAX_RETRIES = 5
_BASE_DELAY = 1.0


class EntraAdapter(BaseAdapter):
    """Read-only adapter for Microsoft Entra ID (Azure AD) via Graph API."""

    source_name: str = SOURCE

    def __init__(self) -> None:
        self._client: httpx.AsyncClient | None = None
        self._access_token: str = ""
        self._tenant_id: str = ""

    # ---- lifecycle ---------------------------------------------------------

    async def connect(self, credentials: dict) -> None:
        """
        Authenticate via OAuth2 client-credentials flow (MSAL).

        Expected keys: tenant_id, client_id, client_secret
        """
        tenant_id = credentials["tenant_id"]
        client_id = credentials["client_id"]
        client_secret = credentials["client_secret"]
        self._tenant_id = tenant_id

        logger.info("entra.connect", tenant_id=tenant_id)

        authority = f"https://login.microsoftonline.com/{tenant_id}"
        app = msal.ConfidentialClientApplication(
            client_id,
            authority=authority,
            client_credential=client_secret,
        )
        result = app.acquire_token_for_client(
            scopes=["https://graph.microsoft.com/.default"]
        )

        if "access_token" not in result:
            error = result.get("error_description", result.get("error", "unknown"))
            logger.error("entra.auth_failed", error=error)
            raise ConnectionError(f"Entra authentication failed: {error}")

        self._access_token = result["access_token"]
        self._client = httpx.AsyncClient(
            headers={
                "Authorization": f"Bearer {self._access_token}",
                "Content-Type": "application/json",
            },
            timeout=30.0,
        )
        logger.info("entra.connected", tenant_id=tenant_id)

    async def test_connection(self) -> bool:
        try:
            if self._client is None:
                return False
            resp = await self._graph_get("/organization")
            return resp is not None
        except Exception:
            return False

    async def disconnect(self) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None
        logger.info("entra.disconnected")

    # ---- extraction --------------------------------------------------------

    async def extract(self) -> GraphSnapshot:
        if self._client is None:
            raise RuntimeError("Adapter not connected — call connect() first")

        logger.info("entra.extract.start")

        subjects: list[Subject] = []
        permissions: list[Permission] = []
        resources: list[Resource] = []
        assignments: list[Assignment] = []

        # 1. Users
        users = await self._get_all_pages("/users?$select=id,displayName,userPrincipalName,mail,userType,"
                                          "accountEnabled,department,jobTitle,lastSignInDateTime,"
                                          "createdDateTime&$top=999")
        for u in users:
            subj = self._map_user(u)
            subjects.append(subj)

        # 2. Service principals
        sps = await self._get_all_pages("/servicePrincipals?$select=id,displayName,appId,"
                                        "servicePrincipalType,accountEnabled,tags&$top=999")
        for sp in sps:
            subj = self._map_service_principal(sp)
            subjects.append(subj)

        # 3. Groups
        groups = await self._get_all_pages("/groups?$select=id,displayName,description,"
                                           "groupTypes,securityEnabled,mailEnabled&$top=999")
        for g in groups:
            subj = self._map_group(g)
            subjects.append(subj)

        # 4. Directory roles → Permissions
        roles = await self._get_all_pages("/directoryRoles?$select=id,displayName,description,roleTemplateId")
        role_perms: dict[str, Permission] = {}
        for r in roles:
            perm = self._map_directory_role(r)
            permissions.append(perm)
            role_perms[r["id"]] = perm

        # 5. Directory role members → Assignments
        for role_raw in roles:
            role_id = role_raw["id"]
            perm = role_perms.get(role_id)
            if perm is None:
                continue
            members = await self._get_all_pages(f"/directoryRoles/{role_id}/members?$select=id")
            for m in members:
                member_subj_id = vektor_id(SOURCE, m["id"])
                assignments.append(
                    Assignment(
                        subject_id=member_subj_id,
                        permission_id=perm.id,
                        source=SOURCE,
                        is_active=True,
                    )
                )

        # 6. User → group membership
        user_subject_map = {s.external_id: s for s in subjects if s.source == SOURCE}
        for u in users:
            uid = u["id"]
            subj_id = vektor_id(SOURCE, uid)
            member_of = await self._get_all_pages(f"/users/{uid}/memberOf?$select=id,displayName,@odata.type")
            for m in member_of:
                target_id = vektor_id(SOURCE, m["id"])
                assignments.append(
                    Assignment(
                        subject_id=subj_id,
                        permission_id=target_id,
                        source=SOURCE,
                        is_active=True,
                        granted_by="entra",
                    )
                )

        # 7. Applications → Resources
        apps = await self._get_all_pages("/applications?$select=id,displayName,appId,createdDateTime&$top=999")
        for app in apps:
            resources.append(
                Resource(
                    id=vektor_id(SOURCE, app["id"]),
                    source=SOURCE,
                    type="entra_application",
                    name=app.get("displayName", app["id"]),
                    sensitivity=Sensitivity.MEDIUM,
                    attributes={"app_id": app.get("appId")},
                )
            )

        # 8. App role assignments for users
        for u in users:
            uid = u["id"]
            subj_id = vektor_id(SOURCE, uid)
            try:
                app_roles = await self._get_all_pages(f"/users/{uid}/appRoleAssignments")
                for ar in app_roles:
                    perm = Permission(
                        id=vektor_id(SOURCE, f"approle:{ar.get('appRoleId', '')}:{ar.get('resourceId', '')}"),
                        source=SOURCE,
                        name=f"AppRole-{ar.get('resourceDisplayName', 'unknown')}",
                        type=PermissionType.ENTITLEMENT,
                        is_privileged=False,
                        attributes={"app_role_id": ar.get("appRoleId")},
                    )
                    permissions.append(perm)
                    assignments.append(
                        Assignment(
                            subject_id=subj_id,
                            permission_id=perm.id,
                            source=SOURCE,
                            is_active=True,
                            granted_at=_parse_dt(ar.get("createdDateTime")),
                        )
                    )
            except Exception as exc:
                logger.warning("entra.app_roles_failed", user_id=uid, error=str(exc))

        logger.info(
            "entra.extract.done",
            subjects=len(subjects),
            permissions=len(permissions),
            resources=len(resources),
            assignments=len(assignments),
        )

        return GraphSnapshot(
            source=SOURCE,
            subjects=subjects,
            permissions=permissions,
            resources=resources,
            assignments=assignments,
        )

    # ---- internal: mapping -------------------------------------------------

    def _map_user(self, u: dict) -> Subject:
        uid = u["id"]
        user_type = u.get("userType", "Member")
        status = SubjectStatus.ACTIVE if u.get("accountEnabled", True) else SubjectStatus.INACTIVE

        return Subject(
            id=vektor_id(SOURCE, uid),
            external_id=uid,
            source=SOURCE,
            type=SubjectType.HUMAN,
            display_name=u.get("displayName", uid),
            email=u.get("mail") or u.get("userPrincipalName"),
            department=u.get("department"),
            status=status,
            last_seen=_parse_dt(u.get("lastSignInDateTime")),
            mfa_enabled=None,  # Would require additional auth methods call
            attributes={
                "user_type": user_type,
                "job_title": u.get("jobTitle"),
                "upn": u.get("userPrincipalName"),
                "is_guest": user_type == "Guest",
            },
            created_at=_parse_dt(u.get("createdDateTime")) or utcnow(),
            updated_at=utcnow(),
        )

    def _map_service_principal(self, sp: dict) -> Subject:
        spid = sp["id"]
        name_lower = sp.get("displayName", "").lower()
        tags = sp.get("tags", [])

        stype = SubjectType.SERVICE_ACCOUNT
        if any(kw in name_lower for kw in ("agent", "ai", "llm", "copilot")):
            stype = SubjectType.AI_AGENT
        if any("agent" in t.lower() for t in tags if isinstance(t, str)):
            stype = SubjectType.AI_AGENT

        return Subject(
            id=vektor_id(SOURCE, spid),
            external_id=spid,
            source=SOURCE,
            type=stype,
            display_name=sp.get("displayName", spid),
            status=SubjectStatus.ACTIVE if sp.get("accountEnabled", True) else SubjectStatus.INACTIVE,
            attributes={
                "app_id": sp.get("appId"),
                "sp_type": sp.get("servicePrincipalType"),
                "tags": tags,
            },
            created_at=utcnow(),
            updated_at=utcnow(),
        )

    def _map_group(self, g: dict) -> Subject:
        gid = g["id"]
        return Subject(
            id=vektor_id(SOURCE, gid),
            external_id=gid,
            source=SOURCE,
            type=SubjectType.GROUP,
            display_name=g.get("displayName", gid),
            status=SubjectStatus.ACTIVE,
            attributes={
                "description": g.get("description"),
                "group_types": g.get("groupTypes", []),
                "security_enabled": g.get("securityEnabled", False),
                "mail_enabled": g.get("mailEnabled", False),
            },
            created_at=utcnow(),
            updated_at=utcnow(),
        )

    def _map_directory_role(self, r: dict) -> Permission:
        name = r.get("displayName", "")
        return Permission(
            id=vektor_id(SOURCE, r["id"]),
            source=SOURCE,
            name=name,
            type=PermissionType.ROLE,
            actions=[name],  # Entra roles are named capabilities
            is_privileged=name in PRIVILEGED_ROLES,
            risk_keywords=["admin"] if "administrator" in name.lower() else [],
            attributes={
                "role_template_id": r.get("roleTemplateId"),
                "description": r.get("description"),
            },
        )

    # ---- internal: Graph API helpers ---------------------------------------

    async def _graph_get(self, path: str) -> dict | None:
        """GET request to Microsoft Graph with exponential backoff."""
        url = f"{GRAPH_BASE}{path}" if path.startswith("/") else path
        for attempt in range(_MAX_RETRIES):
            try:
                resp = await self._client.get(url)
                if resp.status_code == 429:
                    retry_after = int(resp.headers.get("Retry-After", _BASE_DELAY * (2 ** attempt)))
                    logger.warning("entra.rate_limited", retry_after=retry_after, attempt=attempt)
                    await asyncio.sleep(retry_after)
                    continue
                if resp.status_code == 404:
                    return None
                resp.raise_for_status()
                return resp.json()
            except httpx.HTTPStatusError as exc:
                if attempt < _MAX_RETRIES - 1:
                    delay = _BASE_DELAY * (2 ** attempt)
                    logger.warning("entra.request_retry", status=exc.response.status_code, delay=delay)
                    await asyncio.sleep(delay)
                else:
                    logger.error("entra.request_failed", url=url, error=str(exc))
                    raise
        return None

    async def _get_all_pages(self, path: str) -> list[dict]:
        """Fetch all pages from a paginated Graph API endpoint."""
        items: list[dict] = []
        url: str | None = path

        while url:
            data = await self._graph_get(url)
            if data is None:
                break
            items.extend(data.get("value", []))
            url = data.get("@odata.nextLink")

        return items


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_dt(value: str | datetime | None) -> datetime | None:
    """Parse an ISO datetime string to timezone-aware datetime."""
    if value is None:
        return None
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except (ValueError, AttributeError):
        return None
