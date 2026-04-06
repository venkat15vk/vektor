"""
Vektor AI — Okta Adapter

Read-only extraction from Okta's Management API.
Pulls users, groups, applications, admin roles, and MFA factor enrollment.
"""

from __future__ import annotations

import asyncio
import re
from datetime import datetime, timezone
from typing import Any

import httpx
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

SOURCE = "okta"

_OKTA_STATUS_MAP: dict[str, SubjectStatus] = {
    "ACTIVE": SubjectStatus.ACTIVE,
    "STAGED": SubjectStatus.INACTIVE,
    "PROVISIONED": SubjectStatus.ACTIVE,
    "SUSPENDED": SubjectStatus.SUSPENDED,
    "DEPROVISIONED": SubjectStatus.DELETED,
    "LOCKED_OUT": SubjectStatus.SUSPENDED,
    "PASSWORD_EXPIRED": SubjectStatus.ACTIVE,
    "RECOVERY": SubjectStatus.ACTIVE,
}

ADMIN_ROLE_TYPES: set[str] = {
    "SUPER_ADMIN",
    "ORG_ADMIN",
    "APP_ADMIN",
    "USER_ADMIN",
    "HELP_DESK_ADMIN",
    "READ_ONLY_ADMIN",
    "MOBILE_ADMIN",
    "API_ACCESS_MANAGEMENT_ADMIN",
    "REPORT_ADMIN",
    "GROUP_MEMBERSHIP_ADMIN",
}

_MAX_RETRIES = 5
_BASE_DELAY = 1.0


class OktaAdapter(BaseAdapter):
    """Read-only adapter for Okta via Management API."""

    source_name: str = SOURCE

    def __init__(self) -> None:
        self._client: httpx.AsyncClient | None = None
        self._base_url: str = ""
        self._domain: str = ""

    # ---- lifecycle ---------------------------------------------------------

    async def connect(self, credentials: dict) -> None:
        """
        Connect using API token.

        Expected keys: okta_domain, api_token
        """
        domain = credentials["okta_domain"].rstrip("/")
        if not domain.startswith("https://"):
            domain = f"https://{domain}"
        self._domain = domain
        self._base_url = f"{domain}/api/v1"
        api_token = credentials["api_token"]

        logger.info("okta.connect", domain=domain)

        self._client = httpx.AsyncClient(
            headers={
                "Authorization": f"SSWS {api_token}",
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
            timeout=30.0,
        )

        # Verify connectivity
        if not await self.test_connection():
            await self.disconnect()
            raise ConnectionError("Okta connection verification failed")

        logger.info("okta.connected", domain=domain)

    async def test_connection(self) -> bool:
        try:
            if self._client is None:
                return False
            resp = await self._okta_get("/org")
            return resp is not None
        except Exception:
            return False

    async def disconnect(self) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None
        logger.info("okta.disconnected")

    # ---- extraction --------------------------------------------------------

    async def extract(self) -> GraphSnapshot:
        if self._client is None:
            raise RuntimeError("Adapter not connected — call connect() first")

        logger.info("okta.extract.start")

        subjects: list[Subject] = []
        permissions: list[Permission] = []
        resources: list[Resource] = []
        assignments: list[Assignment] = []

        # 1. Users
        users = await self._get_all_pages("/users?limit=200")
        for u in users:
            subj = self._map_user(u)
            subjects.append(subj)

        # 2. Groups → Permission containers
        groups = await self._get_all_pages("/groups?limit=200")
        group_perm_map: dict[str, Permission] = {}
        for g in groups:
            perm = self._map_group(g)
            permissions.append(perm)
            group_perm_map[g["id"]] = perm

        # 3. User → Group assignments
        for u in users:
            uid = u["id"]
            subj_id = vektor_id(SOURCE, uid)
            user_groups = await self._get_all_pages(f"/users/{uid}/groups")
            for ug in user_groups:
                gid = ug["id"]
                perm = group_perm_map.get(gid)
                if perm:
                    assignments.append(
                        Assignment(
                            subject_id=subj_id,
                            permission_id=perm.id,
                            source=SOURCE,
                            is_active=True,
                        )
                    )

        # 4. Applications → Resources
        apps = await self._get_all_pages("/apps?limit=200")
        for app in apps:
            res = self._map_application(app)
            resources.append(res)

        # 5. User → App assignments
        for u in users:
            uid = u["id"]
            subj_id = vektor_id(SOURCE, uid)
            try:
                app_links = await self._get_all_pages(f"/users/{uid}/appLinks")
                for al in app_links:
                    app_id = al.get("appInstanceId", al.get("id", ""))
                    perm = Permission(
                        id=vektor_id(SOURCE, f"applink:{uid}:{app_id}"),
                        source=SOURCE,
                        name=f"App-{al.get('appName', al.get('label', 'unknown'))}",
                        type=PermissionType.ENTITLEMENT,
                        is_privileged=False,
                        attributes={"app_instance_id": app_id, "label": al.get("label")},
                    )
                    permissions.append(perm)
                    res_id = vektor_id(SOURCE, app_id)
                    assignments.append(
                        Assignment(
                            subject_id=subj_id,
                            permission_id=perm.id,
                            resource_id=res_id,
                            source=SOURCE,
                            is_active=True,
                        )
                    )
            except Exception as exc:
                logger.warning("okta.app_links_failed", user_id=uid, error=str(exc))

        # 6. Admin roles for each user
        for u in users:
            uid = u["id"]
            subj_id = vektor_id(SOURCE, uid)
            try:
                roles = await self._get_all_pages(f"/users/{uid}/roles")
                for r in roles:
                    perm = self._map_admin_role(r)
                    permissions.append(perm)
                    assignments.append(
                        Assignment(
                            subject_id=subj_id,
                            permission_id=perm.id,
                            source=SOURCE,
                            is_active=True,
                            granted_at=_parse_dt(r.get("created")),
                        )
                    )
            except Exception as exc:
                logger.warning("okta.roles_failed", user_id=uid, error=str(exc))

        # 7. MFA enrichment
        await self._enrich_mfa(subjects, users)

        logger.info(
            "okta.extract.done",
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
        profile = u.get("profile", {})
        okta_status = u.get("status", "ACTIVE")

        stype = SubjectType.HUMAN
        if profile.get("userType", "").lower() == "service":
            stype = SubjectType.SERVICE_ACCOUNT

        return Subject(
            id=vektor_id(SOURCE, uid),
            external_id=uid,
            source=SOURCE,
            type=stype,
            display_name=f"{profile.get('firstName', '')} {profile.get('lastName', '')}".strip() or uid,
            email=profile.get("email"),
            department=profile.get("department"),
            manager_id=profile.get("managerId"),
            status=_OKTA_STATUS_MAP.get(okta_status, SubjectStatus.ACTIVE),
            last_seen=_parse_dt(u.get("lastLogin")),
            mfa_enabled=False,  # enriched later
            attributes={
                "login": profile.get("login"),
                "title": profile.get("title"),
                "okta_status": okta_status,
            },
            created_at=_parse_dt(u.get("created")) or utcnow(),
            updated_at=_parse_dt(u.get("lastUpdated")) or utcnow(),
        )

    def _map_group(self, g: dict) -> Permission:
        gid = g["id"]
        name = g.get("profile", {}).get("name", g.get("id", ""))
        gtype = g.get("type", "OKTA_GROUP")

        return Permission(
            id=vektor_id(SOURCE, gid),
            source=SOURCE,
            name=name,
            type=PermissionType.GROUP,
            is_privileged=any(
                kw in name.lower() for kw in ("admin", "super", "owner", "privileged")
            ),
            risk_keywords=["admin"] if "admin" in name.lower() else [],
            attributes={"group_type": gtype, "description": g.get("profile", {}).get("description")},
        )

    def _map_application(self, app: dict) -> Resource:
        app_id = app["id"]
        name = app.get("label", app.get("name", app_id))
        # Classify sensitivity by app category
        sign_on = app.get("signOnMode", "").lower()
        sensitivity = Sensitivity.MEDIUM
        if any(kw in name.lower() for kw in ("aws", "azure", "gcp", "vault", "okta")):
            sensitivity = Sensitivity.CRITICAL
        elif any(kw in name.lower() for kw in ("slack", "jira", "github", "salesforce")):
            sensitivity = Sensitivity.HIGH

        return Resource(
            id=vektor_id(SOURCE, app_id),
            source=SOURCE,
            type="okta_application",
            name=name,
            sensitivity=sensitivity,
            attributes={
                "sign_on_mode": sign_on,
                "status": app.get("status"),
            },
        )

    def _map_admin_role(self, r: dict) -> Permission:
        role_type = r.get("type", "UNKNOWN")
        label = r.get("label", role_type)
        return Permission(
            id=vektor_id(SOURCE, f"role:{role_type}"),
            source=SOURCE,
            name=label,
            type=PermissionType.ROLE,
            actions=[role_type],
            is_privileged=role_type in ADMIN_ROLE_TYPES,
            risk_keywords=["admin"] if "ADMIN" in role_type else [],
            attributes={"role_type": role_type},
        )

    # ---- internal: MFA enrichment ------------------------------------------

    async def _enrich_mfa(self, subjects: list[Subject], raw_users: list[dict]) -> None:
        """Check enrolled MFA factors for each user."""
        user_map = {vektor_id(SOURCE, u["id"]): u["id"] for u in raw_users}
        for subj in subjects:
            if subj.type != SubjectType.HUMAN:
                continue
            uid = user_map.get(subj.id)
            if uid is None:
                continue
            try:
                factors = await self._get_all_pages(f"/users/{uid}/factors")
                enrolled = [f for f in factors if f.get("status") == "ACTIVE"]
                subj.mfa_enabled = len(enrolled) > 0
                subj.attributes["mfa_factor_count"] = len(enrolled)
                subj.attributes["mfa_factor_types"] = [f.get("factorType") for f in enrolled]
            except Exception as exc:
                logger.warning("okta.mfa_check_failed", user_id=uid, error=str(exc))

    # ---- internal: API helpers ---------------------------------------------

    async def _okta_get(self, path: str) -> dict | list | None:
        """GET with rate-limit-aware retries."""
        url = f"{self._base_url}{path}" if path.startswith("/") else path

        for attempt in range(_MAX_RETRIES):
            try:
                resp = await self._client.get(url)

                # Respect rate limits
                remaining = resp.headers.get("X-Rate-Limit-Remaining")
                if remaining is not None and int(remaining) < 5:
                    reset = resp.headers.get("X-Rate-Limit-Reset")
                    if reset:
                        import time
                        wait = max(0, int(reset) - int(time.time())) + 1
                        logger.warning("okta.rate_limit_low", remaining=remaining, wait=wait)
                        await asyncio.sleep(min(wait, 30))

                if resp.status_code == 429:
                    reset = resp.headers.get("X-Rate-Limit-Reset")
                    delay = _BASE_DELAY * (2 ** attempt)
                    if reset:
                        import time
                        delay = max(delay, int(reset) - int(time.time()) + 1)
                    logger.warning("okta.rate_limited", delay=delay, attempt=attempt)
                    await asyncio.sleep(delay)
                    continue

                resp.raise_for_status()
                return resp.json()

            except httpx.HTTPStatusError as exc:
                if attempt < _MAX_RETRIES - 1:
                    delay = _BASE_DELAY * (2 ** attempt)
                    logger.warning("okta.request_retry", status=exc.response.status_code, delay=delay)
                    await asyncio.sleep(delay)
                else:
                    logger.error("okta.request_failed", url=url, error=str(exc))
                    raise
        return None

    async def _get_all_pages(self, path: str) -> list[dict]:
        """Fetch all pages using Okta's Link-header cursor pagination."""
        items: list[dict] = []
        url: str | None = f"{self._base_url}{path}" if path.startswith("/") else path

        while url:
            for attempt in range(_MAX_RETRIES):
                try:
                    resp = await self._client.get(url)

                    if resp.status_code == 429:
                        delay = _BASE_DELAY * (2 ** attempt)
                        logger.warning("okta.page_rate_limited", delay=delay)
                        await asyncio.sleep(delay)
                        continue

                    resp.raise_for_status()
                    data = resp.json()
                    if isinstance(data, list):
                        items.extend(data)
                    else:
                        items.extend(data.get("value", [data]))

                    # Parse Link header for next page
                    url = self._parse_next_link(resp.headers.get("Link", ""))
                    break

                except httpx.HTTPStatusError as exc:
                    if attempt < _MAX_RETRIES - 1:
                        await asyncio.sleep(_BASE_DELAY * (2 ** attempt))
                    else:
                        logger.error("okta.pagination_failed", url=url, error=str(exc))
                        url = None
                        break

        return items

    @staticmethod
    def _parse_next_link(link_header: str) -> str | None:
        """Parse Okta's Link header to find the next page URL."""
        if not link_header:
            return None
        # Format: <url>; rel="next", <url>; rel="self"
        for part in link_header.split(","):
            part = part.strip()
            match = re.match(r'<([^>]+)>;\s*rel="next"', part)
            if match:
                return match.group(1)
        return None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_dt(value: str | datetime | None) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except (ValueError, AttributeError):
        return None
