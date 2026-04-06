"""
Vektor AI — Microsoft Entra ID Audit Log Ingester

Ingests audit and sign-in logs from Microsoft Graph API:
- Audit logs: /auditLogs/directoryAudits (IAM changes, role assignments, config)
- Sign-in logs: /auditLogs/signIns (authentication events, MFA, conditional access)

Normalizes all events to ActivityEvent for unified behavioral analysis.
"""

from __future__ import annotations

from datetime import datetime, timezone, timedelta
from typing import Any, AsyncIterator

import httpx
import structlog

from .base import ActivityEvent, BaseLogIngester, EventType

logger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Entra audit event → normalized EventType mapping
# ---------------------------------------------------------------------------

_ENTRA_AUDIT_MAP: dict[str, EventType] = {
    # User lifecycle
    "Add user": EventType.IAM_CREATE_USER,
    "Delete user": EventType.IAM_DELETE_USER,
    "Update user": EventType.IAM_MODIFY_USER,
    "Disable account": EventType.IAM_MODIFY_USER,
    "Enable account": EventType.IAM_MODIFY_USER,
    "Reset user password": EventType.AUTH_PASSWORD_CHANGE,
    "Change user password": EventType.AUTH_PASSWORD_CHANGE,
    "Set force change user password": EventType.AUTH_PASSWORD_CHANGE,

    # Group membership
    "Add member to group": EventType.GROUP_ADD_MEMBER,
    "Remove member from group": EventType.GROUP_REMOVE_MEMBER,
    "Add group": EventType.RESOURCE_CREATE,
    "Delete group": EventType.RESOURCE_DELETE,
    "Update group": EventType.RESOURCE_MODIFY,

    # Role assignments
    "Add member to role": EventType.IAM_ATTACH_POLICY,
    "Remove member from role": EventType.IAM_DETACH_POLICY,
    "Add eligible member to role": EventType.IAM_ATTACH_POLICY,
    "Remove eligible member from role": EventType.IAM_DETACH_POLICY,
    "Add scoped member to role": EventType.IAM_ATTACH_POLICY,

    # Application management
    "Add application": EventType.RESOURCE_CREATE,
    "Delete application": EventType.RESOURCE_DELETE,
    "Update application": EventType.RESOURCE_MODIFY,
    "Add service principal": EventType.IAM_CREATE_USER,
    "Delete service principal": EventType.IAM_DELETE_USER,
    "Update service principal": EventType.IAM_MODIFY_USER,

    # App role assignments
    "Add app role assignment grant to user": EventType.APP_ASSIGNED,
    "Remove app role assignment from user": EventType.APP_UNASSIGNED,
    "Add app role assignment to service principal": EventType.APP_ASSIGNED,

    # Policy / config
    "Add policy": EventType.IAM_CONFIG_CHANGE,
    "Delete policy": EventType.IAM_CONFIG_CHANGE,
    "Update policy": EventType.IAM_CONFIG_CHANGE,
    "Set Company Information": EventType.IAM_CONFIG_CHANGE,
    "Update authorization policy": EventType.IAM_CONFIG_CHANGE,

    # Credentials
    "Add service principal credentials": EventType.IAM_CREATE_KEY,
    "Remove service principal credentials": EventType.IAM_CONFIG_CHANGE,
    "Update application – Certificates and secrets management": EventType.IAM_CREATE_KEY,

    # Consent
    "Consent to application": EventType.APP_ASSIGNED,
    "Add delegated permission grant": EventType.IAM_ATTACH_POLICY,
    "Add app role assignment grant to service principal": EventType.IAM_ATTACH_POLICY,
}

# Privileged Entra activities
_PRIVILEGED_ACTIVITIES = {
    "Add member to role",
    "Remove member from role",
    "Add eligible member to role",
    "Add user",
    "Delete user",
    "Add service principal credentials",
    "Add delegated permission grant",
    "Add app role assignment grant to service principal",
    "Consent to application",
    "Update authorization policy",
    "Add policy",
    "Delete policy",
}

_CONFIG_ACTIVITIES = {
    "Add policy",
    "Delete policy",
    "Update policy",
    "Set Company Information",
    "Update authorization policy",
    "Update application – Certificates and secrets management",
    "Add service principal credentials",
    "Remove service principal credentials",
}


class EntraLogIngester(BaseLogIngester):
    """
    Microsoft Entra ID audit and sign-in log ingester.

    Uses Microsoft Graph API:
    - Audit logs: GET /auditLogs/directoryAudits
    - Sign-in logs: GET /auditLogs/signIns

    Auth: App Registration with AuditLog.Read.All + Directory.Read.All
    (application permissions, not delegated).
    """

    source_name = "entra_audit"

    def __init__(self) -> None:
        self._tenant_id: str = ""
        self._client_id: str = ""
        self._client_secret: str = ""
        self._access_token: str = ""
        self._token_expires_at: datetime = datetime.min.replace(tzinfo=timezone.utc)
        self._client: httpx.AsyncClient | None = None
        self._checkpoint: datetime | None = None
        self._graph_url = "https://graph.microsoft.com/v1.0"

    async def connect(self, credentials: dict[str, Any]) -> None:
        """
        Connect to Microsoft Graph API for Entra audit logs.

        Expected credentials:
        - tenant_id: Azure AD tenant ID
        - client_id: App registration client ID
        - client_secret: App registration client secret
        """
        self._tenant_id = credentials["tenant_id"]
        self._client_id = credentials["client_id"]
        self._client_secret = credentials["client_secret"]

        self._client = httpx.AsyncClient(timeout=httpx.Timeout(30.0))
        await self._refresh_token()

        logger.info("entra_audit_connected", tenant_id=self._tenant_id)

    async def _refresh_token(self) -> None:
        """Obtain or refresh OAuth2 access token via client credentials flow."""
        if self._client is None:
            raise RuntimeError("HTTP client not initialized")

        token_url = (
            f"https://login.microsoftonline.com/{self._tenant_id}/oauth2/v2.0/token"
        )

        resp = await self._client.post(
            token_url,
            data={
                "grant_type": "client_credentials",
                "client_id": self._client_id,
                "client_secret": self._client_secret,
                "scope": "https://graph.microsoft.com/.default",
            },
        )
        resp.raise_for_status()
        data = resp.json()

        self._access_token = data["access_token"]
        expires_in = int(data.get("expires_in", 3600))
        self._token_expires_at = datetime.now(timezone.utc) + timedelta(
            seconds=expires_in - 60  # refresh 60s early
        )

        logger.debug("entra_token_refreshed", expires_in=expires_in)

    async def _ensure_token(self) -> None:
        """Refresh token if expired."""
        if datetime.now(timezone.utc) >= self._token_expires_at:
            await self._refresh_token()

    async def _graph_get(self, url: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Make an authenticated GET request to Microsoft Graph."""
        if self._client is None:
            raise RuntimeError("Not connected")

        await self._ensure_token()

        resp = await self._client.get(
            url,
            params=params,
            headers={"Authorization": f"Bearer {self._access_token}"},
        )

        # Handle throttling
        if resp.status_code == 429:
            retry_after = int(resp.headers.get("Retry-After", "10"))
            logger.warning("entra_throttled", retry_after=retry_after)
            import asyncio
            await asyncio.sleep(retry_after)
            return await self._graph_get(url, params)

        resp.raise_for_status()
        return resp.json()

    async def ingest(
        self,
        start_time: datetime,
        end_time: datetime | None = None,
    ) -> AsyncIterator[ActivityEvent]:
        """Ingest Entra audit and sign-in logs for the given time range."""
        if end_time is None:
            end_time = datetime.now(timezone.utc)

        # Ingest audit logs
        async for event in self._ingest_audit_logs(start_time, end_time):
            yield event

        # Ingest sign-in logs
        async for event in self._ingest_signin_logs(start_time, end_time):
            yield event

    async def get_latest_checkpoint(self) -> datetime | None:
        return self._checkpoint

    async def disconnect(self) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None

    # -------------------------------------------------------------------
    # Audit logs
    # -------------------------------------------------------------------

    async def _ingest_audit_logs(
        self,
        start_time: datetime,
        end_time: datetime,
    ) -> AsyncIterator[ActivityEvent]:
        """Ingest directory audit logs from Microsoft Graph."""
        event_count = 0
        error_count = 0

        # OData filter for time range
        filter_str = (
            f"activityDateTime ge {start_time.strftime('%Y-%m-%dT%H:%M:%SZ')} "
            f"and activityDateTime le {end_time.strftime('%Y-%m-%dT%H:%M:%SZ')}"
        )

        url = f"{self._graph_url}/auditLogs/directoryAudits"
        params: dict[str, Any] = {
            "$filter": filter_str,
            "$orderby": "activityDateTime asc",
            "$top": 999,
        }

        while url:
            data = await self._graph_get(url, params)

            for raw in data.get("value", []):
                try:
                    activity = self._normalize_audit_event(raw)
                    if activity is not None:
                        event_count += 1
                        self._checkpoint = activity.timestamp
                        yield activity
                except Exception as exc:
                    error_count += 1
                    if error_count <= 10:
                        logger.warning(
                            "entra_audit_parse_error",
                            error=str(exc),
                            event_id=raw.get("id", "unknown"),
                        )

            # Follow @odata.nextLink for pagination
            url = data.get("@odata.nextLink", "")
            params = {}  # nextLink includes query params

        logger.info(
            "entra_audit_ingest_complete",
            events=event_count,
            errors=error_count,
        )

    def _normalize_audit_event(self, raw: dict[str, Any]) -> ActivityEvent | None:
        """Normalize an Entra directory audit event."""
        activity_name = raw.get("activityDisplayName", "")
        event_type = _ENTRA_AUDIT_MAP.get(activity_name, EventType.UNKNOWN)

        # Skip unrecognized low-value events
        if event_type == EventType.UNKNOWN and activity_name not in _CONFIG_ACTIVITIES:
            return None

        # Parse actor
        initiated_by = raw.get("initiatedBy", {})
        actor_id = ""
        actor_name = ""
        actor_type = "human"

        if "user" in initiated_by and initiated_by["user"]:
            user = initiated_by["user"]
            actor_id = user.get("userPrincipalName", user.get("id", ""))
            actor_name = user.get("displayName", actor_id)
            actor_type = "human"
        elif "app" in initiated_by and initiated_by["app"]:
            app = initiated_by["app"]
            actor_id = app.get("servicePrincipalId", app.get("appId", ""))
            actor_name = app.get("displayName", actor_id)
            actor_type = "service_account"

        # Parse target(s)
        targets = raw.get("targetResources", [])
        target_id = ""
        target_type = ""
        target_name = ""
        if targets:
            t = targets[0]
            target_id = t.get("id", t.get("userPrincipalName", ""))
            target_type = t.get("type", "")
            target_name = t.get("displayName", target_id)

        # Parse timestamp
        timestamp_str = raw.get("activityDateTime", "")
        timestamp = self._parse_timestamp(timestamp_str)
        if timestamp is None:
            return None

        # Outcome
        result = raw.get("result", "")
        success = result == "success"

        return ActivityEvent(
            source=self.source_name,
            source_event_id=raw.get("id", ""),
            event_type=event_type,
            raw_event_name=activity_name,
            timestamp=timestamp,
            actor_id=actor_id,
            actor_display_name=actor_name,
            actor_type=actor_type,
            target_id=target_id,
            target_type=target_type,
            target_name=target_name,
            source_ip="",  # Not available in audit logs
            user_agent="",
            geo_location="",
            session_id=raw.get("correlationId", ""),
            success=success,
            error_code="" if success else raw.get("resultReason", ""),
            error_message=raw.get("resultReason", ""),
            is_privileged_action=activity_name in _PRIVILEGED_ACTIVITIES,
            is_config_change=activity_name in _CONFIG_ACTIVITIES,
            is_cross_boundary=False,
            raw_payload=raw,
        )

    # -------------------------------------------------------------------
    # Sign-in logs
    # -------------------------------------------------------------------

    async def _ingest_signin_logs(
        self,
        start_time: datetime,
        end_time: datetime,
    ) -> AsyncIterator[ActivityEvent]:
        """Ingest sign-in logs from Microsoft Graph."""
        event_count = 0
        error_count = 0

        filter_str = (
            f"createdDateTime ge {start_time.strftime('%Y-%m-%dT%H:%M:%SZ')} "
            f"and createdDateTime le {end_time.strftime('%Y-%m-%dT%H:%M:%SZ')}"
        )

        url = f"{self._graph_url}/auditLogs/signIns"
        params: dict[str, Any] = {
            "$filter": filter_str,
            "$orderby": "createdDateTime asc",
            "$top": 999,
        }

        while url:
            data = await self._graph_get(url, params)

            for raw in data.get("value", []):
                try:
                    activity = self._normalize_signin_event(raw)
                    if activity is not None:
                        event_count += 1
                        self._checkpoint = activity.timestamp
                        yield activity
                except Exception as exc:
                    error_count += 1
                    if error_count <= 10:
                        logger.warning(
                            "entra_signin_parse_error",
                            error=str(exc),
                            event_id=raw.get("id", "unknown"),
                        )

            url = data.get("@odata.nextLink", "")
            params = {}

        logger.info(
            "entra_signin_ingest_complete",
            events=event_count,
            errors=error_count,
        )

    def _normalize_signin_event(self, raw: dict[str, Any]) -> ActivityEvent | None:
        """Normalize an Entra sign-in log event."""
        # Determine event type based on MFA and status
        status = raw.get("status", {})
        error_code = status.get("errorCode", 0)
        success = error_code == 0

        # Check MFA details
        mfa_detail = raw.get("mfaDetail", {})
        auth_methods = raw.get("authenticationMethodsUsed", [])

        if mfa_detail or auth_methods:
            if success:
                event_type = EventType.AUTH_MFA_SUCCESS
            else:
                event_type = EventType.AUTH_MFA_FAILURE
        else:
            event_type = EventType.AUTH_LOGIN

        # Parse timestamp
        timestamp_str = raw.get("createdDateTime", "")
        timestamp = self._parse_timestamp(timestamp_str)
        if timestamp is None:
            return None

        # Parse location
        location = raw.get("location", {})
        geo_parts = []
        if location.get("city"):
            geo_parts.append(location["city"])
        if location.get("state"):
            geo_parts.append(location["state"])
        if location.get("countryOrRegion"):
            geo_parts.append(location["countryOrRegion"])
        geo_str = ", ".join(geo_parts)

        # App info (what was being accessed)
        app_name = raw.get("appDisplayName", "")
        resource_name = raw.get("resourceDisplayName", "")

        # Device info
        device_detail = raw.get("deviceDetail", {})
        user_agent_str = (
            f"{device_detail.get('operatingSystem', '')} "
            f"{device_detail.get('browser', '')}"
        ).strip()

        return ActivityEvent(
            source=self.source_name,
            source_event_id=raw.get("id", ""),
            event_type=event_type,
            raw_event_name=f"signIn:{app_name or 'unknown'}",
            timestamp=timestamp,
            actor_id=raw.get("userPrincipalName", raw.get("userId", "")),
            actor_display_name=raw.get("userDisplayName", ""),
            actor_type="human",
            target_id=raw.get("resourceId", ""),
            target_type="application",
            target_name=resource_name or app_name,
            source_ip=raw.get("ipAddress", ""),
            user_agent=user_agent_str,
            geo_location=geo_str,
            session_id=raw.get("correlationId", ""),
            success=success,
            error_code=str(error_code) if error_code else "",
            error_message=status.get("failureReason", ""),
            is_privileged_action=False,
            is_config_change=False,
            is_cross_boundary=False,
            raw_payload=raw,
        )

    # -------------------------------------------------------------------
    # Helpers
    # -------------------------------------------------------------------

    def _parse_timestamp(self, time_str: str) -> datetime | None:
        if not time_str:
            return None
        try:
            return datetime.fromisoformat(time_str.replace("Z", "+00:00"))
        except (ValueError, TypeError):
            return None
