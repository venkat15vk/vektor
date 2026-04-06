"""
Vektor AI — Okta System Log Ingester

Ingests Okta system log events via the /api/v1/logs endpoint.
Okta logs cover authentication, authorization, user lifecycle,
app assignments, MFA events, and admin actions.

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
# Okta event type → normalized EventType mapping
# ---------------------------------------------------------------------------

_OKTA_EVENT_MAP: dict[str, EventType] = {
    # Authentication
    "user.session.start": EventType.AUTH_LOGIN,
    "user.session.end": EventType.AUTH_LOGOUT,
    "user.authentication.auth_via_mfa": EventType.AUTH_MFA_SUCCESS,
    "user.authentication.verify": EventType.AUTH_MFA_CHALLENGE,
    "user.mfa.factor.activate": EventType.AUTH_MFA_SUCCESS,
    "user.mfa.factor.deactivate": EventType.AUTH_MFA_FAILURE,
    "user.authentication.sso": EventType.AUTH_LOGIN,
    "user.authentication.auth_via_IDP": EventType.AUTH_LOGIN,
    "policy.evaluate_sign_on": EventType.AUTH_LOGIN,

    # User lifecycle
    "user.lifecycle.create": EventType.IAM_CREATE_USER,
    "user.lifecycle.delete.initiated": EventType.IAM_DELETE_USER,
    "user.lifecycle.deactivate": EventType.IAM_MODIFY_USER,
    "user.lifecycle.activate": EventType.IAM_MODIFY_USER,
    "user.lifecycle.suspend": EventType.IAM_MODIFY_USER,
    "user.lifecycle.unsuspend": EventType.IAM_MODIFY_USER,
    "user.account.update_profile": EventType.IAM_MODIFY_USER,
    "user.account.update_password": EventType.AUTH_PASSWORD_CHANGE,
    "user.account.reset_password": EventType.AUTH_PASSWORD_CHANGE,

    # Group membership
    "group.user_membership.add": EventType.GROUP_ADD_MEMBER,
    "group.user_membership.remove": EventType.GROUP_REMOVE_MEMBER,

    # App assignment
    "application.user_membership.add": EventType.APP_ASSIGNED,
    "application.user_membership.remove": EventType.APP_UNASSIGNED,
    "app.generic.unauth_app_access_attempt": EventType.APP_ACCESS,
    "user.authentication.auth_via_social": EventType.AUTH_LOGIN,

    # Admin / config
    "application.lifecycle.create": EventType.RESOURCE_CREATE,
    "application.lifecycle.delete": EventType.RESOURCE_DELETE,
    "application.lifecycle.update": EventType.RESOURCE_MODIFY,
    "policy.lifecycle.create": EventType.IAM_CONFIG_CHANGE,
    "policy.lifecycle.update": EventType.IAM_CONFIG_CHANGE,
    "policy.lifecycle.delete": EventType.IAM_CONFIG_CHANGE,
    "policy.rule.create": EventType.IAM_CONFIG_CHANGE,
    "policy.rule.update": EventType.IAM_CONFIG_CHANGE,
    "policy.rule.delete": EventType.IAM_CONFIG_CHANGE,
    "system.org.rate_limit.warning": EventType.UNKNOWN,
    "system.org.rate_limit.violation": EventType.UNKNOWN,

    # Role / privilege
    "user.account.privilege.grant": EventType.IAM_ATTACH_POLICY,
    "user.account.privilege.revoke": EventType.IAM_DETACH_POLICY,
}

# Privileged Okta event types
_PRIVILEGED_EVENTS = {
    "user.account.privilege.grant",
    "user.account.privilege.revoke",
    "user.lifecycle.create",
    "user.lifecycle.delete.initiated",
    "application.lifecycle.create",
    "application.lifecycle.delete",
    "policy.lifecycle.create",
    "policy.lifecycle.update",
    "policy.lifecycle.delete",
    "user.account.reset_password",
    "group.user_membership.add",
    "group.user_membership.remove",
}

_CONFIG_EVENTS = {
    "policy.lifecycle.create",
    "policy.lifecycle.update",
    "policy.lifecycle.delete",
    "policy.rule.create",
    "policy.rule.update",
    "policy.rule.delete",
    "application.lifecycle.create",
    "application.lifecycle.update",
    "application.lifecycle.delete",
}


class OktaLogIngester(BaseLogIngester):
    """
    Okta system log ingester.

    Uses the Okta System Log API:
      GET /api/v1/logs?since={ISO8601}&until={ISO8601}&sortOrder=ASCENDING

    Pagination: Okta uses Link headers with `rel="next"` for cursor-based pagination.
    Rate limits: Respects X-Rate-Limit-Remaining headers.
    """

    source_name = "okta_syslog"

    def __init__(self) -> None:
        self._base_url: str = ""
        self._api_token: str = ""
        self._client: httpx.AsyncClient | None = None
        self._checkpoint: datetime | None = None

    async def connect(self, credentials: dict[str, Any]) -> None:
        """
        Connect to Okta System Log API.

        Expected credentials:
        - okta_domain: e.g., "company.okta.com"
        - api_token: Okta API token (read-only admin scope)
        """
        domain = credentials["okta_domain"].rstrip("/")
        if not domain.startswith("https://"):
            domain = f"https://{domain}"
        self._base_url = domain
        self._api_token = credentials["api_token"]

        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(30.0),
            headers={
                "Authorization": f"SSWS {self._api_token}",
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
        )

        # Test connection
        resp = await self._client.get(
            f"{self._base_url}/api/v1/logs",
            params={"limit": 1},
        )
        resp.raise_for_status()

        logger.info("okta_syslog_connected", domain=domain)

    async def ingest(
        self,
        start_time: datetime,
        end_time: datetime | None = None,
    ) -> AsyncIterator[ActivityEvent]:
        """Ingest Okta system log events for the given time range."""
        if self._client is None:
            raise RuntimeError("Not connected. Call connect() first.")

        if end_time is None:
            end_time = datetime.now(timezone.utc)

        event_count = 0
        error_count = 0

        params: dict[str, Any] = {
            "since": start_time.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            "until": end_time.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            "sortOrder": "ASCENDING",
            "limit": 1000,
        }

        url = f"{self._base_url}/api/v1/logs"

        while url:
            resp = await self._client.get(url, params=params)

            # Handle rate limiting
            remaining = int(resp.headers.get("X-Rate-Limit-Remaining", "100"))
            if remaining < 5:
                reset_epoch = int(resp.headers.get("X-Rate-Limit-Reset", "0"))
                if reset_epoch > 0:
                    import asyncio
                    wait_seconds = max(
                        1,
                        reset_epoch - int(datetime.now(timezone.utc).timestamp()),
                    )
                    logger.warning(
                        "okta_rate_limit_approaching",
                        remaining=remaining,
                        waiting_seconds=wait_seconds,
                    )
                    await asyncio.sleep(wait_seconds)
                    continue

            resp.raise_for_status()
            events = resp.json()

            for raw_event in events:
                try:
                    activity = self._normalize_event(raw_event)
                    if activity is not None:
                        event_count += 1
                        self._checkpoint = activity.timestamp
                        yield activity
                except Exception as exc:
                    error_count += 1
                    if error_count <= 10:
                        logger.warning(
                            "okta_event_parse_error",
                            error=str(exc),
                            event_uuid=raw_event.get("uuid", "unknown"),
                        )

            # Follow pagination via Link header
            url = self._get_next_link(resp.headers.get("Link", ""))
            params = {}  # params are embedded in the next URL

        logger.info(
            "okta_syslog_ingest_complete",
            events_ingested=event_count,
            errors=error_count,
        )

    async def get_latest_checkpoint(self) -> datetime | None:
        return self._checkpoint

    async def disconnect(self) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None

    # -------------------------------------------------------------------
    # Normalization
    # -------------------------------------------------------------------

    def _normalize_event(self, raw: dict[str, Any]) -> ActivityEvent | None:
        """Normalize an Okta system log event to ActivityEvent."""
        event_type_str = raw.get("eventType", "")

        # Skip low-value system events
        if event_type_str.startswith("system.") and event_type_str not in _CONFIG_EVENTS:
            return None

        event_type = _OKTA_EVENT_MAP.get(event_type_str, EventType.UNKNOWN)

        # Skip completely unrecognized events to reduce noise
        if event_type == EventType.UNKNOWN and event_type_str not in _CONFIG_EVENTS:
            return None

        # Parse actor
        actor = raw.get("actor", {})
        actor_id = actor.get("alternateId", actor.get("id", ""))
        actor_name = actor.get("displayName", actor_id)
        actor_type_raw = actor.get("type", "User")
        actor_type = "human" if actor_type_raw == "User" else "service_account"

        # Parse target(s) — Okta events can have multiple targets
        targets = raw.get("target", [])
        target_id = ""
        target_type = ""
        target_name = ""
        if targets:
            primary_target = targets[0]
            target_id = primary_target.get("alternateId", primary_target.get("id", ""))
            target_type = primary_target.get("type", "")
            target_name = primary_target.get("displayName", target_id)

        # Parse timestamp
        published = raw.get("published", "")
        timestamp = self._parse_timestamp(published)
        if timestamp is None:
            return None

        # Parse client info
        client = raw.get("client", {})
        geo = client.get("geographicalContext", {})
        source_ip = client.get("ipAddress", "")
        user_agent = client.get("userAgent", {}).get("rawUserAgent", "")
        geo_str = ""
        if geo:
            city = geo.get("city", "")
            country = geo.get("country", "")
            geo_str = f"{city}, {country}" if city else country

        # Parse outcome
        outcome = raw.get("outcome", {})
        success = outcome.get("result", "") == "SUCCESS"
        error_reason = outcome.get("reason", "")

        # Session
        auth_context = raw.get("authenticationContext", {})
        session_id = auth_context.get("externalSessionId", "")

        return ActivityEvent(
            source=self.source_name,
            source_event_id=raw.get("uuid", ""),
            event_type=event_type,
            raw_event_name=event_type_str,
            timestamp=timestamp,
            actor_id=actor_id,
            actor_display_name=actor_name,
            actor_type=actor_type,
            target_id=target_id,
            target_type=target_type,
            target_name=target_name,
            source_ip=source_ip,
            user_agent=user_agent,
            geo_location=geo_str,
            session_id=session_id,
            success=success,
            error_code="" if success else "FAILURE",
            error_message=error_reason,
            is_privileged_action=event_type_str in _PRIVILEGED_EVENTS,
            is_config_change=event_type_str in _CONFIG_EVENTS,
            is_cross_boundary=False,
            raw_payload=raw,
        )

    def _parse_timestamp(self, time_str: str) -> datetime | None:
        """Parse an Okta ISO8601 timestamp."""
        if not time_str:
            return None
        try:
            return datetime.fromisoformat(time_str.replace("Z", "+00:00"))
        except (ValueError, TypeError):
            return None

    def _get_next_link(self, link_header: str) -> str:
        """Extract the 'next' URL from Okta's Link header."""
        if not link_header:
            return ""
        for part in link_header.split(","):
            part = part.strip()
            if 'rel="next"' in part:
                url = part.split(";")[0].strip().strip("<>")
                return url
        return ""
