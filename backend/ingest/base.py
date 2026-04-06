"""
Vektor AI — Base Log Ingester

Defines the unified ActivityEvent model and abstract base for all log ingesters.
Every log source normalizes its events into ActivityEvent objects for
consistent feature computation and behavioral analysis.
"""

from __future__ import annotations

import uuid
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from enum import Enum
from typing import Any, AsyncIterator, Optional

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger(__name__)


class EventType(str, Enum):
    """Normalized event types across all log sources."""
    AUTH_LOGIN = "auth.login"
    AUTH_LOGOUT = "auth.logout"
    AUTH_MFA_CHALLENGE = "auth.mfa_challenge"
    AUTH_MFA_SUCCESS = "auth.mfa_success"
    AUTH_MFA_FAILURE = "auth.mfa_failure"
    AUTH_PASSWORD_CHANGE = "auth.password_change"
    AUTH_SESSION_START = "auth.session_start"

    ACCESS_READ = "access.read"
    ACCESS_WRITE = "access.write"
    ACCESS_DELETE = "access.delete"
    ACCESS_LIST = "access.list"
    ACCESS_ADMIN = "access.admin"

    IAM_CREATE_USER = "iam.create_user"
    IAM_DELETE_USER = "iam.delete_user"
    IAM_MODIFY_USER = "iam.modify_user"
    IAM_CREATE_ROLE = "iam.create_role"
    IAM_DELETE_ROLE = "iam.delete_role"
    IAM_ATTACH_POLICY = "iam.attach_policy"
    IAM_DETACH_POLICY = "iam.detach_policy"
    IAM_CREATE_KEY = "iam.create_access_key"
    IAM_ASSUME_ROLE = "iam.assume_role"
    IAM_PASS_ROLE = "iam.pass_role"
    IAM_CONFIG_CHANGE = "iam.config_change"

    RESOURCE_CREATE = "resource.create"
    RESOURCE_MODIFY = "resource.modify"
    RESOURCE_DELETE = "resource.delete"
    RESOURCE_ACCESS = "resource.access"

    APP_ASSIGNED = "app.user_assigned"
    APP_UNASSIGNED = "app.user_unassigned"
    APP_ACCESS = "app.access"

    GROUP_ADD_MEMBER = "group.add_member"
    GROUP_REMOVE_MEMBER = "group.remove_member"

    UNKNOWN = "unknown"


class ActivityEvent(BaseModel):
    """
    Unified activity event from any log source.

    All log ingesters normalize their source-specific events into this model.
    This feeds:
    - Behavioral features (login patterns, API call counts, usage ratio)
    - Implicit labels (remediation executed → positive label)
    - Anomaly detection models
    """
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    source: str                         # "aws_cloudtrail", "okta_syslog", "entra_audit"
    source_event_id: str                # original event ID from the source
    event_type: EventType               # normalized event type
    raw_event_name: str                 # original event name (e.g., "CreateRole", "user.session.start")
    timestamp: datetime                 # when the event occurred (UTC)

    # Actor
    actor_id: str                       # subject external_id in the source system
    actor_display_name: str = ""
    actor_type: str = "human"           # human, service_account, ai_agent, system

    # Target (what was acted upon)
    target_id: str = ""                 # resource or entity that was the target
    target_type: str = ""               # e.g., "iam_role", "s3_bucket", "user"
    target_name: str = ""

    # Context
    source_ip: str = ""
    user_agent: str = ""
    geo_location: str = ""
    session_id: str = ""

    # Outcome
    success: bool = True
    error_code: str = ""
    error_message: str = ""

    # Risk indicators
    is_privileged_action: bool = False  # action involves privileged permissions
    is_config_change: bool = False      # action modifies system configuration
    is_cross_boundary: bool = False     # action spans system boundaries

    # Raw payload (for debugging / advanced analysis)
    raw_payload: dict[str, Any] = Field(default_factory=dict)


class IngestionResult(BaseModel):
    """Summary of an ingestion run."""
    source: str
    started_at: datetime
    completed_at: datetime
    total_events: int
    events_by_type: dict[str, int] = Field(default_factory=dict)
    errors: int = 0
    warnings: int = 0
    oldest_event: datetime | None = None
    newest_event: datetime | None = None


class BaseLogIngester(ABC):
    """
    Abstract base for all activity log ingesters.

    Each ingester:
    1. Connects to the log source (S3, API, webhook)
    2. Pulls events for a time range
    3. Normalizes them to ActivityEvent objects
    4. Yields events in chronological order for processing
    """

    source_name: str

    @abstractmethod
    async def connect(self, credentials: dict[str, Any]) -> None:
        """Establish connection to the log source."""
        ...

    @abstractmethod
    async def ingest(
        self,
        start_time: datetime,
        end_time: datetime | None = None,
    ) -> AsyncIterator[ActivityEvent]:
        """
        Ingest events from start_time to end_time (default: now).
        Yields normalized ActivityEvent objects in chronological order.
        """
        ...

    @abstractmethod
    async def get_latest_checkpoint(self) -> datetime | None:
        """
        Get the timestamp of the last successfully ingested event.
        Used for incremental ingestion (pick up where we left off).
        """
        ...

    async def ingest_incremental(self) -> AsyncIterator[ActivityEvent]:
        """
        Ingest only new events since the last checkpoint.
        Falls back to 24h lookback if no checkpoint exists.
        """
        checkpoint = await self.get_latest_checkpoint()
        if checkpoint is None:
            from datetime import timedelta
            checkpoint = datetime.now(timezone.utc) - timedelta(hours=24)
            logger.info(
                "no_checkpoint_found",
                source=self.source_name,
                fallback_start=checkpoint.isoformat(),
            )

        async for event in self.ingest(start_time=checkpoint):
            yield event

    async def disconnect(self) -> None:
        """Clean up connections. Override if needed."""
        pass
