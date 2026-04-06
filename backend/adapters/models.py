"""
Vektor AI — Unified Identity Graph Schema

Pydantic v2 models that define the canonical representation of identities,
permissions, resources, and their relationships across all source systems.
Every adapter normalizes its source data into these models.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field, model_validator

# ---------------------------------------------------------------------------
# Namespace for deterministic UUID generation (uuid5)
# ---------------------------------------------------------------------------
VEKTOR_UUID_NAMESPACE = uuid.UUID("a1b2c3d4-e5f6-7890-abcd-ef1234567890")


def vektor_id(source: str, external_id: str) -> str:
    """Generate a deterministic Vektor UUID from source + external_id."""
    return str(uuid.uuid5(VEKTOR_UUID_NAMESPACE, f"{source}:{external_id}"))


def new_id() -> str:
    """Generate a random UUID v4 string."""
    return str(uuid.uuid4())


def utcnow() -> datetime:
    """Return the current UTC datetime (timezone-aware)."""
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------
class SubjectType(str, Enum):
    HUMAN = "human"
    SERVICE_ACCOUNT = "service_account"
    AI_AGENT = "ai_agent"
    GROUP = "group"


class SubjectStatus(str, Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    SUSPENDED = "suspended"
    DELETED = "deleted"


class PermissionType(str, Enum):
    ROLE = "role"
    POLICY = "policy"
    GROUP = "group"
    ENTITLEMENT = "entitlement"


class Sensitivity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


# ---------------------------------------------------------------------------
# Entity Models
# ---------------------------------------------------------------------------
class Subject(BaseModel):
    """Any identity: human user, service account, AI agent, or group."""

    id: str = Field(default_factory=new_id, description="Vektor-generated UUID")
    external_id: str = Field(..., description="Source system's native identifier")
    source: str = Field(..., description='Origin system, e.g. "aws_iam", "okta"')
    type: SubjectType
    display_name: str
    email: Optional[str] = None
    department: Optional[str] = None
    manager_id: Optional[str] = None
    status: SubjectStatus = SubjectStatus.ACTIVE
    last_seen: Optional[datetime] = None
    mfa_enabled: Optional[bool] = None
    attributes: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)

    @model_validator(mode="after")
    def validate_cross_fields(self) -> "Subject":
        if self.type in (SubjectType.AI_AGENT, SubjectType.GROUP):
            self.mfa_enabled = None
        if self.type == SubjectType.GROUP:
            self.department = None
        return self

    model_config = {"populate_by_name": True}


class Permission(BaseModel):
    """A role, policy, group, or entitlement that grants actions on resources."""

    id: str = Field(default_factory=new_id)
    source: str
    name: str
    type: PermissionType
    actions: list[str] = Field(default_factory=list)
    resources: list[str] = Field(default_factory=list)
    is_privileged: bool = False
    risk_keywords: list[str] = Field(default_factory=list)
    attributes: dict[str, Any] = Field(default_factory=dict)


class Resource(BaseModel):
    """Anything an identity can access."""

    id: str = Field(default_factory=new_id)
    source: str
    type: str = Field(..., description='e.g. "s3_bucket", "netsuite_module"')
    name: str
    sensitivity: Sensitivity = Sensitivity.LOW
    attributes: dict[str, Any] = Field(default_factory=dict)


class Assignment(BaseModel):
    """Links a Subject to a Permission, optionally scoped to a Resource."""

    id: str = Field(default_factory=new_id)
    subject_id: str
    permission_id: str
    resource_id: Optional[str] = None
    source: str
    granted_at: Optional[datetime] = None
    granted_by: Optional[str] = None
    last_used: Optional[datetime] = None
    is_active: bool = True


class EscalationStep(BaseModel):
    """A single hop in an escalation chain."""

    action: str
    resource: str
    description: str


class EscalationPath(BaseModel):
    """A detected chain where permissions compose to reach a higher-risk outcome."""

    id: str = Field(default_factory=new_id)
    subject_id: str
    steps: list[EscalationStep]
    end_result: str
    confidence: float = Field(ge=0.0, le=1.0)
    source: str


class GraphSnapshot(BaseModel):
    """Complete extraction result from one source system."""

    source: str
    extracted_at: datetime = Field(default_factory=utcnow)
    subjects: list[Subject] = Field(default_factory=list)
    permissions: list[Permission] = Field(default_factory=list)
    resources: list[Resource] = Field(default_factory=list)
    assignments: list[Assignment] = Field(default_factory=list)
    escalation_paths: list[EscalationPath] = Field(default_factory=list)
    stats: dict[str, int] = Field(default_factory=dict)

    @model_validator(mode="after")
    def compute_stats(self) -> "GraphSnapshot":
        self.stats = {
            "subjects": len(self.subjects),
            "permissions": len(self.permissions),
            "resources": len(self.resources),
            "assignments": len(self.assignments),
            "escalation_paths": len(self.escalation_paths),
        }
        return self
