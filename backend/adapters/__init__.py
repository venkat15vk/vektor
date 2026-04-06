"""
Vektor AI — Identity Source Adapters

Read-only connectors that extract identity data from cloud IAM and ERP systems
and normalise it into the unified graph schema.
"""

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
    vektor_id,
)

__all__ = [
    "BaseAdapter",
    "Assignment",
    "EscalationPath",
    "EscalationStep",
    "GraphSnapshot",
    "Permission",
    "PermissionType",
    "Resource",
    "Sensitivity",
    "Subject",
    "SubjectStatus",
    "SubjectType",
    "vektor_id",
]
