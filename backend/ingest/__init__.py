"""
Vektor AI — Activity Log Ingestion Pipeline

Ingests usage signals from identity source systems:
- AWS CloudTrail logs
- Okta system logs
- Microsoft Entra audit logs

These logs feed the behavioral features in the Universal Feature Store
(avg_daily_api_calls_30d, usage_ratio, login_time_entropy, etc.)
and provide implicit labels for ML model training.
"""

from .base import BaseLogIngester, ActivityEvent, EventType
from .cloudtrail import CloudTrailIngester
from .okta_logs import OktaLogIngester
from .entra_logs import EntraLogIngester

__all__ = [
    "BaseLogIngester",
    "ActivityEvent",
    "EventType",
    "CloudTrailIngester",
    "OktaLogIngester",
    "EntraLogIngester",
]
