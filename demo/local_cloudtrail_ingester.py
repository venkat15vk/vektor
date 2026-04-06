"""
Vektor AI — Local CloudTrail Log Ingester

Reads CloudTrail JSON logs from local files (flaws.cloud dataset,
Invictus attack dataset) and normalizes them to ActivityEvent objects.

Reuses the event mapping logic from backend.ingest.cloudtrail but
swaps the data source from boto3/S3 to local filesystem.
"""

from __future__ import annotations

import gzip
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

import structlog

from backend.ingest.base import (
    ActivityEvent,
    EventType,
    IngestionResult,
)

logger = structlog.get_logger(__name__)

SOURCE = "aws_cloudtrail"

# ---------------------------------------------------------------------------
# Event type mapping — same as backend/ingest/cloudtrail.py
# ---------------------------------------------------------------------------

_IAM_EVENT_MAP: dict[str, EventType] = {
    "CreateUser": EventType.IAM_CREATE_USER,
    "DeleteUser": EventType.IAM_DELETE_USER,
    "UpdateUser": EventType.IAM_MODIFY_USER,
    "CreateRole": EventType.IAM_CREATE_ROLE,
    "DeleteRole": EventType.IAM_DELETE_ROLE,
    "AttachRolePolicy": EventType.IAM_ATTACH_POLICY,
    "AttachUserPolicy": EventType.IAM_ATTACH_POLICY,
    "AttachGroupPolicy": EventType.IAM_ATTACH_POLICY,
    "DetachRolePolicy": EventType.IAM_DETACH_POLICY,
    "DetachUserPolicy": EventType.IAM_DETACH_POLICY,
    "DetachGroupPolicy": EventType.IAM_DETACH_POLICY,
    "PutRolePolicy": EventType.IAM_ATTACH_POLICY,
    "PutUserPolicy": EventType.IAM_ATTACH_POLICY,
    "DeleteRolePolicy": EventType.IAM_DETACH_POLICY,
    "DeleteUserPolicy": EventType.IAM_DETACH_POLICY,
    "CreateAccessKey": EventType.IAM_CREATE_KEY,
    "UpdateAssumeRolePolicy": EventType.IAM_CONFIG_CHANGE,
    "CreatePolicy": EventType.IAM_CONFIG_CHANGE,
    "CreatePolicyVersion": EventType.IAM_CONFIG_CHANGE,
    "AddUserToGroup": EventType.GROUP_ADD_MEMBER,
    "RemoveUserFromGroup": EventType.GROUP_REMOVE_MEMBER,
    "PassRole": EventType.IAM_PASS_ROLE,
}

_STS_EVENT_MAP: dict[str, EventType] = {
    "AssumeRole": EventType.IAM_ASSUME_ROLE,
    "AssumeRoleWithSAML": EventType.IAM_ASSUME_ROLE,
    "AssumeRoleWithWebIdentity": EventType.IAM_ASSUME_ROLE,
    "GetSessionToken": EventType.AUTH_SESSION_START,
    "GetFederationToken": EventType.AUTH_SESSION_START,
}

_AUTH_EVENT_MAP: dict[str, EventType] = {
    "ConsoleLogin": EventType.AUTH_LOGIN,
}

_RESOURCE_EVENT_MAP: dict[str, EventType] = {
    "RunInstances": EventType.RESOURCE_CREATE,
    "TerminateInstances": EventType.RESOURCE_DELETE,
    "CreateBucket": EventType.RESOURCE_CREATE,
    "DeleteBucket": EventType.RESOURCE_DELETE,
    "CreateFunction20150331": EventType.RESOURCE_CREATE,
    "CreateFunction": EventType.RESOURCE_CREATE,
    "DeleteFunction20150331": EventType.RESOURCE_DELETE,
    "DeleteFunction": EventType.RESOURCE_DELETE,
    "PutObject": EventType.ACCESS_WRITE,
    "GetObject": EventType.ACCESS_READ,
    "DeleteObject": EventType.ACCESS_DELETE,
    "ListBuckets": EventType.ACCESS_LIST,
    "ListObjects": EventType.ACCESS_LIST,
    "ListObjectsV2": EventType.ACCESS_LIST,
    "HeadObject": EventType.ACCESS_READ,
    "HeadBucket": EventType.ACCESS_READ,
    "DescribeInstances": EventType.ACCESS_LIST,
    "DescribeSecurityGroups": EventType.ACCESS_LIST,
    "GetBucketPolicy": EventType.ACCESS_READ,
    "GetBucketAcl": EventType.ACCESS_READ,
    "PutBucketPolicy": EventType.ACCESS_ADMIN,
}

_PRIVILEGED_ACTIONS = {
    "CreateRole", "AttachRolePolicy", "PutRolePolicy", "CreateUser",
    "AttachUserPolicy", "PutUserPolicy", "PassRole", "CreateAccessKey",
    "UpdateAssumeRolePolicy", "AssumeRole", "CreatePolicy",
    "CreatePolicyVersion", "DeleteRole", "DeleteUser", "DeletePolicy",
    "PutBucketPolicy", "DeleteBucket", "RunInstances",
    "CreateFunction", "UpdateFunctionCode", "InvokeFunction",
}


def _map_event_type(event_source: str, event_name: str) -> EventType:
    """Map an AWS CloudTrail event to a normalized EventType."""
    if event_source == "iam.amazonaws.com":
        return _IAM_EVENT_MAP.get(event_name, EventType.ACCESS_ADMIN)
    if event_source == "sts.amazonaws.com":
        return _STS_EVENT_MAP.get(event_name, EventType.UNKNOWN)
    if event_source == "signin.amazonaws.com":
        return _AUTH_EVENT_MAP.get(event_name, EventType.AUTH_LOGIN)
    return _RESOURCE_EVENT_MAP.get(event_name, EventType.UNKNOWN)


def _extract_subject_id(user_identity: dict) -> str:
    """Extract a usable subject identifier from CloudTrail userIdentity."""
    # Prefer ARN
    arn = user_identity.get("arn", "")
    if arn:
        return arn
    # Fallback to userName
    username = user_identity.get("userName", "")
    if username:
        return username
    # Fallback to principalId
    return user_identity.get("principalId", "unknown")


def _actor_type(user_identity: dict) -> str:
    """Determine actor type from CloudTrail userIdentity."""
    identity_type = user_identity.get("type", "")
    if identity_type == "AWSService":
        return "service_account"
    if identity_type in ("AssumedRole", "FederatedUser"):
        return "human"
    if identity_type == "IAMUser":
        return "human"
    if identity_type == "Root":
        return "human"
    return "human"


def _extract_target_id(raw: dict) -> str:
    """Extract the target resource ID from a CloudTrail event."""
    resources = raw.get("resources", [])
    if resources:
        return resources[0].get("ARN", "")
    params = raw.get("requestParameters") or {}
    for key in ("roleName", "userName", "groupName", "policyArn",
                "bucketName", "functionName", "instanceId"):
        if key in params:
            return str(params[key])
    return ""


def _extract_target_type(event_source: str) -> str:
    """Map event source to a target type."""
    source_map = {
        "iam.amazonaws.com": "iam_resource",
        "sts.amazonaws.com": "iam_session",
        "s3.amazonaws.com": "s3_bucket",
        "ec2.amazonaws.com": "ec2_instance",
        "lambda.amazonaws.com": "lambda_function",
        "dynamodb.amazonaws.com": "dynamodb_table",
        "kms.amazonaws.com": "kms_key",
    }
    return source_map.get(event_source, "aws_resource")


def _extract_target_name(raw: dict) -> str:
    """Extract a human-readable target name."""
    params = raw.get("requestParameters") or {}
    for key in ("roleName", "userName", "groupName", "policyName",
                "bucketName", "functionName"):
        if key in params:
            return str(params[key])
    return raw.get("eventName", "")


def _parse_cloudtrail_event(raw: dict) -> ActivityEvent | None:
    """Parse a single CloudTrail event record into an ActivityEvent."""
    try:
        event_name = raw.get("eventName", "")
        event_source = raw.get("eventSource", "")
        user_identity = raw.get("userIdentity", {})

        event_type = _map_event_type(event_source, event_name)

        # Parse timestamp
        event_time_str = raw.get("eventTime", "")
        try:
            event_time = datetime.fromisoformat(event_time_str.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            event_time = datetime.now(timezone.utc)

        subject_id = _extract_subject_id(user_identity)

        # Determine success/failure
        error_code = raw.get("errorCode")
        error_message = raw.get("errorMessage")
        success = error_code is None

        return ActivityEvent(
            source=SOURCE,
            source_event_id=raw.get("eventID", ""),
            event_type=event_type,
            raw_event_name=event_name,
            timestamp=event_time,
            actor_id=subject_id,
            actor_display_name=user_identity.get("userName", subject_id),
            actor_type=_actor_type(user_identity),
            target_id=_extract_target_id(raw),
            target_type=_extract_target_type(event_source),
            target_name=_extract_target_name(raw),
            source_ip=raw.get("sourceIPAddress", ""),
            user_agent=raw.get("userAgent", ""),
            success=success,
            error_code=error_code or "",
            error_message=error_message or "",
            is_privileged_action=event_name in _PRIVILEGED_ACTIONS,
            is_config_change=event_type in (
                EventType.IAM_ATTACH_POLICY, EventType.IAM_DETACH_POLICY,
                EventType.IAM_CONFIG_CHANGE, EventType.IAM_CREATE_ROLE,
                EventType.IAM_DELETE_ROLE, EventType.IAM_CREATE_USER,
                EventType.IAM_DELETE_USER,
            ),
            raw_payload=raw,
        )
    except Exception as e:
        logger.debug("cloudtrail.parse_error", error=str(e))
        return None


def load_cloudtrail_file(path: Path) -> list[ActivityEvent]:
    """Load and parse a single CloudTrail log file (JSON or gzipped JSON)."""
    events: list[ActivityEvent] = []

    try:
        if path.suffix == ".gz":
            with gzip.open(path, "rt") as f:
                data = json.load(f)
        else:
            with open(path) as f:
                data = json.load(f)

        # CloudTrail format: {"Records": [...]}
        records = data.get("Records", [])
        if not records and isinstance(data, list):
            records = data

        for raw in records:
            event = _parse_cloudtrail_event(raw)
            if event:
                events.append(event)

    except Exception as e:
        logger.debug("cloudtrail.file_error", file=str(path), error=str(e))

    return events


def load_cloudtrail_directory(
    directory: Path,
    max_files: int | None = None,
    max_events: int | None = None,
) -> tuple[list[ActivityEvent], dict[str, Any]]:
    """
    Load CloudTrail events from all JSON/gz files in a directory tree.

    Returns (events, stats_dict).
    """
    all_events: list[ActivityEvent] = []
    files_processed = 0
    files_failed = 0
    total_records = 0

    # Collect all CloudTrail files
    ct_files = sorted(
        list(directory.rglob("*.json")) + list(directory.rglob("*.json.gz"))
    )

    if max_files:
        ct_files = ct_files[:max_files]

    for ct_file in ct_files:
        events = load_cloudtrail_file(ct_file)
        if events:
            all_events.extend(events)
            files_processed += 1
            total_records += len(events)
        else:
            files_failed += 1

        if max_events and len(all_events) >= max_events:
            all_events = all_events[:max_events]
            break

    # Compute stats
    unique_subjects = len({e.actor_id for e in all_events})
    unique_actions = len({e.raw_event_name for e in all_events})
    unique_ips = len({e.source_ip for e in all_events if e.source_ip})
    privileged_count = sum(1 for e in all_events if e.is_privileged_action)
    error_count = sum(1 for e in all_events if not e.success)

    event_type_dist: dict[str, int] = {}
    for e in all_events:
        et = e.event_type.value
        event_type_dist[et] = event_type_dist.get(et, 0) + 1

    stats = {
        "files_processed": files_processed,
        "files_failed": files_failed,
        "total_events": len(all_events),
        "unique_subjects": unique_subjects,
        "unique_actions": unique_actions,
        "unique_ips": unique_ips,
        "privileged_events": privileged_count,
        "error_events": error_count,
        "event_type_distribution": dict(sorted(event_type_dist.items(),
                                                key=lambda x: -x[1])[:20]),
    }

    if all_events:
        timestamps = [e.timestamp for e in all_events]
        stats["time_range_start"] = min(timestamps).isoformat()
        stats["time_range_end"] = max(timestamps).isoformat()

    logger.info("cloudtrail.local.loaded", **{k: v for k, v in stats.items()
                if k != "event_type_distribution"})

    return all_events, stats
