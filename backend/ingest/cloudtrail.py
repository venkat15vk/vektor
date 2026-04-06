"""
Vektor AI — AWS CloudTrail Log Ingester

Ingests CloudTrail events from:
1. S3 bucket (primary — CloudTrail delivers logs to S3)
2. CloudTrail Lake (alternative — direct query via SQL)
3. CloudTrail Lookup API (fallback — last 90 days, limited)

Normalizes AWS API calls to ActivityEvent objects for behavioral
feature computation and anomaly detection.
"""

from __future__ import annotations

import gzip
import json
from datetime import datetime, timezone, timedelta
from typing import Any, AsyncIterator

import structlog

from .base import (
    ActivityEvent,
    BaseLogIngester,
    EventType,
    IngestionResult,
)

logger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Event type mapping — AWS API action → normalized EventType
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

# Actions considered privileged (subset — aligns with adapter HIGH_RISK_ACTIONS)
_PRIVILEGED_ACTIONS = {
    "CreateRole", "AttachRolePolicy", "PutRolePolicy", "CreateUser",
    "AttachUserPolicy", "PutUserPolicy", "PassRole", "CreateAccessKey",
    "UpdateAssumeRolePolicy", "AssumeRole", "CreatePolicy",
    "CreatePolicyVersion", "DeleteRole", "DeleteUser", "DeletePolicy",
    "PutBucketPolicy", "DeleteBucket", "RunInstances",
    "CreateFunction", "UpdateFunctionCode", "InvokeFunction",
    "GetSecretValue", "Decrypt",
}

# Actions that modify system configuration
_CONFIG_CHANGE_ACTIONS = {
    "CreateRole", "DeleteRole", "AttachRolePolicy", "DetachRolePolicy",
    "PutRolePolicy", "DeleteRolePolicy", "UpdateAssumeRolePolicy",
    "CreateUser", "DeleteUser", "AttachUserPolicy", "DetachUserPolicy",
    "PutUserPolicy", "DeleteUserPolicy", "CreatePolicy", "DeletePolicy",
    "CreatePolicyVersion", "PutBucketPolicy", "PutBucketAcl",
    "ModifyInstanceAttribute", "CreateSecurityGroup",
    "AuthorizeSecurityGroupIngress", "ModifyVpcAttribute",
}


# ---------------------------------------------------------------------------
# CloudTrail Ingester
# ---------------------------------------------------------------------------

class CloudTrailIngester(BaseLogIngester):
    """
    Ingests AWS CloudTrail events and normalizes them to ActivityEvent objects.

    Supports three ingestion modes:
    1. S3 — reads compressed JSON logs from the CloudTrail S3 bucket
    2. Lookup — uses CloudTrail LookupEvents API (last 90 days, max 50k events)
    3. Lake — uses CloudTrail Lake SQL queries (if configured)
    """

    source_name = "aws_cloudtrail"

    def __init__(self) -> None:
        self._s3_client = None
        self._cloudtrail_client = None
        self._bucket: str = ""
        self._prefix: str = ""
        self._region: str = "us-east-1"
        self._checkpoint: datetime | None = None
        self._mode: str = "lookup"  # "s3", "lookup", or "lake"

    async def connect(self, credentials: dict[str, Any]) -> None:
        """
        Connect to AWS for CloudTrail log access.

        Expected credentials:
        - role_arn: IAM role ARN with CloudTrail read + S3 read permissions
        - external_id: external ID for cross-account assume role
        - region: AWS region (default: us-east-1)
        - mode: "s3", "lookup", or "lake" (default: lookup)
        - bucket: S3 bucket name (required if mode=s3)
        - prefix: S3 key prefix (optional, for mode=s3)
        """
        import boto3

        self._region = credentials.get("region", "us-east-1")
        self._mode = credentials.get("mode", "lookup")

        role_arn = credentials.get("role_arn")
        external_id = credentials.get("external_id", "")

        if role_arn:
            sts = boto3.client("sts", region_name=self._region)
            assume_kwargs: dict[str, Any] = {
                "RoleArn": role_arn,
                "RoleSessionName": "vektor-cloudtrail-ingest",
                "DurationSeconds": 3600,
            }
            if external_id:
                assume_kwargs["ExternalId"] = external_id

            resp = sts.assume_role(**assume_kwargs)
            creds = resp["Credentials"]
            session = boto3.Session(
                aws_access_key_id=creds["AccessKeyId"],
                aws_secret_access_key=creds["SecretAccessKey"],
                aws_session_token=creds["SessionToken"],
                region_name=self._region,
            )
        else:
            session = boto3.Session(region_name=self._region)

        self._cloudtrail_client = session.client("cloudtrail")

        if self._mode == "s3":
            self._s3_client = session.client("s3")
            self._bucket = credentials.get("bucket", "")
            self._prefix = credentials.get("prefix", "")
            if not self._bucket:
                raise ValueError("S3 bucket is required when mode='s3'")

        logger.info(
            "cloudtrail_connected",
            region=self._region,
            mode=self._mode,
        )

    async def ingest(
        self,
        start_time: datetime,
        end_time: datetime | None = None,
    ) -> AsyncIterator[ActivityEvent]:
        """
        Ingest CloudTrail events for the given time range.
        Dispatches to the appropriate ingestion method based on mode.
        """
        if end_time is None:
            end_time = datetime.now(timezone.utc)

        logger.info(
            "cloudtrail_ingest_started",
            mode=self._mode,
            start=start_time.isoformat(),
            end=end_time.isoformat(),
        )

        if self._mode == "s3":
            async for event in self._ingest_from_s3(start_time, end_time):
                yield event
        elif self._mode == "lake":
            async for event in self._ingest_from_lake(start_time, end_time):
                yield event
        else:
            async for event in self._ingest_from_lookup(start_time, end_time):
                yield event

    async def get_latest_checkpoint(self) -> datetime | None:
        return self._checkpoint

    # -------------------------------------------------------------------
    # Lookup API ingestion (default)
    # -------------------------------------------------------------------

    async def _ingest_from_lookup(
        self,
        start_time: datetime,
        end_time: datetime,
    ) -> AsyncIterator[ActivityEvent]:
        """
        Ingest via CloudTrail LookupEvents API.
        Limited to last 90 days, max 50 results per page.
        """
        if self._cloudtrail_client is None:
            raise RuntimeError("Not connected. Call connect() first.")

        paginator = self._cloudtrail_client.get_paginator("lookup_events")
        page_iterator = paginator.paginate(
            StartTime=start_time,
            EndTime=end_time,
            MaxResults=50,
        )

        event_count = 0
        error_count = 0

        for page in page_iterator:
            for raw_event in page.get("Events", []):
                try:
                    cloud_trail_event = json.loads(
                        raw_event.get("CloudTrailEvent", "{}")
                    )
                    activity = self._normalize_event(cloud_trail_event)
                    if activity is not None:
                        event_count += 1
                        self._checkpoint = activity.timestamp
                        yield activity
                except Exception as exc:
                    error_count += 1
                    if error_count <= 10:
                        logger.warning(
                            "cloudtrail_event_parse_error",
                            error=str(exc),
                            event_id=raw_event.get("EventId", "unknown"),
                        )

        logger.info(
            "cloudtrail_lookup_complete",
            events_ingested=event_count,
            errors=error_count,
        )

    # -------------------------------------------------------------------
    # S3 ingestion
    # -------------------------------------------------------------------

    async def _ingest_from_s3(
        self,
        start_time: datetime,
        end_time: datetime,
    ) -> AsyncIterator[ActivityEvent]:
        """
        Ingest from S3 bucket where CloudTrail delivers compressed JSON logs.
        Log path format: AWSLogs/{account_id}/CloudTrail/{region}/{year}/{month}/{day}/
        """
        if self._s3_client is None:
            raise RuntimeError("S3 client not initialized. Use mode='s3' in credentials.")

        event_count = 0
        error_count = 0

        # Iterate over each day in the range
        current = start_time.replace(hour=0, minute=0, second=0, microsecond=0)
        while current <= end_time:
            date_prefix = current.strftime("%Y/%m/%d")
            prefix = f"{self._prefix}/{date_prefix}/" if self._prefix else date_prefix

            try:
                list_resp = self._s3_client.list_objects_v2(
                    Bucket=self._bucket,
                    Prefix=prefix,
                )

                for obj in list_resp.get("Contents", []):
                    key = obj["Key"]
                    if not key.endswith(".json.gz"):
                        continue

                    try:
                        get_resp = self._s3_client.get_object(
                            Bucket=self._bucket,
                            Key=key,
                        )
                        compressed = get_resp["Body"].read()
                        decompressed = gzip.decompress(compressed)
                        log_data = json.loads(decompressed)

                        for record in log_data.get("Records", []):
                            event_time = self._parse_timestamp(
                                record.get("eventTime", "")
                            )
                            if event_time and start_time <= event_time <= end_time:
                                activity = self._normalize_event(record)
                                if activity is not None:
                                    event_count += 1
                                    self._checkpoint = activity.timestamp
                                    yield activity

                    except Exception as exc:
                        error_count += 1
                        logger.warning(
                            "cloudtrail_s3_file_error",
                            key=key,
                            error=str(exc),
                        )

                # Handle pagination
                while list_resp.get("IsTruncated"):
                    list_resp = self._s3_client.list_objects_v2(
                        Bucket=self._bucket,
                        Prefix=prefix,
                        ContinuationToken=list_resp["NextContinuationToken"],
                    )
                    for obj in list_resp.get("Contents", []):
                        key = obj["Key"]
                        if not key.endswith(".json.gz"):
                            continue
                        try:
                            get_resp = self._s3_client.get_object(
                                Bucket=self._bucket, Key=key
                            )
                            compressed = get_resp["Body"].read()
                            decompressed = gzip.decompress(compressed)
                            log_data = json.loads(decompressed)
                            for record in log_data.get("Records", []):
                                event_time = self._parse_timestamp(
                                    record.get("eventTime", "")
                                )
                                if event_time and start_time <= event_time <= end_time:
                                    activity = self._normalize_event(record)
                                    if activity is not None:
                                        event_count += 1
                                        self._checkpoint = activity.timestamp
                                        yield activity
                        except Exception as exc:
                            error_count += 1

            except Exception as exc:
                logger.warning(
                    "cloudtrail_s3_list_error",
                    prefix=prefix,
                    error=str(exc),
                )

            current += timedelta(days=1)

        logger.info(
            "cloudtrail_s3_complete",
            events_ingested=event_count,
            errors=error_count,
        )

    # -------------------------------------------------------------------
    # CloudTrail Lake ingestion
    # -------------------------------------------------------------------

    async def _ingest_from_lake(
        self,
        start_time: datetime,
        end_time: datetime,
    ) -> AsyncIterator[ActivityEvent]:
        """
        Ingest via CloudTrail Lake SQL query.
        Requires a CloudTrail Lake event data store to be configured.
        """
        if self._cloudtrail_client is None:
            raise RuntimeError("Not connected. Call connect() first.")

        query = f"""
        SELECT
            eventID, eventTime, eventName, eventSource,
            userIdentity, sourceIPAddress, userAgent,
            requestParameters, responseElements, errorCode, errorMessage
        FROM cloudtrail_logs
        WHERE eventTime >= '{start_time.strftime("%Y-%m-%d %H:%M:%S")}'
          AND eventTime <= '{end_time.strftime("%Y-%m-%d %H:%M:%S")}'
        ORDER BY eventTime ASC
        """

        try:
            response = self._cloudtrail_client.start_query(QueryStatement=query)
            query_id = response["QueryId"]

            # Poll for results
            import time
            while True:
                status_resp = self._cloudtrail_client.get_query_results(
                    QueryId=query_id,
                )
                status = status_resp.get("QueryStatus", "")
                if status == "FINISHED":
                    break
                elif status in ("FAILED", "CANCELLED"):
                    logger.error("cloudtrail_lake_query_failed", status=status)
                    return
                time.sleep(2)

            # Process results
            for row in status_resp.get("QueryResultRows", []):
                record = {item["Key"]: item["Value"] for item in row}
                activity = self._normalize_lake_record(record)
                if activity is not None:
                    self._checkpoint = activity.timestamp
                    yield activity

        except Exception as exc:
            logger.error("cloudtrail_lake_error", error=str(exc))

    # -------------------------------------------------------------------
    # Event normalization
    # -------------------------------------------------------------------

    def _normalize_event(self, record: dict[str, Any]) -> ActivityEvent | None:
        """Normalize a raw CloudTrail JSON record to an ActivityEvent."""
        event_name = record.get("eventName", "")
        event_source = record.get("eventSource", "")
        service = event_source.replace(".amazonaws.com", "")

        # Skip read-only AWS service events (noise)
        if record.get("readOnly") is True and service not in ("iam", "sts"):
            return None

        # Determine event type
        event_type = self._map_event_type(event_name, service)

        # Parse actor from userIdentity
        user_identity = record.get("userIdentity", {})
        actor_id, actor_name, actor_type = self._parse_user_identity(user_identity)

        # Parse target from request parameters
        target_id, target_type, target_name = self._parse_target(
            event_name, record.get("requestParameters") or {}
        )

        # Parse timestamp
        timestamp = self._parse_timestamp(record.get("eventTime", ""))
        if timestamp is None:
            return None

        # Determine risk flags
        is_privileged = event_name in _PRIVILEGED_ACTIONS
        is_config = event_name in _CONFIG_CHANGE_ACTIONS
        success = record.get("errorCode") is None

        return ActivityEvent(
            source=self.source_name,
            source_event_id=record.get("eventID", ""),
            event_type=event_type,
            raw_event_name=f"{service}:{event_name}",
            timestamp=timestamp,
            actor_id=actor_id,
            actor_display_name=actor_name,
            actor_type=actor_type,
            target_id=target_id,
            target_type=target_type,
            target_name=target_name,
            source_ip=record.get("sourceIPAddress", ""),
            user_agent=record.get("userAgent", ""),
            geo_location=record.get("awsRegion", ""),
            session_id=user_identity.get("accessKeyId", ""),
            success=success,
            error_code=record.get("errorCode", ""),
            error_message=record.get("errorMessage", ""),
            is_privileged_action=is_privileged,
            is_config_change=is_config,
            is_cross_boundary=False,
            raw_payload=record,
        )

    def _normalize_lake_record(self, record: dict[str, Any]) -> ActivityEvent | None:
        """Normalize a CloudTrail Lake query result row."""
        # Lake returns flattened key-value pairs; reconstruct enough for _normalize_event
        try:
            user_identity = json.loads(record.get("userIdentity", "{}"))
        except (json.JSONDecodeError, TypeError):
            user_identity = {}

        reconstructed = {
            "eventID": record.get("eventID", ""),
            "eventTime": record.get("eventTime", ""),
            "eventName": record.get("eventName", ""),
            "eventSource": record.get("eventSource", ""),
            "userIdentity": user_identity,
            "sourceIPAddress": record.get("sourceIPAddress", ""),
            "userAgent": record.get("userAgent", ""),
            "errorCode": record.get("errorCode") or None,
            "errorMessage": record.get("errorMessage", ""),
            "requestParameters": {},
        }

        try:
            req_params = json.loads(record.get("requestParameters", "{}"))
            reconstructed["requestParameters"] = req_params
        except (json.JSONDecodeError, TypeError):
            pass

        return self._normalize_event(reconstructed)

    def _map_event_type(self, event_name: str, service: str) -> EventType:
        """Map an AWS API action to a normalized EventType."""
        if service == "iam":
            return _IAM_EVENT_MAP.get(event_name, EventType.IAM_CONFIG_CHANGE)
        elif service == "sts":
            return _STS_EVENT_MAP.get(event_name, EventType.AUTH_SESSION_START)
        elif service == "signin":
            return _AUTH_EVENT_MAP.get(event_name, EventType.AUTH_LOGIN)
        elif event_name.startswith("Create"):
            return EventType.RESOURCE_CREATE
        elif event_name.startswith("Delete") or event_name.startswith("Remove"):
            return EventType.RESOURCE_DELETE
        elif event_name.startswith(("Put", "Update", "Modify")):
            return EventType.RESOURCE_MODIFY
        elif event_name.startswith(("Get", "Describe", "List")):
            return EventType.ACCESS_READ
        else:
            return EventType.UNKNOWN

    def _parse_user_identity(
        self, identity: dict[str, Any]
    ) -> tuple[str, str, str]:
        """
        Extract actor info from CloudTrail userIdentity.

        Returns: (actor_id, display_name, actor_type)
        """
        identity_type = identity.get("type", "")
        arn = identity.get("arn", "")
        principal_id = identity.get("principalId", "")

        if identity_type == "Root":
            return ("root", "Root Account", "human")
        elif identity_type == "IAMUser":
            username = identity.get("userName", principal_id)
            return (username, username, "human")
        elif identity_type == "AssumedRole":
            session_context = identity.get("sessionContext", {})
            session_issuer = session_context.get("sessionIssuer", {})
            role_name = session_issuer.get("userName", "")
            # Check if it's a service-linked or agent role
            actor_type = "service_account"
            if any(tag in role_name.lower() for tag in ("agent", "ai", "llm")):
                actor_type = "ai_agent"
            return (role_name or principal_id, role_name, actor_type)
        elif identity_type == "AWSService":
            service = identity.get("invokedBy", "aws-service")
            return (service, service, "service_account")
        elif identity_type == "FederatedUser":
            fed_user = identity.get("userName", principal_id)
            return (fed_user, fed_user, "human")
        else:
            return (principal_id or arn, principal_id or arn, "human")

    def _parse_target(
        self,
        event_name: str,
        request_params: dict[str, Any],
    ) -> tuple[str, str, str]:
        """
        Extract the target entity from request parameters.

        Returns: (target_id, target_type, target_name)
        """
        # IAM targets
        if "roleName" in request_params:
            name = request_params["roleName"]
            return (name, "iam_role", name)
        elif "userName" in request_params:
            name = request_params["userName"]
            return (name, "iam_user", name)
        elif "groupName" in request_params:
            name = request_params["groupName"]
            return (name, "iam_group", name)
        elif "policyArn" in request_params:
            arn = request_params["policyArn"]
            name = arn.split("/")[-1] if "/" in arn else arn
            return (arn, "iam_policy", name)

        # S3 targets
        elif "bucketName" in request_params:
            name = request_params["bucketName"]
            return (name, "s3_bucket", name)

        # Lambda targets
        elif "functionName" in request_params:
            name = request_params["functionName"]
            return (name, "lambda_function", name)

        # EC2 targets
        elif "instanceId" in request_params:
            iid = request_params["instanceId"]
            return (iid, "ec2_instance", iid)

        # Generic
        elif "roleArn" in request_params:
            arn = request_params["roleArn"]
            name = arn.split("/")[-1] if "/" in arn else arn
            return (arn, "iam_role", name)

        return ("", "", "")

    def _parse_timestamp(self, time_str: str) -> datetime | None:
        """Parse a CloudTrail timestamp string to datetime."""
        if not time_str:
            return None
        try:
            # CloudTrail format: 2024-01-15T10:30:45Z
            return datetime.fromisoformat(time_str.replace("Z", "+00:00"))
        except (ValueError, TypeError):
            try:
                from dateutil.parser import parse
                return parse(time_str).replace(tzinfo=timezone.utc)
            except Exception:
                return None
