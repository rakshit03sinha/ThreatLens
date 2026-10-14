"""AWS CloudTrail JSON Log Parser."""

import json
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from app.parsers.base import BaseParser, ParseResult, ParseDiagnostic
from app.schemas.event import NormalizedEvent
from app.utils.redact import redact_sensitive_dict


class AWSCloudTrailParser(BaseParser):
    format_id = "aws_cloudtrail"
    format_name = "AWS CloudTrail JSON"
    description = "Parses AWS CloudTrail audit, management, and data events in JSON format."

    def can_parse(self, raw_log: str) -> bool:
        trimmed = raw_log.strip()
        if not (trimmed.startswith("{") and trimmed.endswith("}")):
            return False
        try:
            data = json.loads(trimmed)
            if "eventSource" in data and "eventName" in data and ("userIdentity" in data or "awsRegion" in data):
                return True
            return False
        except Exception:
            return False

    def parse(self, raw_log: str) -> ParseResult:
        try:
            data = json.loads(raw_log)
        except Exception as e:
            return ParseResult(
                success=False,
                diagnostics=[ParseDiagnostic(level="error", message=f"JSON decoding error: {str(e)}")],
                raw_preview=raw_log[:200],
            )

        event_name = data.get("eventName", "UnknownCloudTrailEvent")
        event_source = data.get("eventSource", "")
        aws_region = data.get("awsRegion")
        source_ip = data.get("sourceIPAddress")
        if source_ip and (source_ip.endswith(".amazonaws.com") or not any(c.isdigit() for c in source_ip)):
            # AWS internal service call
            client_ip = None
        else:
            client_ip = source_ip

        # User extraction
        user_identity = data.get("userIdentity", {})
        username = (
            user_identity.get("userName")
            or user_identity.get("principalId")
            or (user_identity.get("arn", "").split("/")[-1] if user_identity.get("arn") else None)
        )

        # Timestamp
        timestamp = datetime.now(timezone.utc)
        event_time_str = data.get("eventTime")
        if event_time_str:
            try:
                timestamp = datetime.fromisoformat(event_time_str.replace("Z", "+00:00"))
            except Exception:
                pass

        error_code = data.get("errorCode")
        error_message = data.get("errorMessage")
        action = "failure" if error_code else "success"

        # Threat/Severity classification
        high_risk_calls = {
            "AttachRolePolicy", "AttachUserPolicy", "PutUserPolicy", "CreatePolicyVersion",
            "DeleteTrail", "StopLogging", "AuthorizeSecurityGroupIngress", "CreateAccessKey",
        }
        if event_name in high_risk_calls:
            severity = "high"
        elif error_code:
            severity = "medium"
        else:
            severity = "low"

        parsed_fields = {
            "event_source": event_source,
            "event_name": event_name,
            "aws_region": aws_region,
            "user_identity_type": user_identity.get("type"),
            "account_id": user_identity.get("accountId"),
            "error_code": error_code,
            "error_message": error_message,
            "request_parameters": redact_sensitive_dict(data.get("requestParameters", {})),
        }

        event = NormalizedEvent(
            source_format=self.format_id,
            timestamp=timestamp,
            source_ip=client_ip,
            destination_ip=None,
            hostname=f"aws-{aws_region}" if aws_region else None,
            username=username,
            action=action,
            severity=severity,
            event_type=f"AWS CloudTrail: {event_name}",
            raw_message=self.sanitize(raw_log),
            parsed_fields={k: v for k, v in parsed_fields.items() if v is not None},
        )
        return ParseResult(success=True, event=event)
