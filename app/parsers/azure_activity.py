"""Azure Activity and Security JSON Log Parser."""

import json
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from app.parsers.base import BaseParser, ParseResult, ParseDiagnostic
from app.schemas.event import NormalizedEvent
from app.utils.redact import redact_sensitive_dict


class AzureActivityParser(BaseParser):
    format_id = "azure_activity"
    format_name = "Azure Activity & Security Log"
    description = "Parses Microsoft Azure Activity and Audit logs in JSON format."

    def can_parse(self, raw_log: str) -> bool:
        trimmed = raw_log.strip()
        if not (trimmed.startswith("{") and trimmed.endswith("}")):
            return False
        try:
            data = json.loads(trimmed)
            if any(k in data for k in ["operationName", "resourceId", "callerIpAddress", "subscriptionId", "tenantId"]):
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

        # Operation name can be dict or str
        op_val = data.get("operationName")
        if isinstance(op_val, dict):
            operation_name = op_val.get("value", op_val.get("localizedValue", "UnknownAzureOperation"))
        else:
            operation_name = str(op_val or "UnknownAzureOperation")

        result_type = str(data.get("resultType", data.get("status", "Success"))).lower()
        action = "success" if result_type in ["success", "succeeded", "started", "accepted"] else "failure"

        # Timestamp
        time_str = data.get("time") or data.get("eventTimestamp")
        timestamp = datetime.now(timezone.utc)
        if time_str:
            try:
                timestamp = datetime.fromisoformat(str(time_str).replace("Z", "+00:00"))
            except Exception:
                pass

        caller = data.get("caller") or data.get("claims", {}).get("name") or data.get("identity", {}).get("claims", {}).get("upn")
        caller_ip = data.get("callerIpAddress") or data.get("clientIp")

        resource_id = data.get("resourceId", "")
        subscription_id = data.get("subscriptionId")

        # Severity
        if "roleassignments/write" in operation_name.lower() or "policyassignments/write" in operation_name.lower():
            severity = "high"
        elif action == "failure":
            severity = "medium"
        else:
            severity = "low"

        parsed_fields = {
            "operation_name": operation_name,
            "resource_id": resource_id,
            "subscription_id": subscription_id,
            "result_type": result_type,
            "correlation_id": data.get("correlationId"),
            "properties": redact_sensitive_dict(data.get("properties", {})),
        }

        event = NormalizedEvent(
            source_format=self.format_id,
            timestamp=timestamp,
            source_ip=caller_ip,
            destination_ip=None,
            hostname="azure-cloud",
            username=caller,
            action=action,
            severity=severity,
            event_type=f"Azure: {operation_name}",
            raw_message=self.sanitize(raw_log),
            parsed_fields={k: v for k, v in parsed_fields.items() if v is not None},
        )
        return ParseResult(success=True, event=event)
