"""Windows Event Log Parser (JSON format and common exports)."""

import json
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from app.parsers.base import BaseParser, ParseResult, ParseDiagnostic
from app.schemas.event import NormalizedEvent
from app.utils.redact import redact_sensitive_dict


class WindowsEventParser(BaseParser):
    format_id = "windows"
    format_name = "Windows Event Log"
    description = "Parses Windows Security, System, and Sysmon event logs in JSON or key-value format."

    def can_parse(self, raw_log: str) -> bool:
        trimmed = raw_log.strip()
        if not (trimmed.startswith("{") and trimmed.endswith("}")):
            return False
        try:
            data = json.loads(trimmed)
            if "Event" in data and ("System" in data["Event"] or "EventData" in data["Event"]):
                return True
            if any(k in data for k in ["EventID", "EventId", "TargetUserName", "WorkstationName", "Channel", "Computer"]):
                return True
            return False
        except Exception:
            return False

    def parse(self, raw_log: str) -> ParseResult:
        diagnostics = []
        try:
            data = json.loads(raw_log)
        except Exception as e:
            return ParseResult(
                success=False,
                diagnostics=[ParseDiagnostic(level="error", message=f"JSON decoding error: {str(e)}")],
                raw_preview=raw_log[:200],
            )

        # Handle nested Event / System / EventData or flat dict
        system_data: Dict[str, Any] = {}
        event_data: Dict[str, Any] = {}
        if "Event" in data and isinstance(data["Event"], dict):
            event_obj = data["Event"]
            system_data = event_obj.get("System", {})
            event_data = event_obj.get("EventData", {})
        else:
            system_data = data
            event_data = data.get("EventData", data)

        event_id = str(system_data.get("EventID", event_data.get("EventID", event_data.get("EventId", ""))))
        channel = str(system_data.get("Channel", "Security"))
        hostname = str(system_data.get("Computer", event_data.get("WorkstationName", event_data.get("ComputerName", "")))) or None

        # Extract timestamp
        ts_val = system_data.get("TimeCreated", {}).get("SystemTime") or data.get("timestamp") or data.get("TimeCreated")
        timestamp = datetime.now(timezone.utc)
        if ts_val:
            try:
                if isinstance(ts_val, str):
                    clean_ts = ts_val.replace("Z", "+00:00")
                    timestamp = datetime.fromisoformat(clean_ts)
            except Exception as e:
                diagnostics.append(ParseDiagnostic(level="warning", message=f"Timestamp parse failed: {str(e)}", field="timestamp"))

        # Extract user
        username = (
            event_data.get("TargetUserName")
            or event_data.get("SubjectUserName")
            or event_data.get("User")
            or data.get("username")
            or None
        )
        if username and str(username).endswith("$"):  # Machine accounts kept as hostname or username
            pass

        # Extract IP / Ports
        src_ip = event_data.get("IpAddress") or event_data.get("SourceIp") or event_data.get("ClientAddress") or None
        if src_ip in ["-", "127.0.0.1", "::1", "None"]:
            # Keep if valid IP or allow internal
            if src_ip == "-":
                src_ip = None

        dst_ip = event_data.get("DestinationIp") or None
        src_port = None
        dst_port = None
        for port_field, target in [("IpPort", "src"), ("SourcePort", "src"), ("DestinationPort", "dst")]:
            val = event_data.get(port_field)
            if val and str(val).isdigit():
                if target == "src":
                    src_port = int(val)
                else:
                    dst_port = int(val)

        # Action / Event Type mapping
        event_name_map = {
            "4624": ("Successful Logon", "success", "low"),
            "4625": ("Failed Logon", "failure", "medium"),
            "4672": ("Special Privileges Assigned", "privilege_escalation", "medium"),
            "4720": ("User Account Created", "user_create", "medium"),
            "4726": ("User Account Deleted", "user_delete", "medium"),
            "4728": ("Member Added to Security Group", "group_change", "high"),
            "4732": ("Member Added to Local Group", "group_change", "high"),
            "4738": ("User Account Modified", "user_modify", "medium"),
            "7045": ("New Service Installed", "service_install", "high"),
            "4688": ("Process Creation", "process_create", "informational"),
            "1": ("Sysmon Process Creation", "process_create", "informational"),
            "3": ("Sysmon Network Connection", "network_connect", "informational"),
        }

        desc, action, severity = event_name_map.get(
            event_id,
            (f"Windows Event {event_id}" if event_id else "Windows Security Event", "logon" if "logon" in str(data).lower() else "audit", "informational"),
        )

        # Check logon type in failed/success logons
        logon_type = str(event_data.get("LogonType", ""))
        parsed_fields = {
            "event_id": event_id,
            "channel": channel,
            "logon_type": logon_type,
            "sub_status": event_data.get("SubStatus"),
            "failure_reason": event_data.get("Status"),
            "process_name": event_data.get("NewProcessName") or event_data.get("ProcessName") or event_data.get("ImagePath"),
            "command_line": event_data.get("CommandLine"),
            "service_name": event_data.get("ServiceName"),
            "target_domain_name": event_data.get("TargetDomainName"),
            "raw_event_data": redact_sensitive_dict(event_data),
        }

        # Filter out null keys
        parsed_fields = {k: v for k, v in parsed_fields.items() if v is not None}

        event = NormalizedEvent(
            source_format=self.format_id,
            timestamp=timestamp,
            source_ip=src_ip,
            destination_ip=dst_ip,
            source_port=src_port,
            destination_port=dst_port,
            hostname=hostname,
            username=username,
            action=action,
            severity=severity,
            event_type=desc,
            raw_message=self.sanitize(raw_log),
            parsed_fields=parsed_fields,
        )
        return ParseResult(success=True, event=event, diagnostics=diagnostics)
