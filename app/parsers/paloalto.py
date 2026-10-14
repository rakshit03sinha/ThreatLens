"""Palo Alto Networks Firewall Log Parser."""

import csv
import io
from datetime import datetime, timezone
from typing import Optional
from app.parsers.base import BaseParser, ParseResult, ParseDiagnostic
from app.schemas.event import NormalizedEvent


class PaloAltoParser(BaseParser):
    format_id = "paloalto"
    format_name = "Palo Alto Networks Firewall Log"
    description = "Parses Palo Alto PAN-OS CSV syslog traffic and threat logs."

    def can_parse(self, raw_log: str) -> bool:
        trimmed = raw_log.strip()
        # PAN-OS syslog typically starts with a sequence number or date followed by serial and TYPE
        parts = trimmed.split(",")
        if len(parts) >= 20 and any(t in parts for t in ["TRAFFIC", "THREAT", "SYSTEM", "CONFIG"]):
            return True
        return False

    def parse(self, raw_log: str) -> ParseResult:
        reader = csv.reader(io.StringIO(raw_log.strip()))
        try:
            fields = next(reader)
        except Exception as e:
            return ParseResult(
                success=False,
                diagnostics=[ParseDiagnostic(level="error", message=f"CSV parse error: {str(e)}")],
                raw_preview=raw_log[:200],
            )

        if len(fields) < 20:
            return ParseResult(
                success=False,
                diagnostics=[ParseDiagnostic(level="error", message=f"Palo Alto log has {len(fields)} fields, expected at least 20.")],
                raw_preview=raw_log[:200],
            )

        # Standard PAN-OS Traffic CSV field mapping:
        # Index 3: Type (TRAFFIC, THREAT, SYSTEM)
        # Index 4: Subtype (start, end, drop, deny, url, file, etc.)
        # Index 6: Generated Time
        # Index 7: Source IP
        # Index 8: Destination IP
        # Index 11: Rule Name
        # Index 12: Source User
        # Index 14: Application
        # Index 24: Source Port
        # Index 25: Destination Port
        # Index 29: Protocol
        # Index 30: Action (allow, deny, drop, reset-client, reset-server, reset-both)

        log_type = fields[3].strip() if len(fields) > 3 else "TRAFFIC"
        subtype = fields[4].strip() if len(fields) > 4 else ""
        gen_time_str = fields[6].strip() if len(fields) > 6 else ""
        src_ip = fields[7].strip() if len(fields) > 7 else None
        dst_ip = fields[8].strip() if len(fields) > 8 else None
        rule_name = fields[11].strip() if len(fields) > 11 else None
        username = fields[12].strip() if len(fields) > 12 and fields[12].strip() else None
        app = fields[14].strip() if len(fields) > 14 else None

        src_port = None
        dst_port = None
        if len(fields) > 24 and fields[24].strip().isdigit():
            src_port = int(fields[24].strip())
        if len(fields) > 25 and fields[25].strip().isdigit():
            dst_port = int(fields[25].strip())

        action_raw = fields[30].strip() if len(fields) > 30 else subtype
        action = "deny" if action_raw.lower() in ["deny", "drop", "reset-client", "reset-server", "reset-both"] else "allow"

        severity = "medium" if action == "deny" or log_type == "THREAT" else "informational"

        timestamp = datetime.now(timezone.utc)
        if gen_time_str:
            for fmt in ["%Y/%m/%d %H:%M:%S", "%Y-%m-%d %H:%M:%S"]:
                try:
                    timestamp = datetime.strptime(gen_time_str, fmt).replace(tzinfo=timezone.utc)
                    break
                except Exception:
                    pass

        event = NormalizedEvent(
            source_format=self.format_id,
            timestamp=timestamp,
            source_ip=src_ip,
            destination_ip=dst_ip,
            source_port=src_port,
            destination_port=dst_port,
            username=username,
            action=action,
            severity=severity,
            event_type=f"PAN-OS {log_type} ({subtype})",
            raw_message=self.sanitize(raw_log),
            parsed_fields={
                "type": log_type,
                "subtype": subtype,
                "rule_name": rule_name,
                "application": app,
                "raw_action": action_raw,
            },
        )
        return ParseResult(success=True, event=event)
