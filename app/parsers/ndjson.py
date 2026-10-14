"""NDJSON / JSON Lines Parser."""

import json
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from app.parsers.base import BaseParser, ParseResult, ParseDiagnostic
from app.schemas.event import NormalizedEvent
from app.utils.redact import redact_sensitive_dict


class NDJSONParser(BaseParser):
    format_id = "ndjson"
    format_name = "JSON Lines (NDJSON)"
    description = "Parses single JSON log objects following common generic event schemas."

    def can_parse(self, raw_log: str) -> bool:
        trimmed = raw_log.strip()
        if not (trimmed.startswith("{") and trimmed.endswith("}")):
            return False
        try:
            json.loads(trimmed)
            return True
        except Exception:
            return False

    def parse(self, raw_log: str) -> ParseResult:
        try:
            data = json.loads(raw_log)
        except Exception as e:
            return ParseResult(
                success=False,
                diagnostics=[ParseDiagnostic(level="error", message=f"Invalid JSON: {str(e)}")],
                raw_preview=raw_log[:200],
            )

        # Extract timestamp
        ts_val = data.get("timestamp") or data.get("@timestamp") or data.get("time") or data.get("datetime")
        timestamp = datetime.now(timezone.utc)
        if ts_val:
            try:
                if isinstance(ts_val, (int, float)):
                    # Epoch timestamp
                    timestamp = datetime.fromtimestamp(ts_val, tz=timezone.utc)
                elif isinstance(ts_val, str):
                    timestamp = datetime.fromisoformat(ts_val.replace("Z", "+00:00"))
            except Exception:
                pass

        # Source / Destination IP
        src_ip = data.get("src_ip") or data.get("source_ip") or data.get("src") or data.get("client_ip")
        dst_ip = data.get("dst_ip") or data.get("destination_ip") or data.get("dst") or data.get("server_ip")

        # Ports
        src_port = None
        dst_port = None
        for p in ["src_port", "source_port"]:
            if p in data and str(data[p]).isdigit():
                src_port = int(data[p])
        for p in ["dst_port", "destination_port"]:
            if p in data and str(data[p]).isdigit():
                dst_port = int(data[p])

        hostname = data.get("host") or data.get("hostname") or data.get("computer")
        username = data.get("user") or data.get("username") or data.get("account") or data.get("user_name")
        action = data.get("action") or data.get("status") or "informational"
        severity = data.get("severity") or data.get("level") or "informational"
        event_type = data.get("event_type") or data.get("category") or data.get("event") or "Generic JSON Event"

        event = NormalizedEvent(
            source_format=self.format_id,
            timestamp=timestamp,
            source_ip=str(src_ip) if src_ip else None,
            destination_ip=str(dst_ip) if dst_ip else None,
            source_port=src_port,
            destination_port=dst_port,
            hostname=str(hostname) if hostname else None,
            username=str(username) if username else None,
            action=str(action).lower(),
            severity=str(severity).lower(),
            event_type=str(event_type),
            raw_message=self.sanitize(raw_log),
            parsed_fields=redact_sensitive_dict(data),
        )
        return ParseResult(success=True, event=event)
