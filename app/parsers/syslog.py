"""Generic Syslog Parser (RFC 3164 and RFC 5424)."""

import re
from datetime import datetime, timezone
from typing import Optional
from app.parsers.base import BaseParser, ParseResult, ParseDiagnostic
from app.schemas.event import NormalizedEvent

# RFC 5424: <165>1 2026-10-14T22:14:15.003Z host app-name procid msgid [structured-data] msg
RFC5424_PATTERN = re.compile(
    r"^<(\d{1,3})>1\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(?:\[(.*?)\])?\s*(.*)$"
)

# RFC 3164: <34>Oct 14 21:00:00 host tag: msg
RFC3164_PATTERN = re.compile(
    r"^<(\d{1,3})>([A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+([a-zA-Z0-9_\-\.]+)\s+([^:]+):\s*(.*)$"
)

SEVERITY_MAP = {
    0: ("critical", "emergency"),
    1: ("critical", "alert"),
    2: ("critical", "critical"),
    3: ("high", "error"),
    4: ("medium", "warning"),
    5: ("low", "notice"),
    6: ("informational", "informational"),
    7: ("informational", "debug"),
}


class GenericSyslogParser(BaseParser):
    format_id = "syslog"
    format_name = "Generic Syslog (RFC 3164 / 5424)"
    description = "Parses standard RFC 3164 (BSD syslog) and RFC 5424 structured syslog messages."

    def can_parse(self, raw_log: str) -> bool:
        trimmed = raw_log.strip()
        return bool(trimmed.startswith("<") and (RFC5424_PATTERN.match(trimmed) or RFC3164_PATTERN.match(trimmed)))

    def parse(self, raw_log: str) -> ParseResult:
        trimmed = raw_log.strip()
        now = datetime.now(timezone.utc)
        timestamp = now
        hostname = None
        app_name = None
        severity_label = "informational"
        pri = 13  # default notice

        rfc5424_match = RFC5424_PATTERN.match(trimmed)
        if rfc5424_match:
            pri_str, ts_str, host, app, procid, msgid, sd, msg = rfc5424_match.groups()
            pri = int(pri_str)
            hostname = host if host != "-" else None
            app_name = app if app != "-" else None
            try:
                timestamp = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            except Exception:
                timestamp = now
            message = msg or ""
            structured_data = sd
        else:
            rfc3164_match = RFC3164_PATTERN.match(trimmed)
            if rfc3164_match:
                pri_str, ts_str, host, tag, msg = rfc3164_match.groups()
                pri = int(pri_str)
                hostname = host
                app_name = tag.split("[")[0].strip()
                message = msg
                structured_data = None
            else:
                return ParseResult(
                    success=False,
                    diagnostics=[ParseDiagnostic(level="error", message="Message does not match RFC 5424 or RFC 3164 syntax.")],
                    raw_preview=raw_log[:200],
                )

        facility = pri // 8
        sev_code = pri % 8
        severity_label, sev_name = SEVERITY_MAP.get(sev_code, ("informational", "unknown"))

        # Look for IP addresses in message
        ip_match = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", message)
        src_ip = ip_match[0] if len(ip_match) > 0 else None
        dst_ip = ip_match[1] if len(ip_match) > 1 else None

        action = "deny" if any(w in message.lower() for w in ["drop", "denied", "block", "failed"]) else "allow"

        parsed_fields = {
            "facility": facility,
            "severity_code": sev_code,
            "severity_name": sev_name,
            "app_name": app_name,
            "structured_data": structured_data,
        }

        event = NormalizedEvent(
            source_format=self.format_id,
            timestamp=timestamp,
            source_ip=src_ip,
            destination_ip=dst_ip,
            hostname=hostname,
            action=action,
            severity=severity_label,
            event_type=f"Syslog ({app_name or 'System'})",
            raw_message=self.sanitize(raw_log),
            parsed_fields={k: v for k, v in parsed_fields.items() if v is not None},
        )
        return ParseResult(success=True, event=event)
