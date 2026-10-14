"""Common Event Format (CEF) Parser."""

import re
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from app.parsers.base import BaseParser, ParseResult, ParseDiagnostic
from app.schemas.event import NormalizedEvent

CEF_PREFIX_PATTERN = re.compile(
    r"(?:.*?\s+)?CEF:\s*(\d+)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|(.*)$"
)


class CEFParser(BaseParser):
    format_id = "cef"
    format_name = "Common Event Format (CEF)"
    description = "Parses ArcSight Common Event Format (CEF) syslog and file logs."

    def can_parse(self, raw_log: str) -> bool:
        return bool(CEF_PREFIX_PATTERN.search(raw_log.strip()))

    def parse(self, raw_log: str) -> ParseResult:
        match = CEF_PREFIX_PATTERN.search(raw_log.strip())
        if not match:
            return ParseResult(
                success=False,
                diagnostics=[ParseDiagnostic(level="error", message="Invalid CEF format syntax.")],
                raw_preview=raw_log[:200],
            )

        version, vendor, product, dev_version, event_class, name, sev_str, extension_str = match.groups()

        # Parse extension key-value pairs (key=value with escaped spaces/equals)
        extensions: Dict[str, str] = {}
        # Simple parser for key=val space separated
        tokens = re.findall(r"(\w+)=((?:\\=|\\ |[^\s=])+)", extension_str)
        for k, v in tokens:
            extensions[k] = v.replace(r"\=", "=").replace(r"\ ", " ")

        # Severity mapping (CEF severity can be 0-10 or string)
        sev_int = 1
        try:
            sev_int = int(sev_str)
            if sev_int >= 8:
                severity = "critical" if sev_int >= 9 else "high"
            elif sev_int >= 5:
                severity = "medium"
            elif sev_int >= 3:
                severity = "low"
            else:
                severity = "informational"
        except Exception:
            severity = sev_str.lower() if sev_str else "informational"

        src_ip = extensions.get("src") or extensions.get("sourceAddress")
        dst_ip = extensions.get("dst") or extensions.get("destinationAddress")
        src_port = int(extensions["spt"]) if extensions.get("spt", "").isdigit() else None
        dst_port = int(extensions["dpt"]) if extensions.get("dpt", "").isdigit() else None
        hostname = extensions.get("shost") or extensions.get("dhost") or extensions.get("dvchost")
        username = extensions.get("suser") or extensions.get("duser") or extensions.get("sourceUserName")
        action = extensions.get("act") or extensions.get("action") or "alert"

        # Timestamp in extensions (rt or end)
        timestamp = datetime.now(timezone.utc)
        ts_val = extensions.get("rt") or extensions.get("end") or extensions.get("start")
        if ts_val:
            try:
                if str(ts_val).isdigit():
                    # Milliseconds or seconds epoch
                    ts_num = float(ts_val)
                    if ts_num > 1e11:
                        ts_num /= 1000.0
                    timestamp = datetime.fromtimestamp(ts_num, tz=timezone.utc)
                else:
                    timestamp = datetime.fromisoformat(ts_val.replace("Z", "+00:00"))
            except Exception:
                pass

        event = NormalizedEvent(
            source_format=self.format_id,
            timestamp=timestamp,
            source_ip=src_ip,
            destination_ip=dst_ip,
            source_port=src_port,
            destination_port=dst_port,
            hostname=hostname,
            username=username,
            action=action.lower(),
            severity=severity,
            event_type=f"{product}: {name}",
            raw_message=self.sanitize(raw_log),
            parsed_fields={
                "device_vendor": vendor,
                "device_product": product,
                "device_version": dev_version,
                "event_class_id": event_class,
                "extensions": extensions,
            },
        )
        return ParseResult(success=True, event=event)
