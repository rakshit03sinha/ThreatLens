"""Log Event Extended Format (LEEF) Parser."""

import re
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from app.parsers.base import BaseParser, ParseResult, ParseDiagnostic
from app.schemas.event import NormalizedEvent

LEEF_PATTERN = re.compile(
    r"(?:.*?\s+)?LEEF:(1\.0|2\.0)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|(.*)$"
)


class LEEFParser(BaseParser):
    format_id = "leef"
    format_name = "Log Event Extended Format (LEEF)"
    description = "Parses IBM QRadar Log Event Extended Format (LEEF 1.0 and 2.0)."

    def can_parse(self, raw_log: str) -> bool:
        return bool(LEEF_PATTERN.search(raw_log.strip()))

    def parse(self, raw_log: str) -> ParseResult:
        match = LEEF_PATTERN.search(raw_log.strip())
        if not match:
            return ParseResult(
                success=False,
                diagnostics=[ParseDiagnostic(level="error", message="Invalid LEEF syntax.")],
                raw_preview=raw_log[:200],
            )

        version, vendor, product, prod_version, event_id, remainder = match.groups()

        # Check for optional custom delimiter in LEEF 2.0 (e.g. ^x20)
        delimiter = "\t"
        attributes_str = remainder
        if version == "2.0" and remainder.startswith("^"):
            delim_char = remainder.split("|", 1)[0]
            attributes_str = remainder.split("|", 1)[1]
            if delim_char == r"^x20" or delim_char == "^20":
                delimiter = " "
            elif delim_char == r"^x09" or delim_char == "^09":
                delimiter = "\t"

        # Split key=value pairs
        fields: Dict[str, str] = {}
        # Try both delimiter and standard tab/whitespace separation
        items = attributes_str.split(delimiter) if delimiter in attributes_str else attributes_str.split("\t")
        if len(items) <= 1 and " " in attributes_str:
            items = re.findall(r"(\w+)=([^\t\n\r]+?)(?=\s+\w+=|$)", attributes_str)
            for k, v in items:
                fields[k] = v.strip()
        else:
            for item in items:
                if "=" in item:
                    k, v = item.split("=", 1)
                    fields[k.strip()] = v.strip()

        src_ip = fields.get("src") or fields.get("srcAddress")
        dst_ip = fields.get("dst") or fields.get("dstAddress")
        src_port = int(fields["spt"]) if fields.get("spt", "").isdigit() else None
        dst_port = int(fields["dpt"]) if fields.get("dpt", "").isdigit() else None
        username = fields.get("usrName") or fields.get("srcUser") or fields.get("userName")

        # Timestamp
        timestamp = datetime.now(timezone.utc)
        dev_time = fields.get("devTime") or fields.get("calmTime")
        if dev_time:
            try:
                timestamp = datetime.fromisoformat(dev_time.replace("Z", "+00:00"))
            except Exception:
                pass

        action = "failure" if any(w in event_id.lower() for w in ["fail", "denied", "block"]) else "success"
        severity = "medium" if action == "failure" else "informational"

        event = NormalizedEvent(
            source_format=self.format_id,
            timestamp=timestamp,
            source_ip=src_ip,
            destination_ip=dst_ip,
            source_port=src_port,
            destination_port=dst_port,
            hostname=fields.get("identHostName"),
            username=username,
            action=action,
            severity=severity,
            event_type=f"LEEF {product}: {event_id}",
            raw_message=self.sanitize(raw_log),
            parsed_fields={
                "leef_version": version,
                "vendor": vendor,
                "product": product,
                "event_id": event_id,
                "attributes": fields,
            },
        )
        return ParseResult(success=True, event=event)
