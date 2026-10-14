"""Cisco Network and Security Device Log Parser."""

import re
from datetime import datetime, timezone
from typing import Optional
from app.parsers.base import BaseParser, ParseResult, ParseDiagnostic
from app.schemas.event import NormalizedEvent

# Matches %FACILITY-SEVERITY-MNEMONIC: message
CISCO_HEADER_PATTERN = re.compile(
    r"(?:.*?\s+)?%(ASA|SEC|SYS|FWSM|PIX)-(\d)-([A-Z0-9_]+):\s+(.*)$"
)

# ASA connection pattern: outside:198.51.100.5/443 ... inside:10.0.0.15/49152
ASA_CONN_PATTERN = re.compile(
    r"(?:for|src)\s+([a-zA-Z0-9_\-]+):(\d+\.\d+\.\d+\.\d+)/(\d+)\s+.*?(?:to|dst)\s+([a-zA-Z0-9_\-]+):(\d+\.\d+\.\d+\.\d+)/(\d+)"
)

# IOS ACL pattern: list 101 denied tcp 192.168.1.10(1234) -> 10.0.0.1(80)
IOS_ACL_PATTERN = re.compile(
    r"(denied|permitted)\s+(\w+)\s+(\d+\.\d+\.\d+\.\d+)\((\d+)\)\s*->\s*(\d+\.\d+\.\d+\.\d+)\((\d+)\)"
)


class CiscoDeviceParser(BaseParser):
    format_id = "cisco"
    format_name = "Cisco Network & Security Device Log"
    description = "Parses Cisco ASA, IOS, and FWSM network security device syslog messages."

    def can_parse(self, raw_log: str) -> bool:
        return bool(re.search(r"%(?:ASA|SEC|SYS|FWSM|PIX)-\d-[A-Z0-9_]+:", raw_log))

    def parse(self, raw_log: str) -> ParseResult:
        match = CISCO_HEADER_PATTERN.search(raw_log.strip())
        if not match:
            return ParseResult(
                success=False,
                diagnostics=[ParseDiagnostic(level="error", message="Not a recognized Cisco device log format.")],
                raw_preview=raw_log[:200],
            )

        facility, sev_digit, mnemonic, message = match.groups()
        sev_int = int(sev_digit)

        sev_map = {
            1: "critical", 2: "critical", 3: "high", 4: "medium", 5: "low", 6: "informational", 7: "informational"
        }
        severity = sev_map.get(sev_int, "informational")

        src_ip: Optional[str] = None
        dst_ip: Optional[str] = None
        src_port: Optional[int] = None
        dst_port: Optional[int] = None
        action = "allow" if any(w in message.lower() for w in ["built", "permitted", "permit"]) else "deny"

        # Check ASA IP/Port format
        asa_match = ASA_CONN_PATTERN.search(message)
        if asa_match:
            src_zone, s_ip, s_port, dst_zone, d_ip, d_port = asa_match.groups()
            src_ip = s_ip
            dst_ip = d_ip
            src_port = int(s_port)
            dst_port = int(d_port)
        else:
            # Check IOS ACL format
            ios_match = IOS_ACL_PATTERN.search(message)
            if ios_match:
                act_str, proto, s_ip, s_port, d_ip, d_port = ios_match.groups()
                action = "deny" if act_str == "denied" else "allow"
                src_ip = s_ip
                dst_ip = d_ip
                src_port = int(s_port)
                dst_port = int(d_port)

        event = NormalizedEvent(
            source_format=self.format_id,
            timestamp=datetime.now(timezone.utc),
            source_ip=src_ip,
            destination_ip=dst_ip,
            source_port=src_port,
            destination_port=dst_port,
            action=action,
            severity=severity,
            event_type=f"Cisco {facility} {mnemonic}",
            raw_message=self.sanitize(raw_log),
            parsed_fields={
                "facility": facility,
                "mnemonic": mnemonic,
                "cisco_severity": sev_int,
                "details": message,
            },
        )
        return ParseResult(success=True, event=event)
