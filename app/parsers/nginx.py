"""Nginx Access Log Parser."""

import re
from datetime import datetime, timezone
from typing import Optional
from app.parsers.base import BaseParser, ParseResult, ParseDiagnostic
from app.schemas.event import NormalizedEvent

NGINX_PATTERN = re.compile(
    r'^(\S+)\s+(\S+)\s+(\S+)\s+\[([^\]]+)\]\s+"([A-Z]+)\s+([^"\s]+)(?:\s+(HTTP/[0-9\.]+))?"\s+(\d{3})\s+(\S+)(?:\s+"([^"]*)"\s+"([^"]*)")?'
)


class NginxAccessParser(BaseParser):
    format_id = "nginx"
    format_name = "Nginx Access Log"
    description = "Parses Nginx standard HTTP access log lines."

    def can_parse(self, raw_log: str) -> bool:
        trimmed = raw_log.strip()
        return bool(re.search(r'\[\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2}\s+[^\]]+\]\s+"[A-Z]+\s+', trimmed))

    def parse(self, raw_log: str) -> ParseResult:
        match = NGINX_PATTERN.match(raw_log.strip())
        if not match:
            return ParseResult(
                success=False,
                diagnostics=[ParseDiagnostic(level="error", message="Failed to parse Nginx log pattern.")],
                raw_preview=raw_log[:200],
            )

        client_ip, ident, auth_user, date_str, method, uri, http_version, status_code_str, bytes_sent, referer, user_agent = match.groups()

        status_code = int(status_code_str)
        username = auth_user if auth_user != "-" else None

        timestamp = datetime.now(timezone.utc)
        try:
            timestamp = datetime.strptime(date_str, "%d/%b/%Y:%H:%M:%S %z")
        except Exception:
            pass

        # Action & severity
        if status_code >= 500:
            action = "server_error"
            severity = "medium"
        elif status_code in [401, 403]:
            action = "denied"
            severity = "medium"
        elif status_code == 404:
            action = "not_found"
            severity = "low"
        else:
            action = "allow"
            severity = "informational"

        # Web exploit heuristic
        if any(probe in uri for probe in ["../", "..\\", "/etc/passwd", "win.ini", "union+select", "cmd.exe", "/.env"]):
            severity = "high"
            action = "exploit_probe"

        event = NormalizedEvent(
            source_format=self.format_id,
            timestamp=timestamp,
            source_ip=client_ip,
            destination_ip=None,
            source_port=None,
            destination_port=443 if "https" in (referer or "") else 80,
            hostname=None,
            username=username,
            action=action,
            severity=severity,
            event_type=f"Nginx {method} {status_code}",
            raw_message=self.sanitize(raw_log),
            parsed_fields={
                "method": method,
                "uri": uri,
                "http_version": http_version,
                "status_code": status_code,
                "body_bytes_sent": bytes_sent if bytes_sent != "-" else "0",
                "referer": referer,
                "user_agent": user_agent,
            },
        )
        return ParseResult(success=True, event=event)
