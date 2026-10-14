"""Linux System and Auth Log Parser."""

import re
from datetime import datetime, timezone
from typing import Optional
from app.parsers.base import BaseParser, ParseResult, ParseDiagnostic
from app.schemas.event import NormalizedEvent

MONTH_MAP = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}

# Regex for standard syslog header: Oct 14 21:00:00 hostname service[pid]: message
LINUX_SYSLOG_PATTERN = re.compile(
    r"^([A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+([a-zA-Z0-9_\-\.]+)\s+([a-zA-Z0-9_\-\.]+)(?:\[(\d+)\])?:\s+(.*)$"
)

# Auth specific patterns
SSHD_FAILED_PATTERN = re.compile(r"Failed password for (?:invalid user )?([a-zA-Z0-9_\-\.]+) from (\d+\.\d+\.\d+\.\d+) port (\d+)")
SSHD_ACCEPTED_PATTERN = re.compile(r"Accepted (?:password|publickey) for ([a-zA-Z0-9_\-\.]+) from (\d+\.\d+\.\d+\.\d+) port (\d+)")
SUDO_PATTERN = re.compile(r"^\s*([a-zA-Z0-9_\-\.]+)\s*:\s*TTY=.*?USER=([a-zA-Z0-9_\-\.]+)\s*;\s*COMMAND=(.*)$")
USERADD_PATTERN = re.compile(r"new user: name=([a-zA-Z0-9_\-\.]+)")


class LinuxAuthParser(BaseParser):
    format_id = "linux"
    format_name = "Linux System & Auth Log"
    description = "Parses Linux /var/log/auth.log, secure, and system messages."

    def can_parse(self, raw_log: str) -> bool:
        trimmed = raw_log.strip()
        if any(prog in trimmed for prog in ["sshd", "sudo", "useradd", "groupadd", "systemd", "kernel", "pam_unix"]):
            return True
        return bool(LINUX_SYSLOG_PATTERN.match(trimmed))

    def parse(self, raw_log: str) -> ParseResult:
        trimmed = raw_log.strip()
        match = LINUX_SYSLOG_PATTERN.match(trimmed)

        now = datetime.now(timezone.utc)
        timestamp = now
        hostname = None
        program = None
        pid = None
        message = trimmed

        if match:
            date_str, hostname, program, pid_str, message = match.groups()
            pid = int(pid_str) if pid_str else None
            try:
                parts = date_str.split()
                month = MONTH_MAP.get(parts[0], now.month)
                day = int(parts[1])
                time_parts = [int(p) for p in parts[2].split(":")]
                timestamp = datetime(now.year, month, day, time_parts[0], time_parts[1], time_parts[2], tzinfo=timezone.utc)
            except Exception:
                timestamp = now

        username: Optional[str] = None
        src_ip: Optional[str] = None
        src_port: Optional[int] = None
        action = "audit"
        severity = "informational"
        event_type = f"Linux {program or 'System'} Event"
        parsed_fields = {"program": program, "pid": pid}

        # Check SSHD failed login
        fail_match = SSHD_FAILED_PATTERN.search(message)
        if fail_match:
            username, src_ip, port_str = fail_match.groups()
            src_port = int(port_str) if port_str.isdigit() else None
            action = "failure"
            severity = "medium"
            event_type = "Linux SSH Failed Login"
            parsed_fields["auth_method"] = "password"

        # Check SSHD accepted login
        accept_match = SSHD_ACCEPTED_PATTERN.search(message)
        if accept_match:
            username, src_ip, port_str = accept_match.groups()
            src_port = int(port_str) if port_str.isdigit() else None
            action = "success"
            severity = "low"
            event_type = "Linux SSH Successful Login"

        # Check sudo command execution
        sudo_match = SUDO_PATTERN.search(message)
        if sudo_match:
            calling_user, target_user, command = sudo_match.groups()
            username = calling_user
            action = "privilege_escalation"
            severity = "medium"
            event_type = "Linux Sudo Execution"
            parsed_fields["target_user"] = target_user
            parsed_fields["command"] = command.strip()

        # Check user creation
        useradd_match = USERADD_PATTERN.search(message)
        if useradd_match:
            new_user = useradd_match.group(1)
            username = new_user
            action = "user_create"
            severity = "high"
            event_type = "Linux User Account Created"

        event = NormalizedEvent(
            source_format=self.format_id,
            timestamp=timestamp,
            source_ip=src_ip,
            destination_ip=None,
            source_port=src_port,
            destination_port=22 if (program and "ssh" in program.lower()) else None,
            hostname=hostname,
            username=username,
            action=action,
            severity=severity,
            event_type=event_type,
            raw_message=self.sanitize(raw_log),
            parsed_fields={k: v for k, v in parsed_fields.items() if v is not None},
        )
        return ParseResult(success=True, event=event)
