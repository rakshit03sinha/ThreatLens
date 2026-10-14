"""ThreatLens Catalogue of 11 Deterministic MITRE ATT&CK Aligned Detection Rules."""

import re
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
from app.rules.base import BaseRule, RuleMatch
from app.schemas.event import NormalizedEvent


def ensure_utc(dt: datetime) -> datetime:
    """Normalize datetime to timezone-aware UTC."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


class Rule001BruteForce(BaseRule):
    rule_id = "RULE-001"
    name = "Repeated Failed Logins / Brute-Force Pattern"
    description = "Detects multiple failed authentication attempts within a short time window targeting a single account or from a single source IP."
    severity = "high"
    attack_tactic = "Credential Access"
    attack_technique = "T1110"
    attack_technique_name = "Brute Force"
    default_window_seconds = 300
    default_threshold = 5

    def evaluate(
        self,
        current_event: NormalizedEvent,
        recent_events: List[NormalizedEvent],
        parameters: Optional[Dict[str, Any]] = None,
    ) -> Optional[RuleMatch]:
        params = parameters or {}
        threshold = params.get("threshold", self.default_threshold)
        window = timedelta(seconds=params.get("window_seconds", self.default_window_seconds))

        is_failed = current_event.action in ["failure", "deny", "failed"] or (
            current_event.event_type and "failed" in current_event.event_type.lower()
        )
        if not is_failed:
            return None

        key_user = current_event.username
        key_ip = current_event.source_ip
        if not key_user and not key_ip:
            return None

        curr_ts = ensure_utc(current_event.timestamp)
        cutoff = curr_ts - window
        matching_events = [current_event]

        for ev in recent_events:
            ev_ts = ensure_utc(ev.timestamp)
            if ev.id == current_event.id or ev_ts < cutoff:
                continue
            ev_is_failed = ev.action in ["failure", "deny", "failed"] or (
                ev.event_type and "failed" in ev.event_type.lower()
            )
            if ev_is_failed:
                if (key_user and ev.username == key_user) or (key_ip and ev.source_ip == key_ip):
                    matching_events.append(ev)

        if len(matching_events) >= threshold:
            supporting_ids = [e.id for e in matching_events if e.id]
            corr_key = f"bruteforce:{key_user or key_ip}"
            return RuleMatch(
                rule_id=self.rule_id,
                rule_name=self.name,
                severity=self.severity,
                risk_score=75.0,
                title=f"Brute-Force Pattern Detected: {len(matching_events)} failures for {key_user or key_ip}",
                description=f"Observed {len(matching_events)} failed login attempts within {window.total_seconds()}s.",
                attack_tactic=self.attack_tactic,
                attack_technique=self.attack_technique,
                attack_technique_name=self.attack_technique_name,
                correlation_key=corr_key,
                supporting_event_ids=supporting_ids,
                context_data={
                    "target_user": key_user,
                    "source_ip": key_ip,
                    "attempt_count": len(matching_events),
                },
            )
        return None


class Rule002SuccessAfterBurst(BaseRule):
    rule_id = "RULE-002"
    name = "Successful Login Following a Burst of Failures"
    description = "Detects a successful authentication event immediately following a burst of failed login attempts, suggesting successful credential guessing or compromise."
    severity = "critical"
    attack_tactic = "Credential Access"
    attack_technique = "T1110.001"
    attack_technique_name = "Password Guessing"
    default_window_seconds = 600
    default_threshold = 3

    def evaluate(
        self,
        current_event: NormalizedEvent,
        recent_events: List[NormalizedEvent],
        parameters: Optional[Dict[str, Any]] = None,
    ) -> Optional[RuleMatch]:
        params = parameters or {}
        threshold = params.get("threshold", self.default_threshold)
        window = timedelta(seconds=params.get("window_seconds", self.default_window_seconds))

        is_success = current_event.action in ["success", "allow", "logon"] and (
            current_event.event_type and "success" in current_event.event_type.lower() or current_event.action == "success"
        )
        if not is_success:
            return None

        key_user = current_event.username
        key_ip = current_event.source_ip
        if not key_user and not key_ip:
            return None

        curr_ts = ensure_utc(current_event.timestamp)
        cutoff = curr_ts - window
        prior_failures = []

        for ev in recent_events:
            ev_ts = ensure_utc(ev.timestamp)
            if ev.id == current_event.id or ev_ts < cutoff or ev_ts > curr_ts:
                continue
            ev_is_failed = ev.action in ["failure", "deny", "failed"] or (
                ev.event_type and "failed" in ev.event_type.lower()
            )
            if ev_is_failed:
                if (key_user and ev.username == key_user) or (key_ip and ev.source_ip == key_ip):
                    prior_failures.append(ev)

        if len(prior_failures) >= threshold:
            supporting_ids = [e.id for e in prior_failures if e.id]
            if current_event.id:
                supporting_ids.append(current_event.id)
            corr_key = f"compromise:{key_user or key_ip}"
            return RuleMatch(
                rule_id=self.rule_id,
                rule_name=self.name,
                severity=self.severity,
                risk_score=90.0,
                title=f"Potential Credential Guessing Success for {key_user or key_ip}",
                description=f"Successful logon preceded by {len(prior_failures)} failed attempts within {window.total_seconds()}s.",
                attack_tactic=self.attack_tactic,
                attack_technique=self.attack_technique,
                attack_technique_name=self.attack_technique_name,
                correlation_key=corr_key,
                supporting_event_ids=supporting_ids,
                context_data={
                    "target_user": key_user,
                    "source_ip": key_ip,
                    "prior_failure_count": len(prior_failures),
                },
            )
        return None


class Rule003PrivilegeGroupChange(BaseRule):
    rule_id = "RULE-003"
    name = "Suspicious Privileged Account or Group Change"
    description = "Detects additions to privileged security groups (e.g. Domain Admins, Administrators, wheel, sudoers) or administrative role assignments."
    severity = "high"
    attack_tactic = "Privilege Escalation"
    attack_technique = "T1098"
    attack_technique_name = "Account Manipulation"

    def evaluate(
        self,
        current_event: NormalizedEvent,
        recent_events: List[NormalizedEvent],
        parameters: Optional[Dict[str, Any]] = None,
    ) -> Optional[RuleMatch]:
        raw_lower = current_event.raw_message.lower()
        fields = current_event.parsed_fields or {}
        event_id = str(fields.get("event_id", ""))

        is_priv_group_change = False
        target_group = None

        if event_id in ["4728", "4732", "4756"]:  # Windows Security Group addition
            is_priv_group_change = True
            target_group = str(fields.get("TargetUserName") or "SecurityGroup")
        elif "groupadd" in raw_lower or "usermod -a -g" in raw_lower or "wheel" in raw_lower or "sudoers" in raw_lower:
            is_priv_group_change = True
            target_group = "wheel/sudoers"
        elif any(grp in raw_lower for grp in ["domain admins", "enterprise admins", "administrators"]) and current_event.action in ["group_change", "user_modify", "user_create"]:
            is_priv_group_change = True
            target_group = "Administrators"

        if is_priv_group_change:
            supporting_ids = [current_event.id] if current_event.id else []
            return RuleMatch(
                rule_id=self.rule_id,
                rule_name=self.name,
                severity=self.severity,
                risk_score=80.0,
                title=f"Privileged Group Change: Account added to {target_group or 'Admin Group'}",
                description=f"User {current_event.username or 'unknown'} altered privileged security group membership.",
                attack_tactic=self.attack_tactic,
                attack_technique=self.attack_technique,
                attack_technique_name=self.attack_technique_name,
                correlation_key=f"privchange:{current_event.username or current_event.hostname}",
                supporting_event_ids=supporting_ids,
                context_data={
                    "user": current_event.username,
                    "target_group": target_group,
                    "host": current_event.hostname,
                },
            )
        return None


class Rule004UnusualServiceExecution(BaseRule):
    rule_id = "RULE-004"
    name = "New or Unusual Service/Process Execution"
    description = "Detects installation of new system services or execution of high-risk operational binaries (e.g. PsExec, vssadmin, certutil, procdump)."
    severity = "high"
    attack_tactic = "Persistence"
    attack_technique = "T1543.003"
    attack_technique_name = "Windows Service"

    def evaluate(
        self,
        current_event: NormalizedEvent,
        recent_events: List[NormalizedEvent],
        parameters: Optional[Dict[str, Any]] = None,
    ) -> Optional[RuleMatch]:
        raw_lower = current_event.raw_message.lower()
        fields = current_event.parsed_fields or {}
        event_id = str(fields.get("event_id", ""))

        matched_indicator = None
        if event_id == "7045" or current_event.action == "service_install":
            matched_indicator = f"New Service: {fields.get('service_name', 'Unknown')}"
        else:
            suspicious_bins = ["psexec", "mimikatz", "vssadmin", "certutil -urlcache", "procdump", "nc.exe", "netcat", "whoami /priv"]
            for b in suspicious_bins:
                if b in raw_lower:
                    matched_indicator = f"Suspicious binary/tool invocation: {b}"
                    break

        if matched_indicator:
            supporting_ids = [current_event.id] if current_event.id else []
            return RuleMatch(
                rule_id=self.rule_id,
                rule_name=self.name,
                severity=self.severity,
                risk_score=78.0,
                title=f"Unusual Service/Process Execution on {current_event.hostname or 'host'}",
                description=f"Detected: {matched_indicator}",
                attack_tactic=self.attack_tactic,
                attack_technique=self.attack_technique,
                attack_technique_name=self.attack_technique_name,
                correlation_key=f"execution:{current_event.hostname or current_event.username}",
                supporting_event_ids=supporting_ids,
                context_data={
                    "matched_indicator": matched_indicator,
                    "host": current_event.hostname,
                    "user": current_event.username,
                },
            )
        return None


class Rule005SuspiciousPowerShell(BaseRule):
    rule_id = "RULE-005"
    name = "Suspicious PowerShell or Command-Line Indicators"
    description = "Detects encoded PowerShell commands, execution policy bypass, hidden window styles, or web download expressions in telemetry."
    severity = "high"
    attack_tactic = "Execution"
    attack_technique = "T1059.001"
    attack_technique_name = "PowerShell"

    def evaluate(
        self,
        current_event: NormalizedEvent,
        recent_events: List[NormalizedEvent],
        parameters: Optional[Dict[str, Any]] = None,
    ) -> Optional[RuleMatch]:
        raw = current_event.raw_message.lower()
        cmdline = str(current_event.parsed_fields.get("command_line", "")).lower()
        combined = f"{raw} {cmdline}"

        patterns = [
            (r"-enc(?:odedcommand)?\s+[a-za-z0-9+/=]{10,}", "Encoded PowerShell Command"),
            (r"-executionpolicy\s+bypass", "Execution Policy Bypass"),
            (r"-w(?:indowstyle)?\s+hidden", "Hidden Window Execution"),
            (r"downloadstring\(", "Web DownloadString Cradle"),
            (r"invoke-expression", "Invoke-Expression (IEX) Cradle"),
            (r"invoke-mimikatz", "Invoke-Mimikatz Script"),
        ]

        found_patterns = []
        for pat, label in patterns:
            if re.search(pat, combined):
                found_patterns.append(label)

        if found_patterns:
            supporting_ids = [current_event.id] if current_event.id else []
            return RuleMatch(
                rule_id=self.rule_id,
                rule_name=self.name,
                severity=self.severity,
                risk_score=85.0,
                title=f"Suspicious PowerShell Execution: {', '.join(found_patterns)}",
                description=f"Detected malicious command-line patterns on host {current_event.hostname or 'unknown'}.",
                attack_tactic=self.attack_tactic,
                attack_technique=self.attack_technique,
                attack_technique_name=self.attack_technique_name,
                correlation_key=f"powershell:{current_event.hostname or current_event.username}",
                supporting_event_ids=supporting_ids,
                context_data={
                    "patterns": found_patterns,
                    "host": current_event.hostname,
                    "user": current_event.username,
                },
            )
        return None


class Rule006LateralMovement(BaseRule):
    rule_id = "RULE-006"
    name = "Possible Lateral Movement via Remote Logon / Admin Share"
    description = "Detects network logon to administrative shares (ADMIN$, C$) or remote interactive logons across multiple internal endpoints."
    severity = "high"
    attack_tactic = "Lateral Movement"
    attack_technique = "T1021"
    attack_technique_name = "Remote Services"

    def evaluate(
        self,
        current_event: NormalizedEvent,
        recent_events: List[NormalizedEvent],
        parameters: Optional[Dict[str, Any]] = None,
    ) -> Optional[RuleMatch]:
        raw = current_event.raw_message.lower()
        fields = current_event.parsed_fields or {}
        logon_type = str(fields.get("logon_type", ""))

        matched_indicator = None
        if any(share in raw for share in ["admin$", "c$", "ipc$"]):
            matched_indicator = "Administrative share access (ADMIN$/C$/IPC$)"
        elif logon_type in ["3", "10"] and current_event.source_ip and current_event.hostname:
            # Check if this user logged into > 1 host recently
            curr_ts = ensure_utc(current_event.timestamp)
            cutoff = curr_ts - timedelta(seconds=600)
            other_hosts = {current_event.hostname}
            for ev in recent_events:
                ev_ts = ensure_utc(ev.timestamp)
                if ev_ts >= cutoff and ev.username == current_event.username and ev.hostname:
                    other_hosts.add(ev.hostname)
            if len(other_hosts) >= 2:
                matched_indicator = f"User logged into multiple hosts ({len(other_hosts)} endpoints: {', '.join(other_hosts)})"

        if matched_indicator:
            supporting_ids = [current_event.id] if current_event.id else []
            return RuleMatch(
                rule_id=self.rule_id,
                rule_name=self.name,
                severity=self.severity,
                risk_score=82.0,
                title=f"Potential Lateral Movement: {matched_indicator}",
                description=f"User {current_event.username or 'unknown'} exhibited lateral movement indicators.",
                attack_tactic=self.attack_tactic,
                attack_technique=self.attack_technique,
                attack_technique_name=self.attack_technique_name,
                correlation_key=f"lateral:{current_event.username or current_event.source_ip}",
                supporting_event_ids=supporting_ids,
                context_data={
                    "indicator": matched_indicator,
                    "user": current_event.username,
                    "src_ip": current_event.source_ip,
                    "target_host": current_event.hostname,
                },
            )
        return None


class Rule007UnusualOutboundConnection(BaseRule):
    rule_id = "RULE-007"
    name = "Unusual Outbound Connection to High-Risk Destination"
    description = "Detects outbound network egress to non-standard ports typically associated with remote access trojans or reverse shells (e.g. 4444, 1337, 6667, 9001)."
    severity = "medium"
    attack_tactic = "Command and Control"
    attack_technique = "T1071"
    attack_technique_name = "Application Layer Protocol"

    def evaluate(
        self,
        current_event: NormalizedEvent,
        recent_events: List[NormalizedEvent],
        parameters: Optional[Dict[str, Any]] = None,
    ) -> Optional[RuleMatch]:
        dst_port = current_event.destination_port
        high_risk_ports = {4444, 1337, 6667, 8888, 9001, 31337, 5555}

        if dst_port and dst_port in high_risk_ports and current_event.action in ["allow", "built", "success"]:
            supporting_ids = [current_event.id] if current_event.id else []
            return RuleMatch(
                rule_id=self.rule_id,
                rule_name=self.name,
                severity=self.severity,
                risk_score=70.0,
                title=f"Suspicious Outbound Connection to Port {dst_port}",
                description=f"Outbound connection from {current_event.source_ip or 'internal'} to {current_event.destination_ip}:{dst_port} matches known C2/reverse-shell port profile.",
                attack_tactic=self.attack_tactic,
                attack_technique=self.attack_technique,
                attack_technique_name=self.attack_technique_name,
                correlation_key=f"c2:{current_event.source_ip}:{current_event.destination_ip}",
                supporting_event_ids=supporting_ids,
                context_data={
                    "src_ip": current_event.source_ip,
                    "dst_ip": current_event.destination_ip,
                    "dst_port": dst_port,
                },
            )
        return None


class Rule008MaliciousDNSQuery(BaseRule):
    rule_id = "RULE-008"
    name = "DNS Query to Known Malicious Domain"
    description = "Detects resolution or communication with known command-and-control, phishing, or malware distribution domains."
    severity = "critical"
    attack_tactic = "Command and Control"
    attack_technique = "T1071.004"
    attack_technique_name = "DNS"

    def evaluate(
        self,
        current_event: NormalizedEvent,
        recent_events: List[NormalizedEvent],
        parameters: Optional[Dict[str, Any]] = None,
    ) -> Optional[RuleMatch]:
        fields = current_event.parsed_fields or {}
        query = (
            fields.get("query_name")
            or fields.get("extensions", {}).get("dhost")
            or fields.get("domain")
            or current_event.hostname
        )
        ioc_flag = fields.get("matched_ioc_type") == "domain" or "malicious-c2" in current_event.raw_message.lower()

        if ioc_flag:
            domain_name = query or "malicious-domain"
            supporting_ids = [current_event.id] if current_event.id else []
            return RuleMatch(
                rule_id=self.rule_id,
                rule_name=self.name,
                severity=self.severity,
                risk_score=95.0,
                title=f"Malicious Domain Query: {domain_name}",
                description=f"DNS resolution requested for active threat intelligence domain '{domain_name}'.",
                attack_tactic=self.attack_tactic,
                attack_technique=self.attack_technique,
                attack_technique_name=self.attack_technique_name,
                correlation_key=f"ioc_domain:{domain_name}",
                supporting_event_ids=supporting_ids,
                context_data={
                    "domain": domain_name,
                    "client_ip": current_event.source_ip,
                },
            )
        return None


class Rule009MalwareHashMatch(BaseRule):
    rule_id = "RULE-009"
    name = "Malware File Hash Indicator Match"
    description = "Detects execution, write, or download of a file whose hash matches an active malware indicator in the threat store."
    severity = "critical"
    attack_tactic = "Execution"
    attack_technique = "T1204"
    attack_technique_name = "User Execution"

    def evaluate(
        self,
        current_event: NormalizedEvent,
        recent_events: List[NormalizedEvent],
        parameters: Optional[Dict[str, Any]] = None,
    ) -> Optional[RuleMatch]:
        fields = current_event.parsed_fields or {}
        has_hash_match = (
            fields.get("matched_ioc_type") in ["sha256", "md5", "sha1"]
            or any(k in fields for k in ["file_hash", "sha256", "md5"])
            or "malware_hash" in current_event.raw_message.lower()
        )

        if has_hash_match:
            hash_val = fields.get("matched_ioc_value") or fields.get("sha256") or fields.get("file_hash") or "malware_indicator"
            supporting_ids = [current_event.id] if current_event.id else []
            return RuleMatch(
                rule_id=self.rule_id,
                rule_name=self.name,
                severity=self.severity,
                risk_score=98.0,
                title=f"Malware Indicator Detected (Hash: {str(hash_val)[:16]}...)",
                description=f"File activity matched known malicious payload hash {hash_val}.",
                attack_tactic=self.attack_tactic,
                attack_technique=self.attack_technique,
                attack_technique_name=self.attack_technique_name,
                correlation_key=f"malware:{hash_val}",
                supporting_event_ids=supporting_ids,
                context_data={
                    "hash": hash_val,
                    "host": current_event.hostname,
                    "user": current_event.username,
                },
            )
        return None


class Rule010CloudPrivilegeChange(BaseRule):
    rule_id = "RULE-010"
    name = "Cloud Audit Suspicious Privilege or Policy Change"
    description = "Detects critical IAM permission assignments or policy alterations in AWS CloudTrail or Azure Resource Manager."
    severity = "high"
    attack_tactic = "Privilege Escalation"
    attack_technique = "T1098.001"
    attack_technique_name = "Cloud Role/Policy Modification"

    def evaluate(
        self,
        current_event: NormalizedEvent,
        recent_events: List[NormalizedEvent],
        parameters: Optional[Dict[str, Any]] = None,
    ) -> Optional[RuleMatch]:
        fields = current_event.parsed_fields or {}
        event_name = str(fields.get("event_name", ""))
        op_name = str(fields.get("operation_name", ""))

        suspicious_cloud_ops = [
            "attachrolepolicy", "attachuserpolicy", "putuserpolicy", "createpolicyversion",
            "microsoft.authorization/roleassignments/write",
        ]

        if any(op in event_name.lower() or op in op_name.lower() for op in suspicious_cloud_ops):
            supporting_ids = [current_event.id] if current_event.id else []
            return RuleMatch(
                rule_id=self.rule_id,
                rule_name=self.name,
                severity=self.severity,
                risk_score=84.0,
                title=f"Suspicious Cloud IAM Change: {event_name or op_name}",
                description=f"Cloud caller {current_event.username or 'unknown'} altered role assignments or IAM policies.",
                attack_tactic=self.attack_tactic,
                attack_technique=self.attack_technique,
                attack_technique_name=self.attack_technique_name,
                correlation_key=f"cloud_iam:{current_event.username or current_event.source_ip}",
                supporting_event_ids=supporting_ids,
                context_data={
                    "operation": event_name or op_name,
                    "caller": current_event.username,
                    "caller_ip": current_event.source_ip,
                },
            )
        return None


class Rule011WebExploitProbing(BaseRule):
    rule_id = "RULE-011"
    name = "Web-Server Path Traversal or Exploit Probing"
    description = "Detects directory traversal attempts (../, ..\\), sensitive file reads (/etc/passwd, win.ini), or automated exploit scanners against web endpoints."
    severity = "high"
    attack_tactic = "Initial Access"
    attack_technique = "T1190"
    attack_technique_name = "Exploit Public-Facing Application"

    def evaluate(
        self,
        current_event: NormalizedEvent,
        recent_events: List[NormalizedEvent],
        parameters: Optional[Dict[str, Any]] = None,
    ) -> Optional[RuleMatch]:
        fields = current_event.parsed_fields or {}
        uri = str(fields.get("uri", "")).lower()
        raw = current_event.raw_message.lower()

        indicators = ["../", "..\\", "/etc/passwd", "win.ini", "select+", "union+select", "<script", "eval(", "/.env"]
        matched = [i for i in indicators if i in uri or i in raw]

        if matched or current_event.action == "exploit_probe":
            supporting_ids = [current_event.id] if current_event.id else []
            return RuleMatch(
                rule_id=self.rule_id,
                rule_name=self.name,
                severity=self.severity,
                risk_score=79.0,
                title=f"Web Exploit Probe Detected from {current_event.source_ip or 'unknown IP'}",
                description=f"Request contains signatures: {', '.join(matched) or 'Path Traversal / Exploit Probe'}",
                attack_tactic=self.attack_tactic,
                attack_technique=self.attack_technique,
                attack_technique_name=self.attack_technique_name,
                correlation_key=f"web_probe:{current_event.source_ip}",
                supporting_event_ids=supporting_ids,
                context_data={
                    "signatures": matched,
                    "src_ip": current_event.source_ip,
                    "uri": fields.get("uri"),
                },
            )
        return None


# Rule Registry Catalogue
ALL_RULES: List[BaseRule] = [
    Rule001BruteForce(),
    Rule002SuccessAfterBurst(),
    Rule003PrivilegeGroupChange(),
    Rule004UnusualServiceExecution(),
    Rule005SuspiciousPowerShell(),
    Rule006LateralMovement(),
    Rule007UnusualOutboundConnection(),
    Rule008MaliciousDNSQuery(),
    Rule009MalwareHashMatch(),
    Rule010CloudPrivilegeChange(),
    Rule011WebExploitProbing(),
]
