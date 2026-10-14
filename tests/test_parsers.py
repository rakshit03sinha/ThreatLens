"""ThreatLens Comprehensive Parser Test Suite covering all 12 formats."""

import pytest
from app.parsers.registry import parser_registry


# 1. Windows Event Log
def test_windows_parser():
    raw = '{"Event":{"System":{"EventID":4625,"TimeCreated":{"SystemTime":"2026-10-14T21:00:00Z"},"Computer":"DC01.corp.internal"},"EventData":{"TargetUserName":"admin","IpAddress":"198.51.100.5","IpPort":"54321","Status":"0xC000006D"}}}'
    res = parser_registry.parse_log(raw, format_hint="windows")
    assert res.success is True
    ev = res.event
    assert ev.source_format == "windows"
    assert ev.username == "admin"
    assert ev.source_ip == "198.51.100.5"
    assert ev.source_port == 54321
    assert ev.hostname == "DC01.corp.internal"
    assert ev.action == "failure"
    assert ev.severity == "medium"
    assert "Failed Logon" in ev.event_type


# 2. Linux System/Auth Log
def test_linux_auth_parser():
    raw = "Oct 14 21:00:00 srv01 sshd[12345]: Failed password for invalid user root from 192.168.1.50 port 54321 ssh2"
    res = parser_registry.parse_log(raw, format_hint="linux")
    assert res.success is True
    ev = res.event
    assert ev.source_format == "linux"
    assert ev.username == "root"
    assert ev.source_ip == "192.168.1.50"
    assert ev.source_port == 54321
    assert ev.hostname == "srv01"
    assert ev.action == "failure"
    assert ev.severity == "medium"


# 3. Generic Syslog (RFC 5424 & RFC 3164)
def test_generic_syslog_rfc5424():
    raw = "<165>1 2026-10-14T22:14:15.003Z myhost.example.com evtsys - ID47 [exampleSDID@32473] Connection dropped from 198.51.100.1 to 10.0.0.1"
    res = parser_registry.parse_log(raw, format_hint="syslog")
    assert res.success is True
    ev = res.event
    assert ev.source_format == "syslog"
    assert ev.hostname == "myhost.example.com"
    assert ev.source_ip == "198.51.100.1"
    assert ev.destination_ip == "10.0.0.1"
    assert ev.action == "deny"


def test_generic_syslog_rfc3164():
    raw = "<34>Oct 14 21:00:00 border-router myapp[123]: packet dropped from 198.51.100.5 to 10.0.0.1"
    res = parser_registry.parse_log(raw, format_hint="syslog")
    assert res.success is True
    assert res.event.hostname == "border-router"
    assert res.event.source_ip == "198.51.100.5"


# 4. Cisco Device Log
def test_cisco_device_parser():
    raw = "%ASA-4-106023: Deny tcp src outside:203.0.113.10/54321 dst inside:10.0.0.5/80 by access-group outside_access"
    res = parser_registry.parse_log(raw, format_hint="cisco")
    assert res.success is True
    ev = res.event
    assert ev.source_format == "cisco"
    assert ev.source_ip == "203.0.113.10"
    assert ev.destination_ip == "10.0.0.5"
    assert ev.source_port == 54321
    assert ev.destination_port == 80
    assert ev.action == "deny"
    assert ev.severity == "medium"


# 5. Palo Alto Firewall Log
def test_paloalto_parser():
    raw = "1,2026/10/14 21:00:00,001801000001,TRAFFIC,drop,1,2026/10/14 21:00:00,192.168.1.10,203.0.113.15,192.168.1.10,203.0.113.15,rule_block_malicious,admin,,ssl,vsys1,trust,untrust,ethernet1/1,ethernet1/2,default,1,123456,1,54321,443,54321,443,0x0,tcp,deny,100,0,100,1,2026/10/14 21:00:00,0,any,0,1234,0x0,192.168.0.0,US,0,1,0"
    res = parser_registry.parse_log(raw, format_hint="paloalto")
    assert res.success is True
    ev = res.event
    assert ev.source_format == "paloalto"
    assert ev.source_ip == "192.168.1.10"
    assert ev.destination_ip == "203.0.113.15"
    assert ev.source_port == 54321
    assert ev.destination_port == 443
    assert ev.username == "admin"
    assert ev.action == "deny"


# 6. AWS CloudTrail JSON
def test_aws_cloudtrail_parser():
    raw = '{"eventVersion":"1.08","userIdentity":{"type":"IAMUser","userName":"attacker_user"},"eventTime":"2026-10-14T21:00:00Z","eventSource":"iam.amazonaws.com","eventName":"AttachRolePolicy","awsRegion":"us-east-1","sourceIPAddress":"198.51.100.5","requestParameters":{"roleName":"AdminRole"}}'
    res = parser_registry.parse_log(raw, format_hint="aws_cloudtrail")
    assert res.success is True
    ev = res.event
    assert ev.source_format == "aws_cloudtrail"
    assert ev.username == "attacker_user"
    assert ev.source_ip == "198.51.100.5"
    assert ev.action == "success"
    assert ev.severity == "high"
    assert "AttachRolePolicy" in ev.event_type


# 7. Azure Activity Log
def test_azure_activity_parser():
    raw = '{"time":"2026-10-14T21:00:00Z","resourceId":"/subscriptions/sub1/resourceGroups/rg1","operationName":{"value":"Microsoft.Authorization/roleAssignments/write"},"category":{"value":"Administrative"},"resultType":"Success","caller":"admin@corp.onmicrosoft.com","callerIpAddress":"198.51.100.5"}'
    res = parser_registry.parse_log(raw, format_hint="azure_activity")
    assert res.success is True
    ev = res.event
    assert ev.source_format == "azure_activity"
    assert ev.username == "admin@corp.onmicrosoft.com"
    assert ev.source_ip == "198.51.100.5"
    assert ev.severity == "high"


# 8. NDJSON / JSON Lines
def test_ndjson_parser():
    raw = '{"timestamp":"2026-10-14T21:00:00Z","src_ip":"10.0.0.15","dst_ip":"198.51.100.5","src_port":54321,"dst_port":4444,"user":"victim","host":"workstation01","action":"allow","severity":"warning","event":"Outbound Reverse Shell"}'
    res = parser_registry.parse_log(raw, format_hint="ndjson")
    assert res.success is True
    ev = res.event
    assert ev.source_format == "ndjson"
    assert ev.source_ip == "10.0.0.15"
    assert ev.destination_ip == "198.51.100.5"
    assert ev.source_port == 54321
    assert ev.destination_port == 4444
    assert ev.username == "victim"
    assert ev.hostname == "workstation01"


# 9. CEF (Common Event Format)
def test_cef_parser():
    raw = "CEF:0|SecurityCorp|ThreatSensor|1.0|100|Malicious Domain Query|8|src=10.0.0.15 dst=1.1.1.1 spt=54321 dpt=53 dhost=malicious-c2.example.com suser=alice act=blocked msg=DNS query blocked"
    res = parser_registry.parse_log(raw, format_hint="cef")
    assert res.success is True
    ev = res.event
    assert ev.source_format == "cef"
    assert ev.source_ip == "10.0.0.15"
    assert ev.destination_ip == "1.1.1.1"
    assert ev.source_port == 54321
    assert ev.destination_port == 53
    assert ev.hostname == "malicious-c2.example.com"
    assert ev.username == "alice"
    assert ev.action == "blocked"
    assert ev.severity == "high"


# 10. LEEF (Log Event Extended Format)
def test_leef_parser():
    raw = "LEEF:1.0|IBM|QRadar|7.3.0|LoginFailed|devTime=2026-10-14T21:00:00Z\tsrc=192.168.1.55\tdst=10.0.0.1\tspt=45678\tdpt=22\tusrName=root"
    res = parser_registry.parse_log(raw, format_hint="leef")
    assert res.success is True
    ev = res.event
    assert ev.source_format == "leef"
    assert ev.source_ip == "192.168.1.55"
    assert ev.destination_ip == "10.0.0.1"
    assert ev.source_port == 45678
    assert ev.destination_port == 22
    assert ev.username == "root"
    assert ev.action == "failure"


# 11. Apache HTTP Access Log
def test_apache_access_parser():
    raw = '198.51.100.5 - frank [14/Oct/2026:21:00:00 +0000] "GET /admin/../../etc/passwd HTTP/1.1" 404 153 "http://example.com" "Mozilla/5.0"'
    res = parser_registry.parse_log(raw, format_hint="apache")
    assert res.success is True
    ev = res.event
    assert ev.source_format == "apache"
    assert ev.source_ip == "198.51.100.5"
    assert ev.username == "frank"
    assert ev.action == "exploit_probe"
    assert ev.severity == "high"


# 12. Nginx Access Log
def test_nginx_access_parser():
    raw = '192.168.1.100 - - [14/Oct/2026:21:00:00 +0000] "POST /api/v1/auth/login HTTP/1.1" 200 45 "-" "curl/7.68.0"'
    res = parser_registry.parse_log(raw, format_hint="nginx")
    assert res.success is True
    ev = res.event
    assert ev.source_format == "nginx"
    assert ev.source_ip == "192.168.1.100"
    assert ev.action == "allow"
    assert ev.severity == "informational"


# Auto-detection and diagnostics
def test_parser_auto_detection():
    raw = "Oct 14 21:00:00 auth-server sshd[12345]: Failed password for invalid user admin from 198.51.100.5 port 54321 ssh2"
    res = parser_registry.parse_log(raw)
    assert res.success is True
    assert res.event.source_format == "linux"


def test_parser_invalid_log_diagnostics():
    raw = "This is a random non-log line that should not match any parser"
    res = parser_registry.parse_log(raw)
    assert res.success is False
    assert len(res.diagnostics) > 0
    assert "Could not auto-detect format" in res.diagnostics[0].message
