"""ThreatLens Detection Rules Test Suite covering all 11 detection scenarios."""

from datetime import datetime, timedelta, timezone
import pytest
from app.rules.catalogue import (
    Rule001BruteForce,
    Rule002SuccessAfterBurst,
    Rule003PrivilegeGroupChange,
    Rule004UnusualServiceExecution,
    Rule005SuspiciousPowerShell,
    Rule006LateralMovement,
    Rule007UnusualOutboundConnection,
    Rule008MaliciousDNSQuery,
    Rule009MalwareHashMatch,
    Rule010CloudPrivilegeChange,
    Rule011WebExploitProbing,
)
from app.schemas.event import NormalizedEvent


def make_event(
    event_id: str = "evt-1",
    action: str = "informational",
    user: str = "alice",
    src_ip: str = "192.168.1.10",
    dst_ip: str = "10.0.0.1",
    dst_port: int = 80,
    raw: str = "sample log",
    ts: datetime = None,
    fields: dict = None,
) -> NormalizedEvent:
    return NormalizedEvent(
        id=event_id,
        source_format="test",
        timestamp=ts or datetime.now(timezone.utc),
        source_ip=src_ip,
        destination_ip=dst_ip,
        source_port=54321,
        destination_port=dst_port,
        hostname="srv-host",
        username=user,
        action=action,
        raw_message=raw,
        parsed_fields=fields or {},
    )


# 1. RULE-001: Brute Force
def test_rule_001_brute_force():
    rule = Rule001BruteForce()
    now = datetime.now(timezone.utc)
    # 4 prior failures
    recent = [
        make_event(f"e-{i}", action="failure", user="target_user", ts=now - timedelta(seconds=i * 20))
        for i in range(1, 5)
    ]
    # 5th failure
    curr = make_event("e-5", action="failure", user="target_user", ts=now)
    match = rule.evaluate(curr, recent)
    assert match is not None
    assert match.rule_id == "RULE-001"
    assert match.attack_technique == "T1110"

    # Negative case: below threshold (only 2 failures)
    curr_low = make_event("e-low", action="failure", user="target_user", ts=now)
    match_low = rule.evaluate(curr_low, recent[:1])
    assert match_low is None


# 2. RULE-002: Success After Burst
def test_rule_002_success_after_burst():
    rule = Rule002SuccessAfterBurst()
    now = datetime.now(timezone.utc)
    recent = [
        make_event(f"e-{i}", action="failure", user="admin", ts=now - timedelta(seconds=i * 30))
        for i in range(1, 4)
    ]
    curr = make_event("e-succ", action="success", user="admin", ts=now)
    match = rule.evaluate(curr, recent)
    assert match is not None
    assert match.rule_id == "RULE-002"
    assert match.attack_technique == "T1110.001"

    # Negative case: successful login without prior failures
    match_clean = rule.evaluate(curr, [])
    assert match_clean is None


# 3. RULE-003: Privileged Group Change
def test_rule_003_privilege_group_change():
    rule = Rule003PrivilegeGroupChange()
    curr = make_event(
        "e-group",
        action="group_change",
        user="analyst",
        raw="A member was added to security-enabled global group: Domain Admins",
        fields={"event_id": "4728", "TargetUserName": "Domain Admins"},
    )
    match = rule.evaluate(curr, [])
    assert match is not None
    assert match.rule_id == "RULE-003"
    assert match.attack_technique == "T1098"

    # Negative case: regular standard event
    curr_neg = make_event("e-neg", action="audit", raw="Service restarted normally")
    assert rule.evaluate(curr_neg, []) is None


# 4. RULE-004: Unusual Service Execution
def test_rule_004_unusual_service_execution():
    rule = Rule004UnusualServiceExecution()
    curr = make_event(
        "e-svc",
        action="service_install",
        raw="A service was installed in the system: psexesvc.exe",
        fields={"event_id": "7045", "service_name": "psexesvc"},
    )
    match = rule.evaluate(curr, [])
    assert match is not None
    assert match.rule_id == "RULE-004"
    assert match.attack_technique == "T1543.003"


# 5. RULE-005: Suspicious PowerShell
def test_rule_005_suspicious_powershell():
    rule = Rule005SuspiciousPowerShell()
    curr = make_event(
        "e-ps",
        action="informational",
        raw="powershell.exe -ExecutionPolicy Bypass -w hidden -enc JABzACAAPQAgAE4AZQB3AC0ATwBiAGoAZQBjAHQA...",
        fields={"command_line": "-ExecutionPolicy Bypass -w hidden -enc JABzACAAPQAgAE4AZQB3AC0ATwBiAGoAZQBjAHQA..."},
    )
    match = rule.evaluate(curr, [])
    assert match is not None
    assert match.rule_id == "RULE-005"
    assert match.attack_technique == "T1059.001"


# 6. RULE-006: Lateral Movement
def test_rule_006_lateral_movement():
    rule = Rule006LateralMovement()
    curr = make_event(
        "e-lat",
        action="allow",
        user="compromised_user",
        raw="Connection established to network share \\\\10.0.0.5\\ADMIN$",
        fields={"share_name": "ADMIN$"},
    )
    match = rule.evaluate(curr, [])
    assert match is not None
    assert match.rule_id == "RULE-006"
    assert match.attack_technique == "T1021"


# 7. RULE-007: Unusual Outbound Connection
def test_rule_007_unusual_outbound_connection():
    rule = Rule007UnusualOutboundConnection()
    curr = make_event("e-c2", action="allow", dst_ip="198.51.100.5", dst_port=4444)
    match = rule.evaluate(curr, [])
    assert match is not None
    assert match.rule_id == "RULE-007"
    assert match.attack_technique == "T1071"

    # Negative case: standard port 443
    curr_normal = make_event("e-norm", action="allow", dst_port=443)
    assert rule.evaluate(curr_normal, []) is None


# 8. RULE-008: Malicious DNS Query
def test_rule_008_malicious_dns_query():
    rule = Rule008MaliciousDNSQuery()
    curr = make_event(
        "e-dns",
        raw="DNS Query for malicious-c2.evilcorp.xyz",
        fields={"matched_ioc_type": "domain", "query_name": "malicious-c2.evilcorp.xyz"},
    )
    match = rule.evaluate(curr, [])
    assert match is not None
    assert match.rule_id == "RULE-008"
    assert match.attack_technique == "T1071.004"


# 9. RULE-009: Malware Hash Match
def test_rule_009_malware_hash_match():
    rule = Rule009MalwareHashMatch()
    curr = make_event(
        "e-hash",
        raw="File downloaded: evil.exe sha256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        fields={"matched_ioc_type": "sha256", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
    )
    match = rule.evaluate(curr, [])
    assert match is not None
    assert match.rule_id == "RULE-009"
    assert match.attack_technique == "T1204"


# 10. RULE-010: Cloud Privilege Change
def test_rule_010_cloud_privilege_change():
    rule = Rule010CloudPrivilegeChange()
    curr = make_event(
        "e-cloud",
        raw="AWS IAM AttachRolePolicy invoked by alice",
        fields={"event_name": "AttachRolePolicy"},
    )
    match = rule.evaluate(curr, [])
    assert match is not None
    assert match.rule_id == "RULE-010"
    assert match.attack_technique == "T1098.001"


# 11. RULE-011: Web Exploit Probing
def test_rule_011_web_exploit_probing():
    rule = Rule011WebExploitProbing()
    curr = make_event(
        "e-web",
        raw="GET /admin/../../etc/passwd HTTP/1.1",
        fields={"uri": "/admin/../../etc/passwd"},
    )
    match = rule.evaluate(curr, [])
    assert match is not None
    assert match.rule_id == "RULE-011"
    assert match.attack_technique == "T1190"

    # Negative case: benign web request
    curr_benign = make_event("e-benign", raw="GET /index.html HTTP/1.1", fields={"uri": "/index.html"})
    assert rule.evaluate(curr_benign, []) is None
