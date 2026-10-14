"""ThreatLens IOC Intelligence Test Suite."""

import pytest
from app.services.ioc import is_private_ip, normalize_indicator, ioc_service
from app.schemas.event import NormalizedEvent
from datetime import datetime, timezone


def test_private_ip_detection():
    assert is_private_ip("192.168.1.1") is True
    assert is_private_ip("10.0.0.5") is True
    assert is_private_ip("172.16.0.1") is True
    assert is_private_ip("127.0.0.1") is True
    # Public IPs
    assert is_private_ip("198.51.100.5") is False
    assert is_private_ip("8.8.8.8") is False
    assert is_private_ip("203.0.113.10") is False


def test_indicator_normalization():
    assert normalize_indicator("HTTP://Evil-Domain.com:8080/path", "domain") == "evil-domain.com"
    assert normalize_indicator("https://phishing.site/login", "domain") == "phishing.site"
    assert normalize_indicator("AABBCC11223344", "sha256") == "aabbcc11223344"


@pytest.mark.asyncio
async def test_ioc_matching_flow(db_session):
    # 1. Add an active IOC to store
    ioc = await ioc_service.add_or_update_ioc(
        session=db_session,
        indicator_value="198.51.100.55",
        indicator_type="ipv4",
        severity="critical",
        confidence=95,
        source="ThreatFeed Alpha",
    )
    assert ioc.id is not None

    # 2. Match event containing the IP
    ev = NormalizedEvent(
        source_format="syslog",
        timestamp=datetime.now(timezone.utc),
        source_ip="198.51.100.55",
        action="deny",
        raw_message="Firewall blocked traffic from 198.51.100.55",
    )
    matches = await ioc_service.match_event(db_session, ev, "evt-ioc-test")
    assert len(matches) == 1
    assert matches[0].matched_value == "198.51.100.55"
    assert ev.parsed_fields["matched_ioc_type"] == "ipv4"


@pytest.mark.asyncio
async def test_ioc_sha256_extraction(db_session):
    sha = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    await ioc_service.add_or_update_ioc(
        session=db_session,
        indicator_value=sha,
        indicator_type="sha256",
        severity="critical",
    )

    ev = NormalizedEvent(
        source_format="ndjson",
        timestamp=datetime.now(timezone.utc),
        action="write",
        raw_message=f"Process created evil.bin with sha256={sha}",
    )
    matches = await ioc_service.match_event(db_session, ev, "evt-hash-test")
    assert len(matches) == 1
    assert matches[0].matched_value == sha

