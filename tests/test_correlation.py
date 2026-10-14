"""ThreatLens Alert and Campaign Correlation Test Suite."""

from datetime import datetime, timezone
import pytest
from app.models.rule import Alert
from app.models.campaign import Campaign, CampaignAlert
from app.services.correlation import correlation_service


@pytest.mark.asyncio
async def test_campaign_correlation_flow(db_session):
    now = datetime.now(timezone.utc)

    # 1. First alert creates campaign
    alert1 = Alert(
        alert_id="ALT-TEST-001",
        rule_id="RULE-001",
        rule_name="Brute-Force Pattern",
        title="Brute-force against admin",
        description="Multiple failed logons",
        severity="high",
        risk_score=75.0,
        status="new",
        attack_tactic="Credential Access",
        attack_technique="T1110",
        attack_technique_name="Brute Force",
        correlation_key="bruteforce:admin",
        supporting_event_ids=["e1", "e2"],
        context_data={"user": "admin", "source_ip": "198.51.100.5"},
    )
    db_session.add(alert1)
    await db_session.flush()

    camp1 = await correlation_service.correlate_alert(db_session, alert1)
    assert camp1 is not None
    assert camp1.campaign_id.startswith("CMP-")
    assert camp1.common_signals.get("correlation_key") == "bruteforce:admin"

    initial_score = camp1.risk_score

    # 2. Second alert with same correlation key joins campaign
    alert2 = Alert(
        alert_id="ALT-TEST-002",
        rule_id="RULE-002",
        rule_name="Successful Login After Burst",
        title="Admin compromised",
        description="Success after burst",
        severity="critical",
        risk_score=90.0,
        status="new",
        attack_tactic="Credential Access",
        attack_technique="T1110.001",
        attack_technique_name="Password Guessing",
        correlation_key="bruteforce:admin",
        supporting_event_ids=["e3"],
        context_data={"user": "admin", "source_ip": "198.51.100.5"},
    )
    db_session.add(alert2)
    await db_session.flush()

    camp2 = await correlation_service.correlate_alert(db_session, alert2)
    assert camp2.campaign_id == camp1.campaign_id
    assert camp2.risk_score > initial_score  # score bumped when multi-alert campaign
