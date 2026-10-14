"""ThreatLens Explainable Threat Scoring Engine Test Suite."""

import pytest
from app.services.scoring import scoring_engine, ThreatScoringEngine


def test_scoring_bounds():
    # Test extreme upper bound
    score_high, breakdown_high, expl_high = scoring_engine.calculate_alert_score(
        severity="critical",
        confidence=100.0,
        event_count=50,
        has_ioc_match=True,
        ioc_confidence=100.0,
        in_campaign=True,
        campaign_size=10,
    )
    assert 0.0 <= score_high <= 100.0
    assert score_high >= 90.0

    # Test extreme lower bound
    score_low, breakdown_low, expl_low = scoring_engine.calculate_alert_score(
        severity="informational",
        confidence=0.0,
        event_count=1,
        has_ioc_match=False,
        in_campaign=False,
    )
    assert 0.0 <= score_low <= 100.0
    assert score_low <= 25.0


def test_scoring_factor_contributions():
    score, b, expl = scoring_engine.calculate_alert_score(
        severity="high",
        confidence=80.0,
        event_count=5,
        has_ioc_match=True,
        ioc_confidence=90.0,
    )
    # Check that each factor is non-negative and properly recorded
    assert b.severity_factor > 0
    assert b.confidence_factor > 0
    assert b.frequency_factor > 0
    assert b.ioc_factor > 0
    assert b.campaign_factor == 0.0  # not in campaign
    assert b.normalized_score == score

    # Check explanation contains factor breakdowns
    assert "Base rule severity 'HIGH'" in expl
    assert "Analytic confidence (80.0%)" in expl
    assert "Confirmed Threat Intel IOC indicator match" in expl
    assert f"Final explainable threat score: {score}/100" in expl


def test_custom_weights_configuration():
    custom_engine = ThreatScoringEngine(
        weight_severity=0.50,
        weight_confidence=0.10,
        weight_frequency=0.10,
        weight_ioc=0.20,
        weight_campaign=0.10,
    )
    score, b, expl = custom_engine.calculate_alert_score(
        severity="critical",
        confidence=80.0,
    )
    assert b.severity_factor == 50.0  # 100% of critical * 0.50 weight

