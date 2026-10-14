"""ThreatLens Explainable Threat Scoring Engine."""

from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple
from app.schemas.campaign import ThreatScoreBreakdown

SEVERITY_WEIGHTS = {
    "critical": 40.0,
    "high": 30.0,
    "medium": 20.0,
    "low": 10.0,
    "informational": 5.0,
}


class ThreatScoringEngine:
    """Calculates explainable risk scores normalized between 0 and 100 with factor contributions."""

    def __init__(
        self,
        weight_severity: float = 0.35,
        weight_confidence: float = 0.20,
        weight_frequency: float = 0.15,
        weight_ioc: float = 0.20,
        weight_campaign: float = 0.10,
    ):
        self.w_sev = weight_severity
        self.w_conf = weight_confidence
        self.w_freq = weight_frequency
        self.w_ioc = weight_ioc
        self.w_camp = weight_campaign

    def calculate_alert_score(
        self,
        severity: str,
        confidence: float = 80.0,
        event_count: int = 1,
        has_ioc_match: bool = False,
        ioc_confidence: float = 0.0,
        in_campaign: bool = False,
        campaign_size: int = 1,
    ) -> Tuple[float, ThreatScoreBreakdown, str]:
        # 1. Severity contribution (0-100 scale * weight)
        sev_base = SEVERITY_WEIGHTS.get(severity.lower(), 15.0)
        # Scale base (0-40) to 0-100
        sev_normalized = min(100.0, (sev_base / 40.0) * 100.0)
        c_sev = sev_normalized * self.w_sev

        # 2. Confidence contribution
        conf_clamped = max(0.0, min(100.0, confidence))
        c_conf = conf_clamped * self.w_conf

        # 3. Frequency contribution (logarithmic/stepped scale)
        if event_count <= 1:
            freq_score = 20.0
        elif event_count <= 5:
            freq_score = 50.0
        elif event_count <= 20:
            freq_score = 80.0
        else:
            freq_score = 100.0
        c_freq = freq_score * self.w_freq

        # 4. IOC contribution
        if has_ioc_match:
            ioc_score = max(50.0, min(100.0, ioc_confidence if ioc_confidence > 0 else 85.0))
        else:
            ioc_score = 0.0
        c_ioc = ioc_score * self.w_ioc

        # 5. Campaign breadth contribution
        if in_campaign:
            camp_score = min(100.0, 40.0 + (campaign_size * 15.0))
        else:
            camp_score = 0.0
        c_camp = camp_score * self.w_camp

        raw_total = c_sev + c_conf + c_freq + c_ioc + c_camp
        final_score = round(max(0.0, min(100.0, raw_total)), 1)

        breakdown = ThreatScoreBreakdown(
            severity_factor=round(c_sev, 1),
            confidence_factor=round(c_conf, 1),
            frequency_factor=round(c_freq, 1),
            ioc_factor=round(c_ioc, 1),
            campaign_factor=round(c_camp, 1),
            raw_score=round(raw_total, 1),
            normalized_score=final_score,
        )

        reasons = [
            f"Base rule severity '{severity.upper()}' contributed {breakdown.severity_factor} pts",
            f"Analytic confidence ({confidence}%) added {breakdown.confidence_factor} pts",
            f"Event frequency ({event_count} telemetry occurrences) added {breakdown.frequency_factor} pts",
        ]
        if has_ioc_match:
            reasons.append(f"Confirmed Threat Intel IOC indicator match added {breakdown.ioc_factor} pts")
        if in_campaign:
            reasons.append(f"Multi-alert campaign correlation ({campaign_size} linked alerts) added {breakdown.campaign_factor} pts")

        explanation = "; ".join(reasons) + f". Final explainable threat score: {final_score}/100."
        return final_score, breakdown, explanation


scoring_engine = ThreatScoringEngine()
