"""ThreatLens Campaign and Threat Scoring Schemas."""

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class CampaignAlertSummary(BaseModel):
    alert_id: str
    rule_id: str
    rule_name: str
    severity: str
    risk_score: float
    status: str
    created_at: datetime


class CampaignResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    campaign_id: str
    title: str
    description: str
    status: str
    risk_score: float
    primary_tactic: str
    primary_technique: str
    common_signals: Dict[str, Any]
    correlation_reason: str
    notes: Optional[str] = None
    alerts: List[CampaignAlertSummary] = []
    created_at: datetime
    updated_at: datetime


class CampaignUpdate(BaseModel):
    status: Optional[str] = Field(None, pattern="^(active|investigating|contained|resolved)$")
    notes: Optional[str] = None


class ThreatScoreBreakdown(BaseModel):
    severity_factor: float
    confidence_factor: float
    frequency_factor: float
    ioc_factor: float
    campaign_factor: float
    raw_score: float
    normalized_score: float  # clamped 0-100


class ThreatScoreResponse(BaseModel):
    entity_type: str
    entity_id: str
    total_score: float
    explanation: str
    breakdown: ThreatScoreBreakdown
    calculated_at: datetime


class ThreatScoreCalculateRequest(BaseModel):
    entity_type: str = Field(..., pattern="^(alert|campaign)$")
    entity_id: str
