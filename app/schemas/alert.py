"""ThreatLens Alert and Evidence Schemas."""

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class AlertEvidenceResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    alert_id: str
    event_id: str
    relationship_type: str
    evidence_details: Dict[str, Any]
    created_at: datetime


class AlertResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    alert_id: str
    rule_id: str
    rule_name: str
    title: str
    description: str
    severity: str
    risk_score: float
    status: str
    attack_tactic: str
    attack_technique: str
    attack_technique_name: str
    correlation_key: Optional[str] = None
    supporting_event_ids: List[str]
    context_data: Dict[str, Any]
    analyst_disposition: Optional[str] = None
    disposition_notes: Optional[str] = None
    assigned_to: Optional[str] = None
    evidence_items: List[AlertEvidenceResponse] = []
    created_at: datetime
    updated_at: datetime


class AlertUpdateStatus(BaseModel):
    status: Optional[str] = Field(None, pattern="^(new|triaged|investigating|closed|false_positive)$")
    analyst_disposition: Optional[str] = Field(None, description="e.g. true_positive, false_positive, benign_true_positive")
    disposition_notes: Optional[str] = None
    assigned_to: Optional[str] = None


class AlertFilter(BaseModel):
    rule_id: Optional[str] = None
    severity: Optional[str] = None
    status: Optional[str] = None
    attack_tactic: Optional[str] = None
    attack_technique: Optional[str] = None
    search: Optional[str] = None
