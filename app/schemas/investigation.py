"""ThreatLens Investigation, Playbook, and Audit Schemas."""

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class InvestigationRequest(BaseModel):
    alert_id: Optional[str] = Field(None, description="Optional target alert ID")
    campaign_id: Optional[str] = Field(None, description="Optional target campaign ID")
    question: str = Field(..., min_length=3, max_length=1000, description="Analyst question or inquiry")


class InvestigationResponse(BaseModel):
    inquiry_id: str
    alert_id: Optional[str] = None
    campaign_id: Optional[str] = None
    question: str
    summary: str
    facts: List[str]
    hypotheses: List[str]
    missing_evidence: List[str]
    recommended_defensive_actions: List[str]
    citations: List[str]
    model_used: str
    is_fallback: bool
    created_at: datetime


class PlaybookResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    playbook_id: str
    title: str
    category: str
    attack_technique: str
    description: str
    triage_steps: List[str]
    containment_steps: List[str]
    remediation_steps: List[str]
    created_at: datetime


class PlaybookSearchRequest(BaseModel):
    query: Optional[str] = None
    technique: Optional[str] = None
    category: Optional[str] = None


class AuditLogResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    user_id: Optional[int] = None
    username: str
    action: str
    resource_type: str
    resource_id: Optional[str] = None
    details: Dict[str, Any]
    ip_address: Optional[str] = None
    created_at: datetime


class DashboardMetricsResponse(BaseModel):
    total_events: int
    total_alerts: int
    critical_alerts: int
    high_alerts: int
    active_campaigns: int
    ioc_matches: int
    ingestion_jobs_failed: int
    ai_status: str
