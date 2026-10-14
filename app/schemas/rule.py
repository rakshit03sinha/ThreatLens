"""ThreatLens Detection Rule Schemas."""

from datetime import datetime
from typing import Any, Dict, Optional
from pydantic import BaseModel, ConfigDict, Field


class DetectionRuleResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    rule_id: str
    name: str
    description: str
    severity: str
    status: str
    tactic: str
    technique_id: str
    technique_name: str
    window_seconds: int
    threshold: int
    version: str
    parameters: Dict[str, Any]
    created_at: datetime
    updated_at: datetime


class RuleToggleRequest(BaseModel):
    status: str = Field(..., pattern="^(enabled|disabled)$", description="'enabled' or 'disabled'")
