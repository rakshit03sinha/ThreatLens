"""ThreatLens IOC Schemas."""

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class IOCCreate(BaseModel):
    indicator_value: str = Field(..., min_length=1, max_length=255)
    indicator_type: str = Field(..., pattern="^(ipv4|ipv6|domain|url|sha256|md5|sha1)$")
    severity: str = Field(default="medium", pattern="^(low|medium|high|critical)$")
    confidence: int = Field(default=80, ge=0, le=100)
    source: str = Field(default="ThreatLens ThreatIntel")
    description: Optional[str] = None
    tags: List[str] = Field(default_factory=list)


class IOCResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    indicator_value: str
    indicator_type: str
    severity: str
    confidence: int
    source: str
    description: Optional[str] = None
    tags: List[str]
    first_seen: datetime
    last_seen: datetime
    created_at: datetime


class IOCMatchResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    ioc_id: int
    event_id: str
    alert_id: Optional[str] = None
    matched_field: str
    matched_value: str
    match_context: Dict[str, Any]
    created_at: datetime
    ioc: Optional[IOCResponse] = None


class IOCSearchRequest(BaseModel):
    value: Optional[str] = None
    indicator_type: Optional[str] = None
    severity: Optional[str] = None
    min_confidence: Optional[int] = None
