"""ThreatLens Event Schemas."""

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class NormalizedEvent(BaseModel):
    id: Optional[str] = None
    event_fingerprint: Optional[str] = None
    source_format: str
    timestamp: datetime
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    hostname: Optional[str] = None
    username: Optional[str] = None
    action: Optional[str] = None
    severity: Optional[str] = "informational"
    event_type: Optional[str] = None
    raw_message: str
    parsed_fields: Dict[str, Any] = Field(default_factory=dict)
    ingestion_job_id: Optional[str] = None


class EventResponse(NormalizedEvent):
    model_config = ConfigDict(from_attributes=True)
    id: str
    created_at: datetime


class EventFilter(BaseModel):
    source_format: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    hostname: Optional[str] = None
    username: Optional[str] = None
    action: Optional[str] = None
    severity: Optional[str] = None
    event_type: Optional[str] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    search: Optional[str] = None


class EventIngestSingleRequest(BaseModel):
    format: Optional[str] = Field(
        default=None,
        description="Optional explicit log format hint (e.g., windows, syslog, cisco, paloalto, aws_cloudtrail, azure_activity, ndjson, cef, leef, apache, nginx). If omitted, format auto-detection is attempted.",
    )
    raw_log: str = Field(..., min_length=1, max_length=1000000, description="Raw log line or JSON string")


class EventIngestBatchRequest(BaseModel):
    format: Optional[str] = Field(default=None, description="Optional log format hint applied to the batch")
    events: List[str] = Field(..., min_length=1, max_length=2000, description="List of raw log records")
