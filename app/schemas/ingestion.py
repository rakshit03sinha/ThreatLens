"""ThreatLens Ingestion Job Schemas."""

from datetime import datetime
from typing import Any, Dict, Optional
from pydantic import BaseModel, ConfigDict


class IngestionJobResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    status: str
    source_format: Optional[str] = None
    total_records: int
    accepted_count: int
    rejected_count: int
    processed_count: int
    failed_count: int
    error_summary: Optional[Dict[str, Any]] = None
    created_at: datetime
    updated_at: datetime
