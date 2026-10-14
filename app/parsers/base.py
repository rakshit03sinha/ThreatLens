"""ThreatLens Base Parser Interface and Result Types."""

from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
from app.schemas.event import NormalizedEvent
from app.utils.redact import redact_sensitive_text, redact_sensitive_dict


class ParseDiagnostic(BaseModel):
    level: str = "warning"  # warning, error, info
    message: str
    field: Optional[str] = None


class ParseResult(BaseModel):
    success: bool
    event: Optional[NormalizedEvent] = None
    diagnostics: List[ParseDiagnostic] = Field(default_factory=list)
    raw_preview: Optional[str] = None


class BaseParser(ABC):
    """Abstract base class for all 12 log parsers."""

    format_id: str
    format_name: str
    description: str

    @abstractmethod
    def can_parse(self, raw_log: str) -> bool:
        """Heuristic check to determine if this parser can handle the raw log."""
        pass

    @abstractmethod
    def parse(self, raw_log: str) -> ParseResult:
        """Parse raw log string into a NormalizedEvent."""
        pass

    def sanitize(self, raw_log: str) -> str:
        """Apply redaction to raw log string."""
        return redact_sensitive_text(raw_log)
