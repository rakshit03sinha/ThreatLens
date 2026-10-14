"""ThreatLens Detection Rule Base Interface."""

from abc import ABC, abstractmethod
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
from app.schemas.event import NormalizedEvent


class RuleMatch(BaseModel):
    rule_id: str
    rule_name: str
    severity: str
    risk_score: float
    title: str
    description: str
    attack_tactic: str
    attack_technique: str
    attack_technique_name: str
    correlation_key: Optional[str] = None
    supporting_event_ids: List[str]
    context_data: Dict[str, Any] = Field(default_factory=dict)


class BaseRule(ABC):
    """Abstract base class for MITRE ATT&CK aligned deterministic detection rules."""

    rule_id: str
    name: str
    description: str
    severity: str  # low, medium, high, critical
    attack_tactic: str
    attack_technique: str
    attack_technique_name: str
    default_window_seconds: int = 300
    default_threshold: int = 5
    version: str = "1.0.0"

    @abstractmethod
    def evaluate(
        self,
        current_event: NormalizedEvent,
        recent_events: List[NormalizedEvent],
        parameters: Optional[Dict[str, Any]] = None,
    ) -> Optional[RuleMatch]:
        """Evaluate the rule against current_event and historical context."""
        pass
