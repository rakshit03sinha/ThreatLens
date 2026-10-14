"""ThreatLens Detection Rule, Alert, and Evidence Models."""

from datetime import datetime, timezone
from typing import Optional, Dict, Any, List
from sqlalchemy import String, Integer, Float, DateTime, Text, JSON, ForeignKey, Boolean, Index
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.db.base import Base, TimestampMixin


class DetectionRule(Base, TimestampMixin):
    __tablename__ = "detection_rules"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    rule_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)  # e.g. "RULE-001"
    name: Mapped[str] = mapped_column(String(128), index=True)
    description: Mapped[str] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(32), default="medium", index=True)  # low, medium, high, critical
    status: Mapped[str] = mapped_column(String(32), default="enabled", index=True)  # enabled, disabled
    tactic: Mapped[str] = mapped_column(String(64), index=True)  # e.g. "Credential Access"
    technique_id: Mapped[str] = mapped_column(String(32), index=True)  # e.g. "T1110"
    technique_name: Mapped[str] = mapped_column(String(128))  # e.g. "Brute Force"
    window_seconds: Mapped[int] = mapped_column(Integer, default=300)
    threshold: Mapped[int] = mapped_column(Integer, default=5)
    version: Mapped[str] = mapped_column(String(16), default="1.0.0")
    parameters: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict)


class Alert(Base, TimestampMixin):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    alert_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)  # e.g. "ALT-20261014-XXXX"
    rule_id: Mapped[str] = mapped_column(String(64), index=True)
    rule_name: Mapped[str] = mapped_column(String(128))
    title: Mapped[str] = mapped_column(String(255))
    description: Mapped[str] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(32), index=True)  # low, medium, high, critical
    risk_score: Mapped[float] = mapped_column(Float, default=0.0, index=True)
    status: Mapped[str] = mapped_column(String(32), default="new", index=True)  # new, triaged, investigating, closed, false_positive
    
    # MITRE Alignment
    attack_tactic: Mapped[str] = mapped_column(String(64), index=True)
    attack_technique: Mapped[str] = mapped_column(String(32), index=True)
    attack_technique_name: Mapped[str] = mapped_column(String(128))

    # Correlation and Evidence
    correlation_key: Mapped[Optional[str]] = mapped_column(String(128), index=True, nullable=True)
    supporting_event_ids: Mapped[List[str]] = mapped_column(JSON, default=list)
    context_data: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict)
    
    # Disposition
    analyst_disposition: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    disposition_notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    assigned_to: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    evidence_items: Mapped[List["AlertEvidence"]] = relationship("AlertEvidence", back_populates="alert", cascade="all, delete-orphan")


class AlertEvidence(Base):
    __tablename__ = "alert_evidence"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    alert_id: Mapped[str] = mapped_column(String(64), ForeignKey("alerts.alert_id"), index=True)
    event_id: Mapped[str] = mapped_column(String(64), index=True)
    relationship_type: Mapped[str] = mapped_column(String(64), default="trigger")  # trigger, supporting, antecedent, correlation
    evidence_details: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))

    alert: Mapped[Alert] = relationship("Alert", back_populates="evidence_items")
