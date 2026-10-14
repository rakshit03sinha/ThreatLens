"""ThreatLens Campaign and Threat Scoring Models."""

from datetime import datetime, timezone
from typing import Optional, Dict, Any, List
from sqlalchemy import String, Integer, Float, DateTime, Text, JSON, ForeignKey, Table, Column
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.db.base import Base, TimestampMixin


class CampaignAlert(Base):
    __tablename__ = "campaign_alerts"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    campaign_id: Mapped[str] = mapped_column(String(64), ForeignKey("campaigns.campaign_id"), index=True)
    alert_id: Mapped[str] = mapped_column(String(64), ForeignKey("alerts.alert_id"), index=True)
    added_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))

    campaign: Mapped["Campaign"] = relationship("Campaign", back_populates="alert_associations")


class Campaign(Base, TimestampMixin):
    __tablename__ = "campaigns"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    campaign_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)  # e.g. "CMP-20261014-001"
    title: Mapped[str] = mapped_column(String(255))
    description: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(32), default="active", index=True)  # active, investigating, contained, resolved
    risk_score: Mapped[float] = mapped_column(Float, default=0.0, index=True)
    primary_tactic: Mapped[str] = mapped_column(String(64), default="Initial Access")
    primary_technique: Mapped[str] = mapped_column(String(64), default="Multiple")
    common_signals: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict)
    correlation_reason: Mapped[str] = mapped_column(Text)
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    alert_associations: Mapped[List[CampaignAlert]] = relationship("CampaignAlert", back_populates="campaign", cascade="all, delete-orphan")


class ThreatScore(Base):
    __tablename__ = "threat_scores"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    entity_type: Mapped[str] = mapped_column(String(32), index=True)  # alert, campaign
    entity_id: Mapped[str] = mapped_column(String(64), index=True)
    total_score: Mapped[float] = mapped_column(Float, index=True)
    severity_factor: Mapped[float] = mapped_column(Float, default=0.0)
    confidence_factor: Mapped[float] = mapped_column(Float, default=0.0)
    frequency_factor: Mapped[float] = mapped_column(Float, default=0.0)
    ioc_factor: Mapped[float] = mapped_column(Float, default=0.0)
    campaign_factor: Mapped[float] = mapped_column(Float, default=0.0)
    explanation: Mapped[str] = mapped_column(Text)
    factor_breakdown: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict)
    calculated_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
