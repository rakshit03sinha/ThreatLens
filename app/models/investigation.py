"""ThreatLens Investigation, Playbook, and Audit Log Models."""

from datetime import datetime, timezone
from typing import Optional, Dict, Any, List
from sqlalchemy import String, Integer, DateTime, Text, JSON, ForeignKey, Index
from sqlalchemy.orm import Mapped, mapped_column
from app.db.base import Base, TimestampMixin


class Investigation(Base):
    __tablename__ = "investigations"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    inquiry_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    alert_id: Mapped[Optional[str]] = mapped_column(String(64), index=True, nullable=True)
    campaign_id: Mapped[Optional[str]] = mapped_column(String(64), index=True, nullable=True)
    user_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    question: Mapped[str] = mapped_column(Text)
    answer: Mapped[str] = mapped_column(Text)
    retrieved_evidence: Mapped[List[Dict[str, Any]]] = mapped_column(JSON, default=list)
    citations: Mapped[List[str]] = mapped_column(JSON, default=list)
    model_used: Mapped[str] = mapped_column(String(64), default="deterministic-fallback")
    is_fallback: Mapped[bool] = mapped_column(default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)


class Playbook(Base, TimestampMixin):
    __tablename__ = "playbooks"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    playbook_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)  # PB-BRUTE-FORCE
    title: Mapped[str] = mapped_column(String(128))
    category: Mapped[str] = mapped_column(String(64), index=True)  # Credential Access, Lateral Movement, etc.
    attack_technique: Mapped[str] = mapped_column(String(32), index=True)  # T1110
    description: Mapped[str] = mapped_column(Text)
    triage_steps: Mapped[List[str]] = mapped_column(JSON, default=list)
    containment_steps: Mapped[List[str]] = mapped_column(JSON, default=list)
    remediation_steps: Mapped[List[str]] = mapped_column(JSON, default=list)


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    user_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    username: Mapped[str] = mapped_column(String(64), index=True, default="system")
    action: Mapped[str] = mapped_column(String(64), index=True)  # e.g. rule_disabled, alert_closed, ioc_created
    resource_type: Mapped[str] = mapped_column(String(64), index=True)  # rule, alert, ioc, campaign, event
    resource_id: Mapped[Optional[str]] = mapped_column(String(64), index=True, nullable=True)
    details: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict)
    ip_address: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
