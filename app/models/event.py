"""ThreatLens Event and Ingestion Models."""

from datetime import datetime, timezone
from typing import Optional, Dict, Any
from sqlalchemy import String, Integer, DateTime, Text, JSON, ForeignKey, Index
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.db.base import Base, TimestampMixin


class IngestionJob(Base, TimestampMixin):
    __tablename__ = "ingestion_jobs"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)  # uuid
    status: Mapped[str] = mapped_column(String(32), default="pending", index=True)  # pending, processing, completed, failed
    source_format: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    total_records: Mapped[int] = mapped_column(Integer, default=0)
    accepted_count: Mapped[int] = mapped_column(Integer, default=0)
    rejected_count: Mapped[int] = mapped_column(Integer, default=0)
    processed_count: Mapped[int] = mapped_column(Integer, default=0)
    failed_count: Mapped[int] = mapped_column(Integer, default=0)
    error_summary: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)

    events: Mapped[list["Event"]] = relationship("Event", back_populates="ingestion_job", cascade="all, delete-orphan")


class Event(Base):
    __tablename__ = "events"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)  # stable uuid
    event_fingerprint: Mapped[str] = mapped_column(String(64), unique=True, index=True)  # sha256 fingerprint for deduplication
    source_format: Mapped[str] = mapped_column(String(64), index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    
    # Normalized Common Schema Fields
    source_ip: Mapped[Optional[str]] = mapped_column(String(64), index=True, nullable=True)
    destination_ip: Mapped[Optional[str]] = mapped_column(String(64), index=True, nullable=True)
    source_port: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    destination_port: Mapped[Optional[int]] = mapped_column(Integer, index=True, nullable=True)
    hostname: Mapped[Optional[str]] = mapped_column(String(128), index=True, nullable=True)
    username: Mapped[Optional[str]] = mapped_column(String(128), index=True, nullable=True)
    action: Mapped[Optional[str]] = mapped_column(String(64), index=True, nullable=True)
    severity: Mapped[Optional[str]] = mapped_column(String(32), default="informational", index=True)
    event_type: Mapped[Optional[str]] = mapped_column(String(128), index=True, nullable=True)
    
    # Message & Provider-specific details
    raw_message: Mapped[str] = mapped_column(Text, nullable=False)
    parsed_fields: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict)
    
    # Metadata
    ingestion_job_id: Mapped[Optional[str]] = mapped_column(String(64), ForeignKey("ingestion_jobs.id"), index=True, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)

    ingestion_job: Mapped[Optional[IngestionJob]] = relationship("IngestionJob", back_populates="events")

    __table_args__ = (
        Index("ix_events_user_action_time", "username", "action", "timestamp"),
        Index("ix_events_src_dst_ip", "source_ip", "destination_ip"),
    )
