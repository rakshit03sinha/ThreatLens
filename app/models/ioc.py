"""ThreatLens IOC and Matching Models."""

from datetime import datetime, timezone
from typing import Optional, Dict, Any, List
from sqlalchemy import String, Integer, Float, DateTime, Text, JSON, ForeignKey, Index
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.db.base import Base, TimestampMixin


class IOC(Base, TimestampMixin):
    __tablename__ = "iocs"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    indicator_value: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    indicator_type: Mapped[str] = mapped_column(String(32), index=True)  # ipv4, ipv6, domain, url, sha256, md5, sha1
    severity: Mapped[str] = mapped_column(String(32), default="medium", index=True)  # low, medium, high, critical
    confidence: Mapped[int] = mapped_column(Integer, default=75)  # 0 to 100
    source: Mapped[str] = mapped_column(String(128), default="ThreatLens Internal")
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    tags: Mapped[List[str]] = mapped_column(JSON, default=list)
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))

    matches: Mapped[List["IOCMatch"]] = relationship("IOCMatch", back_populates="ioc", cascade="all, delete-orphan")


class IOCMatch(Base):
    __tablename__ = "ioc_matches"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    ioc_id: Mapped[int] = mapped_column(Integer, ForeignKey("iocs.id"), index=True)
    event_id: Mapped[str] = mapped_column(String(64), index=True)
    alert_id: Mapped[Optional[str]] = mapped_column(String(64), index=True, nullable=True)
    matched_field: Mapped[str] = mapped_column(String(64), index=True)
    matched_value: Mapped[str] = mapped_column(String(255), index=True)
    match_context: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)

    ioc: Mapped[IOC] = relationship("IOC", back_populates="matches")
