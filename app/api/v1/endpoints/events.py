"""ThreatLens Events Query Endpoints."""

import math
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from app.db.session import get_db
from app.models.event import Event
from app.schemas.common import PaginatedResponse
from app.schemas.event import EventResponse

router = APIRouter()


@router.get("", response_model=PaginatedResponse[EventResponse], summary="Search and filter normalized events")
async def list_events(
    source_format: Optional[str] = Query(None, description="Filter by source format (e.g., windows, syslog)"),
    source_ip: Optional[str] = Query(None, description="Filter by source IP"),
    destination_ip: Optional[str] = Query(None, description="Filter by destination IP"),
    hostname: Optional[str] = Query(None, description="Filter by hostname"),
    username: Optional[str] = Query(None, description="Filter by username"),
    action: Optional[str] = Query(None, description="Filter by action (e.g. failure, success, deny)"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    search: Optional[str] = Query(None, description="Free text substring in raw_message"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=1000),
    db: AsyncSession = Depends(get_db),
):
    stmt = select(Event)
    count_stmt = select(func.count(Event.id))

    if source_format:
        stmt = stmt.where(Event.source_format == source_format)
        count_stmt = count_stmt.where(Event.source_format == source_format)
    if source_ip:
        stmt = stmt.where(Event.source_ip == source_ip)
        count_stmt = count_stmt.where(Event.source_ip == source_ip)
    if destination_ip:
        stmt = stmt.where(Event.destination_ip == destination_ip)
        count_stmt = count_stmt.where(Event.destination_ip == destination_ip)
    if hostname:
        stmt = stmt.where(Event.hostname == hostname)
        count_stmt = count_stmt.where(Event.hostname == hostname)
    if username:
        stmt = stmt.where(Event.username == username)
        count_stmt = count_stmt.where(Event.username == username)
    if action:
        stmt = stmt.where(Event.action == action)
        count_stmt = count_stmt.where(Event.action == action)
    if severity:
        stmt = stmt.where(Event.severity == severity)
        count_stmt = count_stmt.where(Event.severity == severity)
    if search:
        pattern = f"%{search}%"
        stmt = stmt.where(Event.raw_message.ilike(pattern))
        count_stmt = count_stmt.where(Event.raw_message.ilike(pattern))

    total = (await db.execute(count_stmt)).scalar() or 0
    total_pages = max(1, math.ceil(total / page_size))

    stmt = stmt.order_by(Event.timestamp.desc()).offset((page - 1) * page_size).limit(page_size)
    events = (await db.execute(stmt)).scalars().all()

    return PaginatedResponse(
        items=events,
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
    )


@router.get("/{event_id}", response_model=EventResponse, summary="Get single normalized event by ID")
async def get_event(event_id: str, db: AsyncSession = Depends(get_db)):
    stmt = select(Event).where(Event.id == event_id)
    event = (await db.execute(stmt)).scalars().first()
    if not event:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Event {event_id} not found")
    return event
