"""ThreatLens IOC Intelligence Endpoints."""

import math
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from app.api.deps import get_current_user_optional
from app.db.session import get_db
from app.models.ioc import IOC, IOCMatch
from app.models.user import User
from app.schemas.common import PaginatedResponse
from app.schemas.ioc import IOCCreate, IOCMatchResponse, IOCResponse
from app.services.audit import audit_service
from app.services.ioc import ioc_service

router = APIRouter()


@router.get("", response_model=PaginatedResponse[IOCResponse], summary="List indicators of compromise")
async def list_iocs(
    indicator_type: Optional[str] = Query(None, description="ipv4, ipv6, domain, url, sha256, md5, sha1"),
    severity: Optional[str] = Query(None, description="low, medium, high, critical"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=1000),
    db: AsyncSession = Depends(get_db),
):
    stmt = select(IOC)
    count_stmt = select(func.count(IOC.id))

    if indicator_type:
        stmt = stmt.where(IOC.indicator_type == indicator_type)
        count_stmt = count_stmt.where(IOC.indicator_type == indicator_type)
    if severity:
        stmt = stmt.where(IOC.severity == severity)
        count_stmt = count_stmt.where(IOC.severity == severity)

    total = (await db.execute(count_stmt)).scalar() or 0
    total_pages = max(1, math.ceil(total / page_size))

    stmt = stmt.order_by(IOC.last_seen.desc()).offset((page - 1) * page_size).limit(page_size)
    iocs = (await db.execute(stmt)).scalars().all()

    return PaginatedResponse(
        items=iocs,
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
    )


@router.post("", response_model=IOCResponse, status_code=status.HTTP_201_CREATED, summary="Create or import an IOC indicator")
async def create_ioc(
    payload: IOCCreate,
    current_user: User = Depends(get_current_user_optional),
    db: AsyncSession = Depends(get_db),
):
    ioc = await ioc_service.add_or_update_ioc(
        session=db,
        indicator_value=payload.indicator_value,
        indicator_type=payload.indicator_type,
        severity=payload.severity,
        confidence=payload.confidence,
        source=payload.source,
        description=payload.description,
        tags=payload.tags,
    )

    username = current_user.username if current_user else "threat_intel_system"
    await audit_service.log_action(
        session=db,
        action="ioc_created",
        resource_type="ioc",
        resource_id=str(ioc.id),
        username=username,
        details={"value": ioc.indicator_value, "type": ioc.indicator_type},
    )

    return ioc


@router.get("/search", response_model=List[IOCResponse], summary="Search for an IOC by substring or exact value")
async def search_ioc(
    q: str = Query(..., min_length=2, description="Search query string"),
    db: AsyncSession = Depends(get_db),
):
    pattern = f"%{q.strip().lower()}%"
    stmt = select(IOC).where(IOC.indicator_value.ilike(pattern)).limit(50)
    res = await db.execute(stmt)
    return res.scalars().all()


@router.get("/{ioc_id}/matches", response_model=List[IOCMatchResponse], summary="Get detection match history for an IOC")
async def get_ioc_matches(ioc_id: int, db: AsyncSession = Depends(get_db)):
    stmt = select(IOCMatch).where(IOCMatch.ioc_id == ioc_id).order_by(IOCMatch.created_at.desc()).limit(100)
    matches = (await db.execute(stmt)).scalars().all()
    return matches
