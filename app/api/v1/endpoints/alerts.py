"""ThreatLens Alert Query and Management Endpoints."""

import math
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.orm import selectinload
from sqlalchemy.ext.asyncio import AsyncSession
from app.api.deps import get_current_user_optional
from app.db.session import get_db
from app.models.rule import Alert, AlertEvidence
from app.models.user import User
from app.schemas.alert import AlertResponse, AlertUpdateStatus
from app.schemas.common import PaginatedResponse
from app.services.audit import audit_service

router = APIRouter()


@router.get("", response_model=PaginatedResponse[AlertResponse], summary="Search and list security alerts")
async def list_alerts(
    rule_id: Optional[str] = Query(None, description="Filter by detection rule ID (e.g. RULE-001)"),
    severity: Optional[str] = Query(None, description="Filter by severity (critical, high, medium, low)"),
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by status (new, triaged, closed)"),
    attack_tactic: Optional[str] = Query(None, description="Filter by MITRE ATT&CK tactic"),
    search: Optional[str] = Query(None, description="Search term in alert title or description"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=1000),
    db: AsyncSession = Depends(get_db),
):
    stmt = select(Alert).options(selectinload(Alert.evidence_items))
    count_stmt = select(func.count(Alert.id))

    if rule_id:
        stmt = stmt.where(Alert.rule_id == rule_id)
        count_stmt = count_stmt.where(Alert.rule_id == rule_id)
    if severity:
        stmt = stmt.where(Alert.severity == severity)
        count_stmt = count_stmt.where(Alert.severity == severity)
    if status_filter:
        stmt = stmt.where(Alert.status == status_filter)
        count_stmt = count_stmt.where(Alert.status == status_filter)
    if attack_tactic:
        stmt = stmt.where(Alert.attack_tactic == attack_tactic)
        count_stmt = count_stmt.where(Alert.attack_tactic == attack_tactic)
    if search:
        pattern = f"%{search}%"
        stmt = stmt.where(Alert.title.ilike(pattern) | Alert.description.ilike(pattern))
        count_stmt = count_stmt.where(Alert.title.ilike(pattern) | Alert.description.ilike(pattern))

    total = (await db.execute(count_stmt)).scalar() or 0
    total_pages = max(1, math.ceil(total / page_size))

    stmt = stmt.order_by(Alert.created_at.desc()).offset((page - 1) * page_size).limit(page_size)
    alerts = (await db.execute(stmt)).scalars().all()

    return PaginatedResponse(
        items=alerts,
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
    )


@router.get("/{alert_id}", response_model=AlertResponse, summary="Get alert details and supporting evidence")
async def get_alert(alert_id: str, db: AsyncSession = Depends(get_db)):
    stmt = (
        select(Alert)
        .where(Alert.alert_id == alert_id)
        .options(selectinload(Alert.evidence_items))
    )
    alert = (await db.execute(stmt)).scalars().first()
    if not alert:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Alert '{alert_id}' not found")
    return alert


@router.patch("/{alert_id}", response_model=AlertResponse, summary="Update alert status and analyst disposition")
async def update_alert(
    alert_id: str,
    payload: AlertUpdateStatus,
    current_user: User = Depends(get_current_user_optional),
    db: AsyncSession = Depends(get_db),
):
    stmt = select(Alert).where(Alert.alert_id == alert_id).options(selectinload(Alert.evidence_items))
    alert = (await db.execute(stmt)).scalars().first()
    if not alert:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Alert '{alert_id}' not found")

    if payload.status:
        alert.status = payload.status
    if payload.analyst_disposition:
        alert.analyst_disposition = payload.analyst_disposition
    if payload.disposition_notes:
        alert.disposition_notes = payload.disposition_notes
    if payload.assigned_to:
        alert.assigned_to = payload.assigned_to

    username = current_user.username if current_user else "anonymous_analyst"
    await audit_service.log_action(
        session=db,
        action="alert_updated",
        resource_type="alert",
        resource_id=alert_id,
        username=username,
        details=payload.model_dump(exclude_unset=True),
    )

    await db.flush()
    return alert
