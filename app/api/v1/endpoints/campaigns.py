"""ThreatLens Campaign Management Endpoints."""

import math
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.orm import selectinload
from sqlalchemy.ext.asyncio import AsyncSession
from app.api.deps import get_current_user_optional
from app.db.session import get_db
from app.models.campaign import Campaign, CampaignAlert
from app.models.rule import Alert
from app.models.user import User
from app.schemas.campaign import CampaignAlertSummary, CampaignResponse, CampaignUpdate
from app.schemas.common import PaginatedResponse
from app.services.audit import audit_service

router = APIRouter()


@router.get("", response_model=PaginatedResponse[CampaignResponse], summary="List incident campaigns")
async def list_campaigns(
    status_filter: Optional[str] = Query(None, alias="status", description="active, investigating, contained, resolved"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=1000),
    db: AsyncSession = Depends(get_db),
):
    stmt = select(Campaign)
    count_stmt = select(func.count(Campaign.id))

    if status_filter:
        stmt = stmt.where(Campaign.status == status_filter)
        count_stmt = count_stmt.where(Campaign.status == status_filter)

    total = (await db.execute(count_stmt)).scalar() or 0
    total_pages = max(1, math.ceil(total / page_size))

    stmt = stmt.order_by(Campaign.updated_at.desc()).offset((page - 1) * page_size).limit(page_size)
    campaigns = (await db.execute(stmt)).scalars().all()

    # Build response with alerts summary
    items = []
    for c in campaigns:
        # Load associated alerts
        assoc_stmt = (
            select(Alert)
            .join(CampaignAlert, CampaignAlert.alert_id == Alert.alert_id)
            .where(CampaignAlert.campaign_id == c.campaign_id)
        )
        linked_alerts = (await db.execute(assoc_stmt)).scalars().all()
        alert_summaries = [
            CampaignAlertSummary(
                alert_id=a.alert_id,
                rule_id=a.rule_id,
                rule_name=a.rule_name,
                severity=a.severity,
                risk_score=a.risk_score,
                status=a.status,
                created_at=a.created_at,
            )
            for a in linked_alerts
        ]
        items.append(
            CampaignResponse(
                id=c.id,
                campaign_id=c.campaign_id,
                title=c.title,
                description=c.description,
                status=c.status,
                risk_score=c.risk_score,
                primary_tactic=c.primary_tactic,
                primary_technique=c.primary_technique,
                common_signals=c.common_signals,
                correlation_reason=c.correlation_reason,
                notes=c.notes,
                alerts=alert_summaries,
                created_at=c.created_at,
                updated_at=c.updated_at,
            )
        )

    return PaginatedResponse(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
    )


@router.get("/{campaign_id}", response_model=CampaignResponse, summary="Get campaign details and linked alert evidence")
async def get_campaign(campaign_id: str, db: AsyncSession = Depends(get_db)):
    stmt = select(Campaign).where(Campaign.campaign_id == campaign_id)
    c = (await db.execute(stmt)).scalars().first()
    if not c:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Campaign '{campaign_id}' not found")

    assoc_stmt = (
        select(Alert)
        .join(CampaignAlert, CampaignAlert.alert_id == Alert.alert_id)
        .where(CampaignAlert.campaign_id == c.campaign_id)
    )
    linked_alerts = (await db.execute(assoc_stmt)).scalars().all()
    alert_summaries = [
        CampaignAlertSummary(
            alert_id=a.alert_id,
            rule_id=a.rule_id,
            rule_name=a.rule_name,
            severity=a.severity,
            risk_score=a.risk_score,
            status=a.status,
            created_at=a.created_at,
        )
        for a in linked_alerts
    ]

    return CampaignResponse(
        id=c.id,
        campaign_id=c.campaign_id,
        title=c.title,
        description=c.description,
        status=c.status,
        risk_score=c.risk_score,
        primary_tactic=c.primary_tactic,
        primary_technique=c.primary_technique,
        common_signals=c.common_signals,
        correlation_reason=c.correlation_reason,
        notes=c.notes,
        alerts=alert_summaries,
        created_at=c.created_at,
        updated_at=c.updated_at,
    )


@router.patch("/{campaign_id}", response_model=CampaignResponse, summary="Update campaign status and analyst notes")
async def update_campaign(
    campaign_id: str,
    payload: CampaignUpdate,
    current_user: User = Depends(get_current_user_optional),
    db: AsyncSession = Depends(get_db),
):
    stmt = select(Campaign).where(Campaign.campaign_id == campaign_id)
    c = (await db.execute(stmt)).scalars().first()
    if not c:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Campaign '{campaign_id}' not found")

    if payload.status:
        c.status = payload.status
    if payload.notes is not None:
        c.notes = payload.notes

    username = current_user.username if current_user else "anonymous_analyst"
    await audit_service.log_action(
        session=db,
        action="campaign_updated",
        resource_type="campaign",
        resource_id=campaign_id,
        username=username,
        details=payload.model_dump(exclude_unset=True),
    )

    await db.flush()
    return await get_campaign(campaign_id, db)
