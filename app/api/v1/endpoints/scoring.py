"""ThreatLens Threat Scoring Query and Calculation Endpoints."""

from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.db.session import get_db
from app.models.campaign import ThreatScore, Campaign
from app.models.rule import Alert
from app.schemas.campaign import ThreatScoreBreakdown, ThreatScoreCalculateRequest, ThreatScoreResponse
from app.services.scoring import scoring_engine

router = APIRouter()


@router.get("/{entity_type}/{entity_id}", response_model=ThreatScoreResponse, summary="Retrieve explainable threat score snapshot")
async def get_threat_score(
    entity_type: str,
    entity_id: str,
    db: AsyncSession = Depends(get_db),
):
    stmt = (
        select(ThreatScore)
        .where(ThreatScore.entity_type == entity_type.lower(), ThreatScore.entity_id == entity_id)
        .order_by(ThreatScore.calculated_at.desc())
    )
    score_rec = (await db.execute(stmt)).scalars().first()
    if score_rec:
        return ThreatScoreResponse(
            entity_type=score_rec.entity_type,
            entity_id=score_rec.entity_id,
            total_score=score_rec.total_score,
            explanation=score_rec.explanation,
            breakdown=ThreatScoreBreakdown(**score_rec.factor_breakdown),
            calculated_at=score_rec.calculated_at,
        )

    # If no snapshot in DB, calculate dynamically
    if entity_type.lower() == "alert":
        alert_stmt = select(Alert).where(Alert.alert_id == entity_id)
        alert = (await db.execute(alert_stmt)).scalars().first()
        if not alert:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Alert '{entity_id}' not found")
        score, breakdown, explanation = scoring_engine.calculate_alert_score(
            severity=alert.severity,
            event_count=len(alert.supporting_event_ids or [1]),
            has_ioc_match="ioc" in (alert.correlation_key or ""),
        )
        return ThreatScoreResponse(
            entity_type="alert",
            entity_id=entity_id,
            total_score=score,
            explanation=explanation,
            breakdown=breakdown,
            calculated_at=datetime.now(timezone.utc),
        )

    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Threat score for {entity_type} {entity_id} not found")


@router.post("/calculate", response_model=ThreatScoreResponse, summary="Calculate or recalculate threat score")
async def calculate_score(
    payload: ThreatScoreCalculateRequest,
    db: AsyncSession = Depends(get_db),
):
    return await get_threat_score(payload.entity_type, payload.entity_id, db)
