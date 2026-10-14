"""ThreatLens RAG Investigation Endpoints."""

from typing import List, Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.db.session import get_db
from app.models.investigation import Investigation
from app.schemas.investigation import InvestigationRequest, InvestigationResponse
from app.services.rag import rag_service

router = APIRouter()


@router.post("/ask", response_model=InvestigationResponse, summary="Ask an AI/deterministic SOC investigation question")
async def ask_investigation_question(
    payload: InvestigationRequest,
    db: AsyncSession = Depends(get_db),
):
    """Executes RAG investigation retrieving events, alerts, IOCs, and playbooks."""
    response = await rag_service.investigate(
        session=db,
        question=payload.question,
        alert_id=payload.alert_id,
        campaign_id=payload.campaign_id,
    )
    return response


@router.get("/history", response_model=List[InvestigationResponse], summary="Retrieve SOC investigation history")
async def get_investigation_history(
    alert_id: Optional[str] = Query(None, description="Filter by target alert ID"),
    campaign_id: Optional[str] = Query(None, description="Filter by target campaign ID"),
    limit: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
):
    stmt = select(Investigation)
    if alert_id:
        stmt = stmt.where(Investigation.alert_id == alert_id)
    if campaign_id:
        stmt = stmt.where(Investigation.campaign_id == campaign_id)

    stmt = stmt.order_by(Investigation.created_at.desc()).limit(limit)
    records = (await db.execute(stmt)).scalars().all()

    return [
        InvestigationResponse(
            inquiry_id=r.inquiry_id,
            alert_id=r.alert_id,
            campaign_id=r.campaign_id,
            question=r.question,
            summary=r.answer,
            facts=[e.get("title", str(e)) for e in (r.retrieved_evidence or []) if isinstance(e, dict)],
            hypotheses=["Historical investigation record retrieved."],
            missing_evidence=[],
            recommended_defensive_actions=[],
            citations=r.citations or [],
            model_used=r.model_used,
            is_fallback=r.is_fallback,
            created_at=r.created_at,
        )
        for r in records
    ]
