"""ThreatLens Dashboard Metrics Endpoints."""

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.config import settings
from app.db.session import get_db
from app.models.event import Event, IngestionJob
from app.models.rule import Alert
from app.models.ioc import IOCMatch
from app.models.campaign import Campaign
from app.schemas.investigation import DashboardMetricsResponse

router = APIRouter()


@router.get("/dashboard", response_model=DashboardMetricsResponse, summary="Get SOC dashboard summary metrics")
async def get_dashboard_metrics(db: AsyncSession = Depends(get_db)):
    """Computes real-time telemetry, alert, campaign, and ingestion statistics."""
    total_events = (await db.execute(select(func.count(Event.id)))).scalar() or 0
    total_alerts = (await db.execute(select(func.count(Alert.id)))).scalar() or 0
    critical_alerts = (
        await db.execute(select(func.count(Alert.id)).where(Alert.severity == "critical"))
    ).scalar() or 0
    high_alerts = (
        await db.execute(select(func.count(Alert.id)).where(Alert.severity == "high"))
    ).scalar() or 0
    active_campaigns = (
        await db.execute(select(func.count(Campaign.id)).where(Campaign.status.in_(["active", "investigating"])))
    ).scalar() or 0
    ioc_matches = (await db.execute(select(func.count(IOCMatch.id)))).scalar() or 0
    failed_jobs = (
        await db.execute(select(func.count(IngestionJob.id)).where(IngestionJob.status == "failed"))
    ).scalar() or 0

    ai_status = f"Groq Active ({settings.GROQ_MODEL})" if settings.is_ai_enabled else "Deterministic Engine (No Key)"

    return DashboardMetricsResponse(
        total_events=total_events,
        total_alerts=total_alerts,
        critical_alerts=critical_alerts,
        high_alerts=high_alerts,
        active_campaigns=active_campaigns,
        ioc_matches=ioc_matches,
        ingestion_jobs_failed=failed_jobs,
        ai_status=ai_status,
    )
