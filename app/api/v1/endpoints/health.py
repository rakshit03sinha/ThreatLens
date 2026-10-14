"""ThreatLens Health and Readiness Endpoints."""

from datetime import datetime, timezone
from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.config import settings
from app.db.session import get_db
from app.schemas.common import HealthResponse, ReadinessResponse

router = APIRouter()


@router.get("/health", response_model=HealthResponse, summary="Liveness probe")
async def health_check():
    """Returns basic service health status for liveness probes."""
    return HealthResponse(
        status="healthy",
        version=settings.APP_VERSION,
        app_env=settings.APP_ENV,
        timestamp=datetime.now(timezone.utc).isoformat(),
    )


@router.get("/ready", response_model=ReadinessResponse, summary="Readiness probe and dependency health")
async def readiness_check(db: AsyncSession = Depends(get_db)):
    """Verifies database connectivity and AI provider availability."""
    db_status = "healthy"
    db_details = {}
    try:
        await db.execute(text("SELECT 1"))
    except Exception as e:
        db_status = "unhealthy"
        db_details["error"] = str(e)

    ai_status = "enabled (Groq)" if settings.is_ai_enabled else "disabled (deterministic fallback)"

    overall = "ready" if db_status == "healthy" else "degraded"
    return ReadinessResponse(
        status=overall,
        database=db_status,
        ai_provider=ai_status,
        version=settings.APP_VERSION,
        details={
            "database_url_type": settings.DATABASE_URL.split(":")[0],
            "groq_model": settings.GROQ_MODEL if settings.is_ai_enabled else None,
            **db_details,
        },
    )
