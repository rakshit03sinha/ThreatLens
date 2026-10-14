"""ThreatLens API v1 Router Aggregator."""

from fastapi import APIRouter
from app.api.v1.endpoints import (
    auth,
    health,
    metrics,
    events,
    ingestion,
    rules,
    alerts,
    iocs,
    campaigns,
    scoring,
    investigations,
    playbooks,
    audit,
)

api_router = APIRouter()

api_router.include_router(auth.router, prefix="/auth", tags=["Authentication"])
api_router.include_router(health.router, prefix="", tags=["Health & Readiness"])
api_router.include_router(metrics.router, prefix="/metrics", tags=["Dashboard Metrics"])
api_router.include_router(events.router, prefix="/events", tags=["Normalized Events"])
api_router.include_router(ingestion.router, prefix="/ingest", tags=["Ingestion Pipeline"])
api_router.include_router(rules.router, prefix="/rules", tags=["Detection Rules"])
api_router.include_router(alerts.router, prefix="/alerts", tags=["Security Alerts"])
api_router.include_router(iocs.router, prefix="/iocs", tags=["Threat Intelligence (IOCs)"])
api_router.include_router(campaigns.router, prefix="/campaigns", tags=["Incident Campaigns"])
api_router.include_router(scoring.router, prefix="/scoring", tags=["Explainable Threat Scoring"])
api_router.include_router(investigations.router, prefix="/investigations", tags=["RAG Investigation"])
api_router.include_router(playbooks.router, prefix="/playbooks", tags=["Incident Playbooks"])
api_router.include_router(audit.router, prefix="/audit", tags=["Audit Log"])
