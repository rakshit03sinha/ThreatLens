"""ThreatLens Ingestion Endpoints."""

from typing import Any, Dict, List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.db.session import get_db
from app.models.event import IngestionJob
from app.parsers.registry import parser_registry
from app.schemas.event import EventIngestBatchRequest, EventIngestSingleRequest
from app.schemas.ingestion import IngestionJobResponse
from app.services.ingestion import ingestion_service

router = APIRouter()


@router.get("/formats", summary="List supported log formats and specifications")
async def list_supported_formats() -> List[Dict[str, str]]:
    """Returns the list of 12 supported log formats and descriptions."""
    return parser_registry.list_formats()


@router.post("/event", summary="Ingest and normalize a single log event")
async def ingest_single_event(
    payload: EventIngestSingleRequest,
    db: AsyncSession = Depends(get_db),
):
    """Ingests, parses, normalizes, evaluates detections, and links alerts for a single log."""
    res = await ingestion_service.ingest_single(
        session=db,
        raw_log=payload.raw_log,
        format_hint=payload.format,
    )
    if not res["success"]:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=res.get("error", "Failed to parse log record"),
        )
    return res


@router.post("/batch", response_model=IngestionJobResponse, summary="Ingest a batch of log records")
async def ingest_batch_events(
    payload: EventIngestBatchRequest,
    db: AsyncSession = Depends(get_db),
):
    """Ingests a batch of logs with record-level diagnostics and job status tracking."""
    job = await ingestion_service.process_batch(
        session=db,
        raw_events=payload.events,
        format_hint=payload.format,
    )
    return job


@router.get("/jobs/{job_id}", response_model=IngestionJobResponse, summary="Check ingestion job status")
async def get_job_status(job_id: str, db: AsyncSession = Depends(get_db)):
    stmt = select(IngestionJob).where(IngestionJob.id == job_id)
    job = (await db.execute(stmt)).scalars().first()
    if not job:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Ingestion job '{job_id}' not found")
    return job
