"""ThreatLens Asynchronous Ingestion Service."""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.event import Event, IngestionJob
from app.parsers.registry import parser_registry
from app.schemas.event import NormalizedEvent
from app.services.ioc import ioc_service
from app.services.detection import detection_service
from app.utils.hashing import generate_event_fingerprint, generate_uuid

logger = logging.getLogger(__name__)


class IngestionService:
    """Handles event ingestion, normalization, deduplication, and persistence."""

    async def create_job(
        self,
        session: AsyncSession,
        total_records: int,
        source_format: Optional[str] = None,
    ) -> IngestionJob:
        job = IngestionJob(
            id=generate_uuid(),
            status="pending",
            source_format=source_format,
            total_records=total_records,
            accepted_count=0,
            rejected_count=0,
            processed_count=0,
            failed_count=0,
            error_summary={},
        )
        session.add(job)
        await session.flush()
        return job

    async def ingest_single(
        self,
        session: AsyncSession,
        raw_log: str,
        format_hint: Optional[str] = None,
        job_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Ingest and process a single log line."""
        # 1. Parse and normalize
        parse_res = parser_registry.parse_log(raw_log, format_hint=format_hint)
        if not parse_res.success or not parse_res.event:
            diag_msgs = [d.message for d in parse_res.diagnostics]
            return {
                "success": False,
                "error": "; ".join(diag_msgs) or "Log normalization failed.",
                "event_id": None,
            }

        norm_event = parse_res.event
        # Generate stable fingerprint
        fingerprint = generate_event_fingerprint(
            str(norm_event.timestamp),
            norm_event.source_format,
            raw_log,
        )

        # 2. Check for deduplication
        existing_stmt = select(Event).where(Event.event_fingerprint == fingerprint)
        existing_event = (await session.execute(existing_stmt)).scalars().first()
        if existing_event:
            return {
                "success": True,
                "event_id": existing_event.id,
                "status": "duplicate",
                "message": "Event already ingested with identical fingerprint.",
            }

        # 3. Persist Event
        event_id = generate_uuid()
        norm_event.id = event_id
        norm_event.event_fingerprint = fingerprint
        norm_event.ingestion_job_id = job_id

        db_event = Event(
            id=event_id,
            event_fingerprint=fingerprint,
            source_format=norm_event.source_format,
            timestamp=norm_event.timestamp,
            source_ip=norm_event.source_ip,
            destination_ip=norm_event.destination_ip,
            source_port=norm_event.source_port,
            destination_port=norm_event.destination_port,
            hostname=norm_event.hostname,
            username=norm_event.username,
            action=norm_event.action,
            severity=norm_event.severity,
            event_type=norm_event.event_type,
            raw_message=norm_event.raw_message,
            parsed_fields=norm_event.parsed_fields,
            ingestion_job_id=job_id,
        )
        session.add(db_event)
        await session.flush()

        # 4. IOC Matching
        await ioc_service.match_event(session, norm_event, event_id)

        # 5. Fetch recent context events for detection rule evaluation
        recent_stmt = (
            select(Event)
            .where(Event.id != event_id)
            .order_by(Event.timestamp.desc())
            .limit(100)
        )
        recent_db_events = (await session.execute(recent_stmt)).scalars().all()
        recent_norm_events = [
            NormalizedEvent(
                id=e.id,
                event_fingerprint=e.event_fingerprint,
                source_format=e.source_format,
                timestamp=e.timestamp,
                source_ip=e.source_ip,
                destination_ip=e.destination_ip,
                source_port=e.source_port,
                destination_port=e.destination_port,
                hostname=e.hostname,
                username=e.username,
                action=e.action,
                severity=e.severity,
                event_type=e.event_type,
                raw_message=e.raw_message,
                parsed_fields=e.parsed_fields,
            )
            for e in recent_db_events
        ]

        # 6. Detection evaluation and alert creation
        alerts = await detection_service.evaluate_and_alert(
            session=session,
            current_event=norm_event,
            event_db_id=event_id,
            recent_events=recent_norm_events,
        )

        return {
            "success": True,
            "event_id": event_id,
            "status": "processed",
            "source_format": norm_event.source_format,
            "alerts_triggered": len(alerts),
        }

    async def process_batch(
        self,
        session: AsyncSession,
        raw_events: List[str],
        format_hint: Optional[str] = None,
        job_id: Optional[str] = None,
    ) -> IngestionJob:
        """Process a batch of log records with record-level fault tolerance."""
        if job_id:
            job_stmt = select(IngestionJob).where(IngestionJob.id == job_id)
            job = (await session.execute(job_stmt)).scalars().first()
            if not job:
                job = await self.create_job(session, len(raw_events), format_hint)
        else:
            job = await self.create_job(session, len(raw_events), format_hint)

        job.status = "processing"
        errors: Dict[str, str] = {}

        for idx, raw_log in enumerate(raw_events):
            try:
                res = await self.ingest_single(
                    session=session,
                    raw_log=raw_log,
                    format_hint=format_hint,
                    job_id=job.id,
                )
                if res["success"]:
                    job.accepted_count += 1
                    job.processed_count += 1
                else:
                    job.rejected_count += 1
                    errors[f"record_{idx}"] = res.get("error", "Failed")
            except Exception as e:
                logger.error(f"Error processing record {idx} in job {job.id}: {str(e)}", exc_info=True)
                job.failed_count += 1
                errors[f"record_{idx}"] = str(e)

        job.status = "completed" if job.failed_count == 0 else ("failed" if job.accepted_count == 0 else "partial")
        job.error_summary = errors if errors else None
        job.updated_at = datetime.now(timezone.utc)
        await session.flush()
        return job


ingestion_service = IngestionService()
