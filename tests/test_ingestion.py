"""ThreatLens Ingestion Service Test Suite."""

import pytest
from app.services.ingestion import ingestion_service


@pytest.mark.asyncio
async def test_single_event_ingestion(db_session):
    raw_log = '{"Event":{"System":{"EventID":4625,"TimeCreated":{"SystemTime":"2026-10-14T21:00:00Z"},"Computer":"DC01"},"EventData":{"TargetUserName":"alice","IpAddress":"198.51.100.10"}}}'
    res = await ingestion_service.ingest_single(db_session, raw_log, format_hint="windows")
    assert res["success"] is True
    assert res["status"] == "processed"
    assert res["event_id"] is not None

    # Idempotency test: Ingesting the same record again should return duplicate status
    res_dup = await ingestion_service.ingest_single(db_session, raw_log, format_hint="windows")
    assert res_dup["success"] is True
    assert res_dup["status"] == "duplicate"
    assert res_dup["event_id"] == res["event_id"]


@pytest.mark.asyncio
async def test_batch_ingestion_and_partial_failure(db_session):
    events = [
        "Oct 14 21:00:00 host1 sshd[100]: Failed password for invalid user admin from 192.168.1.1 port 22 ssh2",
        "INVALID_CORRUPT_LOG_LINE_THAT_CANNOT_PARSE_ANYWHERE",
        "Oct 14 21:00:01 host1 sshd[101]: Accepted password for root from 192.168.1.1 port 22 ssh2",
    ]

    job = await ingestion_service.process_batch(
        session=db_session,
        raw_events=events,
        format_hint=None,  # auto-detect
    )

    assert job.total_records == 3
    assert job.accepted_count == 2
    assert job.rejected_count == 1
    assert job.status in ["partial", "completed"]
    assert "record_1" in job.error_summary

