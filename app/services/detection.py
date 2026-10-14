"""ThreatLens Detection Orchestration Service."""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.rule import Alert, AlertEvidence
from app.models.event import Event
from app.models.campaign import ThreatScore
from app.rules.engine import detection_engine
from app.schemas.event import NormalizedEvent
from app.services.scoring import scoring_engine
from app.services.correlation import correlation_service
from app.utils.hashing import generate_uuid

logger = logging.getLogger(__name__)


class DetectionService:
    """Orchestrates rule evaluation, alert generation, evidence linking, and scoring."""

    async def evaluate_and_alert(
        self,
        session: AsyncSession,
        current_event: NormalizedEvent,
        event_db_id: str,
        recent_events: List[NormalizedEvent],
    ) -> List[Alert]:
        alerts_generated: List[Alert] = []

        # Run detection engine
        matches = detection_engine.evaluate_event(current_event, recent_events)
        if not matches:
            return alerts_generated

        now = datetime.now(timezone.utc)
        for match in matches:
            # Check for existing open alert with same correlation key to avoid duplicates
            existing_alert: Optional[Alert] = None
            if match.correlation_key:
                stmt = select(Alert).where(
                    Alert.correlation_key == match.correlation_key,
                    Alert.status.in_(["new", "triaged", "investigating"]),
                )
                existing_alert = (await session.execute(stmt)).scalars().first()

            if existing_alert:
                # Add supporting event ID and evidence without creating duplicate alert
                existing_ids = list(existing_alert.supporting_event_ids or [])
                if event_db_id not in existing_ids:
                    existing_ids.append(event_db_id)
                    existing_alert.supporting_event_ids = existing_ids
                    existing_alert.updated_at = now
                    # Recalculate score
                    score, breakdown, explanation = scoring_engine.calculate_alert_score(
                        severity=existing_alert.severity,
                        event_count=len(existing_ids),
                        has_ioc_match="ioc" in (existing_alert.correlation_key or ""),
                    )
                    existing_alert.risk_score = score
                    alerts_generated.append(existing_alert)
                continue

            # Calculate explainable threat score
            score, breakdown, explanation = scoring_engine.calculate_alert_score(
                severity=match.severity,
                event_count=len(match.supporting_event_ids) if match.supporting_event_ids else 1,
                has_ioc_match="ioc" in (match.correlation_key or ""),
            )

            alert_id = f"ALT-{now.strftime('%Y%m%d')}-{generate_uuid()[:8].upper()}"
            alert = Alert(
                alert_id=alert_id,
                rule_id=match.rule_id,
                rule_name=match.rule_name,
                title=match.title,
                description=match.description,
                severity=match.severity,
                risk_score=score,
                status="new",
                attack_tactic=match.attack_tactic,
                attack_technique=match.attack_technique,
                attack_technique_name=match.attack_technique_name,
                correlation_key=match.correlation_key,
                supporting_event_ids=match.supporting_event_ids or [event_db_id],
                context_data=match.context_data,
            )
            session.add(alert)
            await session.flush()

            # Create AlertEvidence
            for ev_id in alert.supporting_event_ids:
                evidence = AlertEvidence(
                    alert_id=alert.alert_id,
                    event_id=ev_id,
                    relationship_type="trigger" if ev_id == event_db_id else "supporting",
                    evidence_details={"matched_rule": match.rule_id},
                )
                session.add(evidence)

            # Store ThreatScore snapshot
            ts_record = ThreatScore(
                entity_type="alert",
                entity_id=alert.alert_id,
                total_score=score,
                severity_factor=breakdown.severity_factor,
                confidence_factor=breakdown.confidence_factor,
                frequency_factor=breakdown.frequency_factor,
                ioc_factor=breakdown.ioc_factor,
                campaign_factor=breakdown.campaign_factor,
                explanation=explanation,
                factor_breakdown=breakdown.model_dump(),
            )
            session.add(ts_record)
            await session.flush()

            # Correlate into Campaign
            await correlation_service.correlate_alert(session, alert)
            alerts_generated.append(alert)

        return alerts_generated


detection_service = DetectionService()
