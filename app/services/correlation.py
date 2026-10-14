"""ThreatLens Alert and Campaign Correlation Service."""

import logging
from datetime import datetime, timedelta, timezone
from typing import List, Optional
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.rule import Alert
from app.models.campaign import Campaign, CampaignAlert
from app.services.scoring import scoring_engine
from app.utils.hashing import generate_uuid

logger = logging.getLogger(__name__)


class CorrelationService:
    """Correlates individual security alerts into coherent incident campaigns."""

    def __init__(self, correlation_window_hours: int = 24):
        self.window = timedelta(hours=correlation_window_hours)

    async def correlate_alert(self, session: AsyncSession, alert: Alert) -> Optional[Campaign]:
        """Correlate a newly generated or updated alert into an existing or new campaign."""
        corr_key = alert.correlation_key
        if not corr_key:
            return None

        now = datetime.now(timezone.utc)
        cutoff = now - self.window

        # Check if an active campaign exists with matching key or shared common signal
        stmt = (
            select(Campaign)
            .where(
                Campaign.status.in_(["active", "investigating"]),
                Campaign.created_at >= cutoff,
            )
            .order_by(Campaign.updated_at.desc())
        )
        res = await session.execute(stmt)
        active_campaigns = res.scalars().all()

        target_campaign: Optional[Campaign] = None
        for camp in active_campaigns:
            signals = camp.common_signals or {}
            # Match on explicit correlation key, common IP, user, or technique
            if signals.get("correlation_key") == corr_key:
                target_campaign = camp
                break
            # Or match on same user across multiple techniques
            alert_user = alert.context_data.get("user") or alert.context_data.get("target_user")
            if alert_user and signals.get("user") == alert_user:
                target_campaign = camp
                break
            # Or match on same source IP across multi-stage alerts
            alert_ip = alert.context_data.get("source_ip") or alert.context_data.get("src_ip")
            if alert_ip and signals.get("source_ip") == alert_ip and alert_ip not in ["127.0.0.1", "localhost"]:
                target_campaign = camp
                break

        # Check if alert is already in target campaign
        if target_campaign:
            assoc_stmt = select(CampaignAlert).where(
                CampaignAlert.campaign_id == target_campaign.campaign_id,
                CampaignAlert.alert_id == alert.alert_id,
            )
            existing_assoc = (await session.execute(assoc_stmt)).scalars().first()
            if not existing_assoc:
                session.add(CampaignAlert(campaign_id=target_campaign.campaign_id, alert_id=alert.alert_id))
                target_campaign.updated_at = now
                target_campaign.risk_score = min(100.0, target_campaign.risk_score + 10.0)
                await session.flush()
            return target_campaign

        # Create a new campaign if multiple supporting events or high severity
        signals = {
            "correlation_key": corr_key,
            "user": alert.context_data.get("user") or alert.context_data.get("target_user"),
            "source_ip": alert.context_data.get("source_ip") or alert.context_data.get("src_ip"),
            "host": alert.context_data.get("host") or alert.context_data.get("target_host"),
        }
        clean_signals = {k: v for k, v in signals.items() if v is not None}

        new_camp_id = f"CMP-{now.strftime('%Y%m%d')}-{generate_uuid()[:8].upper()}"
        new_campaign = Campaign(
            campaign_id=new_camp_id,
            title=f"Incident Campaign: {alert.title}",
            description=f"Correlated security incident initiated by {alert.rule_name} ({alert.attack_tactic} / {alert.attack_technique}).",
            status="active",
            risk_score=alert.risk_score,
            primary_tactic=alert.attack_tactic,
            primary_technique=alert.attack_technique,
            common_signals=clean_signals,
            correlation_reason=f"Grouped by shared correlation identifier: {corr_key}",
        )
        session.add(new_campaign)
        await session.flush()

        session.add(CampaignAlert(campaign_id=new_camp_id, alert_id=alert.alert_id))
        await session.flush()
        return new_campaign


correlation_service = CorrelationService()
