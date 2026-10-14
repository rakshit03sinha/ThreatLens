"""ThreatLens Audit Logging Service."""

from typing import Any, Dict, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.investigation import AuditLog


class AuditService:
    """Service to record administrative, security, and analyst actions."""

    async def log_action(
        self,
        session: AsyncSession,
        action: str,
        resource_type: str,
        resource_id: Optional[str] = None,
        username: str = "system",
        user_id: Optional[int] = None,
        details: Optional[Dict[str, Any]] = None,
        ip_address: Optional[str] = None,
    ) -> AuditLog:
        audit_entry = AuditLog(
            user_id=user_id,
            username=username,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            details=details or {},
            ip_address=ip_address,
        )
        session.add(audit_entry)
        await session.flush()
        return audit_entry


audit_service = AuditService()
