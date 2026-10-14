"""ThreatLens Detection Rules Management Endpoints."""

from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.api.deps import get_current_user_optional
from app.db.session import get_db
from app.models.rule import DetectionRule
from app.models.user import User
from app.rules.catalogue import ALL_RULES
from app.rules.engine import detection_engine
from app.schemas.common import MessageResponse
from app.schemas.rule import DetectionRuleResponse, RuleToggleRequest
from app.services.audit import audit_service

router = APIRouter()


@router.get("", summary="List all 11 detection rules and status")
async def list_rules(db: AsyncSession = Depends(get_db)):
    """Returns all 11 detection rules aligned with MITRE ATT&CK."""
    stmt = select(DetectionRule)
    db_rules = (await db.execute(stmt)).scalars().all()
    if db_rules:
        return db_rules

    # Fallback to in-memory catalogue
    return [
        {
            "id": idx + 1,
            "rule_id": r.rule_id,
            "name": r.name,
            "description": r.description,
            "severity": r.severity,
            "status": "enabled" if detection_engine.is_rule_enabled(r.rule_id) else "disabled",
            "tactic": r.attack_tactic,
            "technique_id": r.attack_technique,
            "technique_name": r.attack_technique_name,
            "window_seconds": r.default_window_seconds,
            "threshold": r.default_threshold,
            "version": r.version,
            "parameters": {},
            "created_at": "2026-10-14T00:00:00Z",
            "updated_at": "2026-10-14T00:00:00Z",
        }
        for idx, r in enumerate(ALL_RULES)
    ]


@router.get("/{rule_id}", summary="Get detection rule and MITRE metadata by ID")
async def get_rule(rule_id: str, db: AsyncSession = Depends(get_db)):
    stmt = select(DetectionRule).where(DetectionRule.rule_id == rule_id)
    rule = (await db.execute(stmt)).scalars().first()
    if rule:
        return rule

    # Catalogue lookup
    r = detection_engine.get_rule(rule_id)
    if not r:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Rule '{rule_id}' not found")

    return {
        "rule_id": r.rule_id,
        "name": r.name,
        "description": r.description,
        "severity": r.severity,
        "status": "enabled" if detection_engine.is_rule_enabled(r.rule_id) else "disabled",
        "tactic": r.attack_tactic,
        "technique_id": r.attack_technique,
        "technique_name": r.attack_technique_name,
        "window_seconds": r.default_window_seconds,
        "threshold": r.default_threshold,
        "version": r.version,
    }


@router.patch("/{rule_id}/status", response_model=MessageResponse, summary="Enable or disable a detection rule")
async def toggle_rule_status(
    rule_id: str,
    payload: RuleToggleRequest,
    current_user: User = Depends(get_current_user_optional),
    db: AsyncSession = Depends(get_db),
):
    enabled = payload.status == "enabled"
    success = detection_engine.set_rule_status(rule_id, enabled)
    if not success:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Rule '{rule_id}' not found in engine")

    # Update in DB if present
    stmt = select(DetectionRule).where(DetectionRule.rule_id == rule_id)
    db_rule = (await db.execute(stmt)).scalars().first()
    if db_rule:
        db_rule.status = payload.status

    # Audit log
    username = current_user.username if current_user else "anonymous_analyst"
    await audit_service.log_action(
        session=db,
        action=f"rule_{payload.status}",
        resource_type="rule",
        resource_id=rule_id,
        username=username,
        details={"status": payload.status},
    )

    return MessageResponse(message=f"Rule {rule_id} status updated to '{payload.status}' successfully.")
