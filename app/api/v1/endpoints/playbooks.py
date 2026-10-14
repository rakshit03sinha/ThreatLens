"""ThreatLens Incident Playbooks Endpoints."""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.db.session import get_db
from app.models.investigation import Playbook
from app.schemas.investigation import PlaybookResponse

router = APIRouter()


@router.get("", response_model=List[PlaybookResponse], summary="Search and list SOC runbooks and playbooks")
async def list_playbooks(
    category: Optional[str] = Query(None, description="Category filter (Credential Access, Lateral Movement, etc.)"),
    technique: Optional[str] = Query(None, description="MITRE ATT&CK technique filter (e.g. T1110)"),
    search: Optional[str] = Query(None, description="Keyword search in title or description"),
    db: AsyncSession = Depends(get_db),
):
    stmt = select(Playbook)
    if category:
        stmt = stmt.where(Playbook.category == category)
    if technique:
        stmt = stmt.where(Playbook.attack_technique == technique)
    if search:
        pat = f"%{search}%"
        stmt = stmt.where(Playbook.title.ilike(pat) | Playbook.description.ilike(pat))

    playbooks = (await db.execute(stmt)).scalars().all()
    return playbooks


@router.get("/{playbook_id}", response_model=PlaybookResponse, summary="Get playbook details by ID")
async def get_playbook(playbook_id: str, db: AsyncSession = Depends(get_db)):
    stmt = select(Playbook).where(Playbook.playbook_id == playbook_id)
    pb = (await db.execute(stmt)).scalars().first()
    if not pb:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Playbook '{playbook_id}' not found")
    return pb
