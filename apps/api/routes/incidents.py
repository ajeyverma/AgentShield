"""
AgentShield AI — Incident Management Routes (Phase 11).
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query, status

from apps.api.dependencies import CurrentUser, DbSession
from agentshield.services.incident_service import IncidentService
from agentshield.services.schemas import (
    IncidentCreate,
    IncidentDetailResponse,
    IncidentNoteCreate,
    IncidentNoteResponse,
    IncidentResponse,
    IncidentUpdateStatus,
    PaginatedResponse,
)

router = APIRouter(prefix="/incidents", tags=["Incidents"])


@router.get("", response_model=PaginatedResponse[IncidentResponse])
async def list_incidents(
    user: CurrentUser,
    db: DbSession,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    status_filter: str | None = Query(None, alias="status"),
    severity: str | None = None,
    agent_id: str | None = None,
) -> PaginatedResponse[IncidentResponse]:
    """List security incidents for authenticated tenant."""
    svc = IncidentService(db)
    return await svc.list_incidents(
        tenant_id=user.id,
        page=page,
        size=size,
        status=status_filter,
        severity=severity,
        agent_id=agent_id,
    )


@router.post("", response_model=IncidentResponse, status_code=status.HTTP_201_CREATED)
async def create_incident(
    payload: IncidentCreate,
    user: CurrentUser,
    db: DbSession,
) -> IncidentResponse:
    """Open a new security incident."""
    svc = IncidentService(db)
    return await svc.create_incident(
        tenant_id=user.id,
        created_by=user.id,
        title=payload.title,
        description=payload.description,
        severity=payload.severity,
        agent_id=payload.agent_id,
        alert_id=payload.alert_id,
    )


@router.get("/{incident_id}", response_model=IncidentDetailResponse)
async def get_incident(
    incident_id: str,
    user: CurrentUser,
    db: DbSession,
) -> IncidentDetailResponse:
    """Retrieve full incident details including notes and history."""
    svc = IncidentService(db)
    incident = await svc.get_incident(incident_id=incident_id, tenant_id=user.id)
    if not incident:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found.")
    return incident


@router.patch("/{incident_id}/status", response_model=IncidentResponse)
async def transition_incident_status(
    incident_id: str,
    payload: IncidentUpdateStatus,
    user: CurrentUser,
    db: DbSession,
) -> IncidentResponse:
    """Transition incident status following lifecycle constraints."""
    svc = IncidentService(db)
    try:
        return await svc.transition_status(
            incident_id=incident_id,
            tenant_id=user.id,
            new_status=payload.status,
            actor_id=user.id,
            reason=payload.reason,
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post("/{incident_id}/notes", response_model=IncidentNoteResponse, status_code=status.HTTP_201_CREATED)
async def add_incident_note(
    incident_id: str,
    payload: IncidentNoteCreate,
    user: CurrentUser,
    db: DbSession,
) -> IncidentNoteResponse:
    """Add an investigation note to an active incident."""
    svc = IncidentService(db)
    try:
        return await svc.add_note(
            incident_id=incident_id,
            tenant_id=user.id,
            author_id=user.id,
            note=payload.note,
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
