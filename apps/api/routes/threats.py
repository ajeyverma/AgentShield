"""
AgentShield AI — Threats Routes.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query, status

from apps.api.dependencies import CurrentUser, DbSession
from agentshield.core.exceptions import AuthorizationError
from agentshield.services.schemas import PaginatedResponse, ThreatCreate, ThreatResponse, ThreatUpdate
from agentshield.services.threat_service import ThreatService

router = APIRouter(prefix="/threats", tags=["Threats"])


@router.get("", response_model=PaginatedResponse[ThreatResponse])
async def list_threats(
    user: CurrentUser,
    db: DbSession,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    status_filter: str | None = Query(None, alias="status"),
    severity: str | None = None,
) -> PaginatedResponse[ThreatResponse]:
    """List recorded threat events for the authenticated user."""
    service = ThreatService(db)
    return await service.list_threats(
        user.id,
        page=page,
        size=size,
        status=status_filter,
        severity=severity,
    )


@router.get("/{threat_id}", response_model=ThreatResponse)
async def get_threat(
    threat_id: str,
    user: CurrentUser,
    db: DbSession,
) -> ThreatResponse:
    """Get a specific threat event."""
    service = ThreatService(db)
    threat = await service.get_by_id(threat_id, user.id)
    if not threat:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Threat event not found.")
    return threat


@router.patch("/{threat_id}", response_model=ThreatResponse)
async def update_threat(
    threat_id: str,
    data: ThreatUpdate,
    user: CurrentUser,
    db: DbSession,
) -> ThreatResponse:
    """Update status of a threat event (open, investigating, resolved, dismissed)."""
    service = ThreatService(db)
    try:
        return await service.update_status(threat_id, user.id, data)
    except AuthorizationError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc.message)) from exc


@router.post("", response_model=ThreatResponse, status_code=status.HTTP_201_CREATED)
async def record_threat(
    data: ThreatCreate,
    user: CurrentUser,
    db: DbSession,
) -> ThreatResponse:
    """Record a detected threat event."""
    service = ThreatService(db)
    return await service.record_threat(user.id, data)
