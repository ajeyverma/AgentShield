"""
AgentShield AI — Activity Routes.
"""

from __future__ import annotations

from typing import Any
from fastapi import APIRouter, HTTPException, Query, status

from apps.api.dependencies import CurrentUser, DbSession
from agentshield.services.activity_service import ActivityService
from agentshield.services.schemas import ActivityCreate, ActivityResponse, PaginatedResponse

router = APIRouter(prefix="/activity", tags=["Activity"])


@router.get("", response_model=PaginatedResponse[ActivityResponse])
async def list_activity(
    user: CurrentUser,
    db: DbSession,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    agent_id: str | None = None,
    decision: str | None = None,
    risk_level: str | None = None,
) -> PaginatedResponse[ActivityResponse]:
    """Retrieve paginated activity events for the authenticated user."""
    service = ActivityService(db)
    return await service.list_activity(
        user.id,
        page=page,
        size=size,
        agent_id=agent_id,
        decision=decision,
        risk_level=risk_level,
    )


@router.get("/{event_id}", response_model=ActivityResponse)
async def get_activity_event(
    event_id: str,
    user: CurrentUser,
    db: DbSession,
) -> ActivityResponse:
    """Retrieve a specific activity event record."""
    service = ActivityService(db)
    event = await service.get_by_id(event_id, user.id)
    if not event:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Activity event not found.")
    return event


@router.post("", response_model=ActivityResponse, status_code=status.HTTP_201_CREATED)
async def record_activity(
    data: ActivityCreate,
    user: CurrentUser,
    db: DbSession,
) -> ActivityResponse:
    """Record a tool activity event."""
    service = ActivityService(db)
    return await service.record_activity(user.id, data)


@router.delete("", status_code=status.HTTP_200_OK)
async def clear_activity(
    user: CurrentUser,
    db: DbSession,
) -> dict[str, Any]:
    """Clear all recorded activity events for the authenticated user."""
    service = ActivityService(db)
    deleted = await service.clear_activity(user.id)
    return {"message": "Activity events cleared successfully.", "deleted_count": deleted}
