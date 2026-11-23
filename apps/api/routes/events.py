"""
AgentShield AI — Security Events Routes (Phase 11).
"""

from __future__ import annotations

import math
from datetime import datetime
from typing import Any

from fastapi import APIRouter, HTTPException, Query, status
from sqlalchemy import func, select

from apps.api.dependencies import CurrentUser, DbSession
from agentshield.database.models.security_event import SecurityEventModel
from agentshield.services.schemas import PaginatedResponse, SecurityEventResponse

router = APIRouter(prefix="/events", tags=["Security Events"])


@router.get("", response_model=PaginatedResponse[SecurityEventResponse])
async def list_events(
    user: CurrentUser,
    db: DbSession,
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=200),
    event_type: str | None = None,
    severity: str | None = None,
    component: str | None = None,
    agent_id: str | None = None,
    tool_name: str | None = None,
    decision: str | None = None,
    trace_id: str | None = None,
    correlation_id: str | None = None,
    from_time: datetime | None = None,
    to_time: datetime | None = None,
) -> PaginatedResponse[SecurityEventResponse]:
    """Retrieve security events matching filters with tenant isolation."""
    query = select(SecurityEventModel).where(
        (SecurityEventModel.tenant_id == user.id) | (SecurityEventModel.tenant_id.is_(None))
    )
    count_query = select(func.count(SecurityEventModel.id)).where(
        (SecurityEventModel.tenant_id == user.id) | (SecurityEventModel.tenant_id.is_(None))
    )

    if event_type:
        query = query.where(SecurityEventModel.event_type == event_type)
        count_query = count_query.where(SecurityEventModel.event_type == event_type)
    if severity:
        query = query.where(SecurityEventModel.severity == severity.upper())
        count_query = count_query.where(SecurityEventModel.severity == severity.upper())
    if component:
        query = query.where(SecurityEventModel.component == component.lower())
        count_query = count_query.where(SecurityEventModel.component == component.lower())
    if agent_id:
        query = query.where(SecurityEventModel.agent_id == agent_id)
        count_query = count_query.where(SecurityEventModel.agent_id == agent_id)
    if tool_name:
        query = query.where(SecurityEventModel.tool_name == tool_name)
        count_query = count_query.where(SecurityEventModel.tool_name == tool_name)
    if decision:
        query = query.where(SecurityEventModel.decision == decision.upper())
        count_query = count_query.where(SecurityEventModel.decision == decision.upper())
    if trace_id:
        query = query.where(SecurityEventModel.trace_id == trace_id)
        count_query = count_query.where(SecurityEventModel.trace_id == trace_id)
    if correlation_id:
        query = query.where(SecurityEventModel.correlation_id == correlation_id)
        count_query = count_query.where(SecurityEventModel.correlation_id == correlation_id)
    if from_time:
        query = query.where(SecurityEventModel.created_at >= from_time)
        count_query = count_query.where(SecurityEventModel.created_at >= from_time)
    if to_time:
        query = query.where(SecurityEventModel.created_at <= to_time)
        count_query = count_query.where(SecurityEventModel.created_at <= to_time)

    total = (await db.execute(count_query)).scalar() or 0
    offset = (page - 1) * size
    query = query.order_by(SecurityEventModel.created_at.desc()).offset(offset).limit(size)
    items = (await db.execute(query)).scalars().all()

    pages = math.ceil(total / size) if size > 0 else 0
    return PaginatedResponse(
        items=[SecurityEventResponse.model_validate(i) for i in items],
        total=total,
        page=page,
        size=size,
        pages=pages,
    )


@router.get("/{event_id}", response_model=SecurityEventResponse)
async def get_event(
    event_id: str,
    user: CurrentUser,
    db: DbSession,
) -> SecurityEventResponse:
    """Retrieve an individual security event by id."""
    stmt = select(SecurityEventModel).where(
        SecurityEventModel.id == event_id,
        (SecurityEventModel.tenant_id == user.id) | (SecurityEventModel.tenant_id.is_(None)),
    )
    event = (await db.execute(stmt)).scalar_one_or_none()
    if not event:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Security event not found.")
    return SecurityEventResponse.model_validate(event)
