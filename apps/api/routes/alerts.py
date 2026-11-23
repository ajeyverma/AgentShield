"""
AgentShield AI — Security Alerts Routes (Phase 11).
"""

from __future__ import annotations

import math
from datetime import UTC, datetime

from fastapi import APIRouter, HTTPException, Query, status
from sqlalchemy import func, select

from apps.api.dependencies import CurrentUser, DbSession
from agentshield.database.models.alert import SecurityAlertModel
from agentshield.services.schemas import AlertResponse, AlertUpdateStatus, PaginatedResponse

router = APIRouter(prefix="/alerts", tags=["Security Alerts"])


@router.get("", response_model=PaginatedResponse[AlertResponse])
async def list_alerts(
    user: CurrentUser,
    db: DbSession,
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=200),
    status_filter: str | None = Query(None, alias="status"),
    severity: str | None = None,
    agent_id: str | None = None,
) -> PaginatedResponse[AlertResponse]:
    """Retrieve security alerts matching filters."""
    query = select(SecurityAlertModel).where(
        (SecurityAlertModel.tenant_id == user.id) | (SecurityAlertModel.tenant_id.is_(None))
    )
    count_query = select(func.count(SecurityAlertModel.id)).where(
        (SecurityAlertModel.tenant_id == user.id) | (SecurityAlertModel.tenant_id.is_(None))
    )

    if status_filter:
        query = query.where(SecurityAlertModel.status == status_filter.lower())
        count_query = count_query.where(SecurityAlertModel.status == status_filter.lower())
    if severity:
        query = query.where(SecurityAlertModel.severity == severity.upper())
        count_query = count_query.where(SecurityAlertModel.severity == severity.upper())
    if agent_id:
        query = query.where(SecurityAlertModel.agent_id == agent_id)
        count_query = count_query.where(SecurityAlertModel.agent_id == agent_id)

    total = (await db.execute(count_query)).scalar() or 0
    offset = (page - 1) * size
    query = query.order_by(SecurityAlertModel.updated_at.desc()).offset(offset).limit(size)
    items = (await db.execute(query)).scalars().all()

    pages = math.ceil(total / size) if size > 0 else 0
    return PaginatedResponse(
        items=[AlertResponse.model_validate(i) for i in items],
        total=total,
        page=page,
        size=size,
        pages=pages,
    )


@router.get("/{alert_id}", response_model=AlertResponse)
async def get_alert(
    alert_id: str,
    user: CurrentUser,
    db: DbSession,
) -> AlertResponse:
    """Retrieve an alert by ID."""
    stmt = select(SecurityAlertModel).where(
        SecurityAlertModel.id == alert_id,
        (SecurityAlertModel.tenant_id == user.id) | (SecurityAlertModel.tenant_id.is_(None)),
    )
    alert = (await db.execute(stmt)).scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found.")
    return AlertResponse.model_validate(alert)


@router.patch("/{alert_id}/status", response_model=AlertResponse)
async def update_alert_status(
    alert_id: str,
    payload: AlertUpdateStatus,
    user: CurrentUser,
    db: DbSession,
) -> AlertResponse:
    """Update status of a security alert."""
    stmt = select(SecurityAlertModel).where(
        SecurityAlertModel.id == alert_id,
        (SecurityAlertModel.tenant_id == user.id) | (SecurityAlertModel.tenant_id.is_(None)),
    )
    alert = (await db.execute(stmt)).scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found.")

    alert.status = payload.status
    alert.updated_at = datetime.now(UTC)
    await db.commit()
    await db.refresh(alert)
    return AlertResponse.model_validate(alert)
