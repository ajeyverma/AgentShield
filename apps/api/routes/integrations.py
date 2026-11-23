"""
AgentShield AI — Integrations Routes.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query, status

from apps.api.dependencies import CurrentUser, DbSession
from agentshield.core.exceptions import AuthorizationError
from agentshield.services.integration_service import IntegrationService
from agentshield.services.schemas import (
    IntegrationCreate,
    IntegrationResponse,
    IntegrationUpdate,
    PaginatedResponse,
)

router = APIRouter(prefix="/integrations", tags=["Integrations"])


@router.get("", response_model=PaginatedResponse[IntegrationResponse])
async def list_integrations(
    user: CurrentUser,
    db: DbSession,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
) -> PaginatedResponse[IntegrationResponse]:
    """List framework and platform integration records."""
    service = IntegrationService(db)
    return await service.list_integrations(user.id, page=page, size=size)


@router.post("", response_model=IntegrationResponse, status_code=status.HTTP_201_CREATED)
async def create_integration(
    data: IntegrationCreate,
    user: CurrentUser,
    db: DbSession,
) -> IntegrationResponse:
    """Create an integration connector configuration."""
    service = IntegrationService(db)
    return await service.create_integration(user.id, data)


@router.patch("/{integration_id}", response_model=IntegrationResponse)
async def update_integration(
    integration_id: str,
    data: IntegrationUpdate,
    user: CurrentUser,
    db: DbSession,
) -> IntegrationResponse:
    """Update integration settings or status."""
    service = IntegrationService(db)
    try:
        return await service.update_integration(integration_id, user.id, data)
    except AuthorizationError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc.message)) from exc


@router.delete("/{integration_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_integration(
    integration_id: str,
    user: CurrentUser,
    db: DbSession,
) -> None:
    """Delete an integration record."""
    service = IntegrationService(db)
    try:
        await service.delete_integration(integration_id, user.id)
    except AuthorizationError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc.message)) from exc
