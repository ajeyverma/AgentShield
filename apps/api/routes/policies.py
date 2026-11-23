"""
AgentShield AI — Policies Routes.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query, status

from apps.api.dependencies import CurrentUser, DbSession
from agentshield.core.exceptions import PolicyNotFoundError
from agentshield.services.policy_service import PolicyService
from agentshield.services.schemas import PaginatedResponse, PolicyCreate, PolicyResponse, PolicyUpdate

router = APIRouter(prefix="/policies", tags=["Policies"])


@router.get("", response_model=PaginatedResponse[PolicyResponse])
async def list_policies(
    user: CurrentUser,
    db: DbSession,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    category: str | None = None,
) -> PaginatedResponse[PolicyResponse]:
    """List configured security policies for the authenticated user."""
    service = PolicyService(db)
    return await service.list_policies(user.id, page=page, size=size, category=category)


@router.post("", response_model=PolicyResponse, status_code=status.HTTP_201_CREATED)
async def create_policy(
    data: PolicyCreate,
    user: CurrentUser,
    db: DbSession,
) -> PolicyResponse:
    """Create a new security policy."""
    service = PolicyService(db)
    return await service.create_policy(user.id, data)


@router.get("/{policy_id}", response_model=PolicyResponse)
async def get_policy(
    policy_id: str,
    user: CurrentUser,
    db: DbSession,
) -> PolicyResponse:
    """Get a specific policy."""
    service = PolicyService(db)
    policy = await service.get_by_id(policy_id, user.id)
    if not policy:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Policy not found.")
    return policy


@router.patch("/{policy_id}", response_model=PolicyResponse)
async def update_policy(
    policy_id: str,
    data: PolicyUpdate,
    user: CurrentUser,
    db: DbSession,
) -> PolicyResponse:
    """Update policy attributes."""
    service = PolicyService(db)
    try:
        return await service.update_policy(policy_id, user.id, data)
    except PolicyNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc.message)) from exc


@router.delete("/{policy_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_policy(
    policy_id: str,
    user: CurrentUser,
    db: DbSession,
) -> None:
    """Delete a policy."""
    service = PolicyService(db)
    try:
        await service.delete_policy(policy_id, user.id)
    except PolicyNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc.message)) from exc
