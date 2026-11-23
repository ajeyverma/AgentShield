"""
AgentShield AI — Policies Routes (Phase 10).

Provides full security policy management endpoints, including structured conditions,
priority configuration, conflict detection, version history, and simulation.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, status

from apps.api.dependencies import CurrentUser, DbSession, require_permission
from agentshield.core.exceptions import AuthorizationError, PolicyNotFoundError, ValidationError
from agentshield.realtime.event_broadcaster import broadcaster
from agentshield.security.rbac import Permission
from agentshield.services.policy_service import PolicyService
from agentshield.services.schemas import (
    PaginatedResponse,
    PolicyConflictItem,
    PolicyCreate,
    PolicyResponse,
    PolicySimulationRequest,
    PolicySimulationResponse,
    PolicyUpdate,
    PolicyVersionResponse,
)

router = APIRouter(prefix="/policies", tags=["Policies"])


@router.get("", response_model=PaginatedResponse[PolicyResponse])
async def list_policies(
    user: CurrentUser,
    db: DbSession,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    category: str | None = None,
    is_enabled: bool | None = None,
    _perm: None = Depends(require_permission(Permission.POLICY_VIEW)),
) -> PaginatedResponse[PolicyResponse]:
    """List configured security policies for the authenticated user ordered by priority."""
    service = PolicyService(db)
    return await service.list_policies(user.id, page=page, size=size, category=category, is_enabled=is_enabled)


@router.post("", response_model=PolicyResponse, status_code=status.HTTP_201_CREATED)
async def create_policy(
    data: PolicyCreate,
    user: CurrentUser,
    db: DbSession,
    _perm: None = Depends(require_permission(Permission.POLICY_CREATE)),
) -> PolicyResponse:
    """Create a new security policy with priority, scopes, and structured conditions."""
    service = PolicyService(db)
    try:
        pol = await service.create_policy(user.id, data)
        await broadcaster.broadcast_event(user.id, "security.policy.updated", {"action": "created", "policy_id": pol.id})
        return pol
    except ValidationError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@router.get("/conflicts", response_model=list[PolicyConflictItem])
async def list_policy_conflicts(
    user: CurrentUser,
    db: DbSession,
    _perm: None = Depends(require_permission(Permission.POLICY_VIEW)),
) -> list[PolicyConflictItem]:
    """Analyze active policies for overlapping scopes, shadows, or opposing decisions."""
    service = PolicyService(db)
    return await service.list_conflicts(user.id)


@router.post("/simulate", response_model=PolicySimulationResponse)
async def simulate_policy(
    request: PolicySimulationRequest,
    user: CurrentUser,
    db: DbSession,
    _perm: None = Depends(require_permission(Permission.POLICY_VIEW)),
) -> PolicySimulationResponse:
    """Safely test and evaluate a synthetic action against active policies and threat detectors without executing tools."""
    service = PolicyService(db)
    return await service.simulate(user.id, request)


@router.get("/{policy_id}", response_model=PolicyResponse)
async def get_policy(
    policy_id: str,
    user: CurrentUser,
    db: DbSession,
    _perm: None = Depends(require_permission(Permission.POLICY_VIEW)),
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
    _perm: None = Depends(require_permission(Permission.POLICY_EDIT)),
) -> PolicyResponse:
    """Update policy attributes and record a new version snapshot."""
    service = PolicyService(db)
    try:
        pol = await service.update_policy(policy_id, user.id, data)
        await broadcaster.broadcast_event(user.id, "security.policy.updated", {"action": "updated", "policy_id": pol.id})
        return pol
    except PolicyNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc.message)) from exc
    except ValidationError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@router.post("/{policy_id}/enable", response_model=PolicyResponse)
async def enable_policy(
    policy_id: str,
    user: CurrentUser,
    db: DbSession,
    _perm: None = Depends(require_permission(Permission.POLICY_EDIT)),
) -> PolicyResponse:
    """Enable a security policy."""
    service = PolicyService(db)
    try:
        pol = await service.enable_policy(policy_id, user.id)
        await broadcaster.broadcast_event(user.id, "security.policy.updated", {"action": "enabled", "policy_id": pol.id})
        return pol
    except PolicyNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc.message)) from exc


@router.post("/{policy_id}/disable", response_model=PolicyResponse)
async def disable_policy(
    policy_id: str,
    user: CurrentUser,
    db: DbSession,
    _perm: None = Depends(require_permission(Permission.POLICY_EDIT)),
) -> PolicyResponse:
    """Disable a security policy."""
    service = PolicyService(db)
    try:
        pol = await service.disable_policy(policy_id, user.id)
        await broadcaster.broadcast_event(user.id, "security.policy.updated", {"action": "disabled", "policy_id": pol.id})
        return pol
    except PolicyNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc.message)) from exc


@router.post("/{policy_id}/duplicate", response_model=PolicyResponse, status_code=status.HTTP_201_CREATED)
async def duplicate_policy(
    policy_id: str,
    user: CurrentUser,
    db: DbSession,
    _perm: None = Depends(require_permission(Permission.POLICY_CREATE)),
) -> PolicyResponse:
    """Duplicate an existing policy as a new draft configuration."""
    service = PolicyService(db)
    try:
        pol = await service.duplicate_policy(policy_id, user.id)
        await broadcaster.broadcast_event(user.id, "security.policy.updated", {"action": "created", "policy_id": pol.id})
        return pol
    except PolicyNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc.message)) from exc


@router.get("/{policy_id}/history", response_model=list[PolicyVersionResponse])
async def get_policy_history(
    policy_id: str,
    user: CurrentUser,
    db: DbSession,
    _perm: None = Depends(require_permission(Permission.POLICY_VIEW)),
) -> list[PolicyVersionResponse]:
    """List historical version snapshots of a policy."""
    service = PolicyService(db)
    try:
        return await service.get_history(policy_id, user.id)
    except PolicyNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc.message)) from exc


@router.delete("/{policy_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_policy(
    policy_id: str,
    user: CurrentUser,
    db: DbSession,
    _perm: None = Depends(require_permission(Permission.POLICY_DELETE)),
) -> None:
    """Delete a custom security policy (system default policies cannot be deleted)."""
    service = PolicyService(db)
    try:
        await service.delete_policy(policy_id, user.id)
        await broadcaster.broadcast_event(user.id, "security.policy.updated", {"action": "deleted", "policy_id": policy_id})
    except PolicyNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc.message)) from exc
    except ValidationError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
