"""
AgentShield AI — Emergency Controls Routes (Phase 10).

Provides administrative endpoints for activating lockdown, pausing executions,
disabling agents/tools/MCP servers, and revoking emergency controls.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, status

from apps.api.dependencies import CurrentUser, DbSession, require_permission
from agentshield.core.exceptions import AuthorizationError, ValidationError
from agentshield.security.rbac import Permission, UserRole
from agentshield.services.emergency_service import EmergencyControlService
from agentshield.services.schemas import (
    EmergencyControlCreate,
    EmergencyControlResponse,
    EmergencyControlRevoke,
    EmergencyStatusResponse,
)

router = APIRouter(prefix="/security", tags=["Emergency Controls"])


@router.get("/emergency-status", response_model=EmergencyStatusResponse)
async def get_emergency_status(
    user: CurrentUser,
    db: DbSession,
) -> EmergencyStatusResponse:
    """Check current emergency security status and count of active controls."""
    service = EmergencyControlService(db)
    active_controls = await service.list_controls(user.id, active_only=True)
    is_lockdown = any(c.control_type in ("PAUSE_EXECUTIONS", "EMERGENCY_DENY_MODE") for c in active_controls)
    return EmergencyStatusResponse(
        is_lockdown_active=is_lockdown,
        active_controls_count=len(active_controls),
        active_controls=[EmergencyControlResponse.model_validate(c) for c in active_controls],
    )


@router.get("/emergency-controls", response_model=list[EmergencyControlResponse])
async def list_emergency_controls(
    user: CurrentUser,
    db: DbSession,
    active_only: bool = Query(False),
    _perm: None = Depends(require_permission(Permission.EMERGENCY_CONTROL)),
) -> list[EmergencyControlResponse]:
    """List all configured emergency controls."""
    service = EmergencyControlService(db)
    controls = await service.list_controls(user.id, active_only=active_only)
    return [EmergencyControlResponse.model_validate(c) for c in controls]


@router.post("/emergency-controls", response_model=EmergencyControlResponse, status_code=status.HTTP_201_CREATED)
async def activate_emergency_control(
    data: EmergencyControlCreate,
    user: CurrentUser,
    db: DbSession,
    _perm: None = Depends(require_permission(Permission.EMERGENCY_CONTROL)),
) -> EmergencyControlResponse:
    """Activate an emergency lockdown or disable an agent/tool/integration."""
    service = EmergencyControlService(db)
    user_role = getattr(user, "role", UserRole.OWNER.value)
    try:
        control = await service.activate_control(
            user_id=user.id,
            user_role=user_role,
            control_type=data.control_type,
            target_identifier=data.target_identifier,
            reason=data.reason,
            tenant_id=user.id,
        )
        return EmergencyControlResponse.model_validate(control)
    except (ValidationError, ValueError) as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    except AuthorizationError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc.message)) from exc


@router.post("/emergency-controls/{control_id}/revoke", response_model=EmergencyControlResponse)
async def revoke_emergency_control(
    control_id: str,
    data: EmergencyControlRevoke,
    user: CurrentUser,
    db: DbSession,
    _perm: None = Depends(require_permission(Permission.EMERGENCY_CONTROL)),
) -> EmergencyControlResponse:
    """Revoke an active emergency control, restoring normal operations."""
    service = EmergencyControlService(db)
    user_role = getattr(user, "role", UserRole.OWNER.value)
    try:
        control = await service.revoke_control(
            control_id=control_id,
            user_id=user.id,
            user_role=user_role,
            revocation_reason=data.reason,
        )
        return EmergencyControlResponse.model_validate(control)
    except ValidationError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except AuthorizationError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc.message)) from exc
