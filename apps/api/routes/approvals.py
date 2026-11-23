"""
AgentShield AI — Approvals Routes (Phase 10).

Provides complete human-in-the-loop approval management endpoints with role-based
authorization, argument inspection, approval history, and execution resumption.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, status

from apps.api.dependencies import CurrentUser, DbSession, require_permission
from agentshield.core.exceptions import ApprovalNotFoundError, AuthorizationError, ValidationError
from agentshield.execution.exceptions import ApprovalVerificationError
from agentshield.security.rbac import Permission, UserRole
from agentshield.services.approval_service import ApprovalService
from agentshield.services.schemas import (
    ApprovalApproveRequest,
    ApprovalCancelRequest,
    ApprovalCreate,
    ApprovalDetailResponse,
    ApprovalHistoryResponse,
    ApprovalRejectRequest,
    ApprovalResponse,
    ApprovalUpdate,
    PaginatedResponse,
)

router = APIRouter(prefix="/approvals", tags=["Approvals"])


@router.get("", response_model=PaginatedResponse[ApprovalResponse])
async def list_approvals(
    user: CurrentUser,
    db: DbSession,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    status_filter: str | None = Query(None, alias="status"),
    agent_id: str | None = Query(None),
    tool_name: str | None = Query(None),
    search: str | None = Query(None),
    _perm: None = Depends(require_permission(Permission.APPROVAL_VIEW)),
) -> PaginatedResponse[ApprovalResponse]:
    """List pending and resolved approval requests with optional filters."""
    service = ApprovalService(db)
    return await service.list_approvals(
        user.id,
        page=page,
        size=size,
        status=status_filter,
        agent_id=agent_id,
        tool_name=tool_name,
        search=search,
    )


@router.get("/{approval_id}", response_model=ApprovalDetailResponse)
async def get_approval(
    approval_id: str,
    user: CurrentUser,
    db: DbSession,
    _perm: None = Depends(require_permission(Permission.APPROVAL_VIEW)),
) -> ApprovalDetailResponse:
    """Get full details of a single approval request, including sanitized arguments and threat findings."""
    service = ApprovalService(db)
    approval = await service.get_detail(approval_id, user.id)
    if not approval:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Approval request not found.")
    return approval


@router.post("/{approval_id}/approve", response_model=ApprovalResponse)
async def approve_request(
    approval_id: str,
    data: ApprovalApproveRequest,
    user: CurrentUser,
    db: DbSession,
    _perm: None = Depends(require_permission(Permission.APPROVAL_DECIDE)),
) -> ApprovalResponse:
    """Approve a pending request and resume execution through the gateway."""
    service = ApprovalService(db)
    user_role = getattr(user, "role", UserRole.OWNER.value)
    try:
        return await service.approve_request(
            approval_id=approval_id,
            user_id=user.id,
            user_role=user_role,
            comment=data.comment,
        )
    except ApprovalNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc.message)) from exc
    except (ApprovalVerificationError, ValidationError) as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    except AuthorizationError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc.message)) from exc


@router.post("/{approval_id}/reject", response_model=ApprovalResponse)
async def reject_request(
    approval_id: str,
    data: ApprovalRejectRequest,
    user: CurrentUser,
    db: DbSession,
    _perm: None = Depends(require_permission(Permission.APPROVAL_DECIDE)),
) -> ApprovalResponse:
    """Reject a pending request, halting tool execution."""
    service = ApprovalService(db)
    user_role = getattr(user, "role", UserRole.OWNER.value)
    try:
        return await service.reject_request(
            approval_id=approval_id,
            user_id=user.id,
            user_role=user_role,
            rejection_reason=data.reason,
        )
    except ApprovalNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc.message)) from exc
    except (ApprovalVerificationError, ValidationError) as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    except AuthorizationError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc.message)) from exc


@router.post("/{approval_id}/cancel", response_model=ApprovalResponse)
async def cancel_request(
    approval_id: str,
    data: ApprovalCancelRequest,
    user: CurrentUser,
    db: DbSession,
    _perm: None = Depends(require_permission(Permission.APPROVAL_DECIDE)),
) -> ApprovalResponse:
    """Cancel a pending approval request."""
    service = ApprovalService(db)
    user_role = getattr(user, "role", UserRole.OWNER.value)
    try:
        return await service.cancel_request(
            approval_id=approval_id,
            user_id=user.id,
            user_role=user_role,
            reason=data.reason,
        )
    except ApprovalNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc.message)) from exc
    except (ApprovalVerificationError, ValidationError) as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    except AuthorizationError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc.message)) from exc


@router.get("/{approval_id}/history", response_model=list[ApprovalHistoryResponse])
async def get_approval_history(
    approval_id: str,
    user: CurrentUser,
    db: DbSession,
    _perm: None = Depends(require_permission(Permission.APPROVAL_VIEW)),
) -> list[ApprovalHistoryResponse]:
    """Get the immutable audit history of transitions for an approval request."""
    service = ApprovalService(db)
    return await service.get_history(approval_id, user.id)


@router.patch("/{approval_id}", response_model=ApprovalResponse)
async def update_approval_status(
    approval_id: str,
    data: ApprovalUpdate,
    user: CurrentUser,
    db: DbSession,
    _perm: None = Depends(require_permission(Permission.APPROVAL_DECIDE)),
) -> ApprovalResponse:
    """Legacy approval update endpoint for Phase 3 compatibility."""
    service = ApprovalService(db)
    try:
        return await service.update_status(approval_id, user.id, data)
    except ApprovalNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc.message)) from exc
    except ApprovalVerificationError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@router.post("", response_model=ApprovalResponse, status_code=status.HTTP_201_CREATED)
async def create_approval_request(
    data: ApprovalCreate,
    user: CurrentUser,
    db: DbSession,
) -> ApprovalResponse:
    """Create a standalone pending approval request."""
    service = ApprovalService(db)
    return await service.create_approval_request(user.id, data)
