"""
AgentShield AI — Approvals Routes.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query, status

from apps.api.dependencies import CurrentUser, DbSession
from agentshield.core.exceptions import ApprovalNotFoundError
from agentshield.services.approval_service import ApprovalService
from agentshield.services.schemas import (
    ApprovalCreate,
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
) -> PaginatedResponse[ApprovalResponse]:
    """List pending and resolved approval requests."""
    service = ApprovalService(db)
    return await service.list_approvals(user.id, page=page, size=size, status=status_filter)


@router.get("/{approval_id}", response_model=ApprovalResponse)
async def get_approval(
    approval_id: str,
    user: CurrentUser,
    db: DbSession,
) -> ApprovalResponse:
    """Get a single approval request."""
    service = ApprovalService(db)
    approval = await service.get_by_id(approval_id, user.id)
    if not approval:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Approval request not found.")
    return approval


@router.patch("/{approval_id}", response_model=ApprovalResponse)
async def update_approval_status(
    approval_id: str,
    data: ApprovalUpdate,
    user: CurrentUser,
    db: DbSession,
) -> ApprovalResponse:
    """Approve or reject a pending approval request.

    Note (Phase 3): Updates persisted status only. Tool execution is handled in Phase 4.
    """
    service = ApprovalService(db)
    try:
        return await service.update_status(approval_id, user.id, data)
    except ApprovalNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc.message)) from exc


@router.post("", response_model=ApprovalResponse, status_code=status.HTTP_201_CREATED)
async def create_approval_request(
    data: ApprovalCreate,
    user: CurrentUser,
    db: DbSession,
) -> ApprovalResponse:
    """Create a pending approval request."""
    service = ApprovalService(db)
    return await service.create_approval_request(user.id, data)
