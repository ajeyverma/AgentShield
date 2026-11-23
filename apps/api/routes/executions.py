"""
AgentShield AI — Controlled Tool Execution Routes (Phase 6).
"""

from __future__ import annotations

import uuid
from fastapi import APIRouter, HTTPException, Query, status

from agentshield.contracts.execution import (
    ExecutionApprovalRequest,
    ExecutionRequest,
    ToolExecutionResponse,
)
from agentshield.core.exceptions import AuthorizationError
from agentshield.database.models.agent import Agent
from agentshield.execution.exceptions import (
    ApprovalVerificationError,
    ExecutionGatewayError,
    IdempotencyConflictError,
)
from agentshield.identity.service import AgentService
from agentshield.services.execution_service import ExecutionService
from agentshield.services.schemas import PaginatedResponse
from apps.api.dependencies import CurrentUser, DbSession

router = APIRouter(prefix="/executions", tags=["Controlled Executions"])


@router.post("", response_model=ToolExecutionResponse, status_code=status.HTTP_200_OK)
async def submit_execution(
    payload: ExecutionRequest,
    user: CurrentUser,
    db: DbSession,
) -> ToolExecutionResponse:
    """Submit a tool execution request through the Controlled Execution Gateway.

    Mandatory authorization flow: Agent Auth -> Validation -> Threat Analysis ->
    Phase 4 Security Evaluation -> Authorization Grant -> Adapter Execution.
    """
    # Verify agent ownership
    agent_id = str(payload.agent_id)
    agent_service = AgentService(db)
    try:
        agent = await agent_service.get_agent(agent_id, user.id)
    except AuthorizationError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Agent '{agent_id}' not found or access denied.",
        )

    # Attach verified user identity
    payload.user_id = user.id

    service = ExecutionService(db)
    try:
        return await service.execute_request(
            user_id=user.id,
            agent=agent,
            request=payload,
        )
    except IdempotencyConflictError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc.message)) from exc
    except ExecutionGatewayError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc.message)) from exc


@router.get("", response_model=PaginatedResponse[ToolExecutionResponse])
async def list_executions(
    user: CurrentUser,
    db: DbSession,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    agent_id: str | None = None,
    tool_name: str | None = None,
    status_filter: str | None = Query(None, alias="status"),
    decision: str | None = None,
) -> PaginatedResponse[ToolExecutionResponse]:
    """List execution history with pagination and status filters."""
    service = ExecutionService(db)
    return await service.list_executions(
        user_id=user.id,
        page=page,
        size=size,
        agent_id=agent_id,
        tool_name=tool_name,
        status=status_filter,
        decision=decision,
    )


@router.get("/{execution_id}", response_model=ToolExecutionResponse)
async def get_execution(
    execution_id: str,
    user: CurrentUser,
    db: DbSession,
) -> ToolExecutionResponse:
    """Retrieve detailed state and sanitized result of a specific execution."""
    service = ExecutionService(db)
    res = await service.get_execution_by_id(execution_id, user.id)
    if not res:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Execution '{execution_id}' not found.",
        )
    return res


@router.post("/{execution_id}/approve", response_model=ToolExecutionResponse)
async def approve_execution(
    execution_id: str,
    user: CurrentUser,
    db: DbSession,
    payload: ExecutionApprovalRequest | None = None,
) -> ToolExecutionResponse:
    """Human supervisor approves a PENDING_APPROVAL tool execution.

    Protected strictly by human user permissions; cannot be called with agent credentials.
    Revalidates policy and argument hash before single-use execution.
    """
    service = ExecutionService(db)
    try:
        notes = payload.approval_notes if payload else None
        return await service.approve_and_execute(
            execution_id=execution_id,
            user_id=user.id,
            notes=notes,
        )
    except AuthorizationError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc.message)) from exc
    except ApprovalVerificationError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc.message)) from exc


@router.post("/{execution_id}/cancel", response_model=ToolExecutionResponse)
async def cancel_execution(
    execution_id: str,
    user: CurrentUser,
    db: DbSession,
) -> ToolExecutionResponse:
    """Cancel a pending tool execution."""
    service = ExecutionService(db)
    try:
        return await service.cancel_execution(
            execution_id=execution_id,
            user_id=user.id,
        )
    except AuthorizationError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc.message)) from exc
    except ApprovalVerificationError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc.message)) from exc
