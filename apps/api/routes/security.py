"""
AgentShield AI — Security Decision API Routes (Phase 4).

Exposes action evaluation and decision history endpoints.
"""

from __future__ import annotations

import logging
from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, Query, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select

from apps.api.dependencies import CurrentUser, DbSession, security_bearer
from agentshield.contracts.action import ActionRequest
from agentshield.contracts.decision import SecurityDecision
from agentshield.core.exceptions import AuthenticationError
from agentshield.core.security import decode_access_token
from agentshield.database.models.agent import Agent
from agentshield.identity.service import AgentService, UserService
from agentshield.services.schemas import PaginatedResponse
from agentshield.services.security_service import SecurityService

logger = logging.getLogger("agentshield.api.security")

router = APIRouter(prefix="/security", tags=["Security Core"])


@router.post("/evaluate", response_model=SecurityDecision, status_code=status.HTTP_200_OK)
async def evaluate_action(
    request: ActionRequest,
    db: DbSession,
    x_agent_credential: Annotated[str | None, Header(alias="X-Agent-Credential")] = None,
    bearer_credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(security_bearer)] = None,
) -> SecurityDecision:
    """Evaluate an AI Agent Action Request and return an authoritative SecurityDecision.

    Authentication:
        - Agent Mode: Provide valid `X-Agent-Credential` header.
        - User/Integration Mode: Provide valid `Authorization: Bearer <user_token>`.
    """
    user_id: str | None = None
    agent: Agent | None = None
    agent_service = AgentService(db)

    # 1. Attempt agent credential authentication
    raw_cred = x_agent_credential
    if not raw_cred and bearer_credentials and bearer_credentials.credentials.startswith("ash_"):
        raw_cred = bearer_credentials.credentials

    if raw_cred:
        try:
            agent_resp = await agent_service.authenticate_agent(raw_cred)
            agent = await agent_service.repo.get_by_id(agent_resp.id)
            if agent:
                user_id = agent.owner_user_id
        except AuthenticationError as exc:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc.message)) from exc

    # 2. Alternatively, authenticate via user JWT
    if not user_id and bearer_credentials and bearer_credentials.credentials:
        try:
            payload = decode_access_token(bearer_credentials.credentials)
            user_id = payload.get("sub")
            if user_id:
                user_service = UserService(db)
                user = await user_service.repo.get_by_id(user_id)
                if not user or not user.is_active:
                    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid user.")

                # If request specifies agent_id, verify user owns this agent
                if request.agent_id:
                    agent = await agent_service.repo.get_by_id_and_owner(str(request.agent_id), user_id)
                    if not agent:
                        raise HTTPException(
                            status_code=status.HTTP_404_NOT_FOUND,
                            detail=f"Agent '{request.agent_id}' not found for authenticated user.",
                        )
                else:
                    # Look up first active agent or error
                    agents = await agent_service.repo.list_by_owner(user_id, limit=1)
                    if agents:
                        agent = agents[0]
                    else:
                        raise HTTPException(
                            status_code=status.HTTP_400_BAD_REQUEST,
                            detail="No agent found. Register an agent before evaluating actions.",
                        )
        except AuthenticationError as exc:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc.message)) from exc

    if not user_id or not agent:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Provide X-Agent-Credential or Bearer token.",
        )

    # 3. Evaluate and persist decision
    service = SecurityService(db)
    return await service.evaluate_and_record(
        user_id=user_id,
        agent=agent,
        request=request,
    )


@router.get("/decisions", response_model=PaginatedResponse[dict])
async def list_security_decisions(
    user: CurrentUser,
    db: DbSession,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    agent_id: str | None = None,
    decision: str | None = None,
    risk_level: str | None = None,
) -> PaginatedResponse[dict]:
    """Retrieve historical security decisions for the authenticated user."""
    service = SecurityService(db)
    return await service.list_decisions(
        user_id=user.id,
        page=page,
        size=size,
        agent_id=agent_id,
        decision=decision,
        risk_level=risk_level,
    )


@router.get("/decisions/{decision_id}", response_model=dict)
async def get_security_decision(
    decision_id: str,
    user: CurrentUser,
    db: DbSession,
) -> dict:
    """Retrieve details for a specific security decision."""
    service = SecurityService(db)
    dec = await service.get_decision_by_id(decision_id, user.id)
    if not dec:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Security decision not found.")
    return dec
