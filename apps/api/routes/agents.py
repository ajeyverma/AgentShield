"""
AgentShield AI — Agents Routes.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query, status

from apps.api.dependencies import CurrentUser, DbSession
from agentshield.core.exceptions import AuthenticationError, AuthorizationError
from agentshield.identity.schemas import (
    AgentAuthResponse,
    AgentAuthenticateRequest,
    AgentCreate,
    AgentCreatedResponse,
    AgentResponse,
    AgentUpdate,
)
from agentshield.identity.service import AgentService

router = APIRouter(prefix="/agents", tags=["Agents"])


@router.post("", response_model=AgentCreatedResponse, status_code=status.HTTP_201_CREATED)
async def create_agent(
    data: AgentCreate,
    user: CurrentUser,
    db: DbSession,
) -> AgentCreatedResponse:
    """Register a new AI Agent. Displays the raw credential token only once."""
    service = AgentService(db)
    return await service.register_agent(user.id, data)


@router.get("", response_model=list[AgentResponse])
async def list_agents(
    user: CurrentUser,
    db: DbSession,
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
) -> list[AgentResponse]:
    """List all agents belonging to the authenticated user."""
    service = AgentService(db)
    return await service.list_agents(user.id, skip=skip, limit=limit)


@router.get("/{agent_id}", response_model=AgentResponse)
async def get_agent(
    agent_id: str,
    user: CurrentUser,
    db: DbSession,
) -> AgentResponse:
    """Get details for a specific agent belonging to the authenticated user."""
    service = AgentService(db)
    try:
        return await service.get_agent(agent_id, user.id)
    except AuthorizationError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc.message)) from exc


@router.patch("/{agent_id}", response_model=AgentResponse)
async def update_agent(
    agent_id: str,
    data: AgentUpdate,
    user: CurrentUser,
    db: DbSession,
) -> AgentResponse:
    """Update agent details (name, description, status)."""
    service = AgentService(db)
    try:
        return await service.update_agent(agent_id, user.id, data)
    except AuthorizationError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc.message)) from exc


@router.delete("/{agent_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_agent(
    agent_id: str,
    user: CurrentUser,
    db: DbSession,
) -> None:
    """Delete an agent connector."""
    service = AgentService(db)
    try:
        await service.delete_agent(agent_id, user.id)
    except AuthorizationError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc.message)) from exc


@router.post("/{agent_id}/rotate-credential", response_model=AgentCreatedResponse)
async def rotate_agent_credential(
    agent_id: str,
    user: CurrentUser,
    db: DbSession,
) -> AgentCreatedResponse:
    """Rotate the security credential for an agent. Invalidates the old secret."""
    service = AgentService(db)
    try:
        return await service.rotate_credential(agent_id, user.id)
    except AuthorizationError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc.message)) from exc


@router.post("/authenticate", response_model=AgentAuthResponse)
async def authenticate_agent(
    data: AgentAuthenticateRequest,
    db: DbSession,
) -> AgentAuthResponse:
    """Authenticate an AI Agent using its raw credential token."""
    service = AgentService(db)
    try:
        agent = await service.authenticate_agent(data.credential)
        return AgentAuthResponse(authenticated=True, agent=agent)
    except AuthenticationError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc.message)) from exc
