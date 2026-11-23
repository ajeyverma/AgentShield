"""
AgentShield AI — FastAPI Request Dependencies.

Provides database session injection, user authentication via JWT bearer tokens,
and agent authentication via cryptographic credentials.
"""

from __future__ import annotations

import logging
from typing import Annotated

from fastapi import Depends, Header, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession

from agentshield.core.exceptions import AuthenticationError
from agentshield.core.security import decode_access_token
from agentshield.database.models.agent import Agent
from agentshield.database.models.user import User
from agentshield.database.session import get_async_session
from agentshield.identity.service import AgentService, UserService

logger = logging.getLogger("agentshield.api.deps")

security_bearer = HTTPBearer(auto_error=False)


# ---------------------------------------------------------------------------
# Database Session
# ---------------------------------------------------------------------------

DbSession = Annotated[AsyncSession, Depends(get_async_session)]


# ---------------------------------------------------------------------------
# User Authentication Dependency
# ---------------------------------------------------------------------------


async def get_current_user(
    session: DbSession,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(security_bearer)],
) -> User:
    """Validate JWT token from Authorization header and return active User.

    Raises:
        HTTPException 401: If token is missing, expired, or invalid.
        HTTPException 403: If user account is inactive.
    """
    if not credentials or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Please provide a Bearer access token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = credentials.credentials
    try:
        payload = decode_access_token(token)
    except AuthenticationError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc.message),
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token subject missing.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user_service = UserService(session)
    user = await user_service.repo.get_by_id(user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User no longer exists.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is deactivated.",
        )

    return user


CurrentUser = Annotated[User, Depends(get_current_user)]


# ---------------------------------------------------------------------------
# Agent Authentication Dependency
# ---------------------------------------------------------------------------


async def get_authenticated_agent(
    session: DbSession,
    x_agent_credential: Annotated[str | None, Header(alias="X-Agent-Credential")] = None,
    bearer_credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(security_bearer)] = None,
) -> Agent:
    """Authenticate an AI agent via header or bearer token.

    Never trusts agent identity claims without cryptographic credential validation.
    """
    raw_credential = x_agent_credential
    if not raw_credential and bearer_credentials:
        raw_credential = bearer_credentials.credentials

    if not raw_credential:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing agent credential. Provide X-Agent-Credential header.",
        )

    agent_service = AgentService(session)
    try:
        agent_resp = await agent_service.authenticate_agent(raw_credential)
    except AuthenticationError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc.message),
        ) from exc

    agent = await agent_service.repo.get_by_id(agent_resp.id)
    if not agent or agent.status != "active":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Agent is deactivated or not found.",
        )

    return agent


AuthenticatedAgent = Annotated[Agent, Depends(get_authenticated_agent)]

