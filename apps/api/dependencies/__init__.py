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


# ---------------------------------------------------------------------------
# Universal Caller Identity (User or Agent)
# ---------------------------------------------------------------------------


class CallerContext:
    """Authenticated caller identity, either human user or AI agent."""

    def __init__(self, user_id: str, agent: Agent | None = None, is_agent: bool = False) -> None:
        self.user_id = user_id
        self.agent = agent
        self.is_agent = is_agent


async def get_caller_identity(
    session: DbSession,
    x_agent_credential: Annotated[str | None, Header(alias="X-Agent-Credential")] = None,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(security_bearer)] = None,
) -> CallerContext:
    """Authenticate caller as either a human User (via JWT) or an AI Agent (via credential)."""
    # 1. Check explicit X-Agent-Credential header
    if x_agent_credential:
        agent_service = AgentService(session)
        try:
            agent_resp = await agent_service.authenticate_agent(x_agent_credential)
            agent = await agent_service.repo.get_by_id(agent_resp.id)
            if not agent or agent.status != "active":
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Agent inactive or not found.")
            return CallerContext(user_id=agent.owner_user_id, agent=agent, is_agent=True)
        except AuthenticationError as exc:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc.message)) from exc

    # 2. Check Bearer token
    if not credentials or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Provide Bearer token or X-Agent-Credential header.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = credentials.credentials
    # Try decoding as user JWT first
    try:
        payload = decode_access_token(token)
        user_id = payload.get("sub")
        if user_id:
            user_service = UserService(session)
            user = await user_service.repo.get_by_id(user_id)
            if user and user.is_active:
                return CallerContext(user_id=user.id, agent=None, is_agent=False)
    except Exception:
        pass

    # If not a user JWT, check if it's an agent credential passed as Bearer token
    agent_service = AgentService(session)
    try:
        agent_resp = await agent_service.authenticate_agent(token)
        agent = await agent_service.repo.get_by_id(agent_resp.id)
        if agent and agent.status == "active":
            return CallerContext(user_id=agent.owner_user_id, agent=agent, is_agent=True)
    except Exception:
        pass

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid access token or agent credentials.",
        headers={"WWW-Authenticate": "Bearer"},
    )


CallerIdentity = Annotated[CallerContext, Depends(get_caller_identity)]


# ---------------------------------------------------------------------------
# Role & Permission Dependencies (Phase 10 RBAC)
# ---------------------------------------------------------------------------

from agentshield.security.rbac import (
    Permission,
    UserRole,
    can_approve_risk,
    has_permission,
    parse_user_role,
)


def require_permission(permission: Permission):
    """Enforce specific granular permission on authenticated human user."""
    async def _perm_dependency(user: CurrentUser) -> User:
        role = getattr(user, "role", "OWNER")
        if not has_permission(role, permission):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied: permission '{permission.value}' required for role '{role}'.",
            )
        return user
    return _perm_dependency


def require_role(*roles: UserRole):
    """Enforce that current user possesses at least one of the required roles."""
    async def _role_dependency(user: CurrentUser) -> User:
        user_role = parse_user_role(getattr(user, "role", "OWNER"))
        if user_role not in roles and not getattr(user, "is_superuser", False):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied: role '{user_role.value}' is not authorized for this resource.",
            )
        return user
    return _role_dependency



