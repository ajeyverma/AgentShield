"""
AgentShield AI — Identity Services.

Business logic for User and Agent authentication, authorization, and lifecycle.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from sqlalchemy.ext.asyncio import AsyncSession

from agentshield.core.config import settings
from agentshield.core.exceptions import (
    AgentNotRegisteredError,
    AuthenticationError,
    AuthorizationError,
)
from agentshield.core.security import (
    create_access_token,
    generate_agent_credential,
    hash_password,
    verify_agent_credential,
    verify_password,
)
from agentshield.database.models.agent import Agent
from agentshield.database.models.user import User
from agentshield.identity.repository import AgentRepository, UserRepository
from agentshield.identity.schemas import (
    AgentCreate,
    AgentCreatedResponse,
    AgentResponse,
    AgentUpdate,
    TokenResponse,
    UserCreate,
    UserResponse,
    UserUpdate,
)

logger = logging.getLogger("agentshield.identity")


class UserService:
    """Handles human user registration, login, and profile operations."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.repo = UserRepository(session)

    async def register(self, data: UserCreate) -> UserResponse:
        """Register a new user with securely hashed password."""
        # Uniqueness checks
        if await self.repo.get_by_email(data.email):
            raise ValueError(f"User with email '{data.email}' already exists.")
        if await self.repo.get_by_username(data.username):
            raise ValueError(f"Username '{data.username}' is already taken.")

        user = User(
            email=data.email.lower().strip(),
            username=data.username.strip(),
            hashed_password=hash_password(data.password),
            is_active=True,
            is_superuser=False,
        )
        created = await self.repo.create(user)
        await self.session.commit()
        logger.info("New user registered", extra={"user_id": created.id, "username": created.username})
        return UserResponse.model_validate(created)

    async def authenticate(self, username_or_email: str, password: str) -> TokenResponse:
        """Verify user credentials and issue a JWT access token."""
        user = await self.repo.get_by_username_or_email(username_or_email)
        if not user:
            raise AuthenticationError("Invalid username/email or password.")

        if not user.is_active:
            raise AuthenticationError("User account is inactive.")

        if not verify_password(password, user.hashed_password):
            raise AuthenticationError("Invalid username/email or password.")

        token = create_access_token(
            subject=user.id,
            claims={"username": user.username, "email": user.email},
        )
        return TokenResponse(
            access_token=token,
            expires_in=settings.access_token_expire_minutes * 60,
            user=UserResponse.model_validate(user),
        )

    async def get_by_id(self, user_id: str) -> UserResponse | None:
        user = await self.repo.get_by_id(user_id)
        if not user:
            return None
        return UserResponse.model_validate(user)

    async def update(self, user_id: str, data: UserUpdate) -> UserResponse:
        user = await self.repo.get_by_id(user_id)
        if not user:
            raise ValueError("User not found.")

        if data.email and data.email != user.email:
            existing = await self.repo.get_by_email(data.email)
            if existing and existing.id != user_id:
                raise ValueError(f"Email '{data.email}' is already in use.")
            user.email = data.email.lower().strip()

        if data.username and data.username != user.username:
            existing = await self.repo.get_by_username(data.username)
            if existing and existing.id != user_id:
                raise ValueError(f"Username '{data.username}' is already taken.")
            user.username = data.username.strip()

        if data.password:
            user.hashed_password = hash_password(data.password)

        updated = await self.repo.update(user)
        await self.session.commit()
        return UserResponse.model_validate(updated)


class AgentService:
    """Handles AI Agent registration, credential management, and authentication."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.repo = AgentRepository(session)

    async def register_agent(
        self,
        owner_user_id: str,
        data: AgentCreate,
    ) -> AgentCreatedResponse:
        """Register a new AI Agent and generate its one-time credential."""
        raw_cred, cred_hash = generate_agent_credential()

        agent = Agent(
            owner_user_id=owner_user_id,
            agent_name=data.agent_name.strip(),
            framework=data.framework,
            description=data.description,
            status="active",
            credential_hash=cred_hash,
        )
        created = await self.repo.create(agent)
        await self.session.commit()

        logger.info(
            "Agent registered",
            extra={"agent_id": created.id, "owner_id": owner_user_id, "agent_name": created.agent_name},
        )

        resp = AgentCreatedResponse(
            id=created.id,
            owner_user_id=created.owner_user_id,
            agent_name=created.agent_name,
            framework=created.framework,
            description=created.description,
            status=created.status,
            created_at=created.created_at,
            updated_at=created.updated_at,
            last_seen_at=created.last_seen_at,
            raw_credential=raw_cred,
        )
        return resp

    async def rotate_credential(
        self,
        agent_id: str,
        owner_user_id: str,
    ) -> AgentCreatedResponse:
        """Rotate the credential for an agent. Invalidates the old credential."""
        agent = await self.repo.get_by_id_and_owner(agent_id, owner_user_id)
        if not agent:
            raise AuthorizationError("Agent not found or you do not have permission to rotate it.")

        raw_cred, cred_hash = generate_agent_credential()
        agent.credential_hash = cred_hash
        updated = await self.repo.update(agent)
        await self.session.commit()

        logger.info("Agent credential rotated", extra={"agent_id": agent.id})

        return AgentCreatedResponse(
            id=updated.id,
            owner_user_id=updated.owner_user_id,
            agent_name=updated.agent_name,
            framework=updated.framework,
            description=updated.description,
            status=updated.status,
            created_at=updated.created_at,
            updated_at=updated.updated_at,
            last_seen_at=updated.last_seen_at,
            raw_credential=raw_cred,
        )

    async def authenticate_agent(self, raw_credential: str) -> AgentResponse:
        """Authenticate an incoming request by agent credential.

        Scans registered active agents and verifies the credential using Argon2.
        Updates last_seen_at upon successful verification.
        """
        active_agents = await self.repo.list_all_active()
        matched_agent: Agent | None = None

        for agent in active_agents:
            if verify_agent_credential(raw_credential, agent.credential_hash):
                matched_agent = agent
                break

        if not matched_agent:
            raise AuthenticationError("Invalid agent credential.")

        # Update last_seen_at
        matched_agent.last_seen_at = datetime.now(timezone.utc)
        await self.repo.update(matched_agent)
        await self.session.commit()

        return AgentResponse.model_validate(matched_agent)

    async def list_agents(
        self,
        owner_user_id: str,
        skip: int = 0,
        limit: int = 100,
    ) -> list[AgentResponse]:
        """List all agents belonging to the authenticated user."""
        agents = await self.repo.list_by_owner(owner_user_id, skip=skip, limit=limit)
        return [AgentResponse.model_validate(a) for a in agents]

    async def get_agent(self, agent_id: str, owner_user_id: str) -> AgentResponse:
        """Retrieve a specific agent with ownership verification."""
        agent = await self.repo.get_by_id_and_owner(agent_id, owner_user_id)
        if not agent:
            raise AuthorizationError("Agent not found or access denied.")
        return AgentResponse.model_validate(agent)

    async def update_agent(
        self,
        agent_id: str,
        owner_user_id: str,
        data: AgentUpdate,
    ) -> AgentResponse:
        """Update an agent with ownership verification."""
        agent = await self.repo.get_by_id_and_owner(agent_id, owner_user_id)
        if not agent:
            raise AuthorizationError("Agent not found or access denied.")

        if data.agent_name is not None:
            agent.agent_name = data.agent_name.strip()
        if data.description is not None:
            agent.description = data.description
        if data.status is not None:
            agent.status = data.status

        updated = await self.repo.update(agent)
        await self.session.commit()
        return AgentResponse.model_validate(updated)

    async def delete_agent(self, agent_id: str, owner_user_id: str) -> None:
        """Delete an agent with ownership verification."""
        agent = await self.repo.get_by_id_and_owner(agent_id, owner_user_id)
        if not agent:
            raise AuthorizationError("Agent not found or access denied.")
        await self.repo.delete(agent)
        await self.session.commit()
