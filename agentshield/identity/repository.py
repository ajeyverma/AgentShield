"""
AgentShield AI — Identity Repositories.

Database persistence operations for User and Agent entities.
"""

from __future__ import annotations

from typing import Sequence

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from agentshield.database.models.agent import Agent
from agentshield.database.models.user import User


class UserRepository:
    """Database operations for User entities."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def get_by_id(self, user_id: str) -> User | None:
        stmt = select(User).where(User.id == user_id)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_by_email(self, email: str) -> User | None:
        stmt = select(User).where(User.email == email.lower().strip())
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_by_username(self, username: str) -> User | None:
        stmt = select(User).where(User.username == username.strip())
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_by_username_or_email(self, identifier: str) -> User | None:
        clean = identifier.strip()
        stmt = select(User).where(
            or_(User.username == clean, User.email == clean.lower())
        )
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def create(self, user: User) -> User:
        self.session.add(user)
        await self.session.flush()
        await self.session.refresh(user)
        return user

    async def update(self, user: User) -> User:
        await self.session.flush()
        await self.session.refresh(user)
        return user


class AgentRepository:
    """Database operations for Agent entities."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def get_by_id(self, agent_id: str) -> Agent | None:
        stmt = select(Agent).where(Agent.id == agent_id)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_by_id_and_owner(self, agent_id: str, owner_user_id: str) -> Agent | None:
        stmt = select(Agent).where(
            Agent.id == agent_id,
            Agent.owner_user_id == owner_user_id,
        )
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def list_by_owner(
        self,
        owner_user_id: str,
        skip: int = 0,
        limit: int = 100,
    ) -> Sequence[Agent]:
        stmt = (
            select(Agent)
            .where(Agent.owner_user_id == owner_user_id)
            .order_by(Agent.created_at.desc())
            .offset(skip)
            .limit(limit)
        )
        result = await self.session.execute(stmt)
        return result.scalars().all()

    async def list_all_active(self) -> Sequence[Agent]:
        """Fetch active agents for credential lookup."""
        stmt = select(Agent).where(Agent.status == "active")
        result = await self.session.execute(stmt)
        return result.scalars().all()

    async def create(self, agent: Agent) -> Agent:
        self.session.add(agent)
        await self.session.flush()
        await self.session.refresh(agent)
        return agent

    async def update(self, agent: Agent) -> Agent:
        await self.session.flush()
        await self.session.refresh(agent)
        return agent

    async def delete(self, agent: Agent) -> None:
        await self.session.delete(agent)
        await self.session.flush()
