"""
AgentShield AI — Policy Service.
"""

from __future__ import annotations

import math
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from agentshield.core.exceptions import AuthorizationError, PolicyNotFoundError
from agentshield.database.models.policy import Policy
from agentshield.services.schemas import PaginatedResponse, PolicyCreate, PolicyResponse, PolicyUpdate


class PolicyService:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def list_policies(
        self,
        user_id: str,
        page: int = 1,
        size: int = 20,
        category: str | None = None,
    ) -> PaginatedResponse[PolicyResponse]:
        query = select(Policy).where(Policy.user_id == user_id)
        count_query = select(func.count(Policy.id)).where(Policy.user_id == user_id)

        if category:
            query = query.where(Policy.category == category.lower())
            count_query = count_query.where(Policy.category == category.lower())

        total = (await self.session.execute(count_query)).scalar() or 0
        offset = (page - 1) * size
        query = query.order_by(Policy.created_at.desc()).offset(offset).limit(size)
        items = (await self.session.execute(query)).scalars().all()

        pages = math.ceil(total / size) if size > 0 else 0
        return PaginatedResponse(
            items=[PolicyResponse.model_validate(i) for i in items],
            total=total,
            page=page,
            size=size,
            pages=pages,
        )

    async def get_by_id(self, policy_id: str, user_id: str) -> PolicyResponse | None:
        stmt = select(Policy).where(
            Policy.id == policy_id,
            Policy.user_id == user_id,
        )
        res = (await self.session.execute(stmt)).scalar_one_or_none()
        return PolicyResponse.model_validate(res) if res else None

    async def create_policy(self, user_id: str, data: PolicyCreate) -> PolicyResponse:
        policy = Policy(
            user_id=user_id,
            name=data.name.strip(),
            description=data.description,
            category=data.category.lower(),
            enforcement_mode=data.enforcement_mode.lower(),
            is_enabled=data.is_enabled,
            rules_json=data.rules_json,
        )
        self.session.add(policy)
        await self.session.flush()
        await self.session.refresh(policy)
        await self.session.commit()
        return PolicyResponse.model_validate(policy)

    async def update_policy(self, policy_id: str, user_id: str, data: PolicyUpdate) -> PolicyResponse:
        stmt = select(Policy).where(
            Policy.id == policy_id,
            Policy.user_id == user_id,
        )
        policy = (await self.session.execute(stmt)).scalar_one_or_none()
        if not policy:
            raise PolicyNotFoundError(f"Policy '{policy_id}' not found.")

        if data.name is not None:
            policy.name = data.name.strip()
        if data.description is not None:
            policy.description = data.description
        if data.category is not None:
            policy.category = data.category.lower()
        if data.enforcement_mode is not None:
            policy.enforcement_mode = data.enforcement_mode.lower()
        if data.is_enabled is not None:
            policy.is_enabled = data.is_enabled
        if data.rules_json is not None:
            policy.rules_json = data.rules_json

        policy.version += 1
        await self.session.flush()
        await self.session.refresh(policy)
        await self.session.commit()
        return PolicyResponse.model_validate(policy)

    async def delete_policy(self, policy_id: str, user_id: str) -> None:
        stmt = select(Policy).where(
            Policy.id == policy_id,
            Policy.user_id == user_id,
        )
        policy = (await self.session.execute(stmt)).scalar_one_or_none()
        if not policy:
            raise PolicyNotFoundError(f"Policy '{policy_id}' not found.")
        await self.session.delete(policy)
        await self.session.commit()
