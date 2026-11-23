"""
AgentShield AI — Policy Service (Phase 10).

Authoritative service for policy lifecycle management, version history snapshots,
structured condition validation, policy conflicts detection, and safe simulation.
"""

from __future__ import annotations

import math
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from agentshield.core.exceptions import AuthorizationError, PolicyNotFoundError, ValidationError
from agentshield.database.models.policy import Policy, PolicyVersion
from agentshield.security.condition_validator import validate_conditions_syntax
from agentshield.security.policy_engine import policy_engine
from agentshield.services.policy_simulation_service import PolicySimulationService
from agentshield.services.schemas import (
    PaginatedResponse,
    PolicyConflictItem,
    PolicyCreate,
    PolicyResponse,
    PolicySimulationRequest,
    PolicySimulationResponse,
    PolicyUpdate,
    PolicyVersionResponse,
)


class PolicyService:
    """Manages policy CRUD, versioning, conflict detection, and simulation."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def list_policies(
        self,
        user_id: str,
        page: int = 1,
        size: int = 20,
        category: str | None = None,
        is_enabled: bool | None = None,
    ) -> PaginatedResponse[PolicyResponse]:
        query = select(Policy).where(Policy.user_id == user_id)
        count_query = select(func.count(Policy.id)).where(Policy.user_id == user_id)

        if category:
            query = query.where(Policy.category == category.lower())
            count_query = count_query.where(Policy.category == category.lower())

        if is_enabled is not None:
            query = query.where(Policy.is_enabled == is_enabled)
            count_query = count_query.where(Policy.is_enabled == is_enabled)

        total = (await self.session.execute(count_query)).scalar() or 0
        offset = (page - 1) * size
        query = query.order_by(Policy.priority.asc(), Policy.created_at.desc()).offset(offset).limit(size)
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
        # Validate structured condition syntax if provided
        if data.conditions_json:
            is_valid, err = validate_conditions_syntax(data.conditions_json)
            if not is_valid:
                raise ValidationError(f"Invalid condition syntax: {err}")

        policy = Policy(
            user_id=user_id,
            name=data.name.strip(),
            description=data.description,
            category=data.category.lower(),
            enforcement_mode=data.enforcement_mode.lower(),
            is_enabled=data.is_enabled,
            priority=data.priority,
            agent_scope=data.agent_scope or "*",
            integration_scope=data.integration_scope or "*",
            tool_scope=data.tool_scope or "*",
            action_scope=data.action_scope or "*",
            resource_scope=data.resource_scope or "*",
            conditions_json=data.conditions_json,
            decision=data.decision.upper(),
            rules_json=data.rules_json,
            approval_requirements_json=data.approval_requirements_json,
            version=1,
            created_by=user_id,
        )
        self.session.add(policy)
        await self.session.flush()

        # Create initial immutable snapshot in PolicyVersion
        v1 = PolicyVersion(
            policy_id=policy.id,
            version=1,
            name=policy.name,
            description=policy.description,
            category=policy.category,
            enforcement_mode=policy.enforcement_mode,
            priority=policy.priority,
            decision=policy.decision,
            agent_scope=policy.agent_scope,
            integration_scope=policy.integration_scope,
            tool_scope=policy.tool_scope,
            action_scope=policy.action_scope,
            resource_scope=policy.resource_scope,
            conditions_json=policy.conditions_json,
            rules_json=policy.rules_json,
            approval_requirements_json=policy.approval_requirements_json,
            is_enabled=policy.is_enabled,
            changed_by=user_id,
            change_reason="Initial policy creation",
            created_at=datetime.now(UTC),
        )
        self.session.add(v1)

        await self.session.commit()
        await self.session.refresh(policy)
        return PolicyResponse.model_validate(policy)

    async def update_policy(self, policy_id: str, user_id: str, data: PolicyUpdate) -> PolicyResponse:
        stmt = select(Policy).where(
            Policy.id == policy_id,
            Policy.user_id == user_id,
        )
        policy = (await self.session.execute(stmt)).scalar_one_or_none()
        if not policy:
            raise PolicyNotFoundError(f"Policy '{policy_id}' not found.")

        if data.conditions_json is not None:
            is_valid, err = validate_conditions_syntax(data.conditions_json)
            if not is_valid:
                raise ValidationError(f"Invalid condition syntax: {err}")
            policy.conditions_json = data.conditions_json

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
        if data.priority is not None:
            policy.priority = data.priority
        if data.agent_scope is not None:
            policy.agent_scope = data.agent_scope
        if data.integration_scope is not None:
            policy.integration_scope = data.integration_scope
        if data.tool_scope is not None:
            policy.tool_scope = data.tool_scope
        if data.action_scope is not None:
            policy.action_scope = data.action_scope
        if data.resource_scope is not None:
            policy.resource_scope = data.resource_scope
        if data.decision is not None:
            policy.decision = data.decision.upper()
        if data.rules_json is not None:
            policy.rules_json = data.rules_json
        if data.approval_requirements_json is not None:
            policy.approval_requirements_json = data.approval_requirements_json

        policy.version += 1
        policy.updated_by = user_id

        # Record version snapshot
        version_snap = PolicyVersion(
            policy_id=policy.id,
            version=policy.version,
            name=policy.name,
            description=policy.description,
            category=policy.category,
            enforcement_mode=policy.enforcement_mode,
            priority=policy.priority,
            decision=policy.decision,
            agent_scope=policy.agent_scope,
            integration_scope=policy.integration_scope,
            tool_scope=policy.tool_scope,
            action_scope=policy.action_scope,
            resource_scope=policy.resource_scope,
            conditions_json=policy.conditions_json,
            rules_json=policy.rules_json,
            approval_requirements_json=policy.approval_requirements_json,
            is_enabled=policy.is_enabled,
            changed_by=user_id,
            change_reason="Policy updated",
            created_at=datetime.now(UTC),
        )
        self.session.add(version_snap)

        await self.session.commit()
        await self.session.refresh(policy)
        return PolicyResponse.model_validate(policy)

    async def enable_policy(self, policy_id: str, user_id: str) -> PolicyResponse:
        stmt = select(Policy).where(Policy.id == policy_id, Policy.user_id == user_id)
        policy = (await self.session.execute(stmt)).scalar_one_or_none()
        if not policy:
            raise PolicyNotFoundError(f"Policy '{policy_id}' not found.")
        policy.is_enabled = True
        await self.session.commit()
        await self.session.refresh(policy)
        return PolicyResponse.model_validate(policy)

    async def disable_policy(self, policy_id: str, user_id: str) -> PolicyResponse:
        stmt = select(Policy).where(Policy.id == policy_id, Policy.user_id == user_id)
        policy = (await self.session.execute(stmt)).scalar_one_or_none()
        if not policy:
            raise PolicyNotFoundError(f"Policy '{policy_id}' not found.")
        policy.is_enabled = False
        await self.session.commit()
        await self.session.refresh(policy)
        return PolicyResponse.model_validate(policy)

    async def duplicate_policy(self, policy_id: str, user_id: str) -> PolicyResponse:
        stmt = select(Policy).where(Policy.id == policy_id, Policy.user_id == user_id)
        original = (await self.session.execute(stmt)).scalar_one_or_none()
        if not original:
            raise PolicyNotFoundError(f"Policy '{policy_id}' not found.")

        copy_data = PolicyCreate(
            name=f"Copy of {original.name}",
            description=original.description,
            category=original.category,
            enforcement_mode=original.enforcement_mode,
            is_enabled=original.is_enabled,
            priority=original.priority,
            agent_scope=original.agent_scope,
            integration_scope=original.integration_scope,
            tool_scope=original.tool_scope,
            action_scope=original.action_scope,
            resource_scope=original.resource_scope,
            conditions_json=original.conditions_json,
            decision=original.decision,
            rules_json=original.rules_json,
            approval_requirements_json=original.approval_requirements_json,
        )
        return await self.create_policy(user_id, copy_data)

    async def delete_policy(self, policy_id: str, user_id: str) -> None:
        stmt = select(Policy).where(
            Policy.id == policy_id,
            Policy.user_id == user_id,
        )
        policy = (await self.session.execute(stmt)).scalar_one_or_none()
        if not policy:
            raise PolicyNotFoundError(f"Policy '{policy_id}' not found.")

        if policy.name.lower().startswith("system default") or policy.category == "system":
            raise ValidationError("System default security policies cannot be deleted.")

        await self.session.delete(policy)
        await self.session.commit()

    async def get_history(self, policy_id: str, user_id: str) -> list[PolicyVersionResponse]:
        # Verify ownership
        stmt_check = select(Policy.id).where(Policy.id == policy_id, Policy.user_id == user_id)
        if not (await self.session.execute(stmt_check)).scalar_one_or_none():
            raise PolicyNotFoundError(f"Policy '{policy_id}' not found.")

        stmt = select(PolicyVersion).where(PolicyVersion.policy_id == policy_id).order_by(PolicyVersion.version.desc())
        rows = (await self.session.execute(stmt)).scalars().all()
        return [PolicyVersionResponse.model_validate(r) for r in rows]

    async def list_conflicts(self, user_id: str) -> list[PolicyConflictItem]:
        stmt = select(Policy).where(Policy.user_id == user_id, Policy.is_enabled == True).order_by(Policy.priority.asc())
        policies = list((await self.session.execute(stmt)).scalars().all())
        raw_conflicts = policy_engine.find_conflicts(policies)
        return [PolicyConflictItem(**c) for c in raw_conflicts]

    async def simulate(self, user_id: str, request: PolicySimulationRequest) -> PolicySimulationResponse:
        sim_svc = PolicySimulationService(self.session)
        return await sim_svc.simulate(user_id=user_id, request=request)
