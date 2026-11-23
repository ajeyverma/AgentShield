"""
AgentShield AI — Policy Management Tests (Phase 10).

Verifies CRUD, priority ordering, structured conditions (no eval/exec),
version history snapshots, duplication, and conflict detection.
"""

from __future__ import annotations

import json
import uuid
import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from agentshield.core.exceptions import ValidationError
from agentshield.database.base import Base
from agentshield.database.models.user import User
from agentshield.security.condition_validator import evaluate_conditions, validate_conditions_syntax
from agentshield.services.policy_service import PolicyService
from agentshield.services.schemas import PolicyCreate, PolicyUpdate


@pytest.fixture
async def async_db():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_factory = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)
    async with session_factory() as session:
        yield session

    await engine.dispose()


@pytest.fixture
async def setup_user(async_db: AsyncSession):
    user_id = str(uuid.uuid4())
    user = User(
        id=user_id,
        email="policyadmin@test.com",
        username="policyadmin",
        hashed_password="pw",
        role="OWNER",
    )
    async_db.add(user)
    await async_db.commit()
    return user_id


@pytest.mark.asyncio
async def test_structured_conditions_validator():
    """Verify safe declarative condition evaluation with no arbitrary code execution."""
    # Valid syntax
    valid_cond = [
        {"field": "arguments.path", "operator": "starts_with", "value": "/etc"},
        {"field": "arguments.size", "operator": "greater_than", "value": 100},
    ]
    is_valid, err = validate_conditions_syntax(valid_cond)
    assert is_valid is True

    # Test evaluation
    args = {"path": "/etc/shadow", "size": 500}
    assert evaluate_conditions(valid_cond, {"arguments": args}) is True

    args2 = {"path": "/home/user", "size": 500}
    assert evaluate_conditions(valid_cond, {"arguments": args2}) is False

    # Invalid operator
    invalid_cond = [{"field": "x", "operator": "exec_python", "value": "os.system('ls')"}]
    is_valid2, err2 = validate_conditions_syntax(invalid_cond)
    assert is_valid2 is False
    assert "unsupported operator" in err2.lower()


@pytest.mark.asyncio
async def test_policy_crud_and_versioning(async_db: AsyncSession, setup_user: str):
    user_id = setup_user
    service = PolicyService(async_db)

    # 1. Create policy
    create_dto = PolicyCreate(
        name="Enforce Network Sandbox",
        category="network",
        enforcement_mode="enforce",
        priority=10,
        tool_scope="http_*",
        decision="BLOCK",
        conditions_json=json.dumps([{"field": "arguments.host", "operator": "equals", "value": "malicious.com"}]),
    )
    pol = await service.create_policy(user_id, create_dto)
    assert pol.name == "Enforce Network Sandbox"
    assert pol.priority == 10
    assert pol.version == 1

    # Check v1 snapshot
    history_v1 = await service.get_history(pol.id, user_id)
    assert len(history_v1) == 1
    assert history_v1[0].version == 1

    # 2. Update policy
    update_dto = PolicyUpdate(
        name="Enforce Strict Network Sandbox",
        priority=5,
    )
    updated = await service.update_policy(pol.id, user_id, update_dto)
    assert updated.name == "Enforce Strict Network Sandbox"
    assert updated.priority == 5
    assert updated.version == 2

    # Check v2 snapshot
    history_v2 = await service.get_history(pol.id, user_id)
    assert len(history_v2) == 2
    assert history_v2[0].version == 2

    # 3. Duplicate policy
    dup = await service.duplicate_policy(pol.id, user_id)
    assert dup.name.startswith("Copy of")
    assert dup.priority == 5
    assert dup.version == 1


@pytest.mark.asyncio
async def test_system_default_cannot_be_deleted(async_db: AsyncSession, setup_user: str):
    user_id = setup_user
    service = PolicyService(async_db)

    pol = await service.create_policy(
        user_id,
        PolicyCreate(
            name="System Default Root Shield",
            category="system",
            enforcement_mode="enforce",
            priority=1,
            decision="BLOCK",
        ),
    )

    with pytest.raises(ValidationError, match="System default"):
        await service.delete_policy(pol.id, user_id)


@pytest.mark.asyncio
async def test_policy_conflict_detection(async_db: AsyncSession, setup_user: str):
    user_id = setup_user
    service = PolicyService(async_db)

    # Create two policies with exact same scope and priority but opposing decisions
    await service.create_policy(
        user_id,
        PolicyCreate(
            name="Allow Database Read",
            category="database",
            priority=50,
            tool_scope="postgres",
            action_scope="select",
            decision="ALLOW",
        ),
    )
    await service.create_policy(
        user_id,
        PolicyCreate(
            name="Block Database Read",
            category="database",
            priority=50,
            tool_scope="postgres",
            action_scope="select",
            decision="BLOCK",
        ),
    )

    conflicts = await service.list_conflicts(user_id)
    assert len(conflicts) >= 1
    conflict_types = [c.conflict_type for c in conflicts]
    assert "DECISION_COLLISION" in conflict_types
