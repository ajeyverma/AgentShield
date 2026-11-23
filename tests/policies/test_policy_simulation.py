"""
AgentShield AI — Policy Simulation Tests (Phase 10).

Verifies safe synthetic action evaluation without invoking real tool adapters.
"""

from __future__ import annotations

import uuid
import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from agentshield.database.base import Base
from agentshield.database.models.policy import Policy
from agentshield.database.models.user import User
from agentshield.services.policy_simulation_service import PolicySimulationService
from agentshield.services.schemas import PolicySimulationRequest


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
async def setup_policies(async_db: AsyncSession):
    user_id = str(uuid.uuid4())
    user = User(id=user_id, email="simuser@test.com", username="simuser", hashed_password="pw", role="OWNER")
    async_db.add(user)

    # Policy 1: Block delete files
    p1 = Policy(
        user_id=user_id,
        name="Block FS Deletions",
        category="filesystem",
        enforcement_mode="enforce",
        priority=10,
        tool_scope="sandbox_fs",
        action_scope="delete_*",
        decision="BLOCK",
        is_enabled=True,
    )
    # Policy 2: Ask human for shell commands
    p2 = Policy(
        user_id=user_id,
        name="Require Shell Approval",
        category="terminal",
        enforcement_mode="enforce",
        priority=20,
        tool_scope="bash",
        action_scope="*",
        decision="ASK_HUMAN",
        is_enabled=True,
    )
    async_db.add_all([p1, p2])
    await async_db.commit()
    return user_id


@pytest.mark.asyncio
async def test_policy_simulator_never_executes_tools(async_db: AsyncSession, setup_policies: str):
    user_id = setup_policies
    sim_svc = PolicySimulationService(async_db)

    # 1. Simulate Delete File action -> Should evaluate to BLOCK
    sim_req1 = PolicySimulationRequest(
        tool_name="sandbox_fs",
        operation="delete_file",
        arguments={"path": "/important/data.csv"},
    )
    res1 = await sim_svc.simulate(user_id=user_id, request=sim_req1)

    assert res1.simulated_decision == "BLOCK"
    assert res1.executed_real_tool is False
    assert res1.matched_policy_name == "Block FS Deletions"

    # 2. Simulate Bash Command action -> Should evaluate to ASK_HUMAN
    sim_req2 = PolicySimulationRequest(
        tool_name="bash",
        operation="execute",
        arguments={"command": "whoami"},
    )
    res2 = await sim_svc.simulate(user_id=user_id, request=sim_req2)

    assert res2.simulated_decision == "ASK_HUMAN"
    assert res2.executed_real_tool is False
    assert res2.matched_policy_name in ("Require Shell Approval", "Guard Terminal & Shell Commands")
