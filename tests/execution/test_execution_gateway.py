"""
Tests for Execution Gateway Flow, Idempotency, and Approval Enforcement (Phase 6).
"""

import json
import uuid
from datetime import UTC, datetime, timedelta
import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from agentshield.contracts.execution import ExecutionRequest
from agentshield.database.base import Base
from agentshield.database.models.agent import Agent
from agentshield.database.models.policy import Policy
from agentshield.database.models.user import User
from agentshield.execution.enums import ExecutionStatus
from agentshield.execution.exceptions import ApprovalVerificationError, IdempotencyConflictError
from agentshield.services.execution_service import ExecutionService


@pytest.fixture
async def db_session():
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        connect_args={"check_same_thread": False},
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_factory = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)
    async with session_factory() as session:
        yield session

    await engine.dispose()


@pytest.mark.asyncio
async def test_allow_request_executes_through_adapter(db_session: AsyncSession):
    user_id = str(uuid.uuid4())
    agent_id = str(uuid.uuid4())
    user = User(id=user_id, email="exec_test@test.com", username="exectester", hashed_password="pw", is_active=True)
    agent = Agent(id=agent_id, owner_user_id=user_id, agent_name="ExecAgent", framework="custom", status="active", credential_hash="cred_hash_123")
    db_session.add(user)
    db_session.add(agent)
    await db_session.commit()

    service = ExecutionService(db_session)
    req = ExecutionRequest(
        agent_id=uuid.UUID(agent_id),
        user_id=user_id,
        tool_name="calculator",
        action_name="add",
        arguments={"a": 40, "b": 2},
    )

    resp = await service.execute_request(user_id=user_id, agent=agent, request=req)
    assert resp.decision == "ALLOW"
    assert resp.status == ExecutionStatus.COMPLETED
    assert resp.result == {"operation": "add", "result": 42.0}


@pytest.mark.asyncio
async def test_block_decision_never_invokes_adapter(db_session: AsyncSession):
    user_id = str(uuid.uuid4())
    agent_id = str(uuid.uuid4())
    user = User(id=user_id, email="block_test@test.com", username="blocktester", hashed_password="pw", is_active=True)
    agent = Agent(id=agent_id, owner_user_id=user_id, agent_name="BlockAgent", framework="custom", status="active", credential_hash="cred_hash_123")
    # Add policy that strictly blocks calculator
    policy = Policy(
        user_id=user_id,
        name="Block Calculator",
        category="general",
        enforcement_mode="enforce",
        rules_json=json.dumps({"match": {"tool": "calculator"}, "action": "BLOCK"}),
        is_enabled=True,
    )
    db_session.add(user)
    db_session.add(agent)
    db_session.add(policy)
    await db_session.commit()

    service = ExecutionService(db_session)
    req = ExecutionRequest(
        agent_id=uuid.UUID(agent_id),
        user_id=user_id,
        tool_name="calculator",
        action_name="add",
        arguments={"a": 1, "b": 1},
    )

    resp = await service.execute_request(user_id=user_id, agent=agent, request=req)
    assert resp.decision == "BLOCK"
    assert resp.status == ExecutionStatus.BLOCKED
    assert resp.result is None  # Adapter output must be None!


@pytest.mark.asyncio
async def test_ask_human_never_executes_before_approval(db_session: AsyncSession):
    user_id = str(uuid.uuid4())
    agent_id = str(uuid.uuid4())
    user = User(id=user_id, email="ask_test@test.com", username="asktester", hashed_password="pw", is_active=True)
    agent = Agent(id=agent_id, owner_user_id=user_id, agent_name="AskAgent", framework="custom", status="active", credential_hash="cred_hash_123")
    # Policy requiring approval for sandbox_fs
    policy = Policy(
        user_id=user_id,
        name="Require Approval",
        category="general",
        enforcement_mode="enforce",
        rules_json=json.dumps({"match": {"tool": "sandbox_fs"}, "action": "ASK_HUMAN"}),
        is_enabled=True,
    )
    db_session.add(user)
    db_session.add(agent)
    db_session.add(policy)
    await db_session.commit()

    service = ExecutionService(db_session)
    req = ExecutionRequest(
        agent_id=uuid.UUID(agent_id),
        user_id=user_id,
        tool_name="sandbox_fs",
        action_name="create_file",
        arguments={"path": "doc.txt", "content": "Sensitive Draft"},
    )

    resp = await service.execute_request(user_id=user_id, agent=agent, request=req)
    assert resp.decision == "ASK_HUMAN"
    assert resp.status == ExecutionStatus.PENDING_APPROVAL
    assert resp.result is None  # Never executed yet!
    assert resp.approval_id is not None

    # Now verify approval execution
    approved_resp = await service.approve_and_execute(
        execution_id=str(resp.execution_id),
        user_id=user_id,
        notes="Approved by security officer",
    )
    assert approved_resp.status == ExecutionStatus.COMPLETED
    assert approved_resp.result is not None


@pytest.mark.asyncio
async def test_replayed_approval_rejected(db_session: AsyncSession):
    user_id = str(uuid.uuid4())
    agent_id = str(uuid.uuid4())
    user = User(id=user_id, email="rep_test@test.com", username="reptester", hashed_password="pw", is_active=True)
    agent = Agent(id=agent_id, owner_user_id=user_id, agent_name="RepAgent", framework="custom", status="active", credential_hash="cred_hash_123")
    policy = Policy(
        user_id=user_id,
        name="Require Approval",
        category="general",
        enforcement_mode="enforce",
        rules_json=json.dumps({"match": {"tool": "sandbox_fs"}, "action": "ASK_HUMAN"}),
        is_enabled=True,
    )
    db_session.add(user)
    db_session.add(agent)
    db_session.add(policy)
    await db_session.commit()

    service = ExecutionService(db_session)
    req = ExecutionRequest(
        agent_id=uuid.UUID(agent_id),
        user_id=user_id,
        tool_name="sandbox_fs",
        action_name="create_file",
        arguments={"path": "note.txt", "content": "hello"},
    )
    resp = await service.execute_request(user_id=user_id, agent=agent, request=req)
    exec_id = str(resp.execution_id)

    # First approval succeeds
    await service.approve_and_execute(exec_id, user_id)

    # Replay approval must fail!
    with pytest.raises(ApprovalVerificationError, match="not in PENDING_APPROVAL state"):
        await service.approve_and_execute(exec_id, user_id)


@pytest.mark.asyncio
async def test_idempotency_prevents_duplicate_execution(db_session: AsyncSession):
    user_id = str(uuid.uuid4())
    agent_id = str(uuid.uuid4())
    user = User(id=user_id, email="idem_test@test.com", username="idemtester", hashed_password="pw", is_active=True)
    agent = Agent(id=agent_id, owner_user_id=user_id, agent_name="IdemAgent", framework="custom", status="active", credential_hash="cred_hash_123")
    db_session.add(user)
    db_session.add(agent)
    await db_session.commit()

    service = ExecutionService(db_session)
    idempotency_key = f"idem-{uuid.uuid4()}"
    req = ExecutionRequest(
        agent_id=uuid.UUID(agent_id),
        user_id=user_id,
        tool_name="calculator",
        action_name="add",
        arguments={"a": 5, "b": 10},
        idempotency_key=idempotency_key,
    )

    resp1 = await service.execute_request(user_id=user_id, agent=agent, request=req)
    assert resp1.status == ExecutionStatus.COMPLETED

    # Retry exact request
    resp2 = await service.execute_request(user_id=user_id, agent=agent, request=req)
    assert resp2.execution_id == resp1.execution_id
    assert resp2.result == resp1.result

    # Conflict with same key but altered arguments
    tampered_req = ExecutionRequest(
        agent_id=uuid.UUID(agent_id),
        user_id=user_id,
        tool_name="calculator",
        action_name="add",
        arguments={"a": 999, "b": 10},  # Altered!
        idempotency_key=idempotency_key,
    )
    with pytest.raises(IdempotencyConflictError):
        await service.execute_request(user_id=user_id, agent=agent, request=tampered_req)


@pytest.mark.asyncio
async def test_cross_tenant_approval_rejected(db_session: AsyncSession):
    user_a_id = str(uuid.uuid4())
    user_b_id = str(uuid.uuid4())
    agent_id = str(uuid.uuid4())
    user_a = User(id=user_a_id, email="usera@test.com", username="usera", hashed_password="pw", is_active=True)
    user_b = User(id=user_b_id, email="userb@test.com", username="userb", hashed_password="pw", is_active=True)
    agent = Agent(id=agent_id, owner_user_id=user_a_id, agent_name="AgentA", framework="custom", status="active", credential_hash="cred_hash_123")
    policy = Policy(
        user_id=user_a_id,
        name="Require Approval",
        category="general",
        enforcement_mode="enforce",
        rules_json=json.dumps({"tools": ["sandbox_fs"], "outcome": "ASK_HUMAN"}),
        is_enabled=True,
    )
    db_session.add(user_a)
    db_session.add(user_b)
    db_session.add(agent)
    db_session.add(policy)
    await db_session.commit()

    service = ExecutionService(db_session)
    req = ExecutionRequest(
        agent_id=uuid.UUID(agent_id),
        user_id=user_a_id,
        tool_name="sandbox_fs",
        action_name="create_file",
        arguments={"path": "secret.txt", "content": "confidential"},
    )
    resp = await service.execute_request(user_id=user_a_id, agent=agent, request=req)
    exec_id = str(resp.execution_id)

    # User B attempts to approve User A's execution
    from agentshield.core.exceptions import AuthorizationError
    with pytest.raises(AuthorizationError, match="access denied"):
        await service.approve_and_execute(execution_id=exec_id, user_id=user_b_id)


@pytest.mark.asyncio
async def test_cancel_pending_execution(db_session: AsyncSession):
    user_id = str(uuid.uuid4())
    agent_id = str(uuid.uuid4())
    user = User(id=user_id, email="cancel@test.com", username="canceltester", hashed_password="pw", is_active=True)
    agent = Agent(id=agent_id, owner_user_id=user_id, agent_name="CancelAgent", framework="custom", status="active", credential_hash="cred_hash_123")
    policy = Policy(
        user_id=user_id,
        name="Require Approval",
        category="general",
        enforcement_mode="enforce",
        rules_json=json.dumps({"tools": ["sandbox_fs"], "outcome": "ASK_HUMAN"}),
        is_enabled=True,
    )
    db_session.add(user)
    db_session.add(agent)
    db_session.add(policy)
    await db_session.commit()

    service = ExecutionService(db_session)
    req = ExecutionRequest(
        agent_id=uuid.UUID(agent_id),
        user_id=user_id,
        tool_name="sandbox_fs",
        action_name="create_file",
        arguments={"path": "cancel.txt", "content": "draft"},
    )
    resp = await service.execute_request(user_id=user_id, agent=agent, request=req)
    exec_id = str(resp.execution_id)

    # Cancel execution
    cancel_resp = await service.cancel_execution(execution_id=exec_id, user_id=user_id)
    assert cancel_resp.status == ExecutionStatus.CANCELLED

    # Subsequent approval must fail
    with pytest.raises(ApprovalVerificationError, match="not in PENDING_APPROVAL state"):
        await service.approve_and_execute(execution_id=exec_id, user_id=user_id)
