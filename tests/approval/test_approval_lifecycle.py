"""
AgentShield AI — Approval Lifecycle Tests (Phase 10).

Verifies approval creation, approval execution resumption, rejection,
cancellation, history tracking, and expiration handling.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from agentshield.database.base import Base
from agentshield.database.models.agent import Agent
from agentshield.database.models.user import User
from agentshield.execution.enums import ExecutionStatus
from agentshield.execution.exceptions import ApprovalVerificationError
from agentshield.security.rbac import UserRole
from agentshield.services.approval_service import ApprovalService
from agentshield.services.execution_service import ExecutionService
from agentshield.contracts.execution import ExecutionRequest


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
async def setup_env(async_db: AsyncSession):
    user_id = str(uuid.uuid4())
    user = User(
        id=user_id,
        email="admin@test.com",
        username="admin",
        hashed_password="hashed_pw",
        role=UserRole.OWNER.value,
        is_active=True,
    )
    agent_id = str(uuid.uuid4())
    agent = Agent(
        id=agent_id,
        owner_user_id=user_id,
        agent_name="TestAgent",
        framework="custom",
        status="active",
        credential_hash="cred_hash",
    )
    from agentshield.database.models.policy import Policy
    policy = Policy(
        user_id=user_id,
        name="Require FS Approval",
        category="filesystem",
        enforcement_mode="enforce",
        decision="ASK_HUMAN",
        tool_scope="sandbox_fs",
        action_scope="*",
        is_enabled=True,
    )
    async_db.add(user)
    async_db.add(agent)
    async_db.add(policy)
    await async_db.commit()
    return {"user_id": user_id, "agent_id": agent_id, "agent": agent}


@pytest.mark.asyncio
async def test_approval_lifecycle_approve(async_db: AsyncSession, setup_env: dict):
    user_id = setup_env["user_id"]
    agent = setup_env["agent"]

    # 1. Trigger ASK_HUMAN execution via gateway
    exec_svc = ExecutionService(async_db)
    req = ExecutionRequest(
        request_id=uuid.uuid4(),
        agent_id=uuid.UUID(agent.id),
        user_id=user_id,
        tool_name="sandbox_fs",
        action_name="create_file",
        arguments={"path": "test_appr.txt", "content": "approved data"},
    )
    resp = await exec_svc.execute_request(user_id=user_id, agent=agent, request=req)
    assert resp.decision == "ASK_HUMAN"
    assert resp.status == ExecutionStatus.PENDING_APPROVAL.value

    # 2. Query approval service
    appr_svc = ApprovalService(async_db)
    approvals = await appr_svc.list_approvals(user_id=user_id, status="pending")
    assert approvals.total == 1
    appr_id = approvals.items[0].id

    # 3. Approve request
    approved_resp = await appr_svc.approve_request(
        approval_id=appr_id,
        user_id=user_id,
        user_role=UserRole.OWNER,
        comment="LGTM by owner",
    )
    assert approved_resp.status == "approved"
    assert approved_resp.reviewed_by == user_id
    assert approved_resp.review_comment == "LGTM by owner"

    # 4. Check history record
    history = await appr_svc.get_history(approval_id=appr_id, user_id=user_id)
    assert len(history) == 1
    assert history[0].action == "approve"
    assert history[0].new_status == "approved"


@pytest.mark.asyncio
async def test_approval_lifecycle_reject(async_db: AsyncSession, setup_env: dict):
    user_id = setup_env["user_id"]
    agent = setup_env["agent"]

    exec_svc = ExecutionService(async_db)
    req = ExecutionRequest(
        request_id=uuid.uuid4(),
        agent_id=uuid.UUID(agent.id),
        user_id=user_id,
        tool_name="sandbox_fs",
        action_name="create_file",
        arguments={"path": "reject_test.txt", "content": "bad"},
    )
    await exec_svc.execute_request(user_id=user_id, agent=agent, request=req)

    appr_svc = ApprovalService(async_db)
    approvals = await appr_svc.list_approvals(user_id=user_id, status="pending")
    appr_id = approvals.items[0].id

    # Reject request
    rej_resp = await appr_svc.reject_request(
        approval_id=appr_id,
        user_id=user_id,
        user_role=UserRole.SECURITY_ADMIN,
        rejection_reason="Unsafe path detected",
    )
    assert rej_resp.status == "rejected"
    assert rej_resp.rejection_reason == "Unsafe path detected"

    # Verify execution model halted
    exec_model = await exec_svc.get_execution_by_id(approvals.items[0].execution_id, user_id)
    assert exec_model.status in (ExecutionStatus.BLOCKED.value, ExecutionStatus.CANCELLED.value)


@pytest.mark.asyncio
async def test_approval_lifecycle_cancel(async_db: AsyncSession, setup_env: dict):
    user_id = setup_env["user_id"]
    agent = setup_env["agent"]

    exec_svc = ExecutionService(async_db)
    req = ExecutionRequest(
        request_id=uuid.uuid4(),
        agent_id=uuid.UUID(agent.id),
        user_id=user_id,
        tool_name="sandbox_fs",
        action_name="create_file",
        arguments={"path": "cancel_test.txt", "content": "cancel"},
    )
    await exec_svc.execute_request(user_id=user_id, agent=agent, request=req)

    appr_svc = ApprovalService(async_db)
    approvals = await appr_svc.list_approvals(user_id=user_id, status="pending")
    appr_id = approvals.items[0].id

    # Cancel request
    cancel_resp = await appr_svc.cancel_request(
        approval_id=appr_id,
        user_id=user_id,
        user_role=UserRole.OWNER,
        reason="No longer needed",
    )
    assert cancel_resp.status == "cancelled"


@pytest.mark.asyncio
async def test_approval_expiration_handling(async_db: AsyncSession, setup_env: dict):
    user_id = setup_env["user_id"]
    agent = setup_env["agent"]

    exec_svc = ExecutionService(async_db)
    req = ExecutionRequest(
        request_id=uuid.uuid4(),
        agent_id=uuid.UUID(agent.id),
        user_id=user_id,
        tool_name="sandbox_fs",
        action_name="create_file",
        arguments={"path": "expired.txt", "content": "timeout"},
    )
    await exec_svc.execute_request(user_id=user_id, agent=agent, request=req)

    appr_svc = ApprovalService(async_db)
    approvals = await appr_svc.list_approvals(user_id=user_id, status="pending")
    appr = approvals.items[0]

    # Force expiration in database
    from agentshield.database.models.approval import ApprovalRequest
    from sqlalchemy import select
    stmt = select(ApprovalRequest).where(ApprovalRequest.id == appr.id)
    db_appr = (await async_db.execute(stmt)).scalar_one()
    db_appr.expires_at = datetime.now(UTC) - timedelta(minutes=10)
    await async_db.commit()

    # Attempting to approve must fail with ApprovalVerificationError
    with pytest.raises(ApprovalVerificationError, match="expired"):
        await appr_svc.approve_request(
            approval_id=appr.id,
            user_id=user_id,
            user_role=UserRole.OWNER,
        )

    # Verification: status changed to expired
    refreshed = await appr_svc.get_by_id(appr.id, user_id)
    assert refreshed.status == "expired"
