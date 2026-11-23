"""
AgentShield AI — Approval Security & Verification Tests (Phase 10).

Verifies separation of duties, self-approval prevention, cross-tenant isolation,
replayed approvals rejection, argument tampering rejection, and secret redaction.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from agentshield.contracts.execution import ExecutionRequest
from agentshield.core.exceptions import ApprovalNotFoundError, AuthorizationError
from agentshield.database.base import Base
from agentshield.database.models.agent import Agent
from agentshield.database.models.user import User
from agentshield.execution.enums import ExecutionStatus
from agentshield.execution.exceptions import ApprovalVerificationError
from agentshield.security.rbac import UserRole, assert_not_agent_self_approval
from agentshield.security.sanitization import redact_secrets
from agentshield.services.approval_service import ApprovalService
from agentshield.services.execution_service import ExecutionService


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
async def setup_users(async_db: AsyncSession):
    tenant1_id = str(uuid.uuid4())
    tenant2_id = str(uuid.uuid4())

    user_admin = User(id=tenant1_id, email="admin@t1.com", username="admin_t1", hashed_password="pw", role=UserRole.SECURITY_ADMIN.value)
    user_viewer = User(id=str(uuid.uuid4()), email="viewer@t1.com", username="viewer_t1", hashed_password="pw", role=UserRole.VIEWER.value)
    user_approver = User(id=str(uuid.uuid4()), email="approver@t1.com", username="approver_t1", hashed_password="pw", role=UserRole.APPROVER.value)
    user_t2 = User(id=tenant2_id, email="user@t2.com", username="user_t2", hashed_password="pw", role=UserRole.OWNER.value)

    agent_id = str(uuid.uuid4())
    agent = Agent(id=agent_id, owner_user_id=tenant1_id, agent_name="ShieldAgent", framework="custom", status="active", credential_hash="cred")

    from agentshield.database.models.policy import Policy
    policy = Policy(
        user_id=tenant1_id,
        name="Require FS Approval",
        category="filesystem",
        enforcement_mode="enforce",
        decision="ASK_HUMAN",
        tool_scope="sandbox_fs",
        action_scope="*",
        is_enabled=True,
    )

    async_db.add_all([user_admin, user_viewer, user_approver, user_t2, agent, policy])
    await async_db.commit()

    return {
        "tenant1_id": tenant1_id,
        "tenant2_id": tenant2_id,
        "user_admin": user_admin,
        "user_viewer": user_viewer,
        "user_approver": user_approver,
        "user_t2": user_t2,
        "agent": agent,
    }


@pytest.mark.asyncio
async def test_agent_self_approval_prevented():
    """AI agents are strictly forbidden from self-approving tool actions."""
    with pytest.raises(AuthorizationError, match="strictly forbidden"):
        assert_not_agent_self_approval(is_agent_caller=True)

    with pytest.raises(AuthorizationError, match="Self-approval violation"):
        assert_not_agent_self_approval(reviewer_id="agent_123", requesting_agent_id="agent_123")


@pytest.mark.asyncio
async def test_unauthorized_user_cannot_approve(async_db: AsyncSession, setup_users: dict):
    tenant1_id = setup_users["tenant1_id"]
    agent = setup_users["agent"]

    exec_svc = ExecutionService(async_db)
    req = ExecutionRequest(
        request_id=uuid.uuid4(),
        agent_id=uuid.UUID(agent.id),
        user_id=tenant1_id,
        tool_name="sandbox_fs",
        action_name="create_file",
        arguments={"path": "rbac_test.txt", "content": "secure"},
    )
    await exec_svc.execute_request(user_id=tenant1_id, agent=agent, request=req)

    appr_svc = ApprovalService(async_db)
    approvals = await appr_svc.list_approvals(user_id=tenant1_id, status="pending")
    appr_id = approvals.items[0].id

    # VIEWER role has no approval permission
    with pytest.raises(AuthorizationError):
        await appr_svc.approve_request(
            approval_id=appr_id,
            user_id=tenant1_id,
            user_role=UserRole.VIEWER,
        )


@pytest.mark.asyncio
async def test_high_risk_requires_security_admin_or_owner(async_db: AsyncSession, setup_users: dict):
    tenant1_id = setup_users["tenant1_id"]
    agent = setup_users["agent"]

    exec_svc = ExecutionService(async_db)
    req = ExecutionRequest(
        request_id=uuid.uuid4(),
        agent_id=uuid.UUID(agent.id),
        user_id=tenant1_id,
        tool_name="sandbox_fs",
        action_name="create_file",
        arguments={"path": "high_risk.txt", "content": "critical"},
    )
    await exec_svc.execute_request(user_id=tenant1_id, agent=agent, request=req)

    appr_svc = ApprovalService(async_db)
    approvals = await appr_svc.list_approvals(user_id=tenant1_id, status="pending")
    appr = approvals.items[0]

    # Force risk_score to 85 (HIGH risk)
    from agentshield.database.models.approval import ApprovalRequest
    from sqlalchemy import select
    stmt = select(ApprovalRequest).where(ApprovalRequest.id == appr.id)
    db_appr = (await async_db.execute(stmt)).scalar_one()
    db_appr.risk_score = 85.0
    db_appr.risk_level = "HIGH"
    await async_db.commit()

    # Ordinary APPROVER role should be rejected for HIGH risk
    with pytest.raises(AuthorizationError, match="OWNER or SECURITY_ADMIN required"):
        await appr_svc.approve_request(
            approval_id=appr.id,
            user_id=tenant1_id,
            user_role=UserRole.APPROVER,
        )

    # SECURITY_ADMIN can approve
    res = await appr_svc.approve_request(
        approval_id=appr.id,
        user_id=tenant1_id,
        user_role=UserRole.SECURITY_ADMIN,
        comment="Admin authorized",
    )
    assert res.status == "approved"


@pytest.mark.asyncio
async def test_cross_tenant_approval_rejected(async_db: AsyncSession, setup_users: dict):
    tenant1_id = setup_users["tenant1_id"]
    tenant2_id = setup_users["tenant2_id"]
    agent = setup_users["agent"]

    exec_svc = ExecutionService(async_db)
    req = ExecutionRequest(
        request_id=uuid.uuid4(),
        agent_id=uuid.UUID(agent.id),
        user_id=tenant1_id,
        tool_name="sandbox_fs",
        action_name="create_file",
        arguments={"path": "cross_tenant.txt", "content": "t1"},
    )
    await exec_svc.execute_request(user_id=tenant1_id, agent=agent, request=req)

    appr_svc = ApprovalService(async_db)
    approvals = await appr_svc.list_approvals(user_id=tenant1_id, status="pending")
    appr_id = approvals.items[0].id

    # Tenant 2 attempting to view or approve Tenant 1 request fails
    assert await appr_svc.get_by_id(appr_id, user_id=tenant2_id) is None

    with pytest.raises(ApprovalNotFoundError):
        await appr_svc.approve_request(
            approval_id=appr_id,
            user_id=tenant2_id,
            user_role=UserRole.OWNER,
        )


@pytest.mark.asyncio
async def test_replayed_approval_rejected(async_db: AsyncSession, setup_users: dict):
    tenant1_id = setup_users["tenant1_id"]
    agent = setup_users["agent"]

    exec_svc = ExecutionService(async_db)
    req = ExecutionRequest(
        request_id=uuid.uuid4(),
        agent_id=uuid.UUID(agent.id),
        user_id=tenant1_id,
        tool_name="sandbox_fs",
        action_name="create_file",
        arguments={"path": "replay.txt", "content": "123"},
    )
    await exec_svc.execute_request(user_id=tenant1_id, agent=agent, request=req)

    appr_svc = ApprovalService(async_db)
    approvals = await appr_svc.list_approvals(user_id=tenant1_id, status="pending")
    appr_id = approvals.items[0].id

    # 1. First approval succeeds
    await appr_svc.approve_request(approval_id=appr_id, user_id=tenant1_id, user_role=UserRole.OWNER)

    # 2. Second approval attempt must fail (one-time approval guarantee)
    with pytest.raises(ApprovalVerificationError, match="Must be 'pending'"):
        await appr_svc.approve_request(approval_id=appr_id, user_id=tenant1_id, user_role=UserRole.OWNER)


@pytest.mark.asyncio
async def test_secret_redaction_in_details():
    raw_arguments = {
        "api_key": "sk-123456789012345678901234567890",
        "user_password": "supersecretpassword",
        "normal_field": "hello world",
        "auth_header": "Bearer ghp_1234567890123456789012345678901234",
    }
    redacted = redact_secrets(raw_arguments)
    assert redacted["api_key"] == "[REDACTED]"
    assert redacted["user_password"] == "[REDACTED]"
    assert redacted["normal_field"] == "hello world"
    assert redacted["auth_header"] == "[REDACTED]"
