"""
AgentShield AI — RBAC & Emergency Security Controls Tests (Phase 10).

Verifies role-based permission checks, risk-based authorization thresholds,
global execution pause, targeted agent/tool disablers, and revocation.
"""

from __future__ import annotations

import uuid
import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from agentshield.contracts.execution import ExecutionRequest
from agentshield.core.exceptions import AuthorizationError
from agentshield.database.base import Base
from agentshield.database.models.agent import Agent
from agentshield.database.models.user import User
from agentshield.execution.enums import ExecutionStatus
from agentshield.security.rbac import (
    Permission,
    UserRole,
    can_approve_risk,
    can_manage_emergency_controls,
    has_permission,
)
from agentshield.services.emergency_service import EmergencyControlService
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
async def setup_env(async_db: AsyncSession):
    user_id = str(uuid.uuid4())
    user = User(id=user_id, email="owner@test.com", username="owner", hashed_password="pw", role=UserRole.OWNER.value)
    agent_id = str(uuid.uuid4())
    agent = Agent(id=agent_id, owner_user_id=user_id, agent_name="TestBot", framework="custom", status="active", credential_hash="ch")
    async_db.add_all([user, agent])
    await async_db.commit()
    return {"user_id": user_id, "agent": agent}


def test_rbac_permission_matrix():
    # OWNER has all permissions
    assert has_permission(UserRole.OWNER, Permission.EMERGENCY_EXECUTE) is True
    assert has_permission(UserRole.OWNER, Permission.POLICY_DELETE) is True

    # SECURITY_ADMIN has emergency and approval permissions
    assert has_permission(UserRole.SECURITY_ADMIN, Permission.EMERGENCY_EXECUTE) is True
    assert has_permission(UserRole.SECURITY_ADMIN, Permission.APPROVAL_APPROVE) is True

    # APPROVER cannot delete policies or execute emergency controls
    assert has_permission(UserRole.APPROVER, Permission.POLICY_DELETE) is False
    assert has_permission(UserRole.APPROVER, Permission.EMERGENCY_EXECUTE) is False
    assert has_permission(UserRole.APPROVER, Permission.APPROVAL_APPROVE) is True

    # VIEWER cannot approve or edit
    assert has_permission(UserRole.VIEWER, Permission.APPROVAL_APPROVE) is False
    assert has_permission(UserRole.VIEWER, Permission.POLICY_WRITE) is False
    assert has_permission(UserRole.VIEWER, Permission.POLICY_READ) is True


def test_can_approve_risk_thresholds():
    # Low / Medium risk: APPROVER can approve
    assert can_approve_risk(UserRole.APPROVER, risk_score=40.0, risk_level="MEDIUM") is True

    # High / Critical risk (score >= 70): APPROVER cannot approve
    assert can_approve_risk(UserRole.APPROVER, risk_score=75.0, risk_level="HIGH") is False
    assert can_approve_risk(UserRole.APPROVER, risk_score=30.0, risk_level="CRITICAL") is False

    # SECURITY_ADMIN and OWNER can approve all risks
    assert can_approve_risk(UserRole.SECURITY_ADMIN, risk_score=95.0, risk_level="CRITICAL") is True
    assert can_approve_risk(UserRole.OWNER, risk_score=95.0, risk_level="CRITICAL") is True


@pytest.mark.asyncio
async def test_emergency_lockdown_blocks_gateway_execution(async_db: AsyncSession, setup_env: dict):
    user_id = setup_env["user_id"]
    agent = setup_env["agent"]

    emg_svc = EmergencyControlService(async_db)
    exec_svc = ExecutionService(async_db)

    # 1. Normal execution succeeds
    req = ExecutionRequest(
        request_id=uuid.uuid4(),
        agent_id=uuid.UUID(agent.id),
        user_id=user_id,
        tool_name="calculator",
        action_name="add",
        arguments={"a": 10, "b": 20},
    )
    resp1 = await exec_svc.execute_request(user_id=user_id, agent=agent, request=req)
    assert resp1.status == ExecutionStatus.COMPLETED.value
    assert resp1.result["result"] == 30.0

    # 2. Activate PAUSE_EXECUTIONS lockdown
    control = await emg_svc.activate_control(
        user_id=user_id,
        user_role=UserRole.OWNER,
        control_type="PAUSE_EXECUTIONS",
        target_identifier="*",
        reason="Suspected widespread compromise",
    )
    assert control.is_active is True

    # 3. Subsequent execution must be BLOCKED by emergency control
    resp2 = await exec_svc.execute_request(user_id=user_id, agent=agent, request=req)
    assert resp2.status == ExecutionStatus.BLOCKED.value
    assert resp2.error_code == "EMERGENCY_LOCKDOWN"
    assert "Suspected widespread compromise" in resp2.error_message

    # 4. Revoke control
    await emg_svc.revoke_control(
        control_id=control.id,
        user_id=user_id,
        user_role=UserRole.OWNER,
        revocation_reason="Threat mitigated",
    )

    # 5. Execution resumes normally
    resp3 = await exec_svc.execute_request(user_id=user_id, agent=agent, request=req)
    assert resp3.status == ExecutionStatus.COMPLETED.value


@pytest.mark.asyncio
async def test_emergency_disable_specific_tool(async_db: AsyncSession, setup_env: dict):
    user_id = setup_env["user_id"]
    agent = setup_env["agent"]

    emg_svc = EmergencyControlService(async_db)
    exec_svc = ExecutionService(async_db)

    # Disable calculator tool specifically
    await emg_svc.activate_control(
        user_id=user_id,
        user_role=UserRole.SECURITY_ADMIN,
        control_type="DISABLE_TOOL",
        target_identifier="calculator",
        reason="Vulnerability found in calculator",
    )

    req = ExecutionRequest(
        request_id=uuid.uuid4(),
        agent_id=uuid.UUID(agent.id),
        user_id=user_id,
        tool_name="calculator",
        action_name="add",
        arguments={"a": 1, "b": 2},
    )
    resp = await exec_svc.execute_request(user_id=user_id, agent=agent, request=req)
    assert resp.status == ExecutionStatus.BLOCKED.value
    assert "Tool 'calculator' disabled" in resp.error_message


@pytest.mark.asyncio
async def test_unauthorized_emergency_activation_rejected(async_db: AsyncSession, setup_env: dict):
    user_id = setup_env["user_id"]
    emg_svc = EmergencyControlService(async_db)

    # APPROVER is not permitted to activate emergency controls
    with pytest.raises(AuthorizationError, match="OWNER or SECURITY_ADMIN required"):
        await emg_svc.activate_control(
            user_id=user_id,
            user_role=UserRole.APPROVER,
            control_type="PAUSE_EXECUTIONS",
            target_identifier="*",
            reason="Unauthorized attempt",
        )
