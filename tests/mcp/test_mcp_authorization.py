"""
Tests for MCP Security Engine & Authorization (Phase 8).
"""

import json
import uuid
from datetime import UTC, datetime, timedelta
import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from agentshield.contracts.enums import Decision
from agentshield.database.models.agent import Agent
from agentshield.database.models.approval import ApprovalRequest
from agentshield.database.models.policy import Policy
from agentshield.database.models.execution import ToolExecutionModel
from agentshield.database.models.user import User
from agentshield.mcp_gateway.exceptions import MCPApprovalRequiredError, MCPBlockedError
from agentshield.mcp_gateway.security.authorization import MCPAuthorizationService
from agentshield.mcp_gateway.security.policy_adapter import MCPPolicyAdapter


@pytest.fixture
async def sample_user_and_agent(db_session: AsyncSession):
    user_id = str(uuid.uuid4())
    agent_id = str(uuid.uuid4())

    user = User(
        id=user_id,
        email=f"mcp-user-{uuid.uuid4().hex[:6]}@agentshield.ai",
        username=f"mcp_user_{uuid.uuid4().hex[:6]}",
        hashed_password="hashed_test_password",
        is_active=True,
        is_superuser=False,
    )
    db_session.add(user)

    agent = Agent(
        id=agent_id,
        owner_user_id=user_id,
        agent_name="mcp-test-agent",
        framework="mcp",
        status="active",
        credential_hash="mock_hash",
    )
    db_session.add(agent)
    await db_session.commit()
    return user, agent


@pytest.mark.asyncio
async def test_allow_safe_operation(db_session: AsyncSession, sample_user_and_agent):
    user, agent = sample_user_and_agent
    auth_service = MCPAuthorizationService(db_session)

    decision, grant = await auth_service.evaluate_operation(
        user_id=user.id,
        agent_id=agent.id,
        method="tools/call",
        params={"name": "calculator_add", "arguments": {"a": 5, "b": 10}},
    )

    assert decision.decision == Decision.ALLOW
    assert grant is not None
    assert grant.tool_name == "calculator_add"
    assert grant.is_used is False


@pytest.mark.asyncio
async def test_block_dangerous_filesystem_operation(db_session: AsyncSession, sample_user_and_agent):
    user, agent = sample_user_and_agent
    auth_service = MCPAuthorizationService(db_session)

    # Malicious attempt to read shadow file
    with pytest.raises(MCPBlockedError) as exc_info:
        await auth_service.evaluate_operation(
            user_id=user.id,
            agent_id=agent.id,
            method="tools/call",
            params={"name": "fs_read_file", "arguments": {"path": "/etc/shadow"}},
        )

    assert "blocked" in exc_info.value.message.lower()


@pytest.mark.asyncio
async def test_ask_human_and_approval_consumption_lifecycle(db_session: AsyncSession, sample_user_and_agent):
    user, agent = sample_user_and_agent

    # Add a policy that requires human approval for "send_wire_transfer"
    policy = Policy(
        id=str(uuid.uuid4()),
        user_id=user.id,
        name="Wire Transfer Approval Policy",
        category="financial",
        enforcement_mode="active",
        is_enabled=True,
        version=1,
        rules_json=json.dumps({
            "target_tools": ["send_wire_transfer"],
            "action": "ASK_HUMAN",
            "conditions": [],
        }),
    )
    db_session.add(policy)
    await db_session.commit()

    auth_service = MCPAuthorizationService(db_session)

    # 1. Attempt wire transfer -> must raise MCPApprovalRequiredError
    with pytest.raises(MCPApprovalRequiredError) as exc_info:
        await auth_service.evaluate_operation(
            user_id=user.id,
            agent_id=agent.id,
            method="tools/call",
            params={"name": "send_wire_transfer", "arguments": {"amount": 50000, "recipient": "Acme Corp"}},
        )

    approval_id = exc_info.value.approval_id
    assert approval_id is not None

    # 2. Resuming while still "pending" should raise MCPApprovalRequiredError
    with pytest.raises(MCPApprovalRequiredError):
        await auth_service.evaluate_operation(
            user_id=user.id,
            agent_id=agent.id,
            method="tools/call",
            params={"name": "send_wire_transfer", "arguments": {"amount": 50000, "recipient": "Acme Corp"}},
            approval_id=approval_id,
        )

    # 3. Approve the request
    appr_stmt = await db_session.get(ApprovalRequest, approval_id)
    assert appr_stmt is not None
    appr_stmt.status = "approved"
    await db_session.commit()

    # 4. Attempt with approved approval_id but ALTERED arguments (tamper detection)
    with pytest.raises(MCPBlockedError) as tamper_exc:
        await auth_service.evaluate_operation(
            user_id=user.id,
            agent_id=agent.id,
            method="tools/call",
            params={"name": "send_wire_transfer", "arguments": {"amount": 999999, "recipient": "Attacker"}},
            approval_id=approval_id,
        )
    assert "tamper" in tamper_exc.value.message.lower() or "hash" in tamper_exc.value.message.lower()

    # 5. Attempt with approved approval_id with matching arguments -> succeeds!
    decision, grant = await auth_service.evaluate_operation(
        user_id=user.id,
        agent_id=agent.id,
        method="tools/call",
        params={"name": "send_wire_transfer", "arguments": {"amount": 50000, "recipient": "Acme Corp"}},
        approval_id=approval_id,
    )
    assert decision.decision == Decision.ALLOW
    assert grant is not None

    # 6. Replaying the already consumed approval -> raises MCPBlockedError (single-use grant)
    with pytest.raises(MCPBlockedError) as replay_exc:
        await auth_service.evaluate_operation(
            user_id=user.id,
            agent_id=agent.id,
            method="tools/call",
            params={"name": "send_wire_transfer", "arguments": {"amount": 50000, "recipient": "Acme Corp"}},
            approval_id=approval_id,
        )
    assert "consumed" in replay_exc.value.message.lower() or "single-use" in replay_exc.value.message.lower() or "not in approved state" in replay_exc.value.message.lower()


@pytest.mark.asyncio
async def test_expired_approval_rejected(db_session: AsyncSession, sample_user_and_agent):
    user, agent = sample_user_and_agent
    auth_service = MCPAuthorizationService(db_session)

    # Create an already expired approval
    expired_id = str(uuid.uuid4())
    expired_appr = ApprovalRequest(
        id=expired_id,
        user_id=user.id,
        agent_id=agent.id,
        request_id=str(uuid.uuid4()),
        tool_name="critical_op",
        operation="execute",
        risk_level="HIGH",
        description="Expired test",
        status="approved",
        expires_at=datetime.now(UTC) - timedelta(minutes=10),
    )
    db_session.add(expired_appr)
    await db_session.commit()

    with pytest.raises(MCPBlockedError) as exc_info:
        await auth_service.evaluate_operation(
            user_id=user.id,
            agent_id=agent.id,
            method="tools/call",
            params={"name": "critical_op", "arguments": {}},
            approval_id=expired_id,
        )
    assert "expired" in exc_info.value.message.lower()
