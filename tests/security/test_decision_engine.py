"""
AgentShield AI — Decision Engine & Evaluator Unit Tests (Phase 4).
"""

from __future__ import annotations

import uuid
from agentshield.contracts.action import ActionRequest
from agentshield.contracts.enums import Decision, IntegrationType, ToolCategory
from agentshield.security.engine import SecurityDecisionEngine


USER_ID = str(uuid.uuid4())
AGENT_ID = str(uuid.uuid4())


def _req(tool="read_file", cat=ToolCategory.FILE_SYSTEM, op="read", resource=None, res=None):
    target = resource or res or "/home/user/f.txt"
    return ActionRequest(
        tenant_id=uuid.uuid4(),
        agent_id=uuid.UUID(AGENT_ID),
        user_id=uuid.UUID(USER_ID),
        integration_type=IntegrationType.SDK_OPENAI,
        tool_name=tool,
        tool_category=cat,
        operation=op,
        resource=target,
    )


class TestDecisionEngine:
    def test_valid_authorized_action_allow(self):
        engine = SecurityDecisionEngine()
        req = _req()
        decision = engine.evaluate_action(
            authenticated_user_id=USER_ID,
            authenticated_agent_id=AGENT_ID,
            agent_status="active",
            request=req,
        )
        assert decision.decision == Decision.ALLOW
        assert decision.approval_required is False

    def test_identity_mismatch_blocks(self):
        engine = SecurityDecisionEngine()
        req = _req()
        decision = engine.evaluate_action(
            authenticated_user_id="different-user-id",  # mismatch
            authenticated_agent_id=AGENT_ID,
            agent_status="active",
            request=req,
        )
        assert decision.decision == Decision.BLOCK
        assert any("User identity mismatch" in r for r in decision.reasons)

    def test_deactivated_agent_blocks(self):
        engine = SecurityDecisionEngine()
        req = _req()
        decision = engine.evaluate_action(
            authenticated_user_id=USER_ID,
            authenticated_agent_id=AGENT_ID,
            agent_status="deactivated",
            request=req,
        )
        assert decision.decision == Decision.BLOCK
        assert any("DEACTIVATED" in r for r in decision.reasons)

    def test_mandatory_block_cannot_be_overridden(self):
        engine = SecurityDecisionEngine()
        req = _req(resource="/etc/shadow")
        decision = engine.evaluate_action(
            authenticated_user_id=USER_ID,
            authenticated_agent_id=AGENT_ID,
            agent_status="active",
            request=req,
        )
        assert decision.decision == Decision.BLOCK
        assert decision.approval_required is False

    def test_approval_required_generates_approval_id(self):
        engine = SecurityDecisionEngine()
        req = _req(tool="rm_file", op="delete", res="/home/user/report.pdf")
        decision = engine.evaluate_action(
            authenticated_user_id=USER_ID,
            authenticated_agent_id=AGENT_ID,
            agent_status="active",
            request=req,
        )
        assert decision.decision == Decision.ASK_HUMAN
        assert decision.approval_required is True
        assert decision.approval_id is not None
        assert decision.approval_timeout_seconds == 300
