"""
Tests for Execution Authorization Grants (Phase 6).
"""

import uuid
from datetime import UTC, datetime, timedelta
import pytest
from agentshield.contracts.execution import ExecutionRequest
from agentshield.execution.authorization import ExecutionAuthorizationManager
from agentshield.execution.exceptions import ApprovalVerificationError


def _req(args: dict, tool: str = "calculator", action: str = "add") -> ExecutionRequest:
    return ExecutionRequest(
        request_id=uuid.uuid4(),
        agent_id=uuid.uuid4(),
        user_id="user-123",
        tool_name=tool,
        action_name=action,
        arguments=args,
    )


class TestExecutionAuthorizationManager:
    def setup_method(self):
        self.mgr = ExecutionAuthorizationManager(default_ttl_seconds=5)

    def test_issue_and_consume_grant_valid(self):
        req = _req({"a": 1, "b": 2})
        grant = self.mgr.issue_grant(req, decision_id="dec-1")
        assert grant.is_used is False

        consumed = self.mgr.consume_grant(grant.grant_id, req)
        assert consumed.is_used is True

    def test_replay_attempt_rejected(self):
        req = _req({"a": 1, "b": 2})
        grant = self.mgr.issue_grant(req, decision_id="dec-1")
        self.mgr.consume_grant(grant.grant_id, req)

        # Replay attempt
        with pytest.raises(ApprovalVerificationError, match="Replay attack detected"):
            self.mgr.consume_grant(grant.grant_id, req)

    def test_tampered_arguments_rejected(self):
        req = _req({"a": 1, "b": 2})
        grant = self.mgr.issue_grant(req, decision_id="dec-1")

        # Attacker modifies arguments after grant was issued
        tampered_req = ExecutionRequest(
            request_id=req.request_id,
            agent_id=req.agent_id,
            user_id=req.user_id,
            tool_name=req.tool_name,
            action_name=req.action_name,
            arguments={"a": 1, "b": 999999},  # Altered!
        )

        with pytest.raises(ApprovalVerificationError, match="Tampering detected"):
            self.mgr.consume_grant(grant.grant_id, tampered_req)

    def test_expired_grant_rejected(self):
        req = _req({"a": 1, "b": 2})
        grant = self.mgr.issue_grant(req, decision_id="dec-1", ttl_seconds=-1)  # already expired

        with pytest.raises(ApprovalVerificationError, match="expired"):
            self.mgr.consume_grant(grant.grant_id, req)
