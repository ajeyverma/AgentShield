"""
Tests for AgentShield OpenAI Client Communication and Fail-Closed Enforcement (Phase 7).
"""

from unittest.mock import MagicMock, patch
import httpx
import pytest

from agentshield.integrations.openai_agents.client import AgentShieldOpenAIClient
from agentshield.integrations.openai_agents.configuration import AgentShieldIntegrationConfig
from agentshield.integrations.openai_agents.exceptions import (
    AuthenticationFailureError,
    BackendUnavailableError,
)


class TestAgentShieldOpenAIClient:
    @pytest.fixture
    def config(self):
        return AgentShieldIntegrationConfig(
            backend_url="http://testserver",
            agent_id="agt-test-1",
            agent_credential="agt_credential_secret_123",
            fail_closed=True,
        )

    def test_execute_tool_allow_response(self, config):
        client = AgentShieldOpenAIClient(config)
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "status": "COMPLETED",
            "decision": "ALLOW",
            "execution_id": "exec-abc",
            "result": {"operation": "add", "result": 10.0},
        }

        with patch("httpx.Client.post", return_value=mock_resp):
            res = client.execute_tool("calculator", "add", {"a": 5, "b": 5})
            assert res.status == "COMPLETED"
            assert res.decision == "ALLOW"
            assert res.result == {"operation": "add", "result": 10.0}

    def test_execute_tool_block_response(self, config):
        client = AgentShieldOpenAIClient(config)
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "status": "BLOCKED",
            "decision": "BLOCK",
            "execution_id": "exec-blk",
            "error_code": "SECURITY_BLOCKED",
            "error_message": "Policy violation: division by zero or blocked action.",
        }

        with patch("httpx.Client.post", return_value=mock_resp):
            res = client.execute_tool("calculator", "divide", {"a": 5, "b": 0})
            assert res.status == "BLOCKED"
            assert res.decision == "BLOCK"
            assert res.result is None
            assert "Policy violation" in res.error_message

    def test_execute_tool_ask_human_response(self, config):
        client = AgentShieldOpenAIClient(config)
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "status": "PENDING_APPROVAL",
            "decision": "ASK_HUMAN",
            "execution_id": "exec-pending",
            "approval_id": "appr-pending",
            "result": None,
        }

        with patch("httpx.Client.post", return_value=mock_resp):
            res = client.execute_tool("sandbox_fs", "create_file", {"path": "draft.txt", "content": "confidential"})
            assert res.status == "PENDING_APPROVAL"
            assert res.decision == "ASK_HUMAN"
            assert res.approval_id == "appr-pending"
            assert res.result is None

    def test_backend_unreachable_enforces_fail_closed(self, config):
        client = AgentShieldOpenAIClient(config)
        with patch("httpx.Client.post", side_effect=httpx.ConnectError("Connection refused")):
            res = client.execute_tool("calculator", "add", {"a": 1, "b": 1})
            # Fail closed MUST block execution, never execute locally!
            assert res.status == "BLOCKED"
            assert res.decision == "BLOCK"
            assert res.error_code == "BACKEND_UNAVAILABLE"
            assert "unreachable" in res.error_message.lower()

    def test_authentication_failure_handling(self, config):
        client = AgentShieldOpenAIClient(config)
        mock_resp = MagicMock()
        mock_resp.status_code = 401
        with patch("httpx.Client.post", return_value=mock_resp):
            with pytest.raises(AuthenticationFailureError):
                client.authenticate()
