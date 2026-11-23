"""
End-to-End Tests for OpenAI Agents SDK Interception and Gateway Flow (Phase 7).
"""

import json
import uuid
from unittest.mock import MagicMock, patch
import pytest

from agentshield.integrations.openai_agents.agent_factory import AgentShieldOpenAIAgent
from agentshield.integrations.openai_agents.client import AgentShieldOpenAIClient
from agentshield.integrations.openai_agents.configuration import AgentShieldIntegrationConfig
from agentshield.integrations.openai_agents.schemas import AgentShieldToolResult


class TestOpenAIAgentIntegrationFlow:
    @pytest.fixture
    def config(self):
        return AgentShieldIntegrationConfig(
            agent_id=str(uuid.uuid4()),
            agent_credential="agt_valid_test_credential_12345",
            backend_url="http://mock-gateway",
            model_name="mock-model",
            allowed_tools=["calculator", "sandbox_fs", "mock_email", "mock_http"],
        )

    @pytest.fixture
    def mock_client(self, config):
        client = MagicMock(spec=AgentShieldOpenAIClient)
        client.config = config
        return client

    def test_agent_initialization(self, config, mock_client):
        agent = AgentShieldOpenAIAgent(config=config, client=mock_client)
        assert agent.sdk_agent.name == config.agent_name
        assert len(agent.wrapped_tools) > 0
        tool_names = [t.name for t in agent.wrapped_tools]
        assert "calculator_add" in tool_names
        assert "sandbox_fs_create_file" in tool_names

    def test_allow_outcome_intercepted_and_executed(self, config, mock_client):
        mock_client.execute_tool.return_value = AgentShieldToolResult(
            status="SUCCESS",
            decision="ALLOW",
            execution_id="exec-42",
            result={"operation": "multiply", "result": 12000.0},
        )
        agent = AgentShieldOpenAIAgent(config=config, client=mock_client)

        # Execute wrapped tool directly as the model runner would
        calc_tool = next(t for t in agent.wrapped_tools if t.name == "calculator_multiply")
        output_str = calc_tool.function(a=250.0, b=48.0)

        # Verify gateway client was called
        mock_client.execute_tool.assert_called_once_with(
            tool_name="calculator",
            action_name="multiply",
            arguments={"a": 250.0, "b": 48.0},
        )

        parsed = json.loads(output_str)
        assert parsed["status"] == "SUCCESS"
        assert parsed["result"] == {"operation": "multiply", "result": 12000.0}
        assert len(agent.intercepted_calls) == 1

    def test_block_outcome_never_executes_tool(self, config, mock_client):
        mock_client.execute_tool.return_value = AgentShieldToolResult(
            status="BLOCKED",
            decision="BLOCK",
            execution_id="exec-block",
            error_code="SECURITY_BLOCKED",
            error_message="Filesystem path traversal escape attempt blocked by policy.",
        )
        agent = AgentShieldOpenAIAgent(config=config, client=mock_client)

        fs_tool = next(t for t in agent.wrapped_tools if t.name == "sandbox_fs_read_file")
        output_str = fs_tool.function(path="../../etc/shadow")

        parsed = json.loads(output_str)
        assert parsed["status"] == "BLOCKED"
        assert "path traversal escape attempt blocked" in parsed["error"].lower()

    def test_ask_human_outcome_reports_pending_approval(self, config, mock_client):
        approval_id = str(uuid.uuid4())
        mock_client.execute_tool.return_value = AgentShieldToolResult(
            status="PENDING_APPROVAL",
            decision="ASK_HUMAN",
            execution_id="exec-pending",
            approval_id=approval_id,
            result=None,
        )
        agent = AgentShieldOpenAIAgent(config=config, client=mock_client)

        email_tool = next(t for t in agent.wrapped_tools if t.name == "mock_email_send_email")
        output_str = email_tool.function(to="board@company.com", subject="Confidential", body="Secrets")

        parsed = json.loads(output_str)
        assert parsed["status"] == "PENDING_APPROVAL"
        assert parsed["approval_id"] == approval_id
        assert "requires human approval" in parsed["message"]

    def test_session_summary_tracks_intercepted_invocations(self, config, mock_client):
        mock_client.execute_tool.return_value = AgentShieldToolResult(
            status="SUCCESS",
            decision="ALLOW",
            execution_id="exec-1",
            result=3.0,
        )
        agent = AgentShieldOpenAIAgent(config=config, client=mock_client)

        calc_add = next(t for t in agent.wrapped_tools if t.name == "calculator_add")
        calc_add.function(a=1.0, b=2.0)

        summary = agent.get_session_summary()
        assert summary.total_tool_calls == 1
        assert summary.tool_invocations[0]["tool"] == "calculator"
        assert summary.tool_invocations[0]["action"] == "add"
