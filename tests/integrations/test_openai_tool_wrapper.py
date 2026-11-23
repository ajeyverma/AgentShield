"""
Tests for AgentShield Tool Wrapper and Interception (Phase 7).
"""

import json
from unittest.mock import MagicMock
import pytest

from agentshield.integrations.openai_agents.client import AgentShieldOpenAIClient
from agentshield.integrations.openai_agents.configuration import AgentShieldIntegrationConfig
from agentshield.integrations.openai_agents.schemas import AgentShieldToolResult
from agentshield.integrations.openai_agents.tool_wrapper import AgentShieldToolWrapper


class TestAgentShieldToolWrapper:
    @pytest.fixture
    def mock_client(self):
        client = MagicMock(spec=AgentShieldOpenAIClient)
        client.execute_tool.return_value = AgentShieldToolResult(
            status="SUCCESS",
            decision="ALLOW",
            execution_id="exec-123",
            result={"operation": "add", "result": 42.0},
        )
        return client

    def test_tool_creation_filtered_by_allowlist(self, mock_client):
        # Expose ONLY calculator
        config = AgentShieldIntegrationConfig(
            agent_id="agt-1",
            agent_credential="cred",
            allowed_tools=["calculator"],
        )
        wrapper = AgentShieldToolWrapper(client=mock_client, config=config)
        tools = wrapper.get_wrapped_tools()

        tool_names = [t.name for t in tools]
        assert "calculator_add" in tool_names
        assert "calculator_multiply" in tool_names
        # Filesystem and email should NOT be exposed
        assert not any("sandbox_fs" in name for name in tool_names)
        assert not any("mock_email" in name for name in tool_names)

    def test_wrapper_dispatches_to_gateway_without_local_execution(self, mock_client):
        config = AgentShieldIntegrationConfig(
            agent_id="agt-1",
            agent_credential="cred",
            allowed_tools=["calculator"],
        )
        wrapper = AgentShieldToolWrapper(client=mock_client, config=config)
        raw_res = wrapper._execute_through_gateway("calculator", "add", {"a": 40, "b": 2})

        # Gateway client was called
        mock_client.execute_tool.assert_called_once_with(
            tool_name="calculator",
            action_name="add",
            arguments={"a": 40, "b": 2},
        )
        parsed = json.loads(raw_res)
        assert parsed["status"] == "SUCCESS"
        assert parsed["result"] == {"operation": "add", "result": 42.0}

    def test_unauthorized_tool_call_blocked_at_wrapper(self, mock_client):
        config = AgentShieldIntegrationConfig(
            agent_id="agt-1",
            agent_credential="cred",
            allowed_tools=["calculator"],  # sandbox_fs is NOT allowed
        )
        wrapper = AgentShieldToolWrapper(client=mock_client, config=config)
        raw_res = wrapper._execute_through_gateway("sandbox_fs", "read_file", {"path": "secret.txt"})

        # Gateway client should NOT be called for unlisted tools
        mock_client.execute_tool.assert_not_called()
        parsed = json.loads(raw_res)
        assert parsed["status"] == "BLOCKED"
        assert "not permitted by your AgentShield configuration allowlist" in parsed["error"]

    def test_call_history_recorded(self, mock_client):
        config = AgentShieldIntegrationConfig(
            agent_id="agt-1",
            agent_credential="cred",
            allowed_tools=["calculator"],
        )
        wrapper = AgentShieldToolWrapper(client=mock_client, config=config)
        wrapper._execute_through_gateway("calculator", "multiply", {"a": 3, "b": 7})

        assert len(wrapper.call_history) == 1
        call = wrapper.call_history[0]
        assert call.tool_name == "calculator"
        assert call.action_name == "multiply"
        assert call.arguments == {"a": 3, "b": 7}
