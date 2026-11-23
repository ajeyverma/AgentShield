"""Tests for Anthropic Claude Agent SDK integration (Phase 9)."""

from __future__ import annotations

import uuid
from unittest.mock import MagicMock, patch
import pytest

from agentshield.contracts.enums import IntegrationType
from agentshield.integrations.core.integration_config import AgentShieldIntegrationConfig
from agentshield.integrations.claude_agent_sdk.adapter import ClaudeIntegrationAdapter
from agentshield.integrations.claude_agent_sdk.agent import AgentShieldClaudeAgent
from agentshield.integrations.claude_agent_sdk.tool_wrapper import ClaudeToolWrapper


@pytest.fixture
def claude_config() -> AgentShieldIntegrationConfig:
    return AgentShieldIntegrationConfig(
        backend_url="http://localhost:8000",
        agent_id=str(uuid.uuid4()),
        agent_credential="agt_claude_unit_test_token",
        allowed_tools=["calculator", "sandbox_fs"],
        fail_closed=True,
    )


def test_claude_adapter_metadata(claude_config):
    adapter = ClaudeIntegrationAdapter(claude_config)
    assert adapter.framework_type == IntegrationType.SDK_CLAUDE
    assert "Claude" in adapter.framework_name


def test_claude_tool_definitions(claude_config):
    adapter = ClaudeIntegrationAdapter(claude_config)
    tools = adapter.get_wrapped_tools()
    assert len(tools) > 0

    tool_names = [t["name"] for t in tools]
    assert "calculator_add" in tool_names
    assert "sandbox_fs_read_file" in tool_names
    # Unallowed tool should not appear in specs
    assert not any("mock_email" in name for name in tool_names)

    # Verify input_schema format
    calc_add = next(t for t in tools if t["name"] == "calculator_add")
    assert "input_schema" in calc_add
    assert calc_add["input_schema"]["type"] == "object"
    assert "a" in calc_add["input_schema"]["properties"]


def test_claude_tool_use_block_allow(claude_config):
    adapter = ClaudeIntegrationAdapter(claude_config)
    agent = AgentShieldClaudeAgent(adapter=adapter)

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "status": "COMPLETED",
        "decision": "ALLOW",
        "result": 42.0,
    }

    block = {
        "type": "tool_use",
        "id": "toolu_abc123",
        "name": "calculator_add",
        "input": {"a": 20, "b": 22},
    }

    with patch("httpx.Client.post", return_value=mock_resp):
        res_blocks = agent.process_response_tools([block])
        assert len(res_blocks) == 1
        res = res_blocks[0]
        assert res["type"] == "tool_result"
        assert res["tool_use_id"] == "toolu_abc123"
        assert res["content"] == "42.0"
        assert "is_error" not in res or res["is_error"] is False


def test_claude_tool_use_block_block(claude_config):
    adapter = ClaudeIntegrationAdapter(claude_config)
    agent = AgentShieldClaudeAgent(adapter=adapter)

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "status": "BLOCKED",
        "decision": "BLOCK",
        "error_code": "POLICY_DENIED",
        "error_message": "Access denied by AgentShield policy",
    }

    block = {
        "type": "tool_use",
        "id": "toolu_blocked_1",
        "name": "sandbox_fs_read_file",
        "input": {"path": "../../../etc/shadow"},
    }

    with patch("httpx.Client.post", return_value=mock_resp):
        res_blocks = agent.process_response_tools([block])
        res = res_blocks[0]
        assert res["type"] == "tool_result"
        assert res["tool_use_id"] == "toolu_blocked_1"
        assert res["is_error"] is True
        assert "Access denied" in res["content"]


def test_claude_tool_use_block_ask_human(claude_config):
    adapter = ClaudeIntegrationAdapter(claude_config)
    agent = AgentShieldClaudeAgent(adapter=adapter)

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "status": "PENDING_APPROVAL",
        "decision": "ASK_HUMAN",
        "approval_id": "appr-claude-777",
    }

    block = {
        "type": "tool_use",
        "id": "toolu_ask_1",
        "name": "calculator_multiply",
        "input": {"a": 100, "b": 100},
    }

    with patch("httpx.Client.post", return_value=mock_resp):
        res_blocks = agent.process_response_tools([block])
        res = res_blocks[0]
        assert res["is_error"] is True
        assert "human authorization is required" in res["content"]
        assert "appr-claude-777" in res["content"]
