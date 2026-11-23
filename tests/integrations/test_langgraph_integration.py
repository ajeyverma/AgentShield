"""Tests for LangGraph integration (Phase 9)."""

from __future__ import annotations

import json
import uuid
from unittest.mock import MagicMock, patch
import pytest

from agentshield.contracts.enums import IntegrationType
from agentshield.integrations.core.integration_config import AgentShieldIntegrationConfig
from agentshield.integrations.langgraph.adapter import LangGraphIntegrationAdapter
from agentshield.integrations.langgraph.node import AgentShieldToolNode


@pytest.fixture
def langgraph_config() -> AgentShieldIntegrationConfig:
    return AgentShieldIntegrationConfig(
        backend_url="http://localhost:8000",
        agent_id=str(uuid.uuid4()),
        agent_credential="agt_langgraph_unit_test_token",
        allowed_tools=["calculator", "sandbox_fs", "mock_email"],
        fail_closed=True,
    )


def test_langgraph_adapter_metadata(langgraph_config):
    adapter = LangGraphIntegrationAdapter(langgraph_config)
    assert adapter.framework_type == IntegrationType.SDK_LANGGRAPH
    assert adapter.framework_name == "LangGraph"


def test_langgraph_wrapped_tools(langgraph_config):
    adapter = LangGraphIntegrationAdapter(langgraph_config)
    tools = adapter.get_wrapped_tools()
    assert len(tools) > 0

    tool_names = [t.name for t in tools]
    assert "calculator_add" in tool_names
    assert "sandbox_fs_write_file" in tool_names
    assert "mock_email_send_email" in tool_names

    calc_add = next(t for t in tools if t.name == "calculator_add")
    assert calc_add.args is not None


def test_langgraph_tool_node_execution(langgraph_config):
    adapter = LangGraphIntegrationAdapter(langgraph_config)
    tool_node = adapter.create_tool_node(interrupt_on_approval=True)

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "status": "COMPLETED",
        "decision": "ALLOW",
        "result": 100.0,
    }

    state = {
        "messages": [
            {
                "role": "assistant",
                "tool_calls": [
                    {"id": "call_123", "name": "calculator_add", "args": {"a": 40, "b": 60}},
                ],
            }
        ]
    }

    with patch("httpx.Client.post", return_value=mock_resp):
        out_state = tool_node(state)
        assert out_state["agentshield_interrupted"] is False
        assert len(out_state["messages"]) == 1
        msg = out_state["messages"][0]
        assert msg["role"] == "tool"
        assert msg["status"] == "success"
        assert msg["tool_call_id"] == "call_123"


def test_langgraph_tool_node_approval_interrupt(langgraph_config):
    adapter = LangGraphIntegrationAdapter(langgraph_config)
    tool_node = adapter.create_tool_node(interrupt_on_approval=True)

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "status": "PENDING_APPROVAL",
        "decision": "ASK_HUMAN",
        "approval_id": "appr-lg-1234",
    }

    state = {
        "messages": [
            {
                "role": "assistant",
                "tool_calls": [
                    {"id": "call_email_1", "name": "mock_email_send_email", "args": {"recipient": "ceo@corp.com", "subject": "Alert", "body": "Msg"}},
                ],
            }
        ]
    }

    with patch("httpx.Client.post", return_value=mock_resp):
        out_state = tool_node(state)
        # Verify workflow interruption triggered
        assert out_state["agentshield_interrupted"] is True
        outputs = out_state["agentshield_outputs"]
        assert len(outputs) == 1
        assert outputs[0]["requires_approval"] is True
        assert outputs[0]["approval_request_id"] == "appr-lg-1234"
