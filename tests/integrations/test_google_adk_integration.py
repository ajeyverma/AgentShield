"""Tests for Google ADK / Gemini integration (Phase 9)."""

from __future__ import annotations

import uuid
from unittest.mock import MagicMock, patch
import pytest

from agentshield.contracts.enums import IntegrationType
from agentshield.integrations.core.integration_config import AgentShieldIntegrationConfig
from agentshield.integrations.google_adk.adapter import GoogleADKIntegrationAdapter
from agentshield.integrations.google_adk.agent import AgentShieldGoogleAgent


@pytest.fixture
def google_config() -> AgentShieldIntegrationConfig:
    return AgentShieldIntegrationConfig(
        backend_url="http://localhost:8000",
        agent_id=str(uuid.uuid4()),
        agent_credential="agt_google_adk_unit_test_token",
        allowed_tools=["calculator", "sandbox_fs", "mock_email"],
        fail_closed=True,
    )


def test_google_adk_metadata(google_config):
    adapter = GoogleADKIntegrationAdapter(google_config)
    assert adapter.framework_type == IntegrationType.SDK_GOOGLE_ADK
    assert "Google" in adapter.framework_name


def test_google_adk_function_declarations(google_config):
    adapter = GoogleADKIntegrationAdapter(google_config)
    decls = adapter.get_wrapped_tools()
    assert len(decls) > 0

    decl_names = [d["name"] for d in decls]
    assert "calculator_add" in decl_names
    assert "sandbox_fs_write_file" in decl_names

    calc_decl = next(d for d in decls if d["name"] == "calculator_add")
    assert "parameters" in calc_decl
    assert calc_decl["parameters"]["type"] == "object"


def test_google_adk_simulated_turn_interception(google_config):
    adapter = GoogleADKIntegrationAdapter(google_config)
    agent = adapter.create_agent(agent_name="GeminiAuditor")

    mock_resp_calc = MagicMock()
    mock_resp_calc.status_code = 200
    mock_resp_calc.json.return_value = {
        "status": "COMPLETED",
        "decision": "ALLOW",
        "result": 50.0,
    }

    mock_resp_block = MagicMock()
    mock_resp_block.status_code = 200
    mock_resp_block.json.return_value = {
        "status": "BLOCKED",
        "decision": "BLOCK",
        "error_code": "TRAVERSAL_ATTACK",
        "error_message": "Blocked path traversal",
    }

    def mock_post(url, *args, **kwargs):
        payload = kwargs.get("json", {})
        if payload.get("tool_name") == "calculator":
            return mock_resp_calc
        return mock_resp_block

    simulated_calls = [
        {"name": "calculator_add", "args": {"a": 25, "b": 25}},
        {"name": "sandbox_fs_read_file", "args": {"path": "../../../etc/passwd"}},
    ]

    with patch("httpx.Client.post", side_effect=mock_post):
        turn_result = agent.handle_simulated_turn("test prompt", simulated_calls)
        assert len(turn_result.function_responses) == 2
        assert turn_result.security_blocked is True

        resp0 = turn_result.function_responses[0]["response"]["content"]
        assert resp0["decision"] == "ALLOW"
        assert resp0["success"] is True

        resp1 = turn_result.function_responses[1]["response"]["content"]
        assert resp1["decision"] == "BLOCK"
        assert resp1["success"] is False
