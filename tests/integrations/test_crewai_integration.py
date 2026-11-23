"""Tests for CrewAI integration (Phase 9)."""

from __future__ import annotations

import uuid
from unittest.mock import MagicMock, patch
import pytest

from agentshield.contracts.enums import IntegrationType
from agentshield.integrations.core.integration_config import AgentShieldIntegrationConfig
from agentshield.integrations.crewai.adapter import CrewAIIntegrationAdapter
from agentshield.integrations.crewai.crew import AgentShieldCrewMember


@pytest.fixture
def crewai_config() -> AgentShieldIntegrationConfig:
    return AgentShieldIntegrationConfig(
        backend_url="http://localhost:8000",
        agent_id=str(uuid.uuid4()),
        agent_credential="agt_crewai_unit_test_token",
        allowed_tools=["calculator", "sandbox_fs", "mock_email"],
        fail_closed=True,
    )


def test_crewai_adapter_metadata(crewai_config):
    adapter = CrewAIIntegrationAdapter(crewai_config)
    assert adapter.framework_type == IntegrationType.SDK_CREWAI
    assert adapter.framework_name == "CrewAI"


def test_crewai_member_creation_and_tools(crewai_config):
    adapter = CrewAIIntegrationAdapter(crewai_config)
    lead = adapter.create_crew_member(
        name="LeadAnalyst",
        role="Lead Security Analyst",
        goal="Audit logs",
        allowed_tools=["calculator", "sandbox_fs"],
    )

    assert lead.name == "LeadAnalyst"
    tool_names = [t.name for t in lead.tools]
    assert any("calculator" in n for n in tool_names)
    assert any("sandbox_fs" in n for n in tool_names)
    # mock_email was not granted in lead.allowed_tools
    assert not any("mock_email" in n for n in tool_names)


def test_crewai_delegation_least_privilege(crewai_config):
    adapter = CrewAIIntegrationAdapter(crewai_config)
    lead = adapter.create_crew_member(
        name="LeadAnalyst",
        role="Lead Security Analyst",
        goal="Audit logs",
        allowed_tools=["calculator", "sandbox_fs"],
    )

    # Delegate to sub-agent with only calculator
    sub = lead.delegate_to(
        sub_agent_name="MathAssistant",
        sub_agent_role="Math specialist",
        restricted_tools=["calculator"],
    )

    assert sub.identity.parent_agent_id == lead.identity.agent_id
    assert sub.identity.originating_agent_id == lead.identity.agent_id
    sub_tool_names = [t.name for t in sub.tools]
    assert all("calculator" in n for n in sub_tool_names)
    assert not any("sandbox_fs" in n for n in sub_tool_names)


def test_crewai_tool_run_execution(crewai_config):
    adapter = CrewAIIntegrationAdapter(crewai_config)
    lead = adapter.create_crew_member(
        name="LeadAnalyst",
        role="Lead",
        goal="Calculate",
        allowed_tools=["calculator"],
    )

    calc_tool = next(t for t in lead.tools if t.name == "calculator_multiply")

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "status": "COMPLETED",
        "decision": "ALLOW",
        "result": 99.0,
    }

    with patch("httpx.Client.post", return_value=mock_resp):
        out = calc_tool.run(a=11, b=9)
        assert "99" in str(out)
