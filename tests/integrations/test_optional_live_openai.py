"""
Optional Live End-to-End Tests with OpenAI Model (Phase 7).

Skipped by default in CI / automated test runs unless OPENAI_API_KEY is explicitly configured.
"""

import os
import pytest

from agentshield.integrations.openai_agents import (
    AgentShieldIntegrationConfig,
    AgentShieldOpenAIAgent,
    AgentShieldOpenAIClient,
)
from agentshield.integrations.openai_agents.schemas import AgentShieldToolResult


@pytest.mark.skipif(not os.getenv("OPENAI_API_KEY"), reason="Requires live OPENAI_API_KEY in environment")
def test_live_openai_agent_execution_with_intercepted_tool():
    """Live test running actual OpenAI Agents SDK Runner against OpenAI API with wrapped tools."""
    # Use a dummy client that returns a calculated result
    config = AgentShieldIntegrationConfig(
        agent_id="agt-live-test",
        agent_credential="agt_credential_live",
        allowed_tools=["calculator"],
        model_name=os.getenv("OPENAI_MODEL", "gpt-4o-mini"),
    )
    client = AgentShieldOpenAIClient(config)
    client.execute_tool = lambda tool_name, action_name, arguments: AgentShieldToolResult(
        status="SUCCESS",
        decision="ALLOW",
        execution_id="live-exec-1",
        result={"operation": action_name, "result": 12000.0},
    )

    agent = AgentShieldOpenAIAgent(config=config, client=client)
    result = agent.run("What is 250 multiplied by 48? Please use the calculator tool.", max_turns=3)

    assert result.final_output is not None
    assert len(agent.intercepted_calls) >= 1
    call = agent.intercepted_calls[0]
    assert call.tool_name == "calculator"
    assert call.action_name == "multiply"
