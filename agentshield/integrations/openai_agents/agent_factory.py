"""
AgentShield AI — Agent Factory for OpenAI Agents SDK (Phase 7).
"""

from __future__ import annotations

import logging
import os
from typing import Any

import agents
from agents import Runner, RunResult

from agentshield.integrations.openai_agents.client import AgentShieldOpenAIClient
from agentshield.integrations.openai_agents.configuration import AgentShieldIntegrationConfig
from agentshield.integrations.openai_agents.schemas import (
    OpenAIAgentSessionSummary,
    OpenAIToolCall,
)
from agentshield.integrations.openai_agents.tool_wrapper import AgentShieldToolWrapper

logger = logging.getLogger("agentshield.integrations.openai_agents.factory")


class AgentShieldOpenAIAgent:
    """Production wrapper constructing an AgentShield-secured OpenAI Agents SDK Agent."""

    def __init__(
        self,
        config: AgentShieldIntegrationConfig,
        client: AgentShieldOpenAIClient | None = None,
        model: str | agents.Model | None = None,
    ) -> None:
        self.config = config
        self.client = client or AgentShieldOpenAIClient(config)

        # Set provider API key in environment if supplied in config and not already in env
        if self.config.provider_api_key and "OPENAI_API_KEY" not in os.environ:
            os.environ["OPENAI_API_KEY"] = self.config.provider_api_key

        # Wrap allowed tools through AgentShield
        self.tool_wrapper = AgentShieldToolWrapper(self.client, self.config)
        self.wrapped_tools = self.tool_wrapper.get_wrapped_tools()

        # Instantiate underlying OpenAI Agents SDK Agent
        chosen_model = model or self.config.model_name
        self.sdk_agent = agents.Agent(
            name=self.config.agent_name,
            instructions=self.config.agent_instructions,
            tools=self.wrapped_tools,
            model=chosen_model,
        )
        logger.info(
            "Initialized AgentShieldOpenAIAgent '%s' with %d protected tools.",
            self.config.agent_name,
            len(self.wrapped_tools),
        )

    @property
    def intercepted_calls(self) -> list[OpenAIToolCall]:
        """Audit trail of all tool calls intercepted during this agent's lifetime."""
        return self.tool_wrapper.call_history

    def run(self, input_text: str, max_turns: int = 10, **kwargs: Any) -> RunResult:
        """Synchronously execute agent with natural-language instructions."""
        logger.info("Executing OpenAI agent run for prompt: %s", input_text[:60])
        return Runner.run_sync(
            starting_agent=self.sdk_agent,
            input=input_text,
            max_turns=max_turns,
            **kwargs,
        )

    async def run_async(self, input_text: str, max_turns: int = 10, **kwargs: Any) -> RunResult:
        """Asynchronously execute agent with natural-language instructions."""
        logger.info("Executing async OpenAI agent run for prompt: %s", input_text[:60])
        return await Runner.run(
            starting_agent=self.sdk_agent,
            input=input_text,
            max_turns=max_turns,
            **kwargs,
        )

    def get_session_summary(self) -> OpenAIAgentSessionSummary:
        """Produce an observability summary of decisions and tool invocations."""
        calls = self.tool_wrapper.call_history
        invocations = [
            {"tool": c.tool_name, "action": c.action_name, "timestamp": c.timestamp.isoformat()}
            for c in calls
        ]
        return OpenAIAgentSessionSummary(
            agent_id=self.config.agent_id,
            agent_name=self.config.agent_name,
            model_name=str(self.config.model_name),
            total_tool_calls=len(calls),
            tool_invocations=invocations,
        )
