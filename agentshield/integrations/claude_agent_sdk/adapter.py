"""
AgentShield AI — Anthropic Claude Agent SDK Adapter (Phase 9).
"""

from __future__ import annotations

import logging
from typing import Any

from agentshield.contracts.enums import IntegrationType
from agentshield.integrations.claude_agent_sdk.tool_wrapper import ClaudeToolWrapper
from agentshield.integrations.core.base_adapter import BaseFrameworkAdapter
from agentshield.integrations.core.integration_config import AgentShieldIntegrationConfig
from agentshield.integrations.core.integration_registry import integration_registry
from agentshield.integrations.core.result_handler import AgentShieldToolResult

logger = logging.getLogger("agentshield.integrations.claude_agent_sdk.adapter")


class ClaudeIntegrationAdapter(BaseFrameworkAdapter):
    """Concrete adapter connecting Anthropic Claude agents to the AgentShield gateway."""

    def __init__(self, config: AgentShieldIntegrationConfig) -> None:
        super().__init__(config)
        self.tool_wrapper = ClaudeToolWrapper(self.client, self.config)

    @property
    def framework_type(self) -> IntegrationType:
        return IntegrationType.SDK_CLAUDE

    @property
    def framework_name(self) -> str:
        return "Anthropic Claude Agent SDK"

    def get_wrapped_tools(self) -> list[dict[str, Any]]:
        """Return Anthropic Claude tool schemas for allowlisted tools."""
        return self.tool_wrapper.get_tool_definitions()

    def execute_tool(
        self,
        tool_name: str,
        action_name: str,
        arguments: dict[str, Any],
        approval_id: str | None = None,
    ) -> AgentShieldToolResult:
        """Route tool invocation through AgentShield gateway."""
        return self.tool_wrapper.route_tool_call(
            tool_name=tool_name,
            action_name=action_name,
            arguments=arguments,
            approval_id=approval_id,
        )

    def handle_tool_use_block(
        self,
        tool_use_block: dict[str, Any],
        approval_id: str | None = None,
    ) -> dict[str, Any]:
        """
        Process a Claude tool_use content block:
        {"type": "tool_use", "id": "toolu_123", "name": "calculator_add", "input": {"a": 1, "b": 2}}
        Returns an Anthropic-compliant tool_result content block.
        """
        tool_use_id = tool_use_block.get("id", "toolu_unknown")
        tool_name = tool_use_block.get("name", "")
        arguments = tool_use_block.get("input", {})
        return self.tool_wrapper.handle_tool_use(
            tool_use_id=tool_use_id,
            tool_call_name=tool_name,
            arguments=arguments,
            approval_id=approval_id,
        )


# Register in integration registry
integration_registry.register_adapter_class(IntegrationType.SDK_CLAUDE, ClaudeIntegrationAdapter)
