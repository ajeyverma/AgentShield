"""
AgentShield AI — Anthropic Claude Agent Runner (Phase 9).
"""

from __future__ import annotations

import logging
from typing import Any

from agentshield.integrations.claude_agent_sdk.adapter import ClaudeIntegrationAdapter
from agentshield.integrations.core.agent_identity import AgentIdentity
from agentshield.integrations.core.integration_config import AgentShieldIntegrationConfig

logger = logging.getLogger("agentshield.integrations.claude_agent_sdk.agent")


class AgentShieldClaudeAgent:
    """
    Agent wrapper for Anthropic Claude agents ensuring all tool operations
    are mediated through AgentShield.
    """

    def __init__(
        self,
        adapter: ClaudeIntegrationAdapter,
        agent_name: str = "ClaudeSecureAgent",
        anthropic_api_key: str | None = None,
    ) -> None:
        self.adapter = adapter
        self.agent_name = agent_name
        self.anthropic_api_key = anthropic_api_key
        self.identity = AgentIdentity(
            agent_id=adapter.config.agent_id,
            agent_name=agent_name,
            framework=adapter.framework_type,
            tenant_id=adapter.config.tenant_id or "default-tenant",
            allowed_tools=adapter.config.allowed_tools,
        )

    def get_tools(self) -> list[dict[str, Any]]:
        """Get only AgentShield-allowlisted tool definitions."""
        return self.adapter.get_wrapped_tools()

    def process_response_tools(
        self,
        content_blocks: list[dict[str, Any]],
        approval_id: str | None = None,
    ) -> list[dict[str, Any]]:
        """
        Inspect message blocks from Claude model output;
        intercepts any 'tool_use' blocks and returns corresponding 'tool_result' blocks.
        """
        tool_results: list[dict[str, Any]] = []
        for block in content_blocks:
            if block.get("type") == "tool_use":
                result_block = self.adapter.handle_tool_use_block(block, approval_id=approval_id)
                tool_results.append(result_block)
        return tool_results
