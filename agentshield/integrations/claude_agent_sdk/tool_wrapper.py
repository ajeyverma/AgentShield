"""
AgentShield AI — Anthropic Claude Agent SDK Tool Wrapper (Phase 9).
"""

from __future__ import annotations

import json
import logging
from typing import Any

from agentshield.integrations.core.execution_client import AgentShieldExecutionClient
from agentshield.integrations.core.integration_config import AgentShieldIntegrationConfig
from agentshield.integrations.core.result_handler import AgentShieldToolResult
from agentshield.integrations.core.tool_wrapper import BaseToolWrapper, parse_composite_tool_name

logger = logging.getLogger("agentshield.integrations.claude_agent_sdk.tool_wrapper")


class ClaudeToolWrapper(BaseToolWrapper):
    """
    Exposes only explicitly permitted AgentShield tools in the official
    Anthropic Claude tool specification format.
    """

    def __init__(
        self,
        client: AgentShieldExecutionClient,
        config: AgentShieldIntegrationConfig,
    ) -> None:
        super().__init__(client=client, config=config, framework_name="ClaudeAgentSDK")

    def get_tool_definitions(self) -> list[dict[str, Any]]:
        """
        Build standard Anthropic Claude tool definitions for only allowlisted tools.
        Format matching Claude tool API:
        {
            "name": "<tool_name>_<action_name>",
            "description": "...",
            "input_schema": {...}
        }
        """
        definitions: list[dict[str, Any]] = []
        for tname, action, spec in self.get_allowed_tool_specs():
            composite_name = f"{tname}_{action}"
            definitions.append({
                "name": composite_name,
                "description": f"[{tname}] {spec['description']} (action: {action})",
                "input_schema": spec.get("schema", {"type": "object", "properties": {}}),
            })
        return definitions

    def handle_tool_use(
        self,
        tool_use_id: str,
        tool_call_name: str,
        arguments: dict[str, Any],
        approval_id: str | None = None,
    ) -> dict[str, Any]:
        """
        Handle a Claude tool_use request, route through AgentShield gateway,
        and construct an Anthropic-compliant tool_result content block.
        """
        tool_name, action_name = parse_composite_tool_name(tool_call_name)

        result = self.route_tool_call(
            tool_name=tool_name,
            action_name=action_name,
            arguments=arguments,
            approval_id=approval_id,
        )

        if result.is_allowed():
            return {
                "type": "tool_result",
                "tool_use_id": tool_use_id,
                "content": json.dumps(result.result) if not isinstance(result.result, str) else result.result,
            }
        elif result.is_pending_approval():
            return {
                "type": "tool_result",
                "tool_use_id": tool_use_id,
                "is_error": True,
                "content": (
                    f"Action paused: human authorization is required (Approval ID: {result.approval_id}). "
                    "Cannot execute without verified human approval."
                ),
            }
        else:
            return {
                "type": "tool_result",
                "tool_use_id": tool_use_id,
                "is_error": True,
                "content": result.error_message or "Action blocked by AgentShield security gateway.",
            }
