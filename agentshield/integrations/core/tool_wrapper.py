"""
AgentShield AI — Universal Tool Wrapper & Allowlist Enforcement (Phase 9).
"""

from __future__ import annotations

import json
import logging
from typing import Any
from pydantic import BaseModel, Field

from agentshield.integrations.core.execution_client import AgentShieldExecutionClient
from agentshield.integrations.core.integration_config import AgentShieldIntegrationConfig
from agentshield.integrations.core.result_handler import AgentShieldToolResult

logger = logging.getLogger("agentshield.integrations.core.tool_wrapper")


class ToolInvocationRecord(BaseModel):
    """Audit record of an intercepted framework tool invocation."""

    tool_name: str
    action_name: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    framework: str = "generic"


# Canonical AgentShield tool definitions and input schemas
CANONICAL_TOOLS: dict[str, dict[str, Any]] = {
    "calculator": {
        "description": "Performs mathematical arithmetic calculations safely.",
        "actions": ["add", "subtract", "multiply", "divide"],
        "schema": {
            "type": "object",
            "properties": {
                "a": {"type": "number", "description": "First operand"},
                "b": {"type": "number", "description": "Second operand"},
            },
            "required": ["a", "b"],
        },
    },
    "sandbox_fs": {
        "description": "Safe sandboxed filesystem access restricted to workspace boundary.",
        "actions": ["read_file", "write_file", "list_dir"],
        "schema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Relative file path inside sandbox"},
                "content": {"type": "string", "description": "Content for write_file"},
            },
            "required": ["path"],
        },
    },
    "mock_email": {
        "description": "Outbound email notification tool with security policy inspection.",
        "actions": ["send_email"],
        "schema": {
            "type": "object",
            "properties": {
                "recipient": {"type": "string", "description": "Email address"},
                "subject": {"type": "string", "description": "Email subject line"},
                "body": {"type": "string", "description": "Email message body"},
            },
            "required": ["recipient", "subject", "body"],
        },
    },
    "mock_http": {
        "description": "HTTP client with SSRF protection and domain allowlist filtering.",
        "actions": ["get", "post"],
        "schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Destination HTTP/HTTPS URL"},
                "payload": {"type": "object", "description": "JSON payload for POST"},
            },
            "required": ["url"],
        },
    },
}


def parse_composite_tool_name(composite_name: str) -> tuple[str, str]:
    """Parse composite tool name (e.g. 'sandbox_fs_write_file') into (tool_name, action_name)."""
    for canonical in ["sandbox_fs", "mock_email", "mock_http", "calculator"]:
        prefix = f"{canonical}_"
        if composite_name.startswith(prefix):
            return canonical, composite_name[len(prefix):]
    if "_" in composite_name:
        parts = composite_name.split("_", 1)
        return parts[0], parts[1]
    return composite_name, "execute"


class BaseToolWrapper:
    """
    Base class providing allowlist validation, call recording,
    and gateway routing for all framework-specific tool wrappers.
    """

    def __init__(
        self,
        client: AgentShieldExecutionClient,
        config: AgentShieldIntegrationConfig,
        framework_name: str = "generic",
    ) -> None:
        self.client = client
        self.config = config
        self.framework_name = framework_name
        self.call_history: list[ToolInvocationRecord] = []

    def record_call(self, tool_name: str, action_name: str, arguments: dict[str, Any]) -> None:
        rec = ToolInvocationRecord(
            tool_name=tool_name,
            action_name=action_name,
            arguments=arguments,
            framework=self.framework_name,
        )
        self.call_history.append(rec)
        logger.info("[%s] Intercepted tool call: %s.%s", self.framework_name, tool_name, action_name)

    def route_tool_call(
        self,
        tool_name: str,
        action_name: str,
        arguments: dict[str, Any],
        approval_id: str | None = None,
    ) -> AgentShieldToolResult:
        """Enforce allowlist and forward through AgentShield gateway."""
        # 1. Allowlist enforcement
        if tool_name not in self.config.allowed_tools:
            logger.warning("[%s] Blocked invocation of non-allowlisted tool: %s", self.framework_name, tool_name)
            return AgentShieldToolResult(
                status="BLOCKED",
                decision="BLOCK",
                error_code="TOOL_NOT_ALLOWED",
                error_message=f"Tool '{tool_name}' is not in your configured AgentShield allowlist.",
            )

        self.record_call(tool_name, action_name, arguments)

        # 2. Forward to Controlled Execution Gateway
        return self.client.execute_tool(
            tool_name=tool_name,
            action_name=action_name,
            arguments=arguments,
            approval_id=approval_id,
        )

    def get_allowed_tool_specs(self) -> list[tuple[str, str, dict[str, Any]]]:
        """Return list of (tool_name, action_name, spec) for only allowlisted tools."""
        specs: list[tuple[str, str, dict[str, Any]]] = []
        for tname in self.config.allowed_tools:
            if tname in CANONICAL_TOOLS:
                tool_def = CANONICAL_TOOLS[tname]
                for action in tool_def["actions"]:
                    specs.append((tname, action, tool_def))
        return specs
