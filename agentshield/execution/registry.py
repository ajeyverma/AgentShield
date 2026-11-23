"""
AgentShield AI — Controlled Tool Registry (Phase 6).

Central authority defining all permitted tools, actions, schemas, risk levels,
and adapter bindings.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from agentshield.contracts.enums import ToolCategory
from agentshield.contracts.execution import ToolActionMetadata, ToolMetadataResponse
from agentshield.execution.adapters import (
    BaseToolAdapter,
    CalculatorAdapter,
    MockEmailAdapter,
    MockHttpAdapter,
    SandboxedFilesystemAdapter,
)
from agentshield.execution.exceptions import (
    ActionNotFoundError,
    InvalidArgumentsError,
    ToolDisabledError,
    ToolNotFoundError,
)


@dataclass
class ActionDefinition:
    """Schema and permissions for an individual tool action."""

    action_name: str
    description: str
    required_permissions: list[str] = field(default_factory=list)
    argument_schema: dict[str, type | tuple[type, ...]] = field(default_factory=dict)
    required_fields: list[str] = field(default_factory=list)


@dataclass
class ToolDefinition:
    """Complete specification of a registered tool."""

    tool_name: str
    tool_version: str
    description: str
    category: ToolCategory
    adapter: BaseToolAdapter
    actions: dict[str, ActionDefinition]
    risk_classification: str = "LOW"
    timeout_seconds: float = 5.0
    max_output_bytes: int = 65_536
    is_enabled: bool = True

    def to_metadata(self) -> ToolMetadataResponse:
        return ToolMetadataResponse(
            tool_name=self.tool_name,
            tool_version=self.tool_version,
            description=self.description,
            is_enabled=self.is_enabled,
            risk_classification=self.risk_classification,
            timeout_seconds=self.timeout_seconds,
            max_output_bytes=self.max_output_bytes,
            actions=[
                ToolActionMetadata(
                    action_name=act.action_name,
                    description=act.description,
                    required_permissions=act.required_permissions,
                    argument_schema={k: getattr(v, "__name__", str(v)) for k, v in act.argument_schema.items()},
                )
                for act in self.actions.values()
            ],
        )


class ToolRegistry:
    """Central registry maintaining active tools, schemas, and adapter bindings."""

    def __init__(self) -> None:
        self._tools: dict[str, ToolDefinition] = {}
        self._register_default_tools()

    def register(self, definition: ToolDefinition) -> None:
        self._tools[definition.tool_name.lower()] = definition

    def get(self, tool_name: str) -> ToolDefinition:
        t = self._tools.get(tool_name.lower())
        if not t:
            raise ToolNotFoundError(tool_name)
        if not t.is_enabled:
            raise ToolDisabledError(tool_name)
        return t

    def list_all(self) -> list[ToolDefinition]:
        return list(self._tools.values())

    def enable_tool(self, tool_name: str) -> None:
        t = self._tools.get(tool_name.lower())
        if not t:
            raise ToolNotFoundError(tool_name)
        t.is_enabled = True

    def disable_tool(self, tool_name: str) -> None:
        t = self._tools.get(tool_name.lower())
        if not t:
            raise ToolNotFoundError(tool_name)
        t.is_enabled = False

    def validate_request(self, tool_name: str, action_name: str, arguments: dict[str, Any]) -> ToolDefinition:
        """Verify tool exists, is enabled, supports the action, and validate arguments against schema."""
        tool = self.get(tool_name)
        act = tool.actions.get(action_name.lower())
        if not act:
            raise ActionNotFoundError(tool_name, action_name)

        # Check required fields
        for field_name in act.required_fields:
            if field_name not in arguments:
                raise InvalidArgumentsError(f"Missing required argument '{field_name}' for action '{action_name}'.")

        # Check argument types if specified
        for arg_key, expected_type in act.argument_schema.items():
            if arg_key in arguments and arguments[arg_key] is not None:
                val = arguments[arg_key]
                if not isinstance(val, expected_type):
                    raise InvalidArgumentsError(
                        f"Argument '{arg_key}' expected type {expected_type}, got {type(val).__name__}."
                    )

        return tool

    def _register_default_tools(self) -> None:
        # 1. Calculator
        self.register(
            ToolDefinition(
                tool_name="calculator",
                tool_version="1.0.0",
                description="Controlled arithmetic calculator tool.",
                category=ToolCategory.UNKNOWN,
                adapter=CalculatorAdapter(),
                risk_classification="LOW",
                actions={
                    "add": ActionDefinition("add", "Add two numbers", ["math:calc"], {"a": (int, float), "b": (int, float)}, ["a", "b"]),
                    "subtract": ActionDefinition("subtract", "Subtract two numbers", ["math:calc"], {"a": (int, float), "b": (int, float)}, ["a", "b"]),
                    "multiply": ActionDefinition("multiply", "Multiply two numbers", ["math:calc"], {"a": (int, float), "b": (int, float)}, ["a", "b"]),
                    "divide": ActionDefinition("divide", "Divide two numbers", ["math:calc"], {"a": (int, float), "b": (int, float)}, ["a", "b"]),
                },
            )
        )

        # 2. Sandboxed Filesystem
        self.register(
            ToolDefinition(
                tool_name="sandbox_fs",
                tool_version="1.0.0",
                description="Secure sandboxed filesystem operations within designated boundary.",
                category=ToolCategory.FILE_SYSTEM,
                adapter=SandboxedFilesystemAdapter(),
                risk_classification="MEDIUM",
                actions={
                    "list_files": ActionDefinition("list_files", "List files in sandbox directory", ["fs:read"], {"path": str}, []),
                    "read_file": ActionDefinition("read_file", "Read text file from sandbox", ["fs:read"], {"path": str}, ["path"]),
                    "create_file": ActionDefinition("create_file", "Create new text file in sandbox", ["fs:write"], {"path": str, "content": str}, ["path", "content"]),
                    "modify_file": ActionDefinition("modify_file", "Modify existing text file in sandbox", ["fs:write"], {"path": str, "content": str}, ["path", "content"]),
                },
            )
        )

        # 3. Mock Email
        self.register(
            ToolDefinition(
                tool_name="mock_email",
                tool_version="1.0.0",
                description="Simulated email client without outbound network connectivity.",
                category=ToolCategory.EMAIL,
                adapter=MockEmailAdapter(),
                risk_classification="MEDIUM",
                actions={
                    "create_draft": ActionDefinition("create_draft", "Create draft email", ["email:draft"], {"to": str, "subject": str, "body": str}, ["to", "subject"]),
                    "send_email": ActionDefinition("send_email", "Simulate sending an email", ["email:send"], {"to": str, "subject": str, "body": str}, ["to", "subject"]),
                },
            )
        )

        # 4. Mock HTTP
        self.register(
            ToolDefinition(
                tool_name="mock_http",
                tool_version="1.0.0",
                description="Simulated HTTP client returning predefined mock responses with zero outbound networking.",
                category=ToolCategory.NETWORK,
                adapter=MockHttpAdapter(),
                risk_classification="LOW",
                actions={
                    "get": ActionDefinition("get", "Query mock endpoint", ["net:get"], {"endpoint": str}, ["endpoint"]),
                    "post": ActionDefinition("post", "Post data to mock endpoint", ["net:post"], {"endpoint": str, "payload": dict}, ["endpoint"]),
                },
            )
        )


# Global singleton tool registry
tool_registry = ToolRegistry()
