"""
AgentShield AI — Tool Wrapping and Interception for OpenAI Agents SDK (Phase 7).
"""

from __future__ import annotations

import json
import logging
from typing import Any

import agents
from agents.tool import FunctionTool

from agentshield.integrations.openai_agents.client import AgentShieldOpenAIClient
from agentshield.integrations.openai_agents.configuration import AgentShieldIntegrationConfig
from agentshield.integrations.openai_agents.exceptions import ToolNotAllowedError
from agentshield.integrations.openai_agents.schemas import AgentShieldToolResult, OpenAIToolCall

logger = logging.getLogger("agentshield.integrations.openai_agents.tool_wrapper")


class AgentShieldToolWrapper:
    """Interception wrapper exposing only explicitly permitted AgentShield tools to the OpenAI agent.

    Guarantees:
    - Never executes tools locally or directly on host.
    - All invocations are dispatched to the server-side Controlled Execution Gateway.
    - Strict allowlist filtering.
    """

    def __init__(
        self,
        client: AgentShieldOpenAIClient,
        config: AgentShieldIntegrationConfig,
    ) -> None:
        self.client = client
        self.config = config
        self.call_history: list[OpenAIToolCall] = []

    def _record_call(self, tool_name: str, action_name: str, arguments: dict[str, Any]) -> None:
        call = OpenAIToolCall(tool_name=tool_name, action_name=action_name, arguments=arguments)
        self.call_history.append(call)
        logger.info("Intercepted OpenAI agent tool call: %s.%s", tool_name, action_name)

    def _execute_through_gateway(self, tool_name: str, action_name: str, arguments: dict[str, Any]) -> str:
        """Route tool invocation to AgentShield and return safe JSON output to the agent."""
        if tool_name not in self.config.allowed_tools:
            logger.warning("Agent attempted unauthorized tool invocation: %s", tool_name)
            res = AgentShieldToolResult(
                status="BLOCKED",
                decision="BLOCK",
                error_code="TOOL_NOT_ALLOWED",
                error_message=f"Tool '{tool_name}' is not permitted by your AgentShield configuration allowlist.",
            )
            return json.dumps(res.to_model_output())

        self._record_call(tool_name, action_name, arguments)

        # Dispatch exclusively through AgentShield Gateway client (NEVER local execution)
        result = self.client.execute_tool(
            tool_name=tool_name,
            action_name=action_name,
            arguments=arguments,
        )

        return json.dumps(result.to_model_output())

    def get_wrapped_tools(self) -> list[FunctionTool]:
        """Generate OpenAI Agents SDK FunctionTools for all permitted tools."""
        tools: list[FunctionTool] = []
        allowed = set(self.config.allowed_tools)

        # ── 1. Calculator Tool ──────────────────────────────────────────────
        if "calculator" in allowed:
            def _calc_add(a: float, b: float) -> str:
                """Add two numbers (a + b)."""
                return self._execute_through_gateway("calculator", "add", {"a": a, "b": b})

            calculator_add = agents.function_tool(
                _calc_add,
                name_override="calculator_add",
                description_override="Add two numbers securely through AgentShield.",
            )
            setattr(calculator_add, "function", _calc_add)

            def _calc_sub(a: float, b: float) -> str:
                """Subtract b from a (a - b)."""
                return self._execute_through_gateway("calculator", "subtract", {"a": a, "b": b})

            calculator_subtract = agents.function_tool(
                _calc_sub,
                name_override="calculator_subtract",
                description_override="Subtract number b from number a securely through AgentShield.",
            )
            setattr(calculator_subtract, "function", _calc_sub)

            def _calc_mul(a: float, b: float) -> str:
                """Multiply two numbers (a * b)."""
                return self._execute_through_gateway("calculator", "multiply", {"a": a, "b": b})

            calculator_multiply = agents.function_tool(
                _calc_mul,
                name_override="calculator_multiply",
                description_override="Multiply two numbers securely through AgentShield.",
            )
            setattr(calculator_multiply, "function", _calc_mul)

            def _calc_div(a: float, b: float) -> str:
                """Divide a by b (a / b)."""
                return self._execute_through_gateway("calculator", "divide", {"a": a, "b": b})

            calculator_divide = agents.function_tool(
                _calc_div,
                name_override="calculator_divide",
                description_override="Divide number a by number b securely through AgentShield.",
            )
            setattr(calculator_divide, "function", _calc_div)

            tools.extend([calculator_add, calculator_subtract, calculator_multiply, calculator_divide])

        # ── 2. Sandboxed Filesystem Tool ────────────────────────────────────
        if "sandbox_fs" in allowed:
            def _fs_create(path: str, content: str) -> str:
                """Create a file inside sandbox workspace with specified text content."""
                return self._execute_through_gateway("sandbox_fs", "create_file", {"path": path, "content": content})

            sandbox_fs_create_file = agents.function_tool(
                _fs_create,
                name_override="sandbox_fs_create_file",
                description_override="Create or write text content to a file inside the isolated sandbox directory.",
            )
            setattr(sandbox_fs_create_file, "function", _fs_create)

            def _fs_read(path: str) -> str:
                """Read a file from the sandbox workspace."""
                return self._execute_through_gateway("sandbox_fs", "read_file", {"path": path})

            sandbox_fs_read_file = agents.function_tool(
                _fs_read,
                name_override="sandbox_fs_read_file",
                description_override="Read text content from a file inside the isolated sandbox directory.",
            )
            setattr(sandbox_fs_read_file, "function", _fs_read)

            def _fs_mod(path: str, content: str) -> str:
                """Modify an existing file in the sandbox workspace."""
                return self._execute_through_gateway("sandbox_fs", "modify_file", {"path": path, "content": content})

            sandbox_fs_modify_file = agents.function_tool(
                _fs_mod,
                name_override="sandbox_fs_modify_file",
                description_override="Modify an existing file inside the isolated sandbox directory.",
            )
            setattr(sandbox_fs_modify_file, "function", _fs_mod)

            def _fs_list(path: str = "") -> str:
                """List files in the sandbox workspace directory."""
                return self._execute_through_gateway("sandbox_fs", "list_files", {"path": path})

            sandbox_fs_list_files = agents.function_tool(
                _fs_list,
                name_override="sandbox_fs_list_files",
                description_override="List files in a subdirectory inside the isolated sandbox directory.",
            )
            setattr(sandbox_fs_list_files, "function", _fs_list)

            tools.extend([sandbox_fs_create_file, sandbox_fs_read_file, sandbox_fs_modify_file, sandbox_fs_list_files])

        # ── 3. Mock Email Tool ──────────────────────────────────────────────
        if "mock_email" in allowed:
            def _email_draft(to: str, subject: str, body: str) -> str:
                """Save a simulated email draft."""
                return self._execute_through_gateway("mock_email", "create_draft", {"to": to, "subject": subject, "body": body})

            mock_email_create_draft = agents.function_tool(
                _email_draft,
                name_override="mock_email_create_draft",
                description_override="Save a simulated email draft securely through AgentShield.",
            )
            setattr(mock_email_create_draft, "function", _email_draft)

            def _email_send(to: str, subject: str, body: str) -> str:
                """Simulate sending an email message."""
                return self._execute_through_gateway("mock_email", "send_email", {"to": to, "subject": subject, "body": body})

            mock_email_send_email = agents.function_tool(
                _email_send,
                name_override="mock_email_send_email",
                description_override="Simulate sending an email securely through AgentShield.",
            )
            setattr(mock_email_send_email, "function", _email_send)

            tools.extend([mock_email_create_draft, mock_email_send_email])

        # ── 4. Mock HTTP Tool ───────────────────────────────────────────────
        if "mock_http" in allowed:
            def _http_get(endpoint: str) -> str:
                """Fetch mock data from predefined safe endpoint."""
                return self._execute_through_gateway("mock_http", "get", {"endpoint": endpoint})

            mock_http_get = agents.function_tool(
                _http_get,
                name_override="mock_http_get",
                description_override="Perform a simulated HTTP GET request to allowed mock endpoints (/weather, /status, /rates).",
            )
            setattr(mock_http_get, "function", _http_get)

            def _http_post(endpoint: str, payload: str = "{}") -> str:
                """Send mock data to predefined safe endpoint."""
                return self._execute_through_gateway("mock_http", "post", {"endpoint": endpoint, "payload": payload})

            mock_http_post = agents.function_tool(
                _http_post,
                name_override="mock_http_post",
                description_override="Perform a simulated HTTP POST request to allowed mock endpoints.",
            )
            setattr(mock_http_post, "function", _http_post)

            tools.extend([mock_http_get, mock_http_post])

        return tools
