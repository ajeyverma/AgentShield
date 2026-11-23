"""
AgentShield AI — Sandbox Calculator Adapter (Phase 6).
"""

from __future__ import annotations

from typing import Any

from agentshield.execution.adapters.base import BaseToolAdapter
from agentshield.execution.exceptions import ActionNotFoundError, InvalidArgumentsError


class CalculatorAdapter(BaseToolAdapter):
    """Safe, controlled mathematical calculation adapter."""

    tool_name = "calculator"
    tool_version = "1.0.0"

    def run_action(self, action_name: str, arguments: dict[str, Any], context: dict[str, Any] | None = None) -> Any:
        try:
            a = float(arguments.get("a", 0))
            b = float(arguments.get("b", 0))
        except (ValueError, TypeError) as exc:
            raise InvalidArgumentsError(f"Parameters 'a' and 'b' must be numeric: {exc}") from exc

        if action_name == "add":
            return {"operation": "add", "result": a + b}
        elif action_name == "subtract":
            return {"operation": "subtract", "result": a - b}
        elif action_name == "multiply":
            return {"operation": "multiply", "result": a * b}
        elif action_name == "divide":
            if b == 0:
                raise InvalidArgumentsError("Division by zero is not permitted.")
            return {"operation": "divide", "result": a / b}
        else:
            raise ActionNotFoundError(self.tool_name, action_name)
