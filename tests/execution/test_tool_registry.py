"""
Tests for Controlled Tool Registry (Phase 6).
"""

import pytest
from agentshield.execution.exceptions import (
    ActionNotFoundError,
    InvalidArgumentsError,
    ToolDisabledError,
    ToolNotFoundError,
)
from agentshield.execution.registry import tool_registry


class TestToolRegistry:
    def test_default_tools_registered(self):
        tools = tool_registry.list_all()
        tool_names = {t.tool_name for t in tools}
        assert "calculator" in tool_names
        assert "sandbox_fs" in tool_names
        assert "mock_email" in tool_names
        assert "mock_http" in tool_names

    def test_unknown_tool_rejected(self):
        with pytest.raises(ToolNotFoundError):
            tool_registry.get("unknown_super_tool")

    def test_unknown_action_rejected(self):
        with pytest.raises(ActionNotFoundError):
            tool_registry.validate_request("calculator", "integrate", {"x": 10})

    def test_missing_required_argument_rejected(self):
        with pytest.raises(InvalidArgumentsError):
            tool_registry.validate_request("calculator", "add", {"a": 10})  # missing 'b'

    def test_disabled_tool_cannot_execute(self):
        tool_registry.disable_tool("calculator")
        try:
            with pytest.raises(ToolDisabledError):
                tool_registry.get("calculator")
        finally:
            tool_registry.enable_tool("calculator")
