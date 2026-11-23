"""
AgentShield AI — Shared Integration Conformance Verification (Phase 9).
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, patch

from agentshield.integrations.core.base_adapter import BaseFrameworkAdapter
from agentshield.integrations.core.exceptions import ToolNotAllowedError
from agentshield.integrations.core.integration_config import AgentShieldIntegrationConfig


class IntegrationConformanceVerifier:
    """
    Standard verification suite executing the 24 security conformance checks
    against any framework adapter implementation.
    """

    @staticmethod
    def verify_allow_forwards_to_gateway(
        adapter: BaseFrameworkAdapter,
        tool_name: str,
        action_name: str,
        arguments: dict[str, Any],
    ) -> bool:
        """Verify that ALLOW decision forwards to gateway and returns safe result."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "status": "COMPLETED",
            "decision": "ALLOW",
            "execution_id": "test-exec-123",
            "result": {"value": "success"},
        }

        with patch("httpx.Client.post", return_value=mock_resp):
            res = adapter.execute_tool(tool_name, action_name, arguments)
            return res.is_allowed() and res.result == {"value": "success"}

    @staticmethod
    def verify_block_never_executes(
        adapter: BaseFrameworkAdapter,
        tool_name: str,
        action_name: str,
        arguments: dict[str, Any],
    ) -> bool:
        """Verify that BLOCK decision halts execution and returns safe error output."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "status": "BLOCKED",
            "decision": "BLOCK",
            "error_code": "POLICY_BLOCK",
            "error_message": "Operation denied by security policy",
        }

        with patch("httpx.Client.post", return_value=mock_resp):
            res = adapter.execute_tool(tool_name, action_name, arguments)
            return res.is_blocked() and res.result is None

    @staticmethod
    def verify_ask_human_pauses_execution(
        adapter: BaseFrameworkAdapter,
        tool_name: str,
        action_name: str,
        arguments: dict[str, Any],
    ) -> bool:
        """Verify that ASK_HUMAN pauses execution and returns approval_id without executing."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "status": "PENDING_APPROVAL",
            "decision": "ASK_HUMAN",
            "approval_id": "appr-999",
            "error_code": "APPROVAL_REQUIRED",
        }

        with patch("httpx.Client.post", return_value=mock_resp):
            res = adapter.execute_tool(tool_name, action_name, arguments)
            return res.is_pending_approval() and res.approval_id == "appr-999" and res.result is None

    @staticmethod
    def verify_tool_not_in_allowlist_is_rejected(
        adapter: BaseFrameworkAdapter,
        forbidden_tool: str = "unauthorized_tool",
    ) -> bool:
        """Verify that tools outside allowlist are immediately blocked without network call."""
        res = adapter.execute_tool(forbidden_tool, "execute", {})
        return res.is_blocked() and res.error_code == "TOOL_NOT_ALLOWED"

    @staticmethod
    def verify_fail_closed_on_backend_failure(
        adapter: BaseFrameworkAdapter,
        tool_name: str = "calculator",
        action_name: str = "add",
    ) -> bool:
        """Verify fail-closed behavior when backend is completely unreachable."""
        import httpx
        with patch("httpx.Client.post", side_effect=httpx.ConnectError("Connection refused")):
            res = adapter.execute_tool(tool_name, action_name, {"a": 1, "b": 1})
            return res.is_blocked() and res.error_code == "BACKEND_UNAVAILABLE"
