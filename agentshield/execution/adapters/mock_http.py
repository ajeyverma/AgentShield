"""
AgentShield AI — Mock HTTP Adapter (Phase 6).

Returns predefined mock HTTP responses. Guarantees no arbitrary outbound network
requests or SSRF.
"""

from __future__ import annotations

from typing import Any

from agentshield.execution.adapters.base import BaseToolAdapter
from agentshield.execution.exceptions import ActionNotFoundError, InvalidArgumentsError

# Whitelisted mock endpoints and synthetic responses
PREDEFINED_RESPONSES: dict[str, Any] = {
    "/weather": {"location": "San Francisco", "temp_c": 18, "condition": "Sunny"},
    "/status": {"system": "operational", "version": "1.0.0", "load": "normal"},
    "/rates": {"base": "USD", "EUR": 0.92, "GBP": 0.79, "JPY": 154.2},
}


class MockHttpAdapter(BaseToolAdapter):
    """Controlled mock HTTP client with zero external network connectivity."""

    tool_name = "mock_http"
    tool_version = "1.0.0"

    def run_action(self, action_name: str, arguments: dict[str, Any], context: dict[str, Any] | None = None) -> Any:
        endpoint = str(arguments.get("endpoint", "")).strip().lower()

        if not endpoint:
            raise InvalidArgumentsError("Parameter 'endpoint' is required.")

        # Reject any attempt to supply absolute external URLs
        if "://" in endpoint or endpoint.startswith("//"):
            raise InvalidArgumentsError("External URLs are not permitted. Only predefined local mock endpoints are supported.")

        if endpoint not in PREDEFINED_RESPONSES:
            raise InvalidArgumentsError(
                f"Unknown mock endpoint '{endpoint}'. Available: {list(PREDEFINED_RESPONSES.keys())}"
            )

        if action_name == "get":
            return {
                "endpoint": endpoint,
                "status_code": 200,
                "data": PREDEFINED_RESPONSES[endpoint],
            }
        elif action_name == "post":
            payload = arguments.get("payload", {})
            return {
                "endpoint": endpoint,
                "status_code": 201,
                "received_payload": payload,
                "message": "Mock record created successfully.",
            }
        else:
            raise ActionNotFoundError(self.tool_name, action_name)
