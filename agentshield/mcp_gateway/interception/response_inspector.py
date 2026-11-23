"""
AgentShield AI — MCP Upstream Response Inspector (Phase 8).
"""

from __future__ import annotations

import json
from typing import Any

from agentshield.mcp_gateway.configuration import MCPGatewayConfig, default_mcp_gateway_config
from agentshield.mcp_gateway.exceptions import MCPResponseInspectionError
from agentshield.threat_detection.analyzers.content_analyzer import ContentAnalyzer


class MCPResponseInspector:
    """
    Inspects responses returned by external MCP servers before returning to MCP client.
    - Scans for leaked credentials, secrets, tokens, PII
    - Automatically redacts identified secrets
    - Enforces maximum response payload sizes
    """

    def __init__(self, config: MCPGatewayConfig | None = None) -> None:
        self.config = config or default_mcp_gateway_config

    def inspect_and_sanitize(self, response_payload: dict[str, Any]) -> tuple[dict[str, Any], bool, list[str]]:
        """
        Inspect a JSON-RPC response from an upstream MCP server.
        Returns (sanitized_payload, was_redacted, list_of_detected_secret_types).
        """
        # 1. Size check
        raw_json = json.dumps(response_payload)
        if len(raw_json.encode("utf-8")) > self.config.max_response_size_bytes:
            raise MCPResponseInspectionError(
                f"Response size exceeds maximum limit of {self.config.max_response_size_bytes} bytes"
            )

        # 2. Check if redaction is enabled
        if not self.config.enable_redaction:
            return response_payload, False, []

        result = response_payload.get("result")
        if result is None:
            return response_payload, False, []

        # Redact nested data
        sanitized_result, detected_secrets = ContentAnalyzer.redact_data(result)
        was_redacted = len(detected_secrets) > 0

        if was_redacted:
            sanitized_payload = dict(response_payload)
            sanitized_payload["result"] = sanitized_result
            return sanitized_payload, True, detected_secrets

        return response_payload, False, []
