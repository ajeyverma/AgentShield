"""
AgentShield AI — Safe Streamable HTTP & SSE Transport for MCP (Phase 8).
"""

from __future__ import annotations

from typing import Any
import httpx

from agentshield.mcp_gateway.configuration import MCPGatewayConfig, default_mcp_gateway_config
from agentshield.mcp_gateway.exceptions import MCPSSRFError, MCPTransportError


class StreamableHTTPTransportManager:
    """
    Manages secure remote HTTP / SSE transport connections to upstream MCP servers.
    Enforces SSRF prevention and response size caps.
    """

    def __init__(self, config: MCPGatewayConfig | None = None) -> None:
        self.config = config or default_mcp_gateway_config

    def validate_url(self, url: str) -> None:
        """Validate destination URL against SSRF rules."""
        is_valid, reason = self.config.validate_endpoint_url(url)
        if not is_valid:
            raise MCPSSRFError(reason=reason, endpoint=url)

    async def send_rpc_request(
        self,
        endpoint_url: str,
        payload: dict[str, Any],
        headers: dict[str, str] | None = None,
        timeout: float | None = None,
    ) -> dict[str, Any]:
        """Send JSON-RPC request to remote HTTP MCP endpoint with SSRF check."""
        self.validate_url(endpoint_url)

        req_headers = {"Content-Type": "application/json"}
        if headers:
            req_headers.update(headers)

        req_timeout = timeout or self.config.default_timeout_seconds

        async with httpx.AsyncClient(timeout=req_timeout) as client:
            try:
                response = await client.post(
                    endpoint_url,
                    json=payload,
                    headers=req_headers,
                )
            except Exception as e:
                raise MCPTransportError(f"HTTP request to '{endpoint_url}' failed: {e}")

            if len(response.content) > self.config.max_response_size_bytes:
                raise MCPTransportError(
                    f"Response size {len(response.content)} bytes exceeds maximum allowed limit {self.config.max_response_size_bytes}"
                )

            try:
                return response.json()
            except Exception as e:
                raise MCPTransportError(f"Upstream returned non-JSON response: {e}")
