"""
AgentShield AI — MCP Upstream Client Manager (Phase 8).
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

from agentshield.mcp_gateway.configuration import MCPGatewayConfig, default_mcp_gateway_config
from agentshield.mcp_gateway.exceptions import MCPServerConnectionError, MCPTransportError
from agentshield.mcp_gateway.protocol.messages import make_jsonrpc_response
from agentshield.mcp_gateway.transports.stdio import StdioTransportManager
from agentshield.mcp_gateway.transports.streamable_http import StreamableHTTPTransportManager

logger = logging.getLogger("agentshield.mcp_gateway.client")


class MCPUpstreamClient:
    """
    Manages client connection session to an upstream external MCP server.
    Supports STDIO process transports and Streamable HTTP endpoints.
    """

    def __init__(
        self,
        server_id: str,
        server_name: str,
        transport_type: str,
        endpoint_or_command: str,
        args: list[str] | None = None,
        env: dict[str, str] | None = None,
        config: MCPGatewayConfig | None = None,
    ) -> None:
        self.server_id = server_id
        self.server_name = server_name
        self.transport_type = transport_type.lower()
        self.endpoint_or_command = endpoint_or_command
        self.args = args or []
        self.env = env or {}
        self.config = config or default_mcp_gateway_config

        self.stdio_mgr = StdioTransportManager(self.config)
        self.http_mgr = StreamableHTTPTransportManager(self.config)

        self._process: asyncio.subprocess.Process | None = None
        self._connected: bool = False
        self._capabilities: dict[str, Any] = {}
        self._request_counter: int = 1
        self._lock = asyncio.Lock()

    @property
    def is_connected(self) -> bool:
        return self._connected

    async def connect(self) -> dict[str, Any]:
        """Establish connection to upstream MCP server and perform initialization handshake."""
        if self._connected:
            return self._capabilities

        if self.transport_type == "stdio":
            executable = self.stdio_mgr.resolve_executable(self.endpoint_or_command)
            safe_env = self.stdio_mgr.build_safe_environment(self.env)
            cmd = [executable] + self.args
            try:
                self._process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdin=asyncio.subprocess.PIPE,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    env=safe_env,
                )
            except Exception as e:
                raise MCPServerConnectionError(self.server_id, f"Failed to spawn STDIO process: {e}")

        # Send initialize handshake
        init_payload = {
            "jsonrpc": "2.0",
            "id": "init-1",
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "tools": {"listChanged": True},
                    "resources": {"subscribe": True, "listChanged": True},
                    "prompts": {"listChanged": True},
                },
                "clientInfo": {
                    "name": "AgentShield-MCP-Gateway",
                    "version": "1.0.0",
                },
            },
        }

        try:
            resp = await self._send_raw_message(init_payload)
            if "error" in resp:
                raise MCPServerConnectionError(self.server_id, f"Upstream rejected initialize: {resp['error']}")
            result = resp.get("result", {})
            self._capabilities = result.get("capabilities", {})
            self._connected = True

            # Send notifications/initialized
            await self._send_notification({"jsonrpc": "2.0", "method": "notifications/initialized"})
            return self._capabilities
        except Exception as e:
            await self.close()
            raise MCPServerConnectionError(self.server_id, f"Handshake failed: {e}")

    async def _send_notification(self, payload: dict[str, Any]) -> None:
        """Send one-way notification."""
        if self.transport_type == "stdio" and self._process and self._process.stdin:
            line = json.dumps(payload) + "\n"
            self._process.stdin.write(line.encode("utf-8"))
            await self._process.stdin.drain()
        elif self.transport_type in ("streamable_http", "sse", "http"):
            try:
                await self.http_mgr.send_rpc_request(self.endpoint_or_command, payload)
            except Exception:
                pass  # Notifications are fire-and-forget

    async def _send_raw_message(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Send message across active transport."""
        if self.transport_type == "stdio":
            if not self._process or not self._process.stdin or not self._process.stdout:
                raise MCPTransportError("STDIO transport process is not running")

            line = json.dumps(payload) + "\n"
            async with self._lock:
                self._process.stdin.write(line.encode("utf-8"))
                await self._process.stdin.drain()

                try:
                    raw_line = await asyncio.wait_for(
                        self._process.stdout.readline(),
                        timeout=self.config.default_timeout_seconds,
                    )
                    if not raw_line:
                        raise MCPTransportError("Upstream STDIO process closed output stream prematurely.")
                    return json.loads(raw_line.decode("utf-8").strip())
                except asyncio.TimeoutError:
                    raise MCPTransportError("Upstream STDIO process timed out waiting for response.")
                except Exception as e:
                    raise MCPTransportError(f"STDIO communication failure: {e}")

        elif self.transport_type in ("streamable_http", "sse", "http"):
            return await self.http_mgr.send_rpc_request(
                self.endpoint_or_command,
                payload,
                timeout=self.config.default_timeout_seconds,
            )

        raise MCPTransportError(f"Unsupported transport type: {self.transport_type}")

    async def execute_request(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Dispatch a JSON-RPC request to upstream server and return result payload."""
        if not self._connected:
            await self.connect()

        self._request_counter += 1
        req_id = f"req-{self._request_counter}"
        payload = {
            "jsonrpc": "2.0",
            "id": req_id,
            "method": method,
        }
        if params is not None:
            payload["params"] = params

        return await self._send_raw_message(payload)

    async def close(self) -> None:
        """Close connection and clean up process/network resources."""
        self._connected = False
        if self._process:
            try:
                if self._process.stdin and not self._process.stdin.is_closing():
                    self._process.stdin.close()
                self._process.terminate()
                await asyncio.wait_for(self._process.wait(), timeout=2.0)
            except Exception:
                try:
                    self._process.kill()
                except Exception:
                    pass
            finally:
                self._process = None
