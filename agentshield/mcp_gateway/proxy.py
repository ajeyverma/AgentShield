"""
AgentShield AI — MCP Firewall Gateway Proxy (Phase 8).
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from agentshield.contracts.events import EventComponent, EventSeverity
from agentshield.database.models.mcp import MCPActivityModel, MCPServerModel
from agentshield.mcp_gateway.client import MCPUpstreamClient
from agentshield.mcp_gateway.configuration import MCPGatewayConfig, default_mcp_gateway_config
from agentshield.mcp_gateway.exceptions import (
    MCPApprovalRequiredError,
    MCPBlockedError,
    MCPGatewayError,
    MCPProtocolError,
    MCPSecurityError,
    MCPServerConnectionError,
)
from agentshield.mcp_gateway.interception.response_inspector import MCPResponseInspector
from agentshield.mcp_gateway.protocol.messages import (
    GATEWAY_APPROVAL_REQUIRED,
    GATEWAY_POLICY_BLOCK,
    GATEWAY_SECURITY_VIOLATION,
    GATEWAY_UPSTREAM_ERROR,
    INTERNAL_ERROR,
    INVALID_REQUEST,
    METHOD_NOT_FOUND,
    make_jsonrpc_error,
    make_jsonrpc_response,
)
from agentshield.mcp_gateway.protocol.validation import SUPPORTED_METHODS, validate_jsonrpc_payload
from agentshield.mcp_gateway.registry.server_registry import MCPServerRegistry
from agentshield.mcp_gateway.registry.tool_registry import MCPToolRegistry
from agentshield.mcp_gateway.security.authorization import MCPAuthorizationService
from agentshield.observability.event_publisher import event_publisher

logger = logging.getLogger("agentshield.mcp_gateway.proxy")


class MCPFirewallGateway:
    """
    Core protocol-level security gateway mediating interactions between
    MCP clients and upstream external MCP servers.
    """

    def __init__(
        self,
        config: MCPGatewayConfig | None = None,
        tool_registry: MCPToolRegistry | None = None,
        server_registry: MCPServerRegistry | None = None,
    ) -> None:
        self.config = config or default_mcp_gateway_config
        self.tool_registry = tool_registry or MCPToolRegistry()
        self.server_registry = server_registry or MCPServerRegistry(self.config)
        self.response_inspector = MCPResponseInspector(self.config)
        # Active upstream client connections: server_id -> MCPUpstreamClient
        self._clients: dict[str, MCPUpstreamClient] = {}

    def get_or_create_client(self, server: MCPServerModel) -> MCPUpstreamClient:
        """Retrieve cached client session or create a new one."""
        if server.id in self._clients:
            client = self._clients[server.id]
            if client.is_connected:
                return client

        args = json.loads(server.args_json) if server.args_json else []
        env = json.loads(server.env_json) if server.env_json else {}

        client = MCPUpstreamClient(
            server_id=server.id,
            server_name=server.server_name,
            transport_type=server.transport_type,
            endpoint_or_command=server.endpoint_or_command,
            args=args,
            env=env,
            config=self.config,
        )
        self._clients[server.id] = client
        return client

    async def handle_client_message(
        self,
        session: AsyncSession,
        user_id: str,
        server_id: str,
        raw_payload: str | bytes | dict[str, Any],
        agent_id: str | None = None,
        approval_id: str | None = None,
    ) -> dict[str, Any]:
        """
        Full gateway interception pipeline:
        1. Protocol Validation
        2. Tenant & Server Isolation
        3. Discovery & Schema Inspection
        4. Threat Detection & Security Decision (ALLOW, BLOCK, ASK_HUMAN)
        5. Forwarding to external server (only if authorized)
        6. Response Inspection & Secret Redaction
        7. Audit Logging
        """
        start_time = time.perf_counter()
        req_id: Any = None
        method = "unknown"

        # 1. Protocol Validation
        try:
            payload = validate_jsonrpc_payload(raw_payload)
            req_id = payload.get("id")
            method = payload.get("method", "")
        except MCPProtocolError as e:
            return make_jsonrpc_error(req_id, e.rpc_error_code, e.message)
        except Exception as e:
            return make_jsonrpc_error(req_id, INVALID_REQUEST, f"Protocol validation error: {e}")

        # Check supported method
        if method not in SUPPORTED_METHODS and not ("result" in payload or "error" in payload):
            return make_jsonrpc_error(req_id, METHOD_NOT_FOUND, f"Unsupported MCP method: '{method}'")

        # 2. Tenant Isolation & Server Retrieval
        try:
            server = await self.server_registry.get_server(session, server_id, user_id)
            if not server.is_enabled:
                return make_jsonrpc_error(req_id, GATEWAY_POLICY_BLOCK, f"MCP server '{server.server_name}' is disabled.")
        except Exception as e:
            return make_jsonrpc_error(req_id, GATEWAY_UPSTREAM_ERROR, f"Server access denied: {e}")

        client_uuid = agent_id or str(uuid.uuid4())
        upstream_client = self.get_or_create_client(server)
        params = payload.get("params") or {}

        # 3. Handle Initialize and Ping
        if method == "initialize":
            return make_jsonrpc_response(
                req_id,
                {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {
                        "tools": {"listChanged": True},
                        "resources": {"subscribe": True, "listChanged": True},
                        "prompts": {"listChanged": True},
                    },
                    "serverInfo": {
                        "name": f"AgentShield-MCP-Gateway[{server.server_name}]",
                        "version": "1.0.0",
                    },
                },
            )

        if method == "ping":
            return make_jsonrpc_response(req_id, {})

        # 4. Handle Tool Discovery (`tools/list`)
        if method == "tools/list":
            return await self._handle_tools_list(
                session=session,
                server=server,
                client=upstream_client,
                req_id=req_id,
                user_id=user_id,
                start_time=start_time,
            )

        # 5. Intercept Protected Operations: `tools/call`, `resources/read`, `prompts/get`
        if method in ("tools/call", "resources/read", "prompts/get"):
            return await self._handle_protected_operation(
                session=session,
                server=server,
                client=upstream_client,
                user_id=user_id,
                agent_id=client_uuid,
                req_id=req_id,
                method=method,
                params=params,
                approval_id=approval_id,
                start_time=start_time,
            )

        # 6. Pass through non-sensitive read-only list operations: resources/list, prompts/list
        try:
            upstream_resp = await upstream_client.execute_request(method, params)
            sanitized_resp, was_redacted, _ = self.response_inspector.inspect_and_sanitize(upstream_resp)
            sanitized_resp["id"] = req_id
            return sanitized_resp
        except Exception as e:
            return make_jsonrpc_error(req_id, GATEWAY_UPSTREAM_ERROR, f"Upstream communication failure: {e}")

    async def _handle_tools_list(
        self,
        session: AsyncSession,
        server: MCPServerModel,
        client: MCPUpstreamClient,
        req_id: Any,
        user_id: str,
        start_time: float,
    ) -> dict[str, Any]:
        """Fetch upstream tools, namespace them, and inspect schemas for injection."""
        try:
            upstream_resp = await client.execute_request("tools/list")
        except Exception as e:
            return make_jsonrpc_error(req_id, GATEWAY_UPSTREAM_ERROR, f"Failed to list tools from upstream server: {e}")

        result = upstream_resp.get("result", {})
        raw_tools = result.get("tools", [])
        namespaced_tools: list[dict[str, Any]] = []

        for rt in raw_tools:
            raw_name = rt.get("name", "")
            desc = rt.get("description", "")
            schema = rt.get("inputSchema", {})

            # Register in tool registry to produce namespaced name
            disc_tool = self.tool_registry.register_tool(
                server_id=server.id,
                server_name=server.server_name,
                original_name=raw_name,
                description=desc,
                input_schema=schema,
            )

            # Build namespaced tool descriptor for client
            namespaced_tool = {
                "name": disc_tool.namespaced_name,
                "description": f"[{server.server_name}] {desc}",
                "inputSchema": schema,
            }
            namespaced_tools.append(namespaced_tool)

        duration = (time.perf_counter() - start_time) * 1000
        # Audit discovery
        activity = MCPActivityModel(
            id=str(uuid.uuid4()),
            user_id=user_id,
            server_id=server.id,
            operation_type="tools/list",
            target_name=server.server_name,
            decision="ALLOW",
            status="SUCCESS",
            request_summary=f"tools/list on server '{server.server_name}'",
            response_summary=f"Discovered {len(namespaced_tools)} tools",
            redaction_applied=False,
            threat_count=0,
            duration_ms=duration,
        )
        session.add(activity)
        await session.commit()

        return make_jsonrpc_response(req_id, {"tools": namespaced_tools})

    async def _handle_protected_operation(
        self,
        session: AsyncSession,
        server: MCPServerModel,
        client: MCPUpstreamClient,
        user_id: str,
        agent_id: str,
        req_id: Any,
        method: str,
        params: dict[str, Any],
        approval_id: str | None,
        start_time: float,
    ) -> dict[str, Any]:
        """
        Intercept, evaluate security, and forward protected operations.
        """
        target_name = params.get("name") or params.get("uri") or method
        raw_target_name = target_name
        upstream_params = dict(params)

        # If tools/call, resolve namespaced name back to upstream original name
        if method == "tools/call":
            namespaced_name = params.get("name", "")
            tool_entry = self.tool_registry.get_tool(namespaced_name, server.id)
            if tool_entry:
                raw_target_name = tool_entry.original_name
                upstream_params["name"] = raw_target_name

        auth_service = MCPAuthorizationService(session)

        try:
            decision, grant = await auth_service.evaluate_operation(
                user_id=user_id,
                agent_id=agent_id,
                method=method,
                params=params,
                approval_id=approval_id,
            )
        except MCPBlockedError as e:
            # Operation was BLOCKED — NEVER forward upstream
            duration = (time.perf_counter() - start_time) * 1000
            activity = MCPActivityModel(
                id=str(uuid.uuid4()),
                user_id=user_id,
                server_id=server.id,
                client_id=agent_id,
                operation_type=method,
                target_name=target_name,
                decision="BLOCK",
                status="BLOCKED",
                request_summary=json.dumps(params)[:500],
                response_summary=e.message,
                redaction_applied=False,
                threat_count=1,
                duration_ms=duration,
            )
            session.add(activity)
            await session.commit()
            await event_publisher.publish(
                session=session,
                event_type="mcp.blocked",
                severity=EventSeverity.HIGH,
                component=EventComponent.MCP_GATEWAY,
                tenant_id=user_id,
                agent_id=agent_id,
                tool_name=target_name,
                action=method,
                decision="BLOCK",
                status="BLOCKED",
                latency_ms=duration,
                details={"reason": e.message, "server_id": server.id, "error_code": e.rpc_error_code},
            )
            return make_jsonrpc_error(req_id, e.rpc_error_code, e.message, data=e.details)

        except MCPApprovalRequiredError as e:
            # Operation PAUSED for Human Approval — NEVER forward upstream
            duration = (time.perf_counter() - start_time) * 1000
            activity = MCPActivityModel(
                id=str(uuid.uuid4()),
                user_id=user_id,
                server_id=server.id,
                client_id=agent_id,
                operation_type=method,
                target_name=target_name,
                decision="ASK_HUMAN",
                approval_id=e.approval_id,
                status="PENDING_APPROVAL",
                request_summary=json.dumps(params)[:500],
                response_summary=e.message,
                redaction_applied=False,
                threat_count=0,
                duration_ms=duration,
            )
            session.add(activity)
            await session.commit()
            await event_publisher.publish(
                session=session,
                event_type="mcp.approval_required",
                severity=EventSeverity.MEDIUM,
                component=EventComponent.MCP_GATEWAY,
                tenant_id=user_id,
                agent_id=agent_id,
                tool_name=target_name,
                action=method,
                decision="ASK_HUMAN",
                status="PENDING_APPROVAL",
                latency_ms=duration,
                details={"approval_id": e.approval_id, "server_id": server.id},
            )
            return make_jsonrpc_error(req_id, e.rpc_error_code, e.message, data=e.details)

        # Operation is AUTHORIZED (Decision.ALLOW) -> Forward to upstream external server
        try:
            upstream_resp = await client.execute_request(method, upstream_params)
        except Exception as e:
            duration = (time.perf_counter() - start_time) * 1000
            activity = MCPActivityModel(
                id=str(uuid.uuid4()),
                user_id=user_id,
                server_id=server.id,
                client_id=agent_id,
                operation_type=method,
                target_name=target_name,
                decision="ALLOW",
                status="FAILED",
                request_summary=json.dumps(params)[:500],
                response_summary=f"Upstream execution error: {e}",
                redaction_applied=False,
                threat_count=0,
                duration_ms=duration,
            )
            session.add(activity)
            await session.commit()
            return make_jsonrpc_error(req_id, GATEWAY_UPSTREAM_ERROR, f"Upstream external server error: {e}")

        # 6. Response Inspection & Secret Redaction
        try:
            sanitized_resp, was_redacted, detected_secrets = self.response_inspector.inspect_and_sanitize(upstream_resp)
        except Exception as e:
            duration = (time.perf_counter() - start_time) * 1000
            return make_jsonrpc_error(req_id, GATEWAY_SECURITY_VIOLATION, f"Response inspection violation: {e}")

        duration = (time.perf_counter() - start_time) * 1000
        # 7. Audit Logging
        activity = MCPActivityModel(
            id=str(uuid.uuid4()),
            user_id=user_id,
            server_id=server.id,
            client_id=agent_id,
            operation_type=method,
            target_name=target_name,
            decision="ALLOW",
            decision_id=str(decision.decision_id) if decision else None,
            status="SUCCESS",
            request_summary=json.dumps(params)[:500],
            response_summary=json.dumps(sanitized_resp.get("result", {}))[:500],
            redaction_applied=was_redacted,
            threat_count=len(detected_secrets),
            duration_ms=duration,
        )
        session.add(activity)
        await session.commit()
        await event_publisher.publish(
            session=session,
            event_type="mcp.executed",
            severity=EventSeverity.INFO,
            component=EventComponent.MCP_GATEWAY,
            tenant_id=user_id,
            agent_id=agent_id,
            tool_name=target_name,
            action=method,
            decision="ALLOW",
            status="SUCCESS",
            latency_ms=duration,
            details={"server_id": server.id, "redacted": was_redacted},
        )

        sanitized_resp["id"] = req_id
        return sanitized_resp

    async def close_all(self) -> None:
        """Close all upstream connections."""
        for client in self._clients.values():
            try:
                await client.close()
            except Exception:
                pass
        self._clients.clear()


# Global singleton gateway
mcp_gateway = MCPFirewallGateway()
